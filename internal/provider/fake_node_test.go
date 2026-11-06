package provider

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The node's own settings, as PBS 4.2.8 serves them (see
// internal/pbsclient/node.go and subscription.go): node.cfg through the ACME
// fake, which keeps it, and DNS, time and subscription through fakeNode.
//
// node.cfg, on top of what fakeACME does: PBS reads plain values back
// trimmed, task-log-max-days as a number, the description with a line break
// after every line — an empty one is no description —, and the location in
// its own form; it refuses what its schema refuses, and a newline in a plain
// value.

// fakeNodeConfigJSON is node.cfg as GET answers it.
func fakeNodeConfigJSON(node map[string]string) map[string]any {
	out := make(map[string]any, len(node))
	for key, value := range node {
		if key == "task-log-max-days" {
			n, _ := strconv.ParseInt(value, 10, 64)
			out[key] = n
			continue
		}
		out[key] = value
	}
	return out
}

var (
	fakeOldCommentPattern = regexp.MustCompile(`(?m)^([[:^cntrl:]]*)$`)
	fakeNewCommentPattern = regexp.MustCompile(`\A(?:[[:^cntrl:]]|[\t\n])*\z`)
	fakeCipherPattern     = regexp.MustCompile(`^[0-9A-Za-z_:, +!\-@=.]+$`)
	fakeProxyPattern      = regexp.MustCompile(`^(?:(http|[a-z]+)://)?(?:[^@/]+@)?([^:/@]+|\[[^\]]+\])(?::[0-9]+)?/?$`)
)

// fakeNodeSettingsCheck checks node.cfg as PBS's PUT would write it, and
// puts values in the form PBS reads them back in. It returns PBS's error.
func fakeNodeSettingsCheck(node map[string]string) string {
	for key, value := range node {
		if key != "description" && strings.Contains(value, "\n") {
			return fmt.Sprintf("value for %s contains newlines", key)
		}
		if key != "description" {
			node[key] = strings.TrimSpace(value)
		}
	}
	if proxy, ok := node["http-proxy"]; ok {
		m := fakeProxyPattern.FindStringSubmatch(proxy)
		switch {
		case m == nil || len(proxy) > 128:
			return "parameter verification failed - 'http-proxy': parse_proxy_url failed: missing proxy authority"
		case m[1] != "" && m[1] != "http":
			return fmt.Sprintf("parameter verification failed - 'http-proxy': parse_proxy_url failed: unsupported proxy scheme '%s'", m[1])
		}
	}
	if from, ok := node["email-from"]; ok && (len(from) < 2 || len(from) > 64) {
		return "parameter verification failed - 'email-from': value may only be 64 characters long"
	}
	for _, key := range []string{"ciphers-tls-1.2", "ciphers-tls-1.3"} {
		if ciphers, ok := node[key]; ok && !fakeCipherPattern.MatchString(ciphers) {
			return fmt.Sprintf("parameter verification failed - '%s': value does not match the regex pattern", key)
		}
	}
	if lang, ok := node["default-lang"]; ok && !slices.Contains(nodeLanguages, lang) {
		return fmt.Sprintf("parameter verification failed - 'default-lang': value '%s' is not defined in the enumeration.", lang)
	}
	if days, ok := node["task-log-max-days"]; ok {
		if n, err := strconv.ParseInt(days, 10, 64); err != nil || n < 0 {
			return "parameter verification failed - 'task-log-max-days': value must have a minimum value of 0"
		}
	}
	if text, ok := node["consent-text"]; ok && len(text) > 64*1024 {
		return "parameter verification failed - 'consent-text': value may only be 65536 characters long"
	}
	if description, ok := node["description"]; ok {
		// PBS before proxmox-schema 5.4 wants a line free of control
		// characters; from 5.4, none but line breaks and tabs.
		if !fakeOldCommentPattern.MatchString(description) || !fakeNewCommentPattern.MatchString(description) {
			return "parameter verification failed - 'description': value does not match the regex pattern"
		}
		if description == "" {
			delete(node, "description")
		} else {
			node["description"] = storedDescription(description)
		}
	}
	if raw, ok := node["location"]; ok {
		location, err := pbsclient.ParseNodeLocation(raw)
		switch {
		case err != nil:
			return "value without key, but schema does not define a default key"
		case location.Latitude < -90 || location.Latitude > 90:
			return fmt.Sprintf("value must have a maximum value of 90 (got %v)", location.Latitude)
		case location.Longitude < -180 || location.Longitude > 180:
			return fmt.Sprintf("value must have a maximum value of 180 (got %v)", location.Longitude)
		}
		// PBS writes the keys in its own order, name first.
		canonical := ""
		if location.Name != "" {
			canonical = "name=" + location.Name + ","
		}
		node["location"] = canonical + "latitude=" + strconv.FormatFloat(location.Latitude, 'f', -1, 64) +
			",longitude=" + strconv.FormatFloat(location.Longitude, 'f', -1, 64)
	}
	return ""
}

// fakeNode serves a node's DNS settings, time and subscription:
//
//   - /etc/resolv.conf is kept as text, read and written with PBS's rules:
//     the last search or domain line's first word is search, the first
//     three nameservers are dns1 to dns3, every other line is kept as
//     options, after them; the digest, inside data, is the file's SHA-256.
//     mounted makes writing fail as on a file Docker mounts.
//   - the time zone must be one of zones; timedated makes GET answer it with
//     a line break at the end, as timedatectl does.
//   - a subscription key is checked against shop, the keys the fake shop
//     knows, unless shopDown; any well-formed key it does not know is stored
//     as invalid. noAudit answers GET as to a caller without Sys.Audit on /.
type fakeNode struct {
	mu sync.Mutex

	resolvConf string
	mounted    bool

	timezone  string
	zones     []string
	timedated bool
	now       int64
	offset    int64

	subscription *pbsclient.Subscription
	shop         map[string]pbsclient.Subscription
	shopDown     bool
	noAudit      bool
	shopCalls    int
}

// fakeServerID is the server ID of the fake node.
const fakeServerID = "0E6B456A63FE4892997E9F42EBFAF980"

func newFakeNode(fake *fakePBS) *fakeNode {
	n := &fakeNode{
		resolvConf: "# Generated by the installer\nsearch example.org\nnameserver 192.0.2.53\nnameserver 192.0.2.54\noptions edns0\n",
		timezone:   "Etc/UTC",
		zones:      []string{"UTC", "Etc/UTC", "Europe/Vienna", "America/New_York"},
		now:        1793610046,
		shop:       map[string]pbsclient.Subscription{},
	}
	fake.handle("GET /nodes/localhost/dns", n.getDNS)
	fake.handle("PUT /nodes/localhost/dns", n.updateDNS)
	fake.handle("GET /nodes/localhost/time", n.getTime)
	fake.handle("PUT /nodes/localhost/time", n.setTime)
	fake.handle("GET /nodes/localhost/subscription", n.getSubscription)
	fake.handle("PUT /nodes/localhost/subscription", n.setSubscription)
	fake.handle("DELETE /nodes/localhost/subscription", n.deleteSubscription)
	return n
}

var (
	fakeDomainLine = regexp.MustCompile(`^\s*(?:search|domain)\s+(\S+)\s*`)
	fakeServerLine = regexp.MustCompile(`^\s*nameserver\s+([0-9A-Fa-f:.]+)\s*`)
)

// parseResolvConfLocked reads /etc/resolv.conf as PBS does.
func (n *fakeNode) parseResolvConfLocked() map[string]string {
	sum := sha256.Sum256([]byte(n.resolvConf))
	result := map[string]string{"digest": hex.EncodeToString(sum[:])}
	servers := 0
	var options []string
	for _, line := range strings.Split(strings.TrimSuffix(n.resolvConf, "\n"), "\n") {
		if m := fakeDomainLine.FindStringSubmatch(line); m != nil {
			result["search"] = m[1]
			continue
		}
		if m := fakeServerLine.FindStringSubmatch(line); m != nil {
			if _, err := netip.ParseAddr(m[1]); err == nil {
				servers++
				if servers <= 3 {
					result[fmt.Sprintf("dns%d", servers)] = m[1]
				}
				continue
			}
		}
		if len(options) > 0 || line != "" {
			options = append(options, line)
		}
	}
	if len(options) > 0 {
		result["options"] = strings.Join(options, "\n")
	}
	return result
}

func (n *fakeNode) getDNS(w http.ResponseWriter, _ *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	writeData(w, n.parseResolvConfLocked(), "")
}

func (n *fakeNode) updateDNS(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	n.mu.Lock()
	defer n.mu.Unlock()
	config := n.parseResolvConfLocked()
	if staleDigest(params, config["digest"]) {
		writeError(w, "%s", fakeDigestConflict)
		return
	}
	if !checkDelete(w, params, "dns1", "dns2", "dns3") {
		return
	}
	for _, key := range []string{"dns1", "dns2", "dns3"} {
		if value := params.Get(key); value != "" {
			if addr, err := netip.ParseAddr(value); err != nil || addr.Zone() != "" {
				writeError(w, "parameter verification failed - '%s': value does not match the regex pattern", key)
				return
			}
		}
	}
	for _, key := range params[pbsclient.DeleteParam] {
		delete(config, key)
	}
	for _, key := range []string{"search", "dns1", "dns2", "dns3"} {
		if _, ok := params[key]; ok {
			config[key] = params.Get(key)
		}
	}
	if n.mounted {
		writeError(w, `Atomic rename failed for file "/etc/resolv.conf" - Device or resource busy (os error 16)`)
		return
	}
	var data strings.Builder
	if search, ok := config["search"]; ok {
		data.WriteString("search " + search + "\n")
	}
	for _, key := range []string{"dns1", "dns2", "dns3"} {
		if server, ok := config[key]; ok {
			data.WriteString("nameserver " + server + "\n")
		}
	}
	data.WriteString(config["options"])
	n.resolvConf = data.String()
	writeData(w, nil, "")
}

func (n *fakeNode) getTime(w http.ResponseWriter, _ *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	timezone := n.timezone
	if n.timedated {
		timezone += "\n"
	}
	writeData(w, map[string]any{"timezone": timezone, "time": n.now, "localtime": n.now + n.offset}, "")
}

func (n *fakeNode) setTime(w http.ResponseWriter, req *http.Request) {
	timezone := form(req).Get("timezone")
	n.mu.Lock()
	defer n.mu.Unlock()
	if !slices.Contains(n.zones, timezone) {
		writeError(w, "No such timezone.")
		return
	}
	n.timezone = timezone
	writeData(w, nil, "")
}

func (n *fakeNode) getSubscription(w http.ResponseWriter, _ *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := pbsclient.Subscription{
		Status:   pbsclient.SubscriptionNotFound,
		ServerID: fakeServerID,
		Message:  "There is no subscription key",
		URL:      "https://www.proxmox.com/en/proxmox-backup-server/pricing",
	}
	if n.subscription != nil {
		s = *n.subscription
	}
	if n.noAudit {
		s = pbsclient.Subscription{Status: s.Status, Message: s.Message, URL: s.URL}
	}
	writeData(w, s, "")
}

func (n *fakeNode) setSubscription(w http.ResponseWriter, req *http.Request) {
	key := form(req).Get("key")
	n.mu.Lock()
	defer n.mu.Unlock()
	if !subscriptionKeyPattern.MatchString(key) {
		writeError(w, "invalid subscription key: value does not match the regex pattern")
		return
	}
	n.shopCalls++
	if n.shopDown {
		writeError(w, "Error checking subscription: client error (Connect)")
		return
	}
	verdict, ok := n.shop[key]
	if !ok {
		verdict = pbsclient.Subscription{Status: "invalid", Message: "Invalid license key"}
	}
	verdict.Key = key
	verdict.CheckTime = n.now
	verdict.URL = "https://www.proxmox.com/en/proxmox-backup-server/pricing"
	if verdict.Status == "active" {
		verdict.ServerID = fakeServerID
	}
	n.subscription = &verdict
	writeData(w, nil, "")
}

func (n *fakeNode) deleteSubscription(w http.ResponseWriter, _ *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.subscription == nil {
		writeError(w, "Deleting subscription failed: No such file or directory (os error 2)")
		return
	}
	n.subscription = nil
	writeData(w, nil, "")
}

// --- custom certificates ------------------------------------------------------

// serveCustomCertificates has the ACME fake take uploads of a custom
// certificate as PBS does: it re-encodes the chain, joined by blank lines,
// takes the key or keeps the current one, and checks neither. A chain
// without certificates is written as an empty file, which fails to load.
func serveCustomCertificates(t *testing.T, a *fakeACME) {
	t.Helper()
	a.fake.handle("POST /nodes/localhost/certificates/custom", func(w http.ResponseWriter, req *http.Request) {
		params := form(req)
		var certs []*x509.Certificate
		rest := []byte(params.Get("certificates"))
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				writeError(w, "failed to decode certificate chain: %s", err)
				return
			}
			certs = append(certs, cert)
		}
		if len(certs) == 0 {
			writeError(w, "error loading proxy certificate: no start line")
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		info := certificateInfo(certs[0], certs[1:]...)
		var chain []string
		for _, c := range certs {
			chain = append(chain, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
		}
		info.PEM = strings.Join(chain, "\n")
		a.cert = info
		writeData(w, []pbsclient.CertificateInfo{info}, "")
	})
}
