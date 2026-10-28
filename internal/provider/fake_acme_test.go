package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeACME keeps ACME accounts and plugins, the node's ACME settings and
// the proxy's certificate in memory and serves PBS's API for them through a
// fakePBS, with the behaviour of PBS 4.2's source (see
// internal/pbsclient/acme.go and certificates.go):
//
//   - registering, updating and deactivating an account answer a UPID, and
//     the task does the work when it is first polled; "account 'x' already
//     exists" is refused at once, a missing account fails the task. A CA
//     that returns contacts, as Pebble does, is the default; caForgets
//     makes it one that does not, as Let's Encrypt;
//   - plugins carry the digest of plugins.cfg; the built-in standalone
//     plugin always exists, cannot be created or updated, and deleting it
//     changes nothing; data is taken base64-encoded and returned decoded;
//   - the node's configuration keeps every property as sent, with a digest,
//     refuses a stale digest, deletes before it sets, and refuses the same
//     ACME domain twice; it holds a description too, which the ACME
//     resources must leave alone;
//   - ordering answers a UPID; the task orders nothing for a node without
//     domains, fails for a missing account or plugin, and otherwise installs
//     a certificate a fake CA issued for the domains, lower-cased. Deleting
//     the custom certificate installs a new self-signed one at once.
//
// Tests set up state with addAccount, addPlugin and setNodeProperty, renew
// the certificate as PBS does on its own with renew, and look at state with
// account, plugin, nodeProperty and certificate.
type fakeACME struct {
	fake *fakePBS
	t    *testing.T

	mu         sync.Mutex
	accounts   map[string]fakeProperties
	accountGen int
	// deactivated are the accounts deactivated, in order.
	deactivated []string
	// caForgets makes the CA return no contacts, as Let's Encrypt does.
	caForgets bool
	// registerFailures make the next registration tasks fail with their
	// text, one each. orderFailure makes the next order task fail with its
	// text; orderFailureAfterInstall makes it fail after it installed the
	// certificate, orderNothing end it without one, as for a node whose
	// domains went away.
	registerFailures         []string
	orderFailure             string
	orderFailureAfterInstall string
	orderNothing             bool

	plugins   map[string]fakeProperties
	pluginGen int

	node       map[string]string
	nodeGen    int
	staleNodes int

	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	cert  pbsclient.CertificateInfo

	tasks   map[string]func() string
	taskGen int
}

// fakeACMETaskNode is the node name the ACME fake's UPIDs carry, apart from
// the datastore fake's.
const fakeACMETaskNode = "pbs-acme"

// fakeToS are the terms of service of the directories the fake knows.
var fakeToS = map[string]string{
	pbsclient.DefaultACMEDirectory:  "https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf",
	pbsclient.ACMEStagingDirectory:  "https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf",
	"https://pebble.test:14000/dir": "data:text/plain,Do%20what%20thou%20wilt",
}

// The properties of each kind of entry that are not strings, and what
// updates may delete.
var (
	fakePluginInts       = []string{"validation-delay"}
	fakePluginBools      = []string{"disable"}
	fakePluginDeletable  = []string{"disable", "validation-delay"}
	fakeNodeDeletable    = []string{"acme", "acmedomain0", "acmedomain1", "acmedomain2", "acmedomain3", "acmedomain4", "http-proxy", "email-from", "ciphers-tls-1.3", "ciphers-tls-1.2", "default-lang", "description", "task-log-max-days", "consent-text", "location"}
	fakeNodeDescription  = "PBS for cluster1"
	fakeSelfSignedIssuer = "CN=pbs-test, O=Proxmox Backup Server"
)

// newFakeACME serves the ACME, node configuration and certificate API from
// fake, for node localhost.
func newFakeACME(t *testing.T, fake *fakePBS) *fakeACME {
	t.Helper()
	a := &fakeACME{
		fake:     fake,
		t:        t,
		accounts: map[string]fakeProperties{},
		plugins:  map[string]fakeProperties{},
		node:     map[string]string{"description": fakeNodeDescription},
		tasks:    map[string]func() string{},
	}
	a.caKey, a.ca = fakeCertificate(t, "Fake ACME CA", nil, nil)
	a.cert = a.selfSignedLocked()

	fake.handle("POST /config/acme/account", a.registerAccount)
	fake.handle("GET /config/acme/tos", a.tos)
	fake.handle("POST /config/acme/plugins", a.createPlugin)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /config/acme/account/", a.serveAccount)
		fake.handlePrefix(method+" /config/acme/plugins/", a.servePlugin)
	}
	fake.handle("GET /nodes/localhost/config", a.getNode)
	fake.handle("PUT /nodes/localhost/config", a.updateNode)
	fake.handle("GET /nodes/localhost/certificates/info", a.certificateInfo)
	fake.handle("POST /nodes/localhost/certificates/acme/certificate", a.order)
	fake.handle("DELETE /nodes/localhost/certificates/custom", a.deleteCustom)
	fake.handlePrefix("GET /nodes/"+fakeACMETaskNode+"/tasks/", a.taskStatus)
	return a
}

// fakeCertificate creates a certificate for cn, signed by parent with
// parentKey, or self-signed when parent is nil.
func fakeCertificate(t *testing.T, cn string, dnsNames []string, parent *x509.Certificate, parentKey ...*ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(1790000000, 0),
		NotAfter:              time.Unix(1790000000+90*24*3600, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  parent == nil,
		DNSNames:              dnsNames,
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent, parentKey[0]
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// certificateInfo describes cert as PBS does, the chain after it.
func certificateInfo(cert *x509.Certificate, chain ...*x509.Certificate) pbsclient.CertificateInfo {
	sum := sha256.Sum256(cert.Raw)
	var pemText strings.Builder
	for _, c := range append([]*x509.Certificate{cert}, chain...) {
		_ = pem.Encode(&pemText, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return pbsclient.CertificateInfo{
		Filename:      pbsclient.ProxyCertificateFile,
		Fingerprint:   pbsclient.FormatFingerprint(hex.EncodeToString(sum[:])),
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore.Unix(),
		NotAfter:      cert.NotAfter.Unix(),
		SAN:           cert.DNSNames,
		PEM:           pemText.String(),
		PublicKeyType: "id-ecPublicKey",
		PublicKeyBits: 256,
	}
}

func (a *fakeACME) selfSignedLocked() pbsclient.CertificateInfo {
	_, cert := fakeCertificate(a.t, "pbs-test", nil, nil)
	info := certificateInfo(cert)
	// PBS's own certificate names the host and PBS, in subject and issuer
	// alike.
	info.Subject, info.Issuer = fakeSelfSignedIssuer, fakeSelfSignedIssuer
	return info
}

func (a *fakeACME) issueLocked(domains []string) pbsclient.CertificateInfo {
	_, cert := fakeCertificate(a.t, domains[0], domains, a.ca, a.caKey)
	return certificateInfo(cert, a.ca)
}

// --- test helpers -------------------------------------------------------------

func (a *fakeACME) addAccount(name string, props fakeProperties) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accounts[name] = cloneProperties(props)
}

func (a *fakeACME) account(name string) (fakeProperties, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	props, ok := a.accounts[name]
	return cloneProperties(props), ok
}

func (a *fakeACME) addPlugin(id string, props fakeProperties) {
	a.mu.Lock()
	defer a.mu.Unlock()
	props = cloneProperties(props)
	props["type"] = pbsclient.DNSACMEPluginType
	a.plugins[id] = props
	a.pluginGen++
}

func (a *fakeACME) plugin(id string) (fakeProperties, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	props, ok := a.plugins[id]
	return cloneProperties(props), ok
}

// setNodeProperty changes the node's configuration as another client would;
// "" removes the property.
func (a *fakeACME) setNodeProperty(key, value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if value == "" {
		delete(a.node, key)
	} else {
		a.node[key] = value
	}
	a.nodeGen++
}

func (a *fakeACME) nodeProperty(key string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	value, ok := a.node[key]
	return value, ok
}

func (a *fakeACME) certificate() pbsclient.CertificateInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cert
}

// renew installs a new certificate for the same names, as PBS's daily
// renewal does.
func (a *fakeACME) renew() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cert = a.issueLocked(a.cert.SAN)
}

// install installs a certificate the fake CA issued for domains, as an
// order made outside Terraform does.
func (a *fakeACME) install(domains ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cert = a.issueLocked(domains)
}

// --- serving ------------------------------------------------------------------

func (a *fakeACME) startTaskLocked(workerType, workerID string, run func() string) string {
	a.taskGen++
	upid := fmt.Sprintf("UPID:%s:00000002:00000002:%08X:6AE11CDF:%s:%s:%s:", fakeACMETaskNode, a.taskGen, workerType, workerID, fakeTokenID)
	a.tasks[upid] = run
	return upid
}

func (a *fakeACME) taskStatus(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/nodes/"+fakeACMETaskNode+"/tasks/")
	upid, ok := strings.CutSuffix(rest, "/status")
	if !ok {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exit := "unknown"
	if run, ok := a.tasks[upid]; ok {
		exit = run()
		delete(a.tasks, upid)
	}
	writeData(w, map[string]any{"status": "stopped", "exitstatus": exit, "upid": upid}, "")
}

// contactsLocked turns contact into the CA's contacts the way PBS does:
// split at spaces, semicolons, commas and NULs, empty parts kept, each one
// a mailto: URL. An empty one fails, as Pebble and Let's Encrypt refuse it.
func (a *fakeACME) contactsLocked(contact string) ([]string, string) {
	var contacts []string
	for _, part := range splitLikePBS(contact) {
		if part == "" {
			return nil, "Error: invalidContact: empty contact email"
		}
		contacts = append(contacts, "mailto:"+part)
	}
	if a.caForgets {
		return nil, ""
	}
	return contacts, ""
}

// splitLikePBS splits at every space, semicolon, comma and NUL, keeping the
// empty parts, as Rust's str::split does.
func splitLikePBS(s string) []string {
	parts := []string{""}
	for _, r := range s {
		if r == ' ' || r == ';' || r == ',' || r == 0 {
			parts = append(parts, "")
			continue
		}
		parts[len(parts)-1] += string(r)
	}
	return parts
}

func (a *fakeACME) accountJSON(props fakeProperties) map[string]any {
	account := map[string]any{"status": props["status"]}
	if contacts, ok := props["contact"].([]string); ok && len(contacts) > 0 {
		account["contact"] = contacts
	}
	out := map[string]any{"directory": props["directory"], "location": props["location"], "account": account}
	if tos, ok := props["tos"].(string); ok && tos != "" {
		out["tos"] = tos
	}
	return out
}

func (a *fakeACME) registerAccount(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "contact") {
		return
	}
	name := params.Get("name")
	if name == "" {
		name = "default"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.accounts[name]; exists {
		writeError(w, "account %s already exists", name)
		return
	}
	directory := params.Get("directory")
	if directory == "" {
		directory = pbsclient.DefaultACMEDirectory
	}
	upid := a.startTaskLocked("acme-register", name, func() string {
		if len(a.registerFailures) > 0 {
			failure := a.registerFailures[0]
			a.registerFailures = a.registerFailures[1:]
			return failure
		}
		contacts, failure := a.contactsLocked(params.Get("contact"))
		if failure != "" {
			return failure
		}
		a.accountGen++
		a.accounts[name] = fakeProperties{
			"directory": directory,
			"location":  fmt.Sprintf("https://ca.test/acme/acct/%d", a.accountGen),
			"tos":       params.Get("tos_url"),
			"contact":   contacts,
			"status":    "valid",
		}
		return "OK"
	})
	writeData(w, upid, "")
}

func (a *fakeACME) serveAccount(w http.ResponseWriter, req *http.Request) {
	name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/acme/account/")
	params := form(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	missing := fmt.Sprintf("acme account '%s' does not exist", name)
	switch req.Method {
	case http.MethodGet:
		props, ok := a.accounts[name]
		if !ok {
			writeError(w, "%s", missing)
			return
		}
		writeData(w, a.accountJSON(props), "")
	case http.MethodPut:
		upid := a.startTaskLocked("acme-update", name, func() string {
			props, ok := a.accounts[name]
			if !ok {
				return missing
			}
			if params.Has("contact") {
				contacts, failure := a.contactsLocked(params.Get("contact"))
				if failure != "" {
					return failure
				}
				if !a.caForgets {
					props["contact"] = contacts
				}
			}
			return "OK"
		})
		writeData(w, upid, "")
	case http.MethodDelete:
		upid := a.startTaskLocked("acme-deactivate", name, func() string {
			if _, ok := a.accounts[name]; !ok {
				return missing
			}
			delete(a.accounts, name)
			a.deactivated = append(a.deactivated, name)
			return "OK"
		})
		writeData(w, upid, "")
	}
}

func (a *fakeACME) tos(w http.ResponseWriter, req *http.Request) {
	directory := form(req).Get("directory")
	if directory == "" {
		directory = pbsclient.DefaultACMEDirectory
	}
	tos, ok := fakeToS[directory]
	if !ok {
		writeData(w, nil, "")
		return
	}
	writeData(w, tos, "")
}

func (a *fakeACME) pluginDigestLocked() string { return fakeDigest("acme/plugins.cfg", a.pluginGen) }

// pluginLocked returns a plugin as a read reports it, the built-in
// standalone one included.
func (a *fakeACME) pluginLocked(id string) (fakeProperties, bool) {
	if id == pbsclient.StandaloneACMEPlugin {
		return fakeProperties{"plugin": id, "type": pbsclient.StandaloneACMEPlugin}, true
	}
	props, ok := a.plugins[id]
	if !ok {
		return nil, false
	}
	props = cloneProperties(props)
	props["plugin"] = id
	return props, true
}

// decodeFakeData decodes data as PBS does, or fails like it.
func decodeFakeData(w http.ResponseWriter, encoded string) (string, bool) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		writeError(w, "parameter verification failed - 'data': invalid base64 %s", encoded)
		return "", false
	}
	return string(decoded), true
}

func (a *fakeACME) createPlugin(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "id", "type", "api", "data") {
		return
	}
	id := params.Get("id")
	if params.Get("type") != pbsclient.DNSACMEPluginType {
		writeError(w, "parameter verification failed - 'type': invalid ACME plugin type: %q", params.Get("type"))
		return
	}
	data, ok := decodeFakeData(w, params.Get("data"))
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.pluginLocked(id); exists {
		writeError(w, "parameter verification failed - 'id': ACME plugin ID %q already exists", id)
		return
	}
	props := fakeProperties{"type": pbsclient.DNSACMEPluginType}
	applyFakeForm(props, params, fakePluginInts, fakePluginBools, "id", "type", "data")
	props["data"] = data
	a.plugins[id] = props
	a.pluginGen++
	writeData(w, nil, "")
}

func (a *fakeACME) servePlugin(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/acme/plugins/")
	params := form(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	props, ok := a.pluginLocked(id)
	if !ok {
		writeFakeResponse(w, http.StatusNotFound, "no such plugin")
		return
	}
	switch req.Method {
	case http.MethodGet:
		writeData(w, props, a.pluginDigestLocked())
	case http.MethodPut:
		if staleDigest(params, a.pluginDigestLocked()) {
			writeError(w, "%s", fakeDigestConflict)
			return
		}
		if props["type"] != pbsclient.DNSACMEPluginType {
			writeError(w, "cannot update plugin of type %q", props["type"])
			return
		}
		if !checkDelete(w, params, fakePluginDeletable...) {
			return
		}
		section := a.plugins[id]
		for _, key := range params[pbsclient.DeleteParam] {
			delete(section, key)
		}
		if params.Has("data") {
			data, ok := decodeFakeData(w, params.Get("data"))
			if !ok {
				return
			}
			section["data"] = data
		}
		applyFakeForm(section, params, fakePluginInts, fakePluginBools, "data")
		a.pluginGen++
		writeData(w, nil, "")
	case http.MethodDelete:
		if id != pbsclient.StandaloneACMEPlugin {
			delete(a.plugins, id)
			a.pluginGen++
		}
		writeData(w, nil, "")
	}
}

func (a *fakeACME) nodeDigestLocked() string { return fakeDigest("node.cfg", a.nodeGen) }

func (a *fakeACME) getNode(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	writeData(w, a.node, a.nodeDigestLocked())
}

func (a *fakeACME) updateNode(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.staleNodes > 0 {
		// Someone else wrote node.cfg just before.
		a.staleNodes--
		a.nodeGen++
	}
	if staleDigest(params, a.nodeDigestLocked()) {
		writeError(w, "%s", fakeDigestConflict)
		return
	}
	if !checkDelete(w, params, fakeNodeDeletable...) {
		return
	}
	updated := map[string]string{}
	for k, v := range a.node {
		updated[k] = v
	}
	for _, key := range params[pbsclient.DeleteParam] {
		delete(updated, key)
	}
	for key, values := range params {
		if key != pbsclient.DeleteParam && key != pbsclient.DigestParam {
			updated[key] = values[0]
		}
	}
	seen := map[string]bool{}
	for i := 0; i < pbsclient.MaxACMEDomains; i++ {
		raw, ok := updated[pbsclient.ACMEDomainProperty(i)]
		if !ok {
			continue
		}
		domain, err := pbsclient.ParseACMEDomain(raw)
		if err != nil {
			writeError(w, "parameter verification failed - 'acmedomain%d': %s", i, err)
			return
		}
		if seen[strings.ToLower(domain.Domain)] {
			writeError(w, "duplicate domain '%s' in ACME config", domain.Domain)
			return
		}
		seen[strings.ToLower(domain.Domain)] = true
	}
	a.node = updated
	a.nodeGen++
	writeData(w, nil, "")
}

func (a *fakeACME) certificateInfo(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	writeData(w, []pbsclient.CertificateInfo{a.cert}, "")
}

func (a *fakeACME) order(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	upid := a.startTaskLocked("acme-new-cert", "", func() string {
		var domains []pbsclient.ACMEDomain
		for i := 0; i < pbsclient.MaxACMEDomains; i++ {
			if raw, ok := a.node[pbsclient.ACMEDomainProperty(i)]; ok {
				domain, _ := pbsclient.ParseACMEDomain(raw)
				domains = append(domains, domain)
			}
		}
		if len(domains) == 0 {
			return "OK"
		}
		account, err := pbsclient.NodeConfig{ACME: a.node["acme"]}.ACMEAccountName()
		if err != nil {
			return err.Error()
		}
		if _, ok := a.accounts[account]; !ok {
			return fmt.Sprintf("acme account '%s' does not exist", account)
		}
		var names []string
		for _, domain := range domains {
			plugin := domain.Plugin
			if plugin == "" {
				plugin = pbsclient.StandaloneACMEPlugin
			}
			if _, ok := a.pluginLocked(plugin); !ok {
				return fmt.Sprintf("plugin '%s' for domain '%s' not found!", plugin, domain.Domain)
			}
			names = append(names, strings.ToLower(domain.Domain))
		}
		if failure := a.orderFailure; failure != "" {
			a.orderFailure = ""
			return failure
		}
		if a.orderNothing {
			a.orderNothing = false
			return "OK"
		}
		a.cert = a.issueLocked(names)
		if failure := a.orderFailureAfterInstall; failure != "" {
			a.orderFailureAfterInstall = ""
			return failure
		}
		return "OK"
	})
	writeData(w, upid, "")
}

func (a *fakeACME) deleteCustom(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cert = a.selfSignedLocked()
	writeData(w, nil, "")
}

// fakeACMEDomains lists the node's ACME domain properties by slot, for
// assertions.
func (a *fakeACME) fakeACMEDomains() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var slots []string
	for i := 0; i < pbsclient.MaxACMEDomains; i++ {
		if raw, ok := a.node[pbsclient.ACMEDomainProperty(i)]; ok {
			slots = append(slots, strconv.Itoa(i)+":"+raw)
		}
	}
	slices.Sort(slots)
	return slots
}
