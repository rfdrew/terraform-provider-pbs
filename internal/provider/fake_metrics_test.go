package provider

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeMetricServers keeps the metric servers of metricserver.cfg in memory and
// serves PBS's API for them through a fakePBS, with the behaviour read in PBS
// 4.2's source (see internal/pbsclient/metrics.go):
//
//   - InfluxDB HTTP and UDP servers share one namespace and one digest; each
//     type has its routes, /config/metrics/influxdb-http[/name] and
//     /config/metrics/influxdb-udp[/name], and lists only its own servers,
//     in reverse name order: PBS answers in the order of its hash map, and
//     the data source must sort;
//   - POST and PUT accept the parameters PBS's schema has for the type, and
//     an update's delete only the names PBS accepts, applied before the
//     values; creating needs name and url, or host;
//   - what is left out is not stored, defaults included; enable is stored
//     only when false, and deleting it enables the server; verify-tls is
//     stored when sent, true as well;
//   - the token of an HTTP server is stored, as PBS keeps it in
//     metricserver.cfg, but reads and lists never return it;
//   - a create writes the comment as sent; an update trims it, and deletes
//     an empty one; reads and lists answer every value trimmed, as PBS's
//     parser reads it back from the file — an update starts from that too;
//   - a taken name, of either type, is 400 "metric server 'x' already
//     exists."; a missing server is 400 "no such influxdb-http 'x'" on GET
//     and PUT, and 400 "name 'x' does not exist." on DELETE; a server of the
//     other type answers GET and PUT with "got unexpected type", while
//     DELETE removes it all the same; PUT and DELETE refuse a stale digest,
//     before they look for the server.
//
// Before it saves a server that is enabled after the change — on every
// create and every update — PBS checks it, and answers its 400 when that
// fails, saving nothing. For an HTTP server it sends GET <url>/health with
// the token the request carries, or else the one it stored: the check fails
// for the URLs a test made fail with failTarget, with the reason given; for
// the URLs untrustCertificate marks, only while verify-tls is on, with the
// same "client error (Connect)" PBS 4 gives for any failed connection; and
// with 401 for the URLs requireHealthToken gave a token, unless PBS sends
// that token. For a UDP server PBS only resolves the host: the check fails
// for the host:port a test made fail. A server that is not enabled is not
// checked. Every check is recorded, with the token it sent.
//
// Tests set up state with addServer, failTarget, untrustCertificate and
// requireHealthToken, and look at it with server, checkCount and lastCheck.
type fakeMetricServers struct {
	fake *fakePBS

	mu sync.Mutex
	// types and servers are the sections of metricserver.cfg: each server's
	// type, and its properties as PBS stores them, the token included.
	types   map[string]string
	servers map[string]fakeProperties
	// gen counts the changes to metricserver.cfg, for its digest.
	gen int
	// failures are the targets whose check fails — the URL of an HTTP
	// server, the host:port of a UDP one — with the reason PBS gives.
	failures map[string]string
	// untrusted are the URLs whose certificate PBS does not trust: their
	// check fails while verify-tls is on.
	untrusted map[string]bool
	// healthTokens are the URLs whose /health wants a token, as InfluxDB 3
	// does by default: any other token, or none, gets 401.
	healthTokens map[string]string
	// checks are the checks PBS made, in order.
	checks []fakeMetricServerCheck
}

// fakeMetricServerCheck is one check PBS made of a server before it saved it.
type fakeMetricServerCheck struct {
	serverType string
	// target is the URL of an HTTP server, the host:port of a UDP one.
	target string
	// token is what an HTTP check sent in its Authorization header, if
	// withToken.
	token     string
	withToken bool
}

// fakeMetricServerType is what PBS's API takes for one type of metric
// server.
type fakeMetricServerType struct {
	// target is the property PBS checks the server at: url or host.
	target string
	// create and update are the parameters POST and PUT accept; anything else
	// PBS refuses.
	create, update []string
	// deletable is what an update's delete accepts.
	deletable []string
}

var fakeMetricServerTypes = map[string]fakeMetricServerType{
	pbsclient.MetricServerTypeInfluxDBHTTP: {
		target: "url",
		create: []string{"name", "enable", "url", "token", "organization", "bucket", "max-body-size", "verify-tls", "comment"},
		update: []string{"enable", "url", "token", "organization", "bucket", "max-body-size", "verify-tls", "comment",
			pbsclient.DeleteParam, pbsclient.DigestParam},
		deletable: []string{"enable", "token", "bucket", "organization", "max-body-size", "verify-tls", "comment"},
	},
	pbsclient.MetricServerTypeInfluxDBUDP: {
		target:    "host",
		create:    []string{"name", "enable", "host", "mtu", "comment"},
		update:    []string{"enable", "host", "mtu", "comment", pbsclient.DeleteParam, pbsclient.DigestParam},
		deletable: []string{"enable", "mtu", "comment"},
	},
}

// fakeMetricServerInts are the properties PBS keeps as numbers.
var fakeMetricServerInts = []string{"max-body-size", "mtu"}

// What PBS's check of a server fails with, after "could not connect to
// <url>: " or "cannot connect to <host>: ". PBS 4's HTTP client reports a
// name that does not resolve, a refused connection and a failed TLS
// handshake alike, as fakeInfluxConnectFailed.
const (
	fakeInfluxNotFound      = "got bad status: 404 Not Found"
	fakeInfluxUnauthorized  = "got bad status: 401 Unauthorized"
	fakeInfluxUnavailable   = "got bad status: 503 Service Unavailable"
	fakeInfluxConnectFailed = "client error (Connect)"
	fakeInfluxLookupFailed  = "failed to lookup address information: Name or service not known"
)

// newFakeMetricServers serves the metric server API from fake.
func newFakeMetricServers(fake *fakePBS) *fakeMetricServers {
	m := &fakeMetricServers{
		fake:         fake,
		types:        map[string]string{},
		servers:      map[string]fakeProperties{},
		failures:     map[string]string{},
		untrusted:    map[string]bool{},
		healthTokens: map[string]string{},
	}
	for serverType := range fakeMetricServerTypes {
		base := "/config/metrics/" + serverType
		fake.handle("GET "+base, m.listServers(serverType))
		fake.handle("POST "+base, m.createServer(serverType))
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			fake.handlePrefix(method+" "+base+"/", m.serveServer(serverType))
		}
	}
	return m
}

// --- test helpers -------------------------------------------------------------

// addServer puts a server of the type into metricserver.cfg, replacing one of
// that name of either type; props are as PBS stores them, a token included.
func (m *fakeMetricServers) addServer(name, serverType string, props fakeProperties) {
	m.mu.Lock()
	defer m.mu.Unlock()
	props = cloneProperties(props)
	props["name"] = name
	m.types[name] = serverType
	m.servers[name] = props
	m.gen++
}

// server returns what metricserver.cfg holds of a server, the token
// included, and its type.
func (m *fakeMetricServers) server(name string) (fakeProperties, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	props, ok := m.servers[name]
	return cloneProperties(props), m.types[name], ok
}

// failTarget has PBS's check of the URL or host:port fail with reason; ""
// lets it pass again.
func (m *fakeMetricServers) failTarget(target, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if reason == "" {
		delete(m.failures, target)
		return
	}
	m.failures[target] = reason
}

// untrustCertificate has the InfluxDB server at the URL present a
// certificate PBS does not trust, so that its check fails while verify-tls
// is on.
func (m *fakeMetricServers) untrustCertificate(target string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.untrusted[target] = true
}

// requireHealthToken has the InfluxDB server at the URL answer GET
// <url>/health with 401 unless PBS sends token.
func (m *fakeMetricServers) requireHealthToken(target, token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthTokens[target] = token
}

// checkCount returns how many checks PBS made so far.
func (m *fakeMetricServers) checkCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.checks)
}

// lastCheck returns the most recent check PBS made, failing the test when it
// made none.
func (m *fakeMetricServers) lastCheck(t *testing.T) fakeMetricServerCheck {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.checks) == 0 {
		t.Fatal("PBS checked no metric server")
	}
	return m.checks[len(m.checks)-1]
}

// --- serving ------------------------------------------------------------------

func (m *fakeMetricServers) digestLocked() string {
	return fakeDigest(pbsclient.ConfigMetricServers, m.gen)
}

// readBack is a server as PBS parses it from metricserver.cfg: every value
// trimmed.
func readBack(props fakeProperties) fakeProperties {
	out := cloneProperties(props)
	for key, value := range out {
		if s, ok := value.(string); ok {
			out[key] = strings.TrimSpace(s)
		}
	}
	return out
}

// withoutToken is a server as reads and lists answer it.
func withoutToken(props fakeProperties) fakeProperties {
	out := readBack(props)
	delete(out, "token")
	return out
}

// listServers serves GET /config/metrics/{type}: the servers of the type, in
// reverse name order.
func (m *fakeMetricServers) listServers(serverType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		var names []string
		for name, typ := range m.types {
			if typ == serverType {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		slices.Reverse(names)
		list := make([]fakeProperties, 0, len(names))
		for _, name := range names {
			list = append(list, withoutToken(m.servers[name]))
		}
		writeData(w, list, m.digestLocked())
	}
}

// checkMetricServerForm fails like PBS on parameters the call does not take.
func checkMetricServerForm(w http.ResponseWriter, params url.Values, allowed []string) bool {
	for key := range params {
		if !slices.Contains(allowed, key) {
			writeError(w, "parameter verification failed - '%s': schema does not allow additional properties.", key)
			return false
		}
	}
	return true
}

// applyMetricServerForm sets the properties a create or update carries as
// PBS stores them: numbers typed, enable only when false, verify-tls as
// sent, and strings as sent, but for the comment of an update, which is
// trimmed, and deleted when that leaves nothing.
func applyMetricServerForm(props fakeProperties, params url.Values, update bool) {
	for key, values := range params {
		value := values[0]
		switch {
		case key == "name" || key == pbsclient.DeleteParam || key == pbsclient.DigestParam:
		case slices.Contains(fakeMetricServerInts, key):
			n, _ := strconv.ParseInt(value, 10, 64)
			props[key] = n
		case key == "enable":
			if fakeBool(value) {
				delete(props, key)
			} else {
				props[key] = false
			}
		case key == "verify-tls":
			props[key] = fakeBool(value)
		case key == "comment" && update:
			if comment := strings.TrimSpace(value); comment != "" {
				props[key] = comment
			} else {
				delete(props, key)
			}
		default:
			props[key] = value
		}
	}
}

// createServer serves POST /config/metrics/{type}.
func (m *fakeMetricServers) createServer(serverType string) http.HandlerFunc {
	kind := fakeMetricServerTypes[serverType]
	return func(w http.ResponseWriter, req *http.Request) {
		params := form(req)
		if !checkMetricServerForm(w, params, kind.create) || !checkRequired(w, params, "name", kind.target) {
			return
		}
		name := params.Get("name")
		m.mu.Lock()
		defer m.mu.Unlock()
		if _, exists := m.servers[name]; exists {
			writeError(w, "metric server '%s' already exists.", name)
			return
		}
		props := fakeProperties{"name": name}
		applyMetricServerForm(props, params, false)
		if failure := m.checkLocked(serverType, props); failure != "" {
			writeError(w, "%s", failure)
			return
		}
		m.types[name] = serverType
		m.servers[name] = props
		m.gen++
		writeData(w, nil, "")
	}
}

// serveServer serves /config/metrics/{type}/{name}.
func (m *fakeMetricServers) serveServer(serverType string) http.HandlerFunc {
	kind := fakeMetricServerTypes[serverType]
	return func(w http.ResponseWriter, req *http.Request) {
		name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/metrics/"+serverType+"/")
		params := form(req)
		if req.Method == http.MethodPut &&
			(!checkMetricServerForm(w, params, kind.update) || !checkDelete(w, params, kind.deletable...)) {
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if req.Method != http.MethodGet && staleDigest(params, m.digestLocked()) {
			writeError(w, fakeDigestConflict)
			return
		}
		props, exists := m.servers[name]

		if req.Method == http.MethodDelete {
			// Of either type: PBS removes the section of that name.
			if !exists {
				writeError(w, "name '%s' does not exist.", name)
				return
			}
			delete(m.servers, name)
			delete(m.types, name)
			m.gen++
			writeData(w, nil, "")
			return
		}
		if !exists {
			writeError(w, "no such %s '%s'", serverType, name)
			return
		}
		if m.types[name] != serverType {
			writeError(w, "got unexpected type '%s' for %s '%s'", m.types[name], serverType, name)
			return
		}

		if req.Method == http.MethodGet {
			writeData(w, withoutToken(props), m.digestLocked())
			return
		}
		updated := readBack(props)
		for _, key := range params[pbsclient.DeleteParam] {
			delete(updated, key)
		}
		applyMetricServerForm(updated, params, true)
		if failure := m.checkLocked(serverType, updated); failure != "" {
			writeError(w, "%s", failure)
			return
		}
		m.servers[name] = updated
		m.gen++
		writeData(w, nil, "")
	}
}

// checkLocked checks a server of the type with props, as PBS does before it
// saves one, and returns the text PBS fails with, or "". The token in props
// is the one the request carried, or else the one stored: an update applies
// the request to the stored properties first.
func (m *fakeMetricServers) checkLocked(serverType string, props fakeProperties) string {
	if props["enable"] == false {
		return ""
	}
	if serverType == pbsclient.MetricServerTypeInfluxDBUDP {
		host, _ := props["host"].(string)
		m.checks = append(m.checks, fakeMetricServerCheck{serverType: serverType, target: host})
		if reason := m.failures[host]; reason != "" {
			return "cannot connect to " + host + ": " + reason
		}
		return ""
	}

	target, _ := props["url"].(string)
	token, withToken := props["token"].(string)
	m.checks = append(m.checks, fakeMetricServerCheck{serverType: serverType, target: target, token: token, withToken: withToken})
	if want, ok := m.healthTokens[target]; ok && (!withToken || token != want) {
		return "could not connect to " + target + ": " + fakeInfluxUnauthorized
	}
	reason := m.failures[target]
	if reason == "" && m.untrusted[target] && props["verify-tls"] != false {
		reason = fakeInfluxConnectFailed
	}
	if reason != "" {
		return "could not connect to " + target + ": " + reason
	}
	return ""
}
