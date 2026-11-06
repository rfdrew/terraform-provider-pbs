package provider

import (
	"context"
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestMetricServerResourceSchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, NewInfluxDBHTTPResource())
	requireValidResourceSchema(t, NewInfluxDBUDPResource())
}

// newMetricServerHarness is a fake PBS with the metric server API and a
// provider signed in to it.
func newMetricServerHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeMetricServers) {
	t.Helper()
	fake := newFakePBS()
	servers := newFakeMetricServers(fake)
	return newProtocolHarness(t, fake), fake, servers
}

// What the tests' servers are at, and the token PBS writes with.
const (
	testInfluxURL   = "https://influxdb.example.com:8086"
	testInfluxHost  = "influxdb.example.com:8089"
	testInfluxToken = "first-influx-token"
)

// metricServerKind is one of the two resources, with what a server "influx"
// of it needs.
type metricServerKind struct {
	typeName   string
	serverType string
	// name is how messages call the kind.
	name string
	// target is the attribute PBS checks the server at — url or host, as
	// Terraform and PBS both name it — and address its value.
	target, address string
	// failure is a reason PBS's check of the server fails with, and advice
	// what the provider says about it.
	failure, advice string
}

var (
	metricHTTPKind = metricServerKind{
		typeName: "pbs_metric_server_influxdb_http", serverType: pbsclient.MetricServerTypeInfluxDBHTTP, name: "InfluxDB HTTP",
		target: "url", address: testInfluxURL,
		failure: fakeInfluxConnectFailed, advice: "PBS could not connect to " + testInfluxURL + ", so it saved nothing",
	}
	metricUDPKind = metricServerKind{
		typeName: "pbs_metric_server_influxdb_udp", serverType: pbsclient.MetricServerTypeInfluxDBUDP, name: "InfluxDB UDP",
		target: "host", address: testInfluxHost,
		failure: fakeInfluxLookupFailed,
		advice:  "PBS could not resolve " + testInfluxHost + " or connect a UDP socket to it from its own host",
	}
	metricKinds = []metricServerKind{metricHTTPKind, metricUDPKind}
)

// other is the kind of the other type.
func (k metricServerKind) other() metricServerKind {
	if k.serverType == pbsclient.MetricServerTypeInfluxDBHTTP {
		return metricUDPKind
	}
	return metricHTTPKind
}

// config is the configuration of the server, with attrs on top of what it
// needs; a nil value leaves an attribute out.
func (k metricServerKind) config(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"name": "influx", k.target: k.address}
	maps.Copy(config, attrs)
	return h.resourceValue(t, k.typeName, config)
}

// props are the properties PBS keeps of such a server, with extra on top.
func (k metricServerKind) props(extra fakeProperties) fakeProperties {
	props := fakeProperties{k.target: k.address}
	maps.Copy(props, extra)
	return props
}

// route is the route of a call for the kind: POST creates, the other
// methods name the server.
func (k metricServerKind) route(method, name string) string {
	if method == http.MethodPost {
		return "POST /config/metrics/" + k.serverType
	}
	return method + " /config/metrics/" + k.serverType + "/" + name
}

// checkError is what PBS answers when its check of the server fails.
func (k metricServerKind) checkError() string {
	if k.serverType == pbsclient.MetricServerTypeInfluxDBUDP {
		return "cannot connect to " + k.address + ": " + k.failure
	}
	return "could not connect to " + k.address + ": " + k.failure
}

// requireStored fails the test unless PBS keeps the server "influx", of the
// kind, with exactly the properties want, the token included.
func (k metricServerKind) requireStored(t *testing.T, servers *fakeMetricServers, want fakeProperties) {
	t.Helper()
	want = cloneProperties(want)
	want["name"] = "influx"
	stored, serverType, exists := servers.server("influx")
	if !exists || serverType != k.serverType || !reflect.DeepEqual(stored, want) {
		t.Errorf("stored server = %v of type %q, want %v of type %q", stored, serverType, want, k.serverType)
	}
}

// requireDeletedWithDigest fails the test unless the server "influx" is gone,
// deleted with a digest right after a read of it as the kind.
func (k metricServerKind) requireDeletedWithDigest(t *testing.T, fake *fakePBS, servers *fakeMetricServers) {
	t.Helper()
	if _, _, exists := servers.server("influx"); exists {
		t.Error("destroy left the server")
	}
	routes := fake.routes()
	if n := len(routes); n < 2 || routes[n-2] != k.route(http.MethodGet, "influx") || routes[n-1] != k.route(http.MethodDelete, "influx") {
		t.Errorf("routes = %v, want a read of the server right before its delete", routes)
	}
	if fake.lastCall(t, k.route(http.MethodDelete, "influx")).query.Get(pbsclient.DigestParam) == "" {
		t.Error("DELETE sent no digest")
	}
}

// requireNoCheckAdvice fails the test when an error advises on a check of the
// server, which did not fail.
func requireNoCheckAdvice(t *testing.T, diags []*tfprotov6.Diagnostic) {
	t.Helper()
	for _, d := range diags {
		if strings.Contains(d.Detail, "enable = false") {
			t.Errorf("an error that is no failed check got advice on the check: %s", d.Detail)
		}
	}
}

// The life of an InfluxDB HTTP server: created with what differs from PBS's
// defaults and the token, which PBS checks the server with; updated with only
// what changed, the token only with a new version, and checked by PBS every
// time it is enabled after the update; reset by deleting; destroyed with the
// digest of a read.
func TestInfluxDBHTTPResourceLifecycle(t *testing.T) {
	h, fake, servers := newMetricServerHarness(t)
	k := metricHTTPKind
	put := k.route(http.MethodPut, "influx")
	const newURL = "http://influxdb.lan:8086/influx"

	attrs := map[string]any{"token_wo": testInfluxToken, "token_wo_version": 1, "comment": "Metrics"}
	config := k.config(t, h, attrs)
	inst := h.create(t, k.typeName, config)
	requireForm(t, "POST", fake.lastCall(t, k.route(http.MethodPost, "")).form,
		map[string]string{"name": "influx", "url": testInfluxURL, "token": testInfluxToken, "comment": "Metrics"})
	k.requireStored(t, servers, fakeProperties{"url": testInfluxURL, "token": testInfluxToken, "comment": "Metrics"})
	if check := servers.lastCheck(t); check.target != testInfluxURL || !check.withToken || check.token != testInfluxToken {
		t.Errorf("check = %+v, want %s with the token", check, testInfluxURL)
	}
	if stringAt(t, inst.state, "id") != "influx" || stringAt(t, inst.state, "url") != testInfluxURL ||
		stringAt(t, inst.state, "organization") != pbsclient.DefaultInfluxDBOrganization ||
		stringAt(t, inst.state, "bucket") != pbsclient.DefaultInfluxDBBucket ||
		int64At(t, inst.state, "max_body_size") != pbsclient.DefaultInfluxDBMaxBodySize ||
		!boolAt(t, inst.state, "verify_tls") || !boolAt(t, inst.state, "enable") ||
		stringAt(t, inst.state, "comment") != "Metrics" || !isNullAt(t, inst.state, "token_wo") ||
		int64At(t, inst.state, "token_wo_version") != 1 {
		t.Errorf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, k.typeName, inst.identity), "name"); got != "influx" {
		t.Errorf("identity name = %q", got)
	}
	requireNoPlannedChange(t, h, inst, config)
	if refreshed := h.refresh(t, inst); !refreshed.state.Equal(inst.state) {
		diffs, _ := refreshed.state.Diff(inst.state)
		t.Errorf("refresh changes %v", diffs)
	}

	// Only what changed is sent, and PBS checks the server again, at its new
	// URL, with the token it stored.
	attrs["url"] = newURL
	attrs["organization"] = "metrics"
	attrs["bucket"] = "pbs"
	attrs["max_body_size"] = 1000000
	attrs["verify_tls"] = false
	config = k.config(t, h, attrs)
	inst = h.update(t, inst, config)
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"url": newURL, "organization": "metrics",
		"bucket": "pbs", "max-body-size": "1000000", "verify-tls": "false"})
	k.requireStored(t, servers, fakeProperties{"url": newURL, "token": testInfluxToken, "comment": "Metrics",
		"organization": "metrics", "bucket": "pbs", "max-body-size": int64(1000000), "verify-tls": false})
	if check := servers.lastCheck(t); check.target != newURL || check.token != testInfluxToken {
		t.Errorf("check = %+v, want the new URL with the stored token", check)
	}
	if stringAt(t, inst.state, "url") != newURL || stringAt(t, inst.state, "organization") != "metrics" ||
		stringAt(t, inst.state, "bucket") != "pbs" || int64At(t, inst.state, "max_body_size") != 1000000 ||
		boolAt(t, inst.state, "verify_tls") {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// Back to the defaults, given explicitly or left out: deleted, not
	// written.
	attrs["organization"] = pbsclient.DefaultInfluxDBOrganization
	attrs["max_body_size"] = pbsclient.DefaultInfluxDBMaxBodySize
	attrs["verify_tls"] = true
	delete(attrs, "bucket")
	delete(attrs, "comment")
	config = k.config(t, h, attrs)
	inst = h.update(t, inst, config)
	requireForm(t, "PUT", fake.lastCall(t, put).form,
		map[string]string{"delete": "bucket,comment,max-body-size,organization,verify-tls"})
	k.requireStored(t, servers, fakeProperties{"url": newURL, "token": testInfluxToken})
	if stringAt(t, inst.state, "organization") != pbsclient.DefaultInfluxDBOrganization ||
		stringAt(t, inst.state, "bucket") != pbsclient.DefaultInfluxDBBucket ||
		int64At(t, inst.state, "max_body_size") != pbsclient.DefaultInfluxDBMaxBodySize ||
		!boolAt(t, inst.state, "verify_tls") || !isNullAt(t, inst.state, "comment") {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// Disabled, the server is stored with enable = false and not checked;
	// enabled again, the property goes, and PBS checks the server.
	checks := servers.checkCount()
	attrs["enable"] = false
	inst = h.update(t, inst, k.config(t, h, attrs))
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"enable": "false"})
	k.requireStored(t, servers, fakeProperties{"url": newURL, "token": testInfluxToken, "enable": false})
	if servers.checkCount() != checks || boolAt(t, inst.state, "enable") {
		t.Errorf("a disabled server was checked, or state = %s", inst.state)
	}
	delete(attrs, "enable")
	inst = h.update(t, inst, k.config(t, h, attrs))
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"delete": "enable"})
	k.requireStored(t, servers, fakeProperties{"url": newURL, "token": testInfluxToken})
	if servers.checkCount() != checks+1 || !boolAt(t, inst.state, "enable") {
		t.Errorf("an enabled server was not checked, or state = %s", inst.state)
	}

	// A new token without a new version is not sent ...
	puts := fake.count(put)
	attrs["token_wo"] = "unsent-influx-token"
	inst = h.update(t, inst, k.config(t, h, attrs))
	if fake.count(put) != puts {
		t.Error("a new token_wo without a new version was sent")
	}

	// ... a new version sends it, alone, and PBS checks the server with it.
	attrs["token_wo"] = "second-influx-token"
	attrs["token_wo_version"] = 2
	config = k.config(t, h, attrs)
	inst = h.update(t, inst, config)
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"token": "second-influx-token"})
	k.requireStored(t, servers, fakeProperties{"url": newURL, "token": "second-influx-token"})
	if check := servers.lastCheck(t); check.token != "second-influx-token" {
		t.Errorf("check = %+v, want the new token", check)
	}
	if !isNullAt(t, inst.state, "token_wo") || int64At(t, inst.state, "token_wo_version") != 2 {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// Removing the token and its version sends nothing, and leaves PBS its
	// token, also for the next plan.
	puts = fake.count(put)
	delete(attrs, "token_wo")
	delete(attrs, "token_wo_version")
	config = k.config(t, h, attrs)
	inst = h.update(t, inst, config)
	if fake.count(put) != puts {
		t.Error("removing token_wo sent an update")
	}
	k.requireStored(t, servers, fakeProperties{"url": newURL, "token": "second-influx-token"})
	if !isNullAt(t, inst.state, "token_wo_version") {
		t.Errorf("state = %s", inst.state)
	}
	inst = h.refresh(t, inst)
	requireNoPlannedChange(t, h, inst, config)

	// A comment alone goes out alone, and PBS checks the server for it too,
	// with the token it has.
	checks = servers.checkCount()
	attrs["comment"] = "Metrics of pbs1"
	inst = h.update(t, inst, k.config(t, h, attrs))
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"comment": "Metrics of pbs1"})
	if check := servers.lastCheck(t); servers.checkCount() != checks+1 || check.token != "second-influx-token" {
		t.Errorf("checks = %d, last %+v, want one more with the stored token", servers.checkCount()-checks, check)
	}

	h.destroy(t, inst)
	k.requireDeletedWithDigest(t, fake, servers)
}

// The life of an InfluxDB UDP server: PBS resolves its host before it saves
// it, on every create and on every update after which it is enabled, and
// stores only what differs from its defaults.
func TestInfluxDBUDPResourceLifecycle(t *testing.T) {
	h, fake, servers := newMetricServerHarness(t)
	k := metricUDPKind
	put := k.route(http.MethodPut, "influx")
	const newHost = "[2001:db8::10]:8089"

	attrs := map[string]any{"comment": "Metrics"}
	config := k.config(t, h, attrs)
	inst := h.create(t, k.typeName, config)
	requireForm(t, "POST", fake.lastCall(t, k.route(http.MethodPost, "")).form,
		map[string]string{"name": "influx", "host": testInfluxHost, "comment": "Metrics"})
	k.requireStored(t, servers, fakeProperties{"host": testInfluxHost, "comment": "Metrics"})
	if check := servers.lastCheck(t); check.serverType != k.serverType || check.target != testInfluxHost || check.withToken {
		t.Errorf("check = %+v, want %s", check, testInfluxHost)
	}
	if stringAt(t, inst.state, "id") != "influx" || stringAt(t, inst.state, "host") != testInfluxHost ||
		int64At(t, inst.state, "mtu") != pbsclient.DefaultInfluxDBMTU || !boolAt(t, inst.state, "enable") ||
		stringAt(t, inst.state, "comment") != "Metrics" {
		t.Errorf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, k.typeName, inst.identity), "name"); got != "influx" {
		t.Errorf("identity name = %q", got)
	}
	requireNoPlannedChange(t, h, inst, config)
	if refreshed := h.refresh(t, inst); !refreshed.state.Equal(inst.state) {
		diffs, _ := refreshed.state.Diff(inst.state)
		t.Errorf("refresh changes %v", diffs)
	}

	// Only what changed is sent, and PBS resolves the new host.
	attrs["host"] = newHost
	attrs["mtu"] = 9000
	config = k.config(t, h, attrs)
	inst = h.update(t, inst, config)
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"host": newHost, "mtu": "9000"})
	k.requireStored(t, servers, fakeProperties{"host": newHost, "mtu": int64(9000), "comment": "Metrics"})
	if check := servers.lastCheck(t); check.target != newHost {
		t.Errorf("check = %+v, want the new host", check)
	}
	if stringAt(t, inst.state, "host") != newHost || int64At(t, inst.state, "mtu") != 9000 {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// Back to the default MTU, given explicitly, and without the comment:
	// deleted, not written.
	attrs["mtu"] = pbsclient.DefaultInfluxDBMTU
	delete(attrs, "comment")
	config = k.config(t, h, attrs)
	inst = h.update(t, inst, config)
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"delete": "comment,mtu"})
	k.requireStored(t, servers, fakeProperties{"host": newHost})
	if int64At(t, inst.state, "mtu") != pbsclient.DefaultInfluxDBMTU || !isNullAt(t, inst.state, "comment") {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// Disabled, the server is stored with enable = false and not checked;
	// enabled again, the property goes, and PBS resolves the host.
	checks := servers.checkCount()
	attrs["enable"] = false
	inst = h.update(t, inst, k.config(t, h, attrs))
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"enable": "false"})
	k.requireStored(t, servers, fakeProperties{"host": newHost, "enable": false})
	if servers.checkCount() != checks || boolAt(t, inst.state, "enable") {
		t.Errorf("a disabled server was checked, or state = %s", inst.state)
	}
	delete(attrs, "enable")
	inst = h.update(t, inst, k.config(t, h, attrs))
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"delete": "enable"})
	k.requireStored(t, servers, fakeProperties{"host": newHost})
	if servers.checkCount() != checks+1 || !boolAt(t, inst.state, "enable") {
		t.Errorf("an enabled server was not checked, or state = %s", inst.state)
	}

	// A comment alone goes out alone, and PBS resolves the host for it too.
	attrs["comment"] = "Metrics of pbs1"
	inst = h.update(t, inst, k.config(t, h, attrs))
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"comment": "Metrics of pbs1"})
	if servers.checkCount() != checks+2 {
		t.Errorf("checks = %d, want one more for the comment", servers.checkCount()-checks)
	}

	h.destroy(t, inst)
	k.requireDeletedWithDigest(t, fake, servers)
}

// An HTTP server is imported by name with every property PBS returns. The
// token cannot be, as PBS never returns it, but a configuration with one
// sends it once.
func TestInfluxDBHTTPResourceImport(t *testing.T) {
	h, fake, servers := newMetricServerHarness(t)
	k := metricHTTPKind
	const importedURL = "https://influxdb.example.com:8086/influx"
	// verify-tls is stored as true, as PBS stores it when it is sent.
	servers.addServer("influx", k.serverType, fakeProperties{"url": importedURL, "token": "stored-influx-token",
		"organization": "metrics", "bucket": "pbs", "max-body-size": int64(1000000), "verify-tls": true,
		"enable": false, "comment": "Imported"})

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, k.typeName, "influx"),
		"identity": h.importByIdentity(t, k.typeName, map[string]any{"name": "influx"}),
	} {
		if stringAt(t, inst.state, "id") != "influx" || stringAt(t, inst.state, "name") != "influx" ||
			stringAt(t, inst.state, "url") != importedURL || stringAt(t, inst.state, "organization") != "metrics" ||
			stringAt(t, inst.state, "bucket") != "pbs" || int64At(t, inst.state, "max_body_size") != 1000000 ||
			!boolAt(t, inst.state, "verify_tls") || boolAt(t, inst.state, "enable") ||
			stringAt(t, inst.state, "comment") != "Imported" || !isNullAt(t, inst.state, "token_wo") ||
			!isNullAt(t, inst.state, "token_wo_version") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
		if got := stringAt(t, h.identityValue(t, k.typeName, inst.identity), "name"); got != "influx" {
			t.Errorf("import by %s: identity name = %q", name, got)
		}
	}

	// A configuration without the token matches; one with a token and its
	// version sends the token, alone.
	attrs := map[string]any{"url": importedURL, "organization": "metrics", "bucket": "pbs", "max_body_size": 1000000,
		"enable": false, "comment": "Imported"}
	inst := h.importByID(t, k.typeName, "influx")
	requireNoPlannedChange(t, h, inst, k.config(t, h, attrs))
	attrs["token_wo"] = testInfluxToken
	attrs["token_wo_version"] = 1
	h.update(t, inst, k.config(t, h, attrs))
	requireForm(t, "PUT", fake.lastCall(t, k.route(http.MethodPut, "influx")).form, map[string]string{"token": testInfluxToken})
	k.requireStored(t, servers, fakeProperties{"url": importedURL, "token": testInfluxToken, "organization": "metrics",
		"bucket": "pbs", "max-body-size": int64(1000000), "verify-tls": true, "enable": false, "comment": "Imported"})
}

// A UDP server is imported by name with every property PBS returns.
func TestInfluxDBUDPResourceImport(t *testing.T) {
	h, fake, servers := newMetricServerHarness(t)
	k := metricUDPKind
	const importedHost = "[2001:db8::10]:8089"
	servers.addServer("influx", k.serverType, fakeProperties{"host": importedHost, "mtu": int64(9000), "enable": false,
		"comment": "Imported"})

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, k.typeName, "influx"),
		"identity": h.importByIdentity(t, k.typeName, map[string]any{"name": "influx"}),
	} {
		if stringAt(t, inst.state, "id") != "influx" || stringAt(t, inst.state, "name") != "influx" ||
			stringAt(t, inst.state, "host") != importedHost || int64At(t, inst.state, "mtu") != 9000 ||
			boolAt(t, inst.state, "enable") || stringAt(t, inst.state, "comment") != "Imported" {
			t.Errorf("import by %s = %s", name, inst.state)
		}
		if got := stringAt(t, h.identityValue(t, k.typeName, inst.identity), "name"); got != "influx" {
			t.Errorf("import by %s: identity name = %q", name, got)
		}
	}

	// A configuration of the same server matches, and an update sends what
	// changed.
	attrs := map[string]any{"host": importedHost, "mtu": 9000, "enable": false, "comment": "Imported"}
	inst := h.importByID(t, k.typeName, "influx")
	requireNoPlannedChange(t, h, inst, k.config(t, h, attrs))
	attrs["comment"] = "Imported server"
	h.update(t, inst, k.config(t, h, attrs))
	requireForm(t, "PUT", fake.lastCall(t, k.route(http.MethodPut, "influx")).form, map[string]string{"comment": "Imported server"})
}

// A name a server of the other type holds imports as nothing, with a warning,
// and so does a missing one, silently; an import id that cannot be a name is
// refused.
func TestMetricServerResourceImportOfOtherType(t *testing.T) {
	for _, k := range metricKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, _, servers := newMetricServerHarness(t)
			other := k.other()
			servers.addServer("influx", other.serverType, other.props(nil))

			resp := h.importResource(t, k.typeName, "influx", nil)
			requireNoProtocolErrors(t, resp.Diagnostics)
			imported := resp.ImportedResources[0]
			read := h.read(t, &resourceInstance{typeName: k.typeName,
				state: h.decodeResource(t, k.typeName, imported.State), identity: imported.Identity})
			requireNoProtocolErrors(t, read.Diagnostics)
			requireProtocolWarningContaining(t, read.Diagnostics, "PBS metric server is no "+k.name+" metric server")
			requireProtocolWarningContaining(t, read.Diagnostics, "got unexpected type '"+other.serverType+"'")
			if state := h.decodeResource(t, k.typeName, read.NewState); !state.IsNull() {
				t.Errorf("import of a server of the other type = %s", state)
			}
			if _, serverType, exists := servers.server("influx"); !exists || serverType != other.serverType {
				t.Errorf("the %s server was touched", other.serverType)
			}

			missing := h.importByID(t, k.typeName, "missing")
			if !missing.state.IsNull() {
				t.Errorf("import of a missing server = %s", missing.state)
			}

			resp = h.importResource(t, k.typeName, "influx/x", nil)
			requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS "+k.name+" metric server by its name")
		})
	}
}

// A server replaced outside Terraform by one of the other type, under the
// same name, leaves state with a warning, and destroying the resource leaves
// that server alone, although PBS's delete would remove it.
func TestMetricServerResourceReplacedByOtherType(t *testing.T) {
	for _, k := range metricKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, servers := newMetricServerHarness(t)
			inst := h.create(t, k.typeName, k.config(t, h, nil))
			other := k.other()
			servers.addServer("influx", other.serverType, other.props(nil))

			resp := h.read(t, inst)
			requireNoProtocolErrors(t, resp.Diagnostics)
			requireProtocolWarningContaining(t, resp.Diagnostics, "PBS metric server is no "+k.name+" metric server")
			requireProtocolWarningContaining(t, resp.Diagnostics, "not of type "+k.serverType)
			if state := h.decodeResource(t, k.typeName, resp.NewState); !state.IsNull() {
				t.Errorf("refresh kept the server: %s", state)
			}

			destroyed := syncDestroyResponse(t, h, inst)
			requireNoProtocolErrors(t, destroyed.Diagnostics)
			requireProtocolWarningContaining(t, destroyed.Diagnostics, "so it was not deleted")
			if _, serverType, exists := servers.server("influx"); !exists || serverType != other.serverType {
				t.Errorf("destroy deleted the %s server", other.serverType)
			}
			if fake.count(k.route(http.MethodDelete, "influx")) != 0 || fake.count(other.route(http.MethodDelete, "influx")) != 0 {
				t.Errorf("routes = %v, want no DELETE", fake.routes())
			}
		})
	}
}

// The delete sends the digest of its read, and reads again when another
// writer changed metricserver.cfg in between; a server already gone is no
// error.
func TestMetricServerResourceDeleteRetriesOnDigestConflict(t *testing.T) {
	for _, k := range metricKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, servers := newMetricServerHarness(t)
			inst := h.create(t, k.typeName, k.config(t, h, nil))
			get, del := k.route(http.MethodGet, "influx"), k.route(http.MethodDelete, "influx")
			reads := fake.count(get)

			bumped := false
			fake.handle(del, func(w http.ResponseWriter, req *http.Request) {
				if !bumped {
					bumped = true
					servers.addServer("other", metricUDPKind.serverType, metricUDPKind.props(nil))
				}
				servers.serveServer(k.serverType)(w, req)
			})
			h.destroy(t, inst)
			if _, _, exists := servers.server("influx"); exists {
				t.Error("destroy left the server")
			}
			if _, _, exists := servers.server("other"); !exists {
				t.Error("destroy deleted the server the other writer added")
			}
			if fake.count(del) != 2 || fake.count(get) != reads+2 {
				t.Errorf("DELETE was sent %d times after %d reads, want 2 after 2", fake.count(del), fake.count(get)-reads)
			}
			if fake.lastCall(t, del).query.Get(pbsclient.DigestParam) == "" {
				t.Error("DELETE sent no digest")
			}

			h.destroy(t, inst)
			if fake.count(del) != 2 {
				t.Errorf("a server already gone was deleted again: routes = %v", fake.routes())
			}
		})
	}
}

// InfluxDB HTTP and UDP servers share one namespace: a name a server of either
// type holds fails the create, on name, with advice to import it, before PBS
// checks anything.
func TestMetricServerResourceNameTaken(t *testing.T) {
	for _, k := range metricKinds {
		for _, holder := range []metricServerKind{k, k.other()} {
			t.Run(k.typeName+"/"+holder.serverType, func(t *testing.T) {
				h, _, servers := newMetricServerHarness(t)
				servers.addServer("influx", holder.serverType, holder.props(fakeProperties{"comment": "Taken"}))

				resp := directoryCreateResponse(t, h, k.typeName, k.config(t, h, nil))
				requireProtocolErrorOn(t, resp.Diagnostics, tftypes.NewAttributePath().WithAttributeName("name"))
				requireProtocolErrorContaining(t, resp.Diagnostics, `PBS already has a metric server "influx"`)
				requireProtocolErrorContaining(t, resp.Diagnostics, "InfluxDB HTTP and UDP servers share one namespace")
				requireProtocolErrorContaining(t, resp.Diagnostics, "If it is an "+k.name+" server, import it")
				requireProtocolErrorContaining(t, resp.Diagnostics, "metric server 'influx' already exists.")
				holder.requireStored(t, servers, holder.props(fakeProperties{"comment": "Taken"}))
				if servers.checkCount() != 0 {
					t.Error("PBS checked a server whose name is taken")
				}
			})
		}
	}
}

// PBS checks an HTTP server before it saves it: a check that fails saves
// nothing, and the error says what to look at, and that enable = false saves
// the server without the check. The token stays out of the error. PBS 4 does
// not say why it could not connect, so for an https:// URL the advice covers
// the certificate too.
func TestInfluxDBHTTPResourceCheckFailures(t *testing.T) {
	k := metricHTTPKind
	for name, tc := range map[string]struct{ reason, advice string }{
		"unauthorized":    {fakeInfluxUnauthorized, "answered GET " + testInfluxURL + "/health with 401, refusing the token or the lack of one"},
		"no InfluxDB API": {fakeInfluxNotFound, "without /api/v2"},
		"not ready":       {fakeInfluxUnavailable, "answered GET " + testInfluxURL + "/health with 503 instead of a 2xx"},
		"not connected":   {fakeInfluxConnectFailed, "the PBS host, not the machine running Terraform, reaches the URL's host and port"},
		"not connected, the certificate": {fakeInfluxConnectFailed,
			"add an internal CA to the PBS host's trust store (/usr/local/share/ca-certificates, then update-ca-certificates)"},
	} {
		t.Run(name, func(t *testing.T) {
			h, _, servers := newMetricServerHarness(t)
			servers.failTarget(testInfluxURL, tc.reason)

			resp := directoryCreateResponse(t, h, k.typeName, k.config(t, h, map[string]any{
				"token_wo": testInfluxToken, "token_wo_version": 1}))
			requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to create PBS InfluxDB HTTP metric server")
			requireProtocolErrorContaining(t, resp.Diagnostics, "PBS sends GET "+testInfluxURL+"/health from its own host")
			requireProtocolErrorContaining(t, resp.Diagnostics, tc.advice)
			requireProtocolErrorContaining(t, resp.Diagnostics, "To save the server without the check, set `enable = false`.")
			requireProtocolErrorContaining(t, resp.Diagnostics, "could not connect to "+testInfluxURL+": "+tc.reason)
			requireNoSecretIn(t, resp.Diagnostics, testInfluxToken)
			if state := h.decodeResource(t, k.typeName, resp.NewState); !state.IsNull() {
				t.Errorf("state = %s after a failed check", state)
			}
			if _, _, exists := servers.server("influx"); exists {
				t.Error("PBS saved a server whose check failed")
			}
		})
	}
}

// A certificate PBS does not trust fails the check only while verify_tls is
// on: the server is saved without it, and turning it on again fails the
// update, which changes nothing. Without verification, a failed connection
// to an https:// URL is no matter of certificates; to an http:// URL never.
func TestInfluxDBHTTPResourceVerifyTLS(t *testing.T) {
	h, _, servers := newMetricServerHarness(t)
	k := metricHTTPKind
	servers.untrustCertificate(testInfluxURL)

	inst := h.create(t, k.typeName, k.config(t, h, map[string]any{"verify_tls": false}))
	k.requireStored(t, servers, fakeProperties{"url": testInfluxURL, "verify-tls": false})

	resp := directoryUpdateResponse(t, h, inst, k.config(t, h, nil))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to update PBS InfluxDB HTTP metric server")
	requireProtocolErrorContaining(t, resp.Diagnostics, "`verify_tls = false` skips the verification, but then PBS "+
		"sends the token to whatever answers at the URL")
	k.requireStored(t, servers, fakeProperties{"url": testInfluxURL, "verify-tls": false})

	servers.failTarget(testInfluxURL, fakeInfluxConnectFailed)
	resp = directoryUpdateResponse(t, h, inst, k.config(t, h, map[string]any{"verify_tls": false, "comment": "Metrics"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "For an https:// URL, the server must speak TLS on that port.")
	for _, d := range resp.Diagnostics {
		if strings.Contains(d.Detail, "trust store") {
			t.Errorf("advice without verification mentions the trust store: %s", d.Detail)
		}
	}

	const plainURL = "http://influxdb.example.com:8086"
	servers.failTarget(plainURL, fakeInfluxConnectFailed)
	resp = directoryCreateResponse(t, h, k.typeName, k.config(t, h, map[string]any{"name": "plain", "url": plainURL}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS could not connect to "+plainURL+", so it saved nothing")
	for _, d := range resp.Diagnostics {
		if strings.Contains(d.Detail, "https://") || strings.Contains(d.Detail, "certificate") {
			t.Errorf("advice for an http:// URL mentions TLS: %s", d.Detail)
		}
	}
}

// PBS checks an HTTP server with the token the change sends, or else with the
// one it has: an InfluxDB that wants a token refuses a server without one,
// and a wrong new token fails the update, which keeps the token PBS has.
func TestInfluxDBHTTPResourceCheckToken(t *testing.T) {
	h, _, servers := newMetricServerHarness(t)
	k := metricHTTPKind
	servers.requireHealthToken(testInfluxURL, testInfluxToken)

	resp := directoryCreateResponse(t, h, k.typeName, k.config(t, h, nil))
	requireProtocolErrorContaining(t, resp.Diagnostics, "with 401, refusing the token or the lack of one")
	requireProtocolErrorContaining(t, resp.Diagnostics, "the one in `token_wo` when `token_wo_version` changes")
	if check := servers.lastCheck(t); check.withToken {
		t.Errorf("check = %+v, want one without a token", check)
	}

	attrs := map[string]any{"token_wo": testInfluxToken, "token_wo_version": 1}
	inst := h.create(t, k.typeName, k.config(t, h, attrs))

	// An update that sends no token is checked with the stored one ...
	attrs["comment"] = "Metrics"
	inst = h.update(t, inst, k.config(t, h, attrs))
	if check := servers.lastCheck(t); !check.withToken || check.token != testInfluxToken {
		t.Errorf("check = %+v, want the stored token", check)
	}

	// ... and one with a token InfluxDB refuses fails, and changes nothing.
	resp = directoryUpdateResponse(t, h, inst, k.config(t, h, map[string]any{
		"token_wo": "wrong-influx-token", "token_wo_version": 2, "comment": "Metrics of pbs1"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to update PBS InfluxDB HTTP metric server")
	requireProtocolErrorContaining(t, resp.Diagnostics, "with 401, refusing the token or the lack of one")
	requireNoSecretIn(t, resp.Diagnostics, "wrong-influx-token", testInfluxToken)
	if check := servers.lastCheck(t); check.token != "wrong-influx-token" {
		t.Errorf("check = %+v, want the new token", check)
	}
	k.requireStored(t, servers, fakeProperties{"url": testInfluxURL, "token": testInfluxToken, "comment": "Metrics"})
}

// PBS checks a server of either type before it saves it, and not at all while
// it is disabled: a server PBS cannot reach fails the create, but is saved
// and changed with enable = false; enabling it fails until PBS reaches it,
// and a server PBS no longer reaches fails every update. A failed check saves
// nothing.
func TestMetricServerResourceCheckFollowsEnable(t *testing.T) {
	for _, k := range metricKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, servers := newMetricServerHarness(t)
			put := k.route(http.MethodPut, "influx")
			servers.failTarget(k.address, k.failure)

			resp := directoryCreateResponse(t, h, k.typeName, k.config(t, h, nil))
			requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to create PBS "+k.name+" metric server")
			requireProtocolErrorContaining(t, resp.Diagnostics, k.advice)
			requireProtocolErrorContaining(t, resp.Diagnostics, "To save the server without the check, set `enable = false`.")
			requireProtocolErrorContaining(t, resp.Diagnostics, k.checkError())
			if _, _, exists := servers.server("influx"); exists {
				t.Error("PBS saved a server whose check failed")
			}
			if k.serverType == pbsclient.MetricServerTypeInfluxDBUDP {
				requireProtocolErrorContaining(t, resp.Diagnostics, "the name must resolve on the PBS host")
			}

			attrs := map[string]any{"enable": false, "comment": "Not yet"}
			inst := h.create(t, k.typeName, k.config(t, h, attrs))
			attrs["comment"] = "Not yet reachable"
			inst = h.update(t, inst, k.config(t, h, attrs))
			k.requireStored(t, servers, k.props(fakeProperties{"enable": false, "comment": "Not yet reachable"}))
			if servers.checkCount() != 1 {
				t.Errorf("PBS made %d checks, want only the one of the failed create", servers.checkCount())
			}

			delete(attrs, "enable")
			attrs["comment"] = "Reachable"
			resp = directoryUpdateResponse(t, h, inst, k.config(t, h, attrs))
			requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"delete": "enable", "comment": "Reachable"})
			requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to update PBS "+k.name+" metric server")
			requireProtocolErrorContaining(t, resp.Diagnostics, k.advice)
			requireProtocolErrorContaining(t, resp.Diagnostics, "set `enable = false`")
			requireProtocolErrorContaining(t, resp.Diagnostics, k.checkError())
			k.requireStored(t, servers, k.props(fakeProperties{"enable": false, "comment": "Not yet reachable"}))

			servers.failTarget(k.address, "")
			inst = h.update(t, inst, k.config(t, h, attrs))
			k.requireStored(t, servers, k.props(fakeProperties{"comment": "Reachable"}))
			if !boolAt(t, inst.state, "enable") {
				t.Errorf("state = %s", inst.state)
			}

			servers.failTarget(k.address, k.failure)
			attrs["comment"] = "Moved"
			resp = directoryUpdateResponse(t, h, inst, k.config(t, h, attrs))
			requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"comment": "Moved"})
			requireProtocolErrorContaining(t, resp.Diagnostics, k.checkError())
			k.requireStored(t, servers, k.props(fakeProperties{"comment": "Reachable"}))
		})
	}
}

// Failed calls are errors that name the privilege they need, without advice
// on a check that did not fail. A server whose read-back fails is still
// recorded: tainted after a create, as planned after an update.
func TestMetricServerResourceAPIErrors(t *testing.T) {
	for _, k := range metricKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, servers := newMetricServerHarness(t)
			post, get := k.route(http.MethodPost, ""), k.route(http.MethodGet, "influx")
			put, del := k.route(http.MethodPut, "influx"), k.route(http.MethodDelete, "influx")

			fake.reply(post, http.StatusForbidden, "permission check failed")
			resp := directoryCreateResponse(t, h, k.typeName, k.config(t, h, nil))
			requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to create PBS "+k.name+" metric server")
			requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Modify on /")
			requireNoCheckAdvice(t, resp.Diagnostics)
			fake.handle(post, servers.createServer(k.serverType))

			fake.reply(get, http.StatusForbidden, "permission check failed")
			resp = directoryCreateResponse(t, h, k.typeName, k.config(t, h, map[string]any{"comment": "Metrics"}))
			requireProtocolErrorContaining(t, resp.Diagnostics, "it is marked tainted")
			requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /")
			state := h.decodeResource(t, k.typeName, resp.NewState)
			if state.IsNull() || stringAt(t, state, "id") != "influx" || stringAt(t, state, "comment") != "Metrics" {
				t.Errorf("state = %s, want the server as planned", state)
			}
			if _, _, exists := servers.server("influx"); !exists {
				t.Error("the server was not created")
			}
			fake.handle(get, nil)
			inst := h.refresh(t, &resourceInstance{typeName: k.typeName, state: state, identity: resp.NewIdentity})

			fake.reply(get, http.StatusInternalServerError, "unable to parse metricserver.cfg")
			requireProtocolErrorContaining(t, h.read(t, inst).Diagnostics, "Unable to read PBS "+k.name+" metric server")
			resp = directoryUpdateResponse(t, h, inst, k.config(t, h, map[string]any{"comment": "Changed"}))
			requireProtocolErrorContaining(t, resp.Diagnostics, "the change was recorded in state")
			if state := h.decodeResource(t, k.typeName, resp.NewState); stringAt(t, state, "comment") != "Changed" {
				t.Errorf("state = %s, want the update as planned", state)
			}
			fake.handle(get, nil)

			fake.reply(put, http.StatusForbidden, "permission check failed")
			resp = directoryUpdateResponse(t, h, inst, k.config(t, h, map[string]any{"comment": "Other"}))
			requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to update PBS "+k.name+" metric server")
			requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Modify on /")
			requireNoCheckAdvice(t, resp.Diagnostics)

			fake.reply(del, http.StatusForbidden, "permission check failed")
			destroyed := syncDestroyResponse(t, h, inst)
			requireProtocolErrorContaining(t, destroyed.Diagnostics, "Unable to delete PBS "+k.name+" metric server")
			requireProtocolErrorContaining(t, destroyed.Diagnostics, "Sys.Modify on /")
		})
	}
}

// A token Terraform has not resolved by the apply is never sent as an empty
// one.
func TestInfluxDBHTTPResourceUnknownToken(t *testing.T) {
	h, fake, _ := newMetricServerHarness(t)
	k := metricHTTPKind
	unresolved := map[string]any{"token_wo": tfUnknown, "token_wo_version": 1}

	resp := directoryCreateResponse(t, h, k.typeName, k.config(t, h, unresolved))
	requireProtocolErrorContaining(t, resp.Diagnostics, "token_wo_version is set, but token_wo is not known")
	requireProtocolErrorOn(t, resp.Diagnostics, tftypes.NewAttributePath().WithAttributeName("token_wo"))

	inst := h.create(t, k.typeName, k.config(t, h, nil))
	resp = directoryUpdateResponse(t, h, inst, k.config(t, h, unresolved))
	requireProtocolErrorContaining(t, resp.Diagnostics, "token_wo_version changed, but token_wo is not known")
	if fake.count(k.route(http.MethodPost, "")) != 1 || fake.count(k.route(http.MethodPut, "influx")) != 0 {
		t.Errorf("routes = %v, want one create and no update", fake.routes())
	}
}

func TestMetricServerResourceValidation(t *testing.T) {
	h, _, _ := newMetricServerHarness(t)
	const (
		urlError  = "must be an http:// or https:// URL"
		hostError = "must be <host>:<port>"
	)
	type invalid struct {
		attrs map[string]any
		want  string
	}
	cases := map[metricServerKind]map[string]invalid{
		metricHTTPKind: {
			"no scheme":                {map[string]any{"url": "influxdb.example.com:8086"}, urlError},
			"upper-case scheme":        {map[string]any{"url": "HTTP://influxdb.example.com"}, urlError},
			"other scheme":             {map[string]any{"url": "udp://influxdb.example.com:8089"}, urlError},
			"credentials":              {map[string]any{"url": "https://pbs:secret@influxdb.example.com"}, urlError},
			"user":                     {map[string]any{"url": "https://pbs@influxdb.example.com"}, urlError},
			"query":                    {map[string]any{"url": "https://influxdb.example.com/?org=pbs"}, urlError},
			"query without a path":     {map[string]any{"url": "https://influxdb.example.com?org=pbs"}, urlError},
			"fragment":                 {map[string]any{"url": "https://influxdb.example.com/#metrics"}, urlError},
			"space in the path":        {map[string]any{"url": "https://influxdb.example.com/in flux"}, urlError},
			"non-ASCII path":           {map[string]any{"url": "https://influxdb.example.com/zürich"}, urlError},
			"non-ASCII host":           {map[string]any{"url": "https://influxdb.zürich.example"}, urlError},
			"padded":                   {map[string]any{"url": " https://influxdb.example.com"}, urlError},
			"no host":                  {map[string]any{"url": "https://"}, urlError},
			"no host, a path":          {map[string]any{"url": "https:///influx"}, urlError},
			"port 0":                   {map[string]any{"url": "https://influxdb.example.com:0"}, urlError},
			"port 65536":               {map[string]any{"url": "https://influxdb.example.com:65536"}, urlError},
			"5-digit port, a 0 first":  {map[string]any{"url": "https://influxdb.example.com:08086"}, urlError},
			"empty port":               {map[string]any{"url": "https://influxdb.example.com:"}, urlError},
			"unbracketed IPv6":         {map[string]any{"url": "https://2001:db8::10"}, urlError},
			"unbracketed IPv6, a port": {map[string]any{"url": "https://2001:db8::10:8086"}, urlError},
			"IPv6 with a zone":         {map[string]any{"url": "https://[fe80::1%eth0]:8086"}, urlError},
			"IPv4 in brackets":         {map[string]any{"url": "https://[192.0.2.10]:8086"}, urlError},
			"underscore":               {map[string]any{"url": "https://influx_db.example.com"}, urlError},
			"trailing dot":             {map[string]any{"url": "https://influxdb.example.com."}, urlError},
			"max_body_size 0":          {map[string]any{"max_body_size": 0}, "value must be at least 1"},
			"empty organization":       {map[string]any{"organization": ""}, "string length must be between 1 and 32"},
			"long organization":        {map[string]any{"organization": strings.Repeat("o", 33)}, "string length must be between 1 and 32"},
			"padded organization":      {map[string]any{"organization": " pbs"}, "must not begin or end with white space"},
			"empty bucket":             {map[string]any{"bucket": ""}, "string length must be between 1 and 32"},
			"long bucket":              {map[string]any{"bucket": strings.Repeat("b", 33)}, "string length must be between 1 and 32"},
			"bucket on two lines":      {map[string]any{"bucket": "pbs\nmetrics"}, "must be a single line"},
			"token without a version":  {map[string]any{"token_wo": testInfluxToken}, `"token_wo_version" must be specified`},
			"version without a token":  {map[string]any{"token_wo_version": 1}, `"token_wo" must be specified`},
			"empty token":              {map[string]any{"token_wo": "", "token_wo_version": 1}, "string length must be at least 1"},
		},
		metricUDPKind: {
			"no port":               {map[string]any{"host": "influxdb.example.com"}, hostError},
			"empty port":            {map[string]any{"host": "influxdb.example.com:"}, hostError},
			"no host":               {map[string]any{"host": ":8089"}, hostError},
			"URL":                   {map[string]any{"host": "udp://influxdb.example.com:8089"}, hostError},
			"path":                  {map[string]any{"host": "influxdb.example.com:8089/metrics"}, hostError},
			"unbracketed IPv6":      {map[string]any{"host": "2001:db8::10:8089"}, hostError},
			"IPv6 without a port":   {map[string]any{"host": "[2001:db8::10]"}, hostError},
			"IPv6 with a zone":      {map[string]any{"host": "[fe80::1%eth0]:8089"}, hostError},
			"IPv4 in brackets":      {map[string]any{"host": "[192.0.2.10]:8089"}, hostError},
			"underscore":            {map[string]any{"host": "influx_db.example.com:8089"}, hostError},
			"trailing dot":          {map[string]any{"host": "influxdb.example.com.:8089"}, hostError},
			"non-ASCII host":        {map[string]any{"host": "influxdb.zürich.example:8089"}, hostError},
			"space":                 {map[string]any{"host": "influxdb.example.com :8089"}, hostError},
			"port 0":                {map[string]any{"host": "influxdb.example.com:0"}, hostError},
			"port 65536":            {map[string]any{"host": "influxdb.example.com:65536"}, hostError},
			"5-digit port, 0 first": {map[string]any{"host": "influxdb.example.com:08089"}, hostError},
			"MTU 50":                {map[string]any{"mtu": 50}, "value must be between 51 and 65535"},
			"MTU above 65535":       {map[string]any{"mtu": 65536}, "value must be between 51 and 65535"},
		},
	}
	for _, k := range metricKinds {
		maps.Copy(cases[k], map[string]invalid{
			"short name":              {map[string]any{"name": "in"}, "string length must be between 3 and 32"},
			"long name":               {map[string]any{"name": strings.Repeat("i", 33)}, "string length must be between 3 and 32"},
			"name starting with -":    {map[string]any{"name": "-influx"}, "must start with a letter, a digit or an underscore"},
			"name with a slash":       {map[string]any{"name": "influx/x"}, "must start with a letter, a digit or an underscore"},
			"empty comment":           {map[string]any{"comment": ""}, "string length must be between 1 and 128"},
			"comment on two lines":    {map[string]any{"comment": "a\nb"}, "must be a single line"},
			"padded comment":          {map[string]any{"comment": "Metrics "}, "must not begin or end with white space"},
			"comment longer than 128": {map[string]any{"comment": strings.Repeat("c", 129)}, "string length must be between 1 and 128"},
		})
	}
	for k, kindCases := range cases {
		for name, tc := range kindCases {
			t.Run(k.typeName+"/"+name, func(t *testing.T) {
				requireProtocolErrorContaining(t, h.validateResource(t, k.typeName, k.config(t, h, tc.attrs)), tc.want)
			})
		}
	}

	for _, attrs := range []map[string]any{
		{"url": "http://influxdb.example.com"},
		{"url": "https://192.0.2.10:8086"},
		{"url": "https://[2001:db8::10]:8086"},
		{"url": "https://[::1]"},
		{"url": "http://localhost:1"},
		{"url": "http://localhost:0089"},
		{"url": "https://influxdb.example.com:65535/proxy/influxdb"},
		{"url": "https://metrics.example.com/influx-db_2.x~v", "max_body_size": 1, "verify_tls": false},
		{"organization": strings.Repeat("o", 32), "bucket": "telegraf/autogen"},
		{"name": "_influx.db-1", "token_wo": testInfluxToken, "token_wo_version": 1, "comment": strings.Repeat("c", 128)},
	} {
		requireNoProtocolErrors(t, h.validateResource(t, metricHTTPKind.typeName, metricHTTPKind.config(t, h, attrs)))
	}
	for _, attrs := range []map[string]any{
		{"host": "192.0.2.10:8089"},
		{"host": "[2001:db8::10]:8089"},
		{"host": "[::1]:1"},
		{"host": "localhost:65535", "mtu": 51},
		{"host": "localhost:0089", "mtu": 400},
		{"mtu": 65535, "enable": false, "name": "_influx.db-1"},
	} {
		requireNoProtocolErrors(t, h.validateResource(t, metricUDPKind.typeName, metricUDPKind.config(t, h, attrs)))
	}

	// A token that fails validation is not repeated in the error.
	for _, token := range []string{"SecretInfluxToken\n", " SecretInfluxToken"} {
		diags := h.validateResource(t, metricHTTPKind.typeName, metricHTTPKind.config(t, h, map[string]any{
			"token_wo": token, "token_wo_version": 1}))
		requireProtocolErrorContaining(t, diags, "the value is not shown")
		requireNoSecretIn(t, diags, "SecretInfluxToken")
	}
}

// The fake answers as PBS does: one namespace and digest for both types, the
// token kept but never returned, enable stored only when false, the comment
// trimmed by an update only, deletions before values, and a check of every
// server that is enabled after the change.
func TestFakeMetricServers(t *testing.T) {
	fake := newFakePBS()
	servers := newFakeMetricServers(fake)
	client := fake.configured(t).client
	ctx := context.Background()
	httpType, udpType := pbsclient.MetricServerTypeInfluxDBHTTP, pbsclient.MetricServerTypeInfluxDBUDP

	if err := client.CreateMetricServer(ctx, httpType, url.Values{"name": {"influx"}, "url": {testInfluxURL},
		"token": {testInfluxToken}, "enable": {"true"}, "verify-tls": {"true"}, "comment": {" Metrics "}}); err != nil {
		t.Fatal(err)
	}
	metricHTTPKind.requireStored(t, servers, fakeProperties{"url": testInfluxURL, "token": testInfluxToken,
		"verify-tls": true, "comment": " Metrics "})
	var item map[string]any
	if _, err := client.Get(ctx, pbsclient.Path("config", "metrics", httpType, "influx"), nil, &item); err != nil ||
		item["url"] != testInfluxURL || item["token"] != nil {
		t.Errorf("GET = %v, %v; want the server without its token", item, err)
	}
	var list []map[string]any
	if _, err := client.Get(ctx, pbsclient.Path("config", "metrics", httpType), nil, &list); err != nil ||
		len(list) != 1 || list[0]["token"] != nil {
		t.Errorf("list = %v, %v; want the server without its token", list, err)
	}

	stale := strings.Repeat("0", 64)
	for name, tc := range map[string]struct {
		err  error
		is   func(error) bool
		want string
	}{
		"name of the other type": {client.CreateMetricServer(ctx, udpType, url.Values{"name": {"influx"}, "host": {testInfluxHost}}),
			pbsclient.IsAlreadyExists, "metric server 'influx' already exists."},
		"parameter of the other type": {client.CreateMetricServer(ctx, httpType, url.Values{"name": {"other"}, "url": {testInfluxURL},
			"host": {testInfluxHost}}), nil, "'host': schema does not allow additional properties"},
		"no host": {client.CreateMetricServer(ctx, udpType, url.Values{"name": {"other"}}), nil, "'host': parameter is missing"},
		"undeletable url": {client.UpdateMetricServer(ctx, httpType, "influx", url.Values{"delete": {"url"}}), nil,
			"'delete': value 'url' is not defined in the enumeration"},
		"update as the other type": {client.UpdateMetricServer(ctx, udpType, "influx", url.Values{"mtu": {"9000"}}),
			pbsclient.IsOfOtherType, "got unexpected type 'influxdb-http' for influxdb-udp 'influx'"},
		"stale digest": {client.UpdateMetricServer(ctx, httpType, "influx", url.Values{"digest": {stale}}),
			pbsclient.IsDigestConflict, "detected modified configuration"},
		"update of a missing server": {client.UpdateMetricServer(ctx, httpType, "missing", url.Values{"comment": {"x"}}),
			pbsclient.IsNotFound, "no such influxdb-http 'missing'"},
		"delete of a missing server": {client.DeleteMetricServer(ctx, udpType, "missing", ""), pbsclient.IsNotFound,
			"name 'missing' does not exist."},
		"read as the other type": {func() error { _, _, err := client.GetInfluxDBUDPServer(ctx, "influx"); return err }(),
			pbsclient.IsOfOtherType, "got unexpected type 'influxdb-http' for influxdb-udp 'influx'"},
		"read of a missing server": {func() error { _, _, err := client.GetInfluxDBHTTPServer(ctx, "missing"); return err }(),
			pbsclient.IsNotFound, "no such influxdb-http 'missing'"},
	} {
		if tc.err == nil || !strings.Contains(tc.err.Error(), tc.want) || (tc.is != nil && !tc.is(tc.err)) {
			t.Errorf("%s: error = %v, want %q", name, tc.err, tc.want)
		}
	}

	// An update trims the comment, deletes before it sets, and checks the
	// server with the token it sends, or the stored one, unless it disables
	// the server.
	update := func(params url.Values) {
		t.Helper()
		if err := client.UpdateMetricServer(ctx, httpType, "influx", params); err != nil {
			t.Fatal(err)
		}
	}
	update(url.Values{"comment": {"  Trimmed  "}})
	if check := servers.lastCheck(t); check.token != testInfluxToken {
		t.Errorf("check = %+v, want the stored token", check)
	}
	update(url.Values{"delete": {"comment", "token"}, "comment": {"Kept"}, "token": {"second-influx-token"}})
	if check := servers.lastCheck(t); check.token != "second-influx-token" {
		t.Errorf("check = %+v, want the token sent", check)
	}
	metricHTTPKind.requireStored(t, servers, fakeProperties{"url": testInfluxURL, "token": "second-influx-token",
		"verify-tls": true, "comment": "Kept"})
	checks := servers.checkCount()
	update(url.Values{"comment": {" "}, "enable": {"false"}, "delete": {"token"}})
	metricHTTPKind.requireStored(t, servers, fakeProperties{"url": testInfluxURL, "verify-tls": true, "enable": false})
	update(url.Values{"delete": {"enable"}})
	if check := servers.lastCheck(t); servers.checkCount() != checks+1 || check.withToken {
		t.Errorf("checks = %d, last %+v; want one, of the enabled server, without a token", servers.checkCount()-checks, check)
	}
	metricHTTPKind.requireStored(t, servers, fakeProperties{"url": testInfluxURL, "verify-tls": true})

	// A failed check saves nothing; an untrusted certificate fails only with
	// verify-tls. Every reason is one MetricServerCheckFailureOf knows.
	servers.untrustCertificate(testInfluxURL)
	if err := client.UpdateMetricServer(ctx, httpType, "influx", url.Values{"comment": {"Failed"}}); err == nil {
		t.Error("an update failing the check was saved")
	}
	update(url.Values{"comment": {"Unverified"}, "verify-tls": {"false"}})
	metricHTTPKind.requireStored(t, servers, fakeProperties{"url": testInfluxURL, "verify-tls": false, "comment": "Unverified"})
	for reason, want := range map[string]pbsclient.MetricServerCheck{
		fakeInfluxNotFound:      pbsclient.MetricServerNoHealth,
		fakeInfluxUnauthorized:  pbsclient.MetricServerUnauthorized,
		fakeInfluxUnavailable:   pbsclient.MetricServerBadStatus,
		fakeInfluxConnectFailed: pbsclient.MetricServerUnreachable,
	} {
		servers.failTarget("https://check.example.com", reason)
		err := client.CreateMetricServer(ctx, httpType, url.Values{"name": {"check"}, "url": {"https://check.example.com"}})
		if got, _ := pbsclient.MetricServerCheckFailureOf(err); got != want {
			t.Errorf("%s: check failure %v of %v, want %v", reason, got, err, want)
		}
	}
	servers.failTarget(testInfluxHost, fakeInfluxLookupFailed)
	err := client.CreateMetricServer(ctx, udpType, url.Values{"name": {"udp"}, "host": {testInfluxHost}})
	if got, _ := pbsclient.MetricServerCheckFailureOf(err); got != pbsclient.MetricServerUnreachable {
		t.Errorf("UDP check failure %v of %v", got, err)
	}
	if _, _, exists := servers.server("check"); exists {
		t.Error("a server whose check failed was saved")
	}

	// Each type lists its own servers, in reverse name order; a delete
	// removes a server of either type.
	servers.addServer("a", httpType, fakeProperties{"url": testInfluxURL})
	servers.addServer("b", udpType, fakeProperties{"host": testInfluxHost})
	httpServers, err := client.ListInfluxDBHTTPServers(ctx)
	if err != nil || len(httpServers) != 2 || httpServers[0].Name != "influx" || httpServers[1].Name != "a" {
		t.Errorf("HTTP servers = %+v, %v", httpServers, err)
	}
	udpServers, err := client.ListInfluxDBUDPServers(ctx)
	if err != nil || len(udpServers) != 1 || udpServers[0].Name != "b" {
		t.Errorf("UDP servers = %+v, %v", udpServers, err)
	}
	if err := client.DeleteMetricServer(ctx, udpType, "influx", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, exists := servers.server("influx"); exists {
		t.Error("DELETE under influxdb-udp left the HTTP server")
	}
}
