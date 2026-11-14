package provider

import (
	"net/http"
	"slices"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestMetricServerListResources(t *testing.T) {
	h, fake, servers := newMetricServerHarness(t)
	h.create(t, metricHTTPKind.typeName, metricHTTPKind.config(t, h, map[string]any{
		"token_wo": testInfluxToken, "token_wo_version": 1, "bucket": "pbs", "comment": "Monitoring",
	}))
	h.create(t, metricHTTPKind.typeName, metricHTTPKind.config(t, h, map[string]any{"name": "archive", "enable": false, "verify_tls": false}))
	h.create(t, metricUDPKind.typeName, metricUDPKind.config(t, h, map[string]any{"name": "udp", "mtu": 1400, "comment": "Telegraf"}))
	// A server PBS has without the provider, and one it cannot check.
	servers.addServer("legacy", pbsclient.MetricServerTypeInfluxDBUDP, metricUDPKind.props(fakeProperties{"enable": false}))

	// Without resources, each list names the servers of its type, from one
	// call: the types share a namespace, not a list.
	for kind, want := range map[metricServerKind][]string{
		metricHTTPKind: {"archive", "influx"},
		metricUDPKind:  {"legacy", "udp"},
	} {
		route := "GET /config/metrics/" + kind.serverType
		before := fake.count(route)
		results := h.listedObjects(t, kind.typeName, listRequest{})
		if got := listedIdentities(t, results, "name"); !slices.Equal(got, want) {
			t.Fatalf("%s listed %q, want %q", kind.typeName, got, want)
		}
		if fake.count(route) != before+1 || !results[0].resource.IsNull() {
			t.Fatalf("%s: a list without resources made %d calls", kind.typeName, fake.count(route)-before)
		}
	}
	requireListedDisplayNames(t, h.listedObjects(t, metricHTTPKind.typeName, listRequest{}), "archive", "influx — Monitoring")

	// With resources, each result is what importing the server gives, and
	// its generated configuration plans no change: the token, which an
	// import does not read, stays as PBS has it.
	checks := servers.checkCount()
	httpServers := h.listedObjects(t, metricHTTPKind.typeName, listRequest{includeResource: true})
	for _, result := range httpServers {
		h.requireListedLikeImport(t, metricHTTPKind.typeName, result)
	}
	if boolAt(t, httpServers[0].resource, "enable") || stringAt(t, httpServers[1].resource, "bucket") != "pbs" ||
		!isNullAt(t, httpServers[1].resource, "token_wo_version") {
		t.Fatalf("listed %s, %s", httpServers[0].resource, httpServers[1].resource)
	}
	udpServers := h.listedObjects(t, metricUDPKind.typeName, listRequest{includeResource: true})
	for _, result := range udpServers {
		h.requireListedLikeImport(t, metricUDPKind.typeName, result)
	}
	if int64At(t, udpServers[1].resource, "mtu") != 1400 || boolAt(t, udpServers[0].resource, "enable") {
		t.Fatalf("listed %s, %s", udpServers[0].resource, udpServers[1].resource)
	}
	if stored, _, _ := servers.server("influx"); stored["token"] != testInfluxToken || servers.checkCount() != checks {
		t.Fatalf("listing changed the servers: %v, %d checks", stored, servers.checkCount()-checks)
	}

	if got := h.listedObjects(t, metricUDPKind.typeName, listRequest{limit: 1}); len(got) != 1 {
		t.Fatalf("a limit of 1 listed %d", len(got))
	}
}

// A failed listing fails the list block, with the privilege it needs.
func TestMetricServerListResourcesListFails(t *testing.T) {
	h, fake, _ := newMetricServerHarness(t)
	for _, kind := range metricKinds {
		fake.reply("GET /config/metrics/"+kind.serverType, http.StatusForbidden, "permission check failed")
		results := h.listResources(t, kind.typeName, listRequest{})
		if len(results) != 1 {
			t.Fatalf("%s: got %d results", kind.typeName, len(results))
		}
		requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS "+kind.name+" metric servers")
		requireProtocolErrorContaining(t, results[0].diagnostics, metricServerReadPrivilege)
	}
}
