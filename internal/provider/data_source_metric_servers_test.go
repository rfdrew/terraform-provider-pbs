package provider

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestMetricServersDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, NewMetricServersDataSource())
}

// The data source lists the servers of both types, sorted by name, although
// PBS lists each type in no particular order: what a server leaves out reads
// as PBS's default, the attributes of the other type are null, and no token
// is anywhere, as PBS returns none.
func TestMetricServersDataSource(t *testing.T) {
	h, fake, servers := newMetricServerHarness(t)
	config := h.dataSourceValue(t, "pbs_metric_servers", map[string]any{})
	httpList, udpList := "GET /config/metrics/"+pbsclient.MetricServerTypeInfluxDBHTTP, "GET /config/metrics/"+pbsclient.MetricServerTypeInfluxDBUDP

	if empty := h.readDataSource(t, "pbs_metric_servers", config); lengthAt(t, empty, "servers") != 0 {
		t.Errorf("pbs_metric_servers = %s, want no servers", empty)
	}

	servers.addServer("zeta", pbsclient.MetricServerTypeInfluxDBHTTP, fakeProperties{"url": testInfluxURL, "token": testInfluxToken})
	servers.addServer("alpha", pbsclient.MetricServerTypeInfluxDBUDP, fakeProperties{"host": testInfluxHost})
	servers.addServer("lab", pbsclient.MetricServerTypeInfluxDBHTTP, fakeProperties{"url": "http://influxdb.lan:8086/influx",
		"organization": "metrics", "bucket": "pbs", "max-body-size": int64(1000000), "verify-tls": false, "enable": false,
		"comment": "Lab"})
	servers.addServer("office", pbsclient.MetricServerTypeInfluxDBUDP, fakeProperties{"host": "[2001:db8::10]:8089",
		"mtu": int64(9000), "enable": false, "comment": "Office"})

	list := h.readDataSource(t, "pbs_metric_servers", config)
	if lengthAt(t, list, "servers") != 4 || stringAt(t, list, "servers", 0, "name") != "alpha" ||
		stringAt(t, list, "servers", 1, "name") != "lab" || stringAt(t, list, "servers", 2, "name") != "office" ||
		stringAt(t, list, "servers", 3, "name") != "zeta" {
		t.Fatalf("pbs_metric_servers = %s, want alpha, lab, office and zeta", list)
	}
	httpAttributes := []string{"url", "organization", "bucket", "max_body_size", "verify_tls"}
	udpAttributes := []string{"host", "mtu"}
	requireNull := func(i int, names []string) {
		t.Helper()
		for _, name := range names {
			if !isNullAt(t, list, "servers", i, name) {
				t.Errorf("servers[%d].%s = %s, want null", i, name, valueAt(t, list, "servers", i, name))
			}
		}
	}

	if stringAt(t, list, "servers", 0, "type") != pbsclient.MetricServerTypeInfluxDBUDP ||
		stringAt(t, list, "servers", 0, "host") != testInfluxHost ||
		int64At(t, list, "servers", 0, "mtu") != pbsclient.DefaultInfluxDBMTU ||
		!boolAt(t, list, "servers", 0, "enable") || !isNullAt(t, list, "servers", 0, "comment") {
		t.Errorf("alpha = %s", valueAt(t, list, "servers", 0))
	}
	requireNull(0, httpAttributes)

	if stringAt(t, list, "servers", 1, "type") != pbsclient.MetricServerTypeInfluxDBHTTP ||
		stringAt(t, list, "servers", 1, "url") != "http://influxdb.lan:8086/influx" ||
		stringAt(t, list, "servers", 1, "organization") != "metrics" || stringAt(t, list, "servers", 1, "bucket") != "pbs" ||
		int64At(t, list, "servers", 1, "max_body_size") != 1000000 || boolAt(t, list, "servers", 1, "verify_tls") ||
		boolAt(t, list, "servers", 1, "enable") || stringAt(t, list, "servers", 1, "comment") != "Lab" {
		t.Errorf("lab = %s", valueAt(t, list, "servers", 1))
	}
	requireNull(1, udpAttributes)

	if stringAt(t, list, "servers", 2, "type") != pbsclient.MetricServerTypeInfluxDBUDP ||
		stringAt(t, list, "servers", 2, "host") != "[2001:db8::10]:8089" || int64At(t, list, "servers", 2, "mtu") != 9000 ||
		boolAt(t, list, "servers", 2, "enable") || stringAt(t, list, "servers", 2, "comment") != "Office" {
		t.Errorf("office = %s", valueAt(t, list, "servers", 2))
	}
	requireNull(2, httpAttributes)

	if stringAt(t, list, "servers", 3, "type") != pbsclient.MetricServerTypeInfluxDBHTTP ||
		stringAt(t, list, "servers", 3, "url") != testInfluxURL ||
		stringAt(t, list, "servers", 3, "organization") != pbsclient.DefaultInfluxDBOrganization ||
		stringAt(t, list, "servers", 3, "bucket") != pbsclient.DefaultInfluxDBBucket ||
		int64At(t, list, "servers", 3, "max_body_size") != pbsclient.DefaultInfluxDBMaxBodySize ||
		!boolAt(t, list, "servers", 3, "verify_tls") || !boolAt(t, list, "servers", 3, "enable") ||
		!isNullAt(t, list, "servers", 3, "comment") {
		t.Errorf("zeta = %s", valueAt(t, list, "servers", 3))
	}
	requireNull(3, udpAttributes)

	// The token PBS keeps for zeta is in no attribute.
	for name := range harnessObjectAttributes(t, valueAt(t, list, "servers", 3)) {
		if strings.Contains(name, "token") {
			t.Errorf("servers have an attribute %s", name)
		}
	}
	if strings.Contains(list.String(), testInfluxToken) {
		t.Errorf("pbs_metric_servers shows the token: %s", list)
	}
	if fake.count(httpList) != 2 || fake.count(udpList) != 2 {
		t.Errorf("routes = %v, want each list read twice", fake.routes())
	}

	// A failed list fails the data source, with the privilege it needs.
	fake.reply(udpList, http.StatusForbidden, "permission check failed")
	resp := h.readDataSourceResponse(t, "pbs_metric_servers", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS InfluxDB UDP metric servers")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /")
	fake.reply(httpList, http.StatusForbidden, "permission check failed")
	resp = h.readDataSourceResponse(t, "pbs_metric_servers", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS InfluxDB HTTP metric servers")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /")
}
