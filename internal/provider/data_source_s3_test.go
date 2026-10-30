package provider

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestS3DataSourceSchemasAreValid(t *testing.T) {
	requireValidDataSourceSchema(t, &s3EndpointDataSource{})
	requireValidDataSourceSchema(t, &s3EndpointsDataSource{})
	requireValidDataSourceSchema(t, &s3BucketsDataSource{})
}

// requireS3ErrorOn fails the test unless an error is attached to the
// top-level attribute name.
func requireS3ErrorOn(t *testing.T, diags []*tfprotov6.Diagnostic, name string) {
	t.Helper()
	want := tftypes.NewAttributePath().WithAttributeName(name)
	for _, d := range diags {
		if d.Severity == tfprotov6.DiagnosticSeverityError && d.Attribute != nil && d.Attribute.Equal(want) {
			return
		}
	}
	t.Fatalf("expected an error on %s, got %v", name, diags)
}

// The S3 endpoint data sources never show the secret key, which PBS does
// not return, and show fingerprints as pbs_fingerprint does.
func TestS3EndpointDataSources(t *testing.T) {
	h, _, s3, _ := newS3EndpointHarness(t)
	s3.addEndpoint("wasabi", fakeProperties{"endpoint": "s3.{{region}}.wasabisys.com", "port": int64(443),
		"region": "eu-central-2", "access-key": "WASABIACCESSKEY", "fingerprint": strings.ToUpper(testS3EndpointFingerprint),
		"path-style": true, "rate-in": "10 MiB", "burst-out": "1 GiB",
		"provider-quirks":       []string{"skip-if-none-match-header", "delete-objects-via-delete-object"},
		"limit-active-requests": int64(50), "limit-passive-requests": int64(200), "use-node-proxy": true,
		"put-rate-limit": int64(100)}, "wasabi-secret")
	s3.addEndpoint("backblaze", fakeProperties{"endpoint": testS3EndpointHost, "access-key": testS3EndpointAccessKey,
		"path-style": false, "use-node-proxy": false}, "backblaze-secret")
	s3.addEndpoint("minio", fakeProperties{"endpoint": "172.16.0.200", "port": int64(9000), "access-key": "minioadmin",
		"path-style": true, "fingerprint": strings.ReplaceAll(testS3EndpointFingerprint, ":", "")}, "minio-secret")

	endpoint := h.readDataSource(t, "pbs_s3_endpoint", h.dataSourceValue(t, "pbs_s3_endpoint", map[string]any{"id": "wasabi"}))
	if stringAt(t, endpoint, "id") != "wasabi" || stringAt(t, endpoint, "endpoint") != "s3.{{region}}.wasabisys.com" ||
		int64At(t, endpoint, "port") != 443 || stringAt(t, endpoint, "region") != "eu-central-2" ||
		stringAt(t, endpoint, "access_key") != "WASABIACCESSKEY" ||
		stringAt(t, endpoint, "fingerprint") != testS3EndpointFingerprint || !boolAt(t, endpoint, "path_style") ||
		stringAt(t, endpoint, "rate_in") != "10 MiB" || !isNullAt(t, endpoint, "burst_in") ||
		!isNullAt(t, endpoint, "rate_out") || stringAt(t, endpoint, "burst_out") != "1 GiB" ||
		lengthAt(t, endpoint, "provider_quirks") != 2 || int64At(t, endpoint, "limit_active_requests") != 50 ||
		int64At(t, endpoint, "limit_passive_requests") != 200 || !boolAt(t, endpoint, "use_node_proxy") {
		t.Errorf("pbs_s3_endpoint = %s", endpoint)
	}
	if strings.Contains(endpoint.String(), "secret") {
		t.Errorf("pbs_s3_endpoint shows the secret key: %s", endpoint)
	}

	endpoints := h.readDataSource(t, "pbs_s3_endpoints", h.dataSourceValue(t, "pbs_s3_endpoints", map[string]any{}))
	var ids []string
	for i := range lengthAt(t, endpoints, "endpoints") {
		ids = append(ids, stringAt(t, endpoints, "endpoints", i, "id"))
	}
	if strings.Join(ids, ",") != "backblaze,minio,wasabi" {
		t.Errorf("endpoints = %q, want them sorted by ID", ids)
	}
	if stringAt(t, endpoints, "endpoints", 0, "endpoint") != testS3EndpointHost ||
		boolAt(t, endpoints, "endpoints", 0, "path_style") || boolAt(t, endpoints, "endpoints", 0, "use_node_proxy") ||
		!isNullAt(t, endpoints, "endpoints", 0, "port") || !isNullAt(t, endpoints, "endpoints", 0, "region") ||
		!isNullAt(t, endpoints, "endpoints", 0, "fingerprint") || !isNullAt(t, endpoints, "endpoints", 0, "provider_quirks") ||
		!isNullAt(t, endpoints, "endpoints", 0, "rate_in") || !isNullAt(t, endpoints, "endpoints", 0, "limit_active_requests") {
		t.Errorf("pbs_s3_endpoints backblaze = %s", valueAt(t, endpoints, "endpoints", 0))
	}
	if stringAt(t, endpoints, "endpoints", 1, "fingerprint") != testS3EndpointFingerprint ||
		int64At(t, endpoints, "endpoints", 1, "port") != 9000 || !boolAt(t, endpoints, "endpoints", 1, "path_style") ||
		stringAt(t, endpoints, "endpoints", 2, "fingerprint") != testS3EndpointFingerprint ||
		stringAt(t, endpoints, "endpoints", 2, "access_key") != "WASABIACCESSKEY" {
		t.Errorf("pbs_s3_endpoints = %s", endpoints)
	}
	if strings.Contains(endpoints.String(), "secret") {
		t.Errorf("pbs_s3_endpoints shows a secret key: %s", endpoints)
	}

	resp := h.readDataSourceResponse(t, "pbs_s3_endpoint", h.dataSourceValue(t, "pbs_s3_endpoint", map[string]any{"id": "missing"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS has no S3 endpoint "missing"`)
	requireS3ErrorOn(t, resp.Diagnostics, "id")

	// Without endpoints, or without Sys.Audit on any, the list is empty.
	h, _, _, _ = newS3EndpointHarness(t)
	none := h.readDataSource(t, "pbs_s3_endpoints", h.dataSourceValue(t, "pbs_s3_endpoints", map[string]any{}))
	if lengthAt(t, none, "endpoints") != 0 {
		t.Errorf("pbs_s3_endpoints = %s, want an empty list", none)
	}
}

// A bucket list answers what the endpoint's access key sees, sorted; an
// endpoint PBS does not have, or cannot reach, fails it with advice.
func TestS3BucketsDataSource(t *testing.T) {
	h, fake, s3, _ := newS3EndpointHarness(t)
	for _, id := range []string{"wasabi", "empty", "down", "broken"} {
		s3.addEndpoint(id, fakeProperties{"endpoint": "s3.{{region}}.wasabisys.com", "access-key": "WASABIACCESSKEY",
			"path-style": true}, "wasabi-secret")
	}
	for _, name := range []string{"pbs-offsite", "archive", "pbs-local"} {
		s3.addBucket("wasabi", name)
	}
	s3.setUnreachable("down")
	fake.reply("GET /config/s3/broken/list-buckets", http.StatusBadRequest, "client creation failed")

	buckets := h.readDataSource(t, "pbs_s3_buckets", h.dataSourceValue(t, "pbs_s3_buckets", map[string]any{"s3_endpoint": "wasabi"}))
	var names []string
	for i := range lengthAt(t, buckets, "buckets") {
		names = append(names, stringAt(t, buckets, "buckets", i, "name"))
	}
	if strings.Join(names, ",") != "archive,pbs-local,pbs-offsite" || stringAt(t, buckets, "s3_endpoint") != "wasabi" {
		t.Errorf("pbs_s3_buckets = %s, want the buckets sorted by name", buckets)
	}
	empty := h.readDataSource(t, "pbs_s3_buckets", h.dataSourceValue(t, "pbs_s3_buckets", map[string]any{"s3_endpoint": "empty"}))
	if lengthAt(t, empty, "buckets") != 0 {
		t.Errorf("pbs_s3_buckets = %s, want an empty list", empty)
	}

	// PBS answers a missing endpoint with "config lookup failed" alone.
	resp := h.readDataSourceResponse(t, "pbs_s3_buckets", h.dataSourceValue(t, "pbs_s3_buckets", map[string]any{"s3_endpoint": "missing"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS S3 endpoint not found")
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS has no S3 endpoint "missing"`)
	requireS3ErrorOn(t, resp.Diagnostics, "s3_endpoint")

	// PBS keeps the cause of a failed list in its journal, so the error says
	// what to check.
	for _, id := range []string{"down", "broken"} {
		resp = h.readDataSourceResponse(t, "pbs_s3_buckets", h.dataSourceValue(t, "pbs_s3_buckets", map[string]any{"s3_endpoint": id}))
		requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list the buckets of a PBS S3 endpoint")
		requireProtocolErrorContaining(t, resp.Diagnostics, "PBS reports no cause")
		requireProtocolErrorContaining(t, resp.Diagnostics, `S3 endpoint "`+id+`"`)
	}

	// PBS 4.0.4 to 4.0.7 have S3 endpoints but cannot list buckets.
	fake.reply("GET /config/s3/empty/list-buckets", http.StatusNotFound, "Path '/api2/json/config/s3/empty/list-buckets' not found.")
	resp = h.readDataSourceResponse(t, "pbs_s3_buckets", h.dataSourceValue(t, "pbs_s3_buckets", map[string]any{"s3_endpoint": "empty"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS cannot list the buckets of an S3 endpoint")
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS 4.0.8 added listing the buckets")

	// Listing buckets needs more than reading the endpoint.
	fake.reply("GET /config/s3/wasabi/list-buckets", http.StatusForbidden, "permission check failed")
	resp = h.readDataSourceResponse(t, "pbs_s3_buckets", h.dataSourceValue(t, "pbs_s3_buckets", map[string]any{"s3_endpoint": "wasabi"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "(Sys.Audit on /)")
}
