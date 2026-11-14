package provider

import (
	"net/http"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestS3EndpointListResource(t *testing.T) {
	h, fake, s3, _ := newS3EndpointHarness(t)
	h.create(t, "pbs_s3_endpoint", s3EndpointConfig(t, h, map[string]any{
		"secret_key_wo": "s3cr3t", "secret_key_wo_version": 1, "region": "eu-central-003", "rate_in": "100 MiB",
	}))
	h.create(t, "pbs_s3_endpoint", s3EndpointConfig(t, h, map[string]any{
		"id": "minio", "endpoint": "minio.lan", "port": 9000, "path_style": true, "fingerprint": testS3EndpointFingerprint,
		"secret_key_wo": "minio-secret", "secret_key_wo_version": 1,
	}))

	// Without resources, one call names every endpoint; an endpoint has no
	// comment, so its display name says where it points.
	before, reads := fake.count("GET /config/s3"), fake.count("GET /config/s3/minio")
	results := h.listedObjects(t, "pbs_s3_endpoint", listRequest{})
	if got, want := listedIdentities(t, results, "id"), []string{"backblaze", "minio"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	if fake.count("GET /config/s3") != before+1 || fake.count("GET /config/s3/minio") != reads {
		t.Fatalf("a list without resources made %v", fake.routes())
	}
	requireListedDisplayNames(t, results, "backblaze — "+testS3EndpointHost, "minio — minio.lan:9000")

	// With resources, each result is what importing the endpoint gives, but
	// for the access key, which is sensitive and left out: the generated
	// configuration lacks it, and it is required. Filled in, it plans no
	// change; the secret key stays as PBS has it.
	results = h.listedObjects(t, "pbs_s3_endpoint", listRequest{includeResource: true})
	for _, result := range results {
		if !isNullAt(t, result.resource, "access_key") || !isNullAt(t, result.resource, "secret_key_wo_version") {
			t.Fatalf("listed %s", result.resource)
		}
		config := h.requireListedNeedsValues(t, "pbs_s3_endpoint", result, generatedError{missingRequiredSummary, generatedAttributePath("access_key")})
		h.requireFilledInPlansOnly(t, "pbs_s3_endpoint", result, filledIn(t, config, map[string]tftypes.Value{
			"access_key": tftypes.NewValue(tftypes.String, testS3EndpointAccessKey),
		}))
	}
	if stringAt(t, results[0].resource, "rate_in") != "100 MiB" || int64At(t, results[1].resource, "port") != 9000 ||
		!boolAt(t, results[1].resource, "path_style") {
		t.Fatalf("listed %s, %s", results[0].resource, results[1].resource)
	}
	if s3.secretKey("minio") != "minio-secret" {
		t.Fatal("listing changed the secret key")
	}

	// PBS needs the secret key only to create the endpoint again: a new id
	// fails in the plan without it.
	renamed := filledIn(t, h.generateConfig(t, "pbs_s3_endpoint", results[1].resource), map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, "minio-2"), "access_key": tftypes.NewValue(tftypes.String, testS3EndpointAccessKey),
	})
	plan := h.plan(t, "pbs_s3_endpoint", h.importListed(t, "pbs_s3_endpoint", results[1]), renamed)
	requireProtocolErrorContaining(t, plan.Diagnostics, "Missing S3 secret key")
}

// PBS lists only the endpoints the provider may audit, and refuses no one;
// a failed listing fails the list block.
func TestS3EndpointListResourceListFails(t *testing.T) {
	h, fake, _, _ := newS3EndpointHarness(t)
	fake.reply("GET /config/s3", http.StatusInternalServerError, "unable to parse s3.cfg")
	results := h.listResources(t, "pbs_s3_endpoint", listRequest{})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS S3 endpoints")
}

func TestTrafficControlRuleListResource(t *testing.T) {
	h, fake, rules := newTrafficControlHarness(t)
	h.create(t, "pbs_traffic_control_rule", trafficControlRuleConfig(t, h, map[string]any{
		"rate_in": "10 MiB", "burst_in": "20 MiB", "timeframe": []any{"mon..fri 8:00-18:00"}, "comment": "Office",
	}))
	h.create(t, "pbs_traffic_control_rule", trafficControlRuleConfig(t, h, map[string]any{
		"name": "backup-users", "network": []any{"0.0.0.0/0", "::/0"}, "users": []any{"backup@pbs"}, "rate_out": "1 GiB",
	}))
	rules.addRule("exempt", fakeProperties{"network": []string{"198.51.100.7/32"}})

	// Without resources, the list of the current rates names every rule: it
	// needs Sys.Audit, the configuration's list Sys.Modify.
	results := h.listedObjects(t, "pbs_traffic_control_rule", listRequest{})
	if got, want := listedIdentities(t, results, "name"), []string{"backup-users", "exempt", "office"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	requireListedDisplayNames(t, results, "backup-users", "exempt", "office — Office")
	if fake.count("GET /admin/traffic-control") != 1 || fake.count("GET /config/traffic-control") != 0 {
		t.Fatalf("listing called %v", fake.routes())
	}

	results = h.listedObjects(t, "pbs_traffic_control_rule", listRequest{includeResource: true})
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_traffic_control_rule", result)
	}
	if stringAt(t, results[2].resource, "burst_in") != "20 MiB" || trafficControlStringsAt(t, results[0].resource, "users") != "backup@pbs" {
		t.Fatalf("listed %s, %s", results[0].resource, results[2].resource)
	}

	if got := h.listedObjects(t, "pbs_traffic_control_rule", listRequest{limit: 2, includeResource: true}); len(got) != 2 {
		t.Fatalf("a limit of 2 listed %d", len(got))
	}
}

// A failed listing fails the list block, with the privilege it needs; a
// rule that disappears before its read is left out.
func TestTrafficControlRuleListResourceErrors(t *testing.T) {
	h, fake, rules := newTrafficControlHarness(t)
	rules.addRule("gone", fakeProperties{"network": []string{"192.0.2.0/24"}})
	rules.addRule("kept", fakeProperties{"network": []string{"198.51.100.0/24"}})
	fake.reply("GET /config/traffic-control/gone", http.StatusBadRequest, "no such rule 'gone'")
	results := h.listedObjects(t, "pbs_traffic_control_rule", listRequest{includeResource: true})
	if got := listedIdentities(t, results, "name"); !slices.Equal(got, []string{"kept"}) {
		t.Fatalf("listed %q", got)
	}

	fake.reply("GET /admin/traffic-control", http.StatusForbidden, "permission check failed")
	all := h.listResources(t, "pbs_traffic_control_rule", listRequest{})
	if len(all) != 1 {
		t.Fatalf("got %d results", len(all))
	}
	requireProtocolErrorContaining(t, all[0].diagnostics, "Unable to list PBS traffic control rules")
	requireProtocolErrorContaining(t, all[0].diagnostics, trafficControlReadPrivilege)
}
