package provider

import (
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestS3EndpointResourceSchemaIsValid(t *testing.T) {
	requireValidResourceSchema(t, &s3EndpointResource{})
}

// newS3EndpointHarness is a fake PBS with the S3 endpoint and datastore API
// and a provider signed in to it. version, when set, is what GET /version
// answers.
func newS3EndpointHarness(t *testing.T, version ...string) (*protocolHarness, *fakePBS, *fakeS3, *fakeDatastores) {
	t.Helper()
	fake := newFakePBS()
	if len(version) > 0 {
		fake.reply("GET /version", http.StatusOK, version[0])
	}
	datastores := newFakeDatastores(fake)
	s3 := newFakeS3(fake, datastores)
	return newProtocolHarness(t, fake), fake, s3, datastores
}

const (
	// testS3EndpointFingerprint is a certificate fingerprint as PBS shows it.
	testS3EndpointFingerprint = "3b:8e:21:0f:c4:5d:96:a7:12:e0:4f:6b:d9:33:a8:c1:70:5e:2d:9b:84:f6:1a:c3:07:bd:52:e9:6c:48:af:13"
	// testS3EndpointHost and testS3EndpointAccessKey are what the endpoint
	// "backblaze" of s3EndpointConfig needs.
	testS3EndpointHost      = "{{bucket}}.s3.{{region}}.backblazeb2.com"
	testS3EndpointAccessKey = "005c0ffee000000000000001"
)

// s3EndpointConfig is the configuration of an S3 endpoint "backblaze", with
// attrs on top of what it needs; a nil value leaves an attribute out.
func s3EndpointConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"id": "backblaze", "endpoint": testS3EndpointHost, "access_key": testS3EndpointAccessKey}
	for k, v := range attrs {
		if v == nil {
			delete(config, k)
			continue
		}
		config[k] = v
	}
	return h.resourceValue(t, "pbs_s3_endpoint", config)
}

// withS3Attrs returns base with attrs on top, leaving base as it is.
func withS3Attrs(base, attrs map[string]any) map[string]any {
	out := maps.Clone(base)
	maps.Copy(out, attrs)
	return out
}

func TestS3EndpointResourceLifecycle(t *testing.T) {
	h, fake, s3, _ := newS3EndpointHarness(t)

	// The fingerprint as OpenSSL prints it, upper case, and a rate in a
	// spelling of its own. PBS gets the fingerprint as it shows it, and state
	// keeps the configuration's spelling of both.
	upper := strings.ToUpper(testS3EndpointFingerprint)
	first := map[string]any{
		"region":                "eu-central-003",
		"fingerprint":           upper,
		"rate_in":               "10MiB",
		"provider_quirks":       []any{"skip-if-none-match-header"},
		"secret_key_wo":         "first-secret",
		"secret_key_wo_version": 1,
	}
	config := s3EndpointConfig(t, h, first)
	inst := h.create(t, "pbs_s3_endpoint", config)

	created := fake.lastCall(t, "POST /config/s3")
	want := map[string]string{"id": "backblaze", "endpoint": testS3EndpointHost, "access-key": testS3EndpointAccessKey,
		"secret-key": "first-secret", "region": "eu-central-003", "fingerprint": testS3EndpointFingerprint,
		"rate-in": "10MiB", "provider-quirks": "skip-if-none-match-header"}
	for name, value := range want {
		if got := created.form.Get(name); got != value {
			t.Errorf("POST %s = %q, want %q", name, got, value)
		}
	}
	if len(created.form) != len(want) {
		t.Errorf("POST form = %v, want what differs from PBS's defaults, the ID and the secret key alone", created.form)
	}
	if stringAt(t, inst.state, "fingerprint") != upper || stringAt(t, inst.state, "rate_in") != "10MiB" ||
		stringAt(t, inst.state, "access_key") != testS3EndpointAccessKey || boolAt(t, inst.state, "path_style") ||
		boolAt(t, inst.state, "use_node_proxy") || !isNullAt(t, inst.state, "port") || !isNullAt(t, inst.state, "burst_in") ||
		!isNullAt(t, inst.state, "limit_active_requests") || !isNullAt(t, inst.state, "secret_key_wo") ||
		int64At(t, inst.state, "secret_key_wo_version") != 1 {
		t.Errorf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_s3_endpoint", inst.identity), "id"); got != "backblaze" {
		t.Errorf("identity id = %q", got)
	}
	// PBS writes the rate back its own way, which state does not show.
	if stored, _ := s3.endpoint("backblaze"); stored["rate-in"] != "10 MiB" || s3.secretKey("backblaze") != "first-secret" {
		t.Errorf("stored endpoint = %v, secret key %q", stored, s3.secretKey("backblaze"))
	}
	replan := h.plan(t, "pbs_s3_endpoint", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_s3_endpoint", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}
	if refreshed := h.refresh(t, inst); !refreshed.state.Equal(inst.state) {
		diffs, _ := refreshed.state.Diff(inst.state)
		t.Errorf("refresh changes %v", diffs)
	}

	// New spellings of the same fingerprint and rate send nothing, and
	// neither does a new secret key without a new version.
	inst = h.update(t, inst, s3EndpointConfig(t, h, withS3Attrs(first, map[string]any{
		"fingerprint":   strings.ReplaceAll(testS3EndpointFingerprint, ":", ""),
		"rate_in":       "10 MiB",
		"secret_key_wo": "unsent-secret",
	})))
	if n := fake.count("PUT /config/s3/backblaze"); n != 0 {
		t.Errorf("new spellings of the same values were sent: %v", fake.lastCall(t, "PUT /config/s3/backblaze").form)
	}
	if got := s3.secretKey("backblaze"); got != "first-secret" {
		t.Errorf("secret key = %q, want it unchanged without a new version", got)
	}

	// Everything else changes in place, the access key among it; the secret
	// key stays as long as its version does.
	every := map[string]any{
		"endpoint":               "s3.{{region}}.example.com",
		"port":                   9000,
		"region":                 "us-east-1",
		"fingerprint":            testS3EndpointFingerprint,
		"access_key":             "AKIAEXAMPLE2",
		"path_style":             true,
		"provider_quirks":        []any{"skip-if-none-match-header", "delete-objects-via-delete-object"},
		"rate_in":                "10MiB",
		"burst_in":               "20MiB",
		"rate_out":               "1.5GB",
		"burst_out":              "2GB",
		"limit_active_requests":  50,
		"limit_passive_requests": 200,
		"use_node_proxy":         true,
		"secret_key_wo":          "first-secret",
		"secret_key_wo_version":  1,
	}
	config = s3EndpointConfig(t, h, every)
	planned := h.plan(t, "pbs_s3_endpoint", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 0 {
		t.Errorf("RequiresReplace = %v, want an update in place", planned.RequiresReplace)
	}
	inst = h.update(t, inst, config)
	updated := fake.lastCall(t, "PUT /config/s3/backblaze")
	want = map[string]string{"endpoint": "s3.{{region}}.example.com", "port": "9000", "region": "us-east-1",
		"access-key": "AKIAEXAMPLE2", "path-style": "true", "burst-in": "20MiB", "rate-out": "1.5GB", "burst-out": "2GB",
		"limit-active-requests": "50", "limit-passive-requests": "200", "use-node-proxy": "true"}
	for name, value := range want {
		if got := updated.form.Get(name); got != value {
			t.Errorf("PUT %s = %q, want %q", name, got, value)
		}
	}
	if got := strings.Join(updated.form["provider-quirks"], ","); got != "delete-objects-via-delete-object,skip-if-none-match-header" {
		t.Errorf("PUT provider-quirks = %q", got)
	}
	if len(updated.form) != len(want)+1 {
		t.Errorf("PUT form = %v, want the changed properties alone, without the secret key", updated.form)
	}
	if stored, _ := s3.endpoint("backblaze"); stored["rate-out"] != "1.5 GB" || stored["access-key"] != "AKIAEXAMPLE2" {
		t.Errorf("stored endpoint = %v", stored)
	}
	if stringAt(t, inst.state, "rate_out") != "1.5GB" || int64At(t, inst.state, "port") != 9000 ||
		!boolAt(t, inst.state, "use_node_proxy") || lengthAt(t, inst.state, "provider_quirks") != 2 {
		t.Errorf("state = %s", inst.state)
	}
	replan = h.plan(t, "pbs_s3_endpoint", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_s3_endpoint", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	// A new version sends the new secret key, and nothing else.
	every["secret_key_wo"], every["secret_key_wo_version"] = "second-secret", 2
	inst = h.update(t, inst, s3EndpointConfig(t, h, every))
	updated = fake.lastCall(t, "PUT /config/s3/backblaze")
	if len(updated.form) != 1 || updated.form.Get("secret-key") != "second-secret" {
		t.Errorf("PUT form = %v, want the secret key alone", updated.form)
	}
	if got := s3.secretKey("backblaze"); got != "second-secret" {
		t.Errorf("secret key = %q after a new version", got)
	}

	// Back to the defaults: deleted, not written; the secret key stays.
	inst = h.update(t, inst, s3EndpointConfig(t, h, map[string]any{"endpoint": "s3.{{region}}.example.com", "access_key": "AKIAEXAMPLE2"}))
	updated = fake.lastCall(t, "PUT /config/s3/backblaze")
	wantDelete := "burst-in,burst-out,fingerprint,limit-active-requests,limit-passive-requests,path-style,port," +
		"provider-quirks,rate-in,rate-out,region,use-node-proxy"
	if got := strings.Join(updated.form["delete"], ","); got != wantDelete {
		t.Errorf("delete = %q, want %q", got, wantDelete)
	}
	if len(updated.form) != 1 {
		t.Errorf("PUT form = %v, want only deletions", updated.form)
	}
	if stored, _ := s3.endpoint("backblaze"); len(stored) != 3 || s3.secretKey("backblaze") != "second-secret" {
		t.Errorf("stored endpoint = %v, secret key %q, want id, endpoint and access-key, and the secret key kept",
			stored, s3.secretKey("backblaze"))
	}
	if !isNullAt(t, inst.state, "secret_key_wo_version") || boolAt(t, inst.state, "path_style") ||
		boolAt(t, inst.state, "use_node_proxy") || !isNullAt(t, inst.state, "provider_quirks") ||
		!isNullAt(t, inst.state, "region") || !isNullAt(t, inst.state, "rate_in") {
		t.Errorf("state = %s", inst.state)
	}

	// An endpoint deleted outside Terraform is gone from state, and
	// destroying it is no error.
	s3.mu.Lock()
	delete(s3.endpoints, "backblaze")
	s3.mu.Unlock()
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept a deleted endpoint: %s", refreshed.state)
	}
	h.destroy(t, inst)
	if n := fake.count("DELETE /config/s3/backblaze"); n != 1 {
		t.Errorf("DELETE was sent %d times, want 1", n)
	}
}

// An import reads what PBS has, without the secret key, which the next
// apply that has one sends.
func TestS3EndpointResourceImport(t *testing.T) {
	h, fake, s3, _ := newS3EndpointHarness(t)
	// use-node-proxy as PBS stores it when it was sent false, and the
	// deprecated put-rate-limit, which the resource leaves alone.
	upper := strings.ToUpper(testS3EndpointFingerprint)
	s3.addEndpoint("wasabi", fakeProperties{"endpoint": "s3.{{region}}.wasabisys.com", "region": "eu-central-2",
		"access-key": "WASABIACCESSKEY", "fingerprint": upper, "path-style": true, "use-node-proxy": false,
		"rate-in": "10 MiB", "provider-quirks": []string{"skip-if-none-match-header"}, "put-rate-limit": int64(100)},
		"wasabi-secret")

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_s3_endpoint", "wasabi"),
		"identity": h.importByIdentity(t, "pbs_s3_endpoint", map[string]any{"id": "wasabi"}),
	} {
		if stringAt(t, inst.state, "id") != "wasabi" || stringAt(t, inst.state, "endpoint") != "s3.{{region}}.wasabisys.com" ||
			stringAt(t, inst.state, "region") != "eu-central-2" || stringAt(t, inst.state, "access_key") != "WASABIACCESSKEY" ||
			stringAt(t, inst.state, "fingerprint") != upper || !boolAt(t, inst.state, "path_style") ||
			boolAt(t, inst.state, "use_node_proxy") || stringAt(t, inst.state, "rate_in") != "10 MiB" ||
			lengthAt(t, inst.state, "provider_quirks") != 1 || !isNullAt(t, inst.state, "port") ||
			!isNullAt(t, inst.state, "secret_key_wo_version") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
		if got := stringAt(t, h.identityValue(t, "pbs_s3_endpoint", inst.identity), "id"); got != "wasabi" {
			t.Errorf("import by %s: identity id = %q", name, got)
		}
	}

	// After an import, the secret key may stay out of the configuration, and
	// the configuration's spellings of the same values send nothing.
	inst := h.importByID(t, "pbs_s3_endpoint", "wasabi")
	attrs := map[string]any{"id": "wasabi", "endpoint": "s3.{{region}}.wasabisys.com", "region": "eu-central-2",
		"access_key": "WASABIACCESSKEY", "fingerprint": testS3EndpointFingerprint, "path_style": true, "rate_in": "10MiB",
		"provider_quirks": []any{"skip-if-none-match-header"}}
	inst = h.update(t, inst, h.resourceValue(t, "pbs_s3_endpoint", attrs))
	if n := fake.count("PUT /config/s3/wasabi"); n != 0 {
		t.Errorf("new spellings of the same values were sent: %v", fake.lastCall(t, "PUT /config/s3/wasabi").form)
	}

	// The next apply with the secret key sends it, and nothing else.
	attrs["secret_key_wo"], attrs["secret_key_wo_version"] = "new-secret", 1
	inst = h.update(t, inst, h.resourceValue(t, "pbs_s3_endpoint", attrs))
	if updated := fake.lastCall(t, "PUT /config/s3/wasabi"); len(updated.form) != 1 || updated.form.Get("secret-key") != "new-secret" {
		t.Errorf("PUT form = %v, want the secret key alone", updated.form)
	}
	if got := s3.secretKey("wasabi"); got != "new-secret" {
		t.Errorf("secret key = %q", got)
	}
	if stored, _ := s3.endpoint("wasabi"); stored["put-rate-limit"] != int64(100) || stored["use-node-proxy"] != false {
		t.Errorf("stored endpoint = %v, want put-rate-limit and use-node-proxy left alone", stored)
	}
	if int64At(t, inst.state, "secret_key_wo_version") != 1 {
		t.Errorf("state = %s", inst.state)
	}

	// An endpoint that does not exist imports as nothing, which Terraform
	// reports; an ID PBS cannot have is refused.
	if missing := h.importByID(t, "pbs_s3_endpoint", "missing"); !missing.state.IsNull() {
		t.Errorf("import of a missing endpoint = %s", missing.state)
	}
	resp := h.importResource(t, "pbs_s3_endpoint", "wasabi/eu", nil)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unexpected import identifier")
}

func TestS3EndpointResourceErrors(t *testing.T) {
	h, fake, s3, datastores := newS3EndpointHarness(t)
	s3.addEndpoint("wasabi", fakeProperties{"endpoint": "s3.{{region}}.wasabisys.com", "access-key": "WASABIACCESSKEY",
		"path-style": true}, "wasabi-secret")

	// Creating one needs the secret key, and so does a new ID, which
	// replaces it.
	planned := h.plan(t, "pbs_s3_endpoint", nil, s3EndpointConfig(t, h, nil))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Missing S3 secret key")
	inst := h.importByID(t, "pbs_s3_endpoint", "wasabi")
	renamed := map[string]any{"id": "wasabi2", "endpoint": "s3.{{region}}.wasabisys.com", "access_key": "WASABIACCESSKEY",
		"path_style": true}
	planned = h.plan(t, "pbs_s3_endpoint", inst, h.resourceValue(t, "pbs_s3_endpoint", renamed))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Missing S3 secret key")
	planned = h.plan(t, "pbs_s3_endpoint", inst, h.resourceValue(t, "pbs_s3_endpoint",
		withS3Attrs(renamed, map[string]any{"secret_key_wo": "wasabi-secret", "secret_key_wo_version": 1})))
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 1 || !strings.Contains(planned.RequiresReplace[0].String(), "id") {
		t.Errorf("RequiresReplace = %v, want id", planned.RequiresReplace)
	}

	// An endpoint that exists is imported, not created.
	config := s3EndpointConfig(t, h, map[string]any{"id": "wasabi", "secret_key_wo": "other-secret", "secret_key_wo_version": 1})
	planned = h.plan(t, "pbs_s3_endpoint", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, "pbs_s3_endpoint", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "import it")
	if got := s3.secretKey("wasabi"); got != "wasabi-secret" {
		t.Errorf("secret key = %q, want the existing endpoint untouched", got)
	}

	// An endpoint PBS created but the provider could not read back is
	// recorded in state all the same, so that Terraform marks it tainted.
	fake.reply("GET /config/s3/backblaze", http.StatusInternalServerError, "unable to read s3.cfg")
	config = s3EndpointConfig(t, h, map[string]any{"secret_key_wo": "b2-secret", "secret_key_wo_version": 1})
	planned = h.plan(t, "pbs_s3_endpoint", nil, config)
	applied = h.apply(t, "pbs_s3_endpoint", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "marked tainted")
	if state := h.decodeResource(t, "pbs_s3_endpoint", applied.NewState); state.IsNull() || stringAt(t, state, "id") != "backblaze" {
		t.Errorf("state = %s, want the endpoint recorded", state)
	}
	if _, exists := s3.endpoint("backblaze"); !exists || s3.secretKey("backblaze") != "b2-secret" {
		t.Error("the endpoint was not created")
	}

	// PBS refuses to delete an endpoint a datastore uses.
	datastores.addDatastore("offsite", fakeProperties{"path": "/var/cache/pbs/offsite",
		"backend": "bucket=backups,client=wasabi,type=s3"})
	resp := syncDestroyResponse(t, h, inst)
	requireProtocolErrorContaining(t, resp.Diagnostics, "destroy the datastore first")
	requireProtocolErrorContaining(t, resp.Diagnostics, "in-use by datastore offsite")
	if _, exists := s3.endpoint("wasabi"); !exists {
		t.Error("the endpoint was deleted")
	}

	// Datastores on another endpoint, or on a file system, do not hold it.
	datastores.setDatastoreProperty("offsite", "backend", "type=s3,client=wasabi-old,bucket=backups")
	datastores.addDatastore("local", fakeProperties{"path": "/mnt/local"})
	h.destroy(t, inst)
	if _, exists := s3.endpoint("wasabi"); exists {
		t.Error("the endpoint still exists")
	}
}

// Rate limits need PBS 4.1, the quirk delete-objects-via-delete-object
// 4.1.6, and the request limits and the node's proxy 4.2.4.
func TestS3EndpointResourceVersionGates(t *testing.T) {
	const (
		version415 = `{"data":{"release":"5","repoid":"0123456789abcdef","version":"4.1"}}`
		version423 = `{"data":{"release":"3","repoid":"0123456789abcdef","version":"4.2"}}`
	)
	slowDeletes := []any{"delete-objects-via-delete-object"}
	for name, tc := range map[string]struct {
		version string
		attrs   map[string]any
		want    string
	}{
		"rate_in on 4.0":                 {fakeVersion40, map[string]any{"rate_in": "10MiB"}, "rate_in needs PBS 4.1 or newer"},
		"burst_in on 4.0":                {fakeVersion40, map[string]any{"burst_in": "10MiB"}, "burst_in needs PBS 4.1 or newer"},
		"rate_out on 4.0":                {fakeVersion40, map[string]any{"rate_out": "10MiB"}, "rate_out needs PBS 4.1 or newer"},
		"burst_out on 4.0":               {fakeVersion40, map[string]any{"burst_out": "10MiB"}, "burst_out needs PBS 4.1 or newer"},
		"slow deletes on 4.1.5":          {version415, map[string]any{"provider_quirks": slowDeletes}, "provider_quirks needs PBS 4.1.6 or newer"},
		"limit_active_requests on 4.2.3": {version423, map[string]any{"limit_active_requests": 10}, "limit_active_requests needs PBS 4.2.4 or newer"},
		"limit_passive_requests on 4.2.3": {version423, map[string]any{"limit_passive_requests": 10},
			"limit_passive_requests needs PBS 4.2.4 or newer"},
		"use_node_proxy on 4.2.3": {version423, map[string]any{"use_node_proxy": true}, "use_node_proxy needs PBS 4.2.4 or newer"},

		"nothing new on 4.0":            {fakeVersion40, nil, ""},
		"use_node_proxy false on 4.0":   {fakeVersion40, map[string]any{"use_node_proxy": false}, ""},
		"other quirk on 4.0":            {fakeVersion40, map[string]any{"provider_quirks": []any{"skip-if-none-match-header"}}, ""},
		"rates on 4.1.5":                {version415, map[string]any{"rate_in": "1MiB", "burst_in": "2MiB", "rate_out": "1GB", "burst_out": "2GB"}, ""},
		"slow deletes on 4.2.3":         {version423, map[string]any{"provider_quirks": slowDeletes}, ""},
		"request limits on PBS 4.2.8":   {fakeVersionJSON, map[string]any{"limit_active_requests": 10, "limit_passive_requests": 20}, ""},
		"use_node_proxy on PBS 4.2.8":   {fakeVersionJSON, map[string]any{"use_node_proxy": true}, ""},
		"rates and quirks on PBS 4.2.8": {fakeVersionJSON, map[string]any{"rate_in": "1MiB", "provider_quirks": slowDeletes}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			h, _, _, _ := newS3EndpointHarness(t, tc.version)
			attrs := withS3Attrs(map[string]any{"secret_key_wo": "s3cr3t", "secret_key_wo_version": 1}, tc.attrs)
			planned := h.plan(t, "pbs_s3_endpoint", nil, s3EndpointConfig(t, h, attrs))
			if tc.want == "" {
				requireNoProtocolErrors(t, planned.Diagnostics)
				return
			}
			requireProtocolErrorContaining(t, planned.Diagnostics, tc.want)
		})
	}
}

func TestS3EndpointResourceValidation(t *testing.T) {
	h, _, _, _ := newS3EndpointHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"scheme":             {map[string]any{"endpoint": "https://s3.example.com"}, "endpoint"},
		"port in endpoint":   {map[string]any{"endpoint": "s3.example.com:9000"}, "endpoint"},
		"path":               {map[string]any{"endpoint": "s3.example.com/backups"}, "endpoint"},
		"bucket alone":       {map[string]any{"endpoint": "{{bucket}}"}, "endpoint"},
		"region last":        {map[string]any{"endpoint": "s3.example.com.{{region}}"}, "endpoint"},
		"bucket inside":      {map[string]any{"endpoint": "example.{{bucket}}.com"}, "endpoint"},
		"bracketed IPv6":     {map[string]any{"endpoint": "[fd00::1]"}, "endpoint"},
		"short region":       {map[string]any{"region": "a"}, "region"},
		"upper-case region":  {map[string]any{"region": "EU-1"}, "region"},
		"dotted region":      {map[string]any{"region": "eu.west"}, "region"},
		"unknown quirk":      {map[string]any{"provider_quirks": []any{"skip-if-none-match"}}, "provider_quirks"},
		"no quirks":          {map[string]any{"provider_quirks": []any{}}, "provider_quirks"},
		"port 0":             {map[string]any{"port": 0}, "port"},
		"port 65536":         {map[string]any{"port": 65536}, "port"},
		"padded access key":  {map[string]any{"access_key": " AKIAPADDED"}, "access_key"},
		"empty access key":   {map[string]any{"access_key": ""}, "access_key"},
		"short fingerprint":  {map[string]any{"fingerprint": "3b:8e:21"}, "fingerprint"},
		"no requests":        {map[string]any{"limit_active_requests": 0}, "limit_active_requests"},
		"bad size":           {map[string]any{"rate_in": "10MIB"}, "rate_in"},
		"short id":           {map[string]any{"id": "ab"}, "id"},
		"secret, no version": {map[string]any{"secret_key_wo": "s3cr3t"}, "secret_key_wo_version"},
		"padded secret":      {map[string]any{"secret_key_wo": " s3cr3t", "secret_key_wo_version": 1}, "secret_key_wo"},
		"empty secret":       {map[string]any{"secret_key_wo": "", "secret_key_wo_version": 1}, "secret_key_wo"},
	} {
		t.Run(name, func(t *testing.T) {
			diags := h.validateResource(t, "pbs_s3_endpoint", s3EndpointConfig(t, h, tc.attrs))
			requireProtocolErrorContaining(t, diags, tc.want)
			for _, d := range diags {
				if strings.Contains(d.Detail, "AKIAPADDED") || strings.Contains(d.Detail, "s3cr3t") {
					t.Errorf("the error repeats a key: %s", d.Detail)
				}
			}
		})
	}
	for _, endpoint := range []string{"{{bucket}}.s3.{{region}}.amazonaws.com", "s3.{{region}}.amazonaws.com",
		"172.16.0.200", "localhost", "S3.Example.COM", "fd00::1"} {
		requireNoProtocolErrors(t, h.validateResource(t, "pbs_s3_endpoint", s3EndpointConfig(t, h, map[string]any{"endpoint": endpoint})))
	}
	for _, region := range []string{"eu-central-1", "auto", "nbg1", "_x", strings.Repeat("a", 32)} {
		requireNoProtocolErrors(t, h.validateResource(t, "pbs_s3_endpoint", s3EndpointConfig(t, h, map[string]any{"region": region})))
	}
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_s3_endpoint", s3EndpointConfig(t, h, map[string]any{
		"port": 65535, "fingerprint": strings.ReplaceAll(strings.ToUpper(testS3EndpointFingerprint), ":", ""),
		"provider_quirks":       []any{"skip-if-none-match-header", "delete-objects-via-delete-object"},
		"limit_active_requests": 1, "limit_passive_requests": 1, "access_key": "AKIA EXAMPLE",
	})))
}

// ValidateConfig warns about endpoints PBS takes but cannot use as meant.
func TestS3EndpointResourceWarnings(t *testing.T) {
	h, _, _, _ := newS3EndpointHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"bucket in host and path":            {map[string]any{"endpoint": "{{bucket}}.s3.example.com", "path_style": true}, "{{bucket}} with path_style"},
		"no bucket":                          {map[string]any{"endpoint": "s3.example.com"}, "No bucket in the requests"},
		"no bucket, path_style false":        {map[string]any{"endpoint": "172.16.0.200", "path_style": false}, "No bucket in the requests"},
		"IPv6 address":                       {map[string]any{"endpoint": "fd00::1", "path_style": true}, "IPv6 address"},
		"IPv6 address, no bucket either":     {map[string]any{"endpoint": "::1"}, "IPv6 address"},
		"IPv6 address, path_style not known": {map[string]any{"endpoint": "fd00::1", "path_style": tfUnknown}, "IPv6 address"},
	} {
		t.Run(name, func(t *testing.T) {
			diags := h.validateResource(t, "pbs_s3_endpoint", s3EndpointConfig(t, h, tc.attrs))
			requireNoProtocolErrors(t, diags)
			requireProtocolWarningContaining(t, diags, tc.want)
		})
	}
	for name, attrs := range map[string]map[string]any{
		"bucket in the host":   {"endpoint": "{{bucket}}.s3.example.com"},
		"bucket in the path":   {"endpoint": "s3.example.com", "path_style": true},
		"IPv4 address":         {"endpoint": "172.16.0.200", "path_style": true},
		"endpoint not known":   {"endpoint": tfUnknown},
		"path_style not known": {"endpoint": "s3.example.com", "path_style": tfUnknown},
	} {
		t.Run("no warning, "+name, func(t *testing.T) {
			for _, d := range h.validateResource(t, "pbs_s3_endpoint", s3EndpointConfig(t, h, attrs)) {
				if d.Severity == tfprotov6.DiagnosticSeverityWarning || d.Severity == tfprotov6.DiagnosticSeverityError {
					t.Errorf("unexpected %s: %s: %s", d.Severity, d.Summary, d.Detail)
				}
			}
		})
	}
}
