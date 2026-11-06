package provider

import (
	"encoding/base64"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestNodeConfigResourceSchemaIsValid(t *testing.T) {
	requireValidResourceSchema(t, &nodeConfigResource{})
}

func nodeConfigConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	return h.resourceValue(t, "pbs_node_config", attrs)
}

// decimal is a number as Terraform parses one from a configuration: exact,
// with more precision than a float64.
func decimal(t *testing.T, s string) *big.Float {
	t.Helper()
	f, ok := new(big.Float).SetPrec(512).SetString(s)
	if !ok {
		t.Fatalf("%q is not a number", s)
	}
	return f
}

func TestNodeConfigResourceLifecycle(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	// Settings made before Terraform: ACME settings, which belong to
	// pbs_node_acme, and an HTTP proxy the configuration leaves out.
	acme.setNodeProperty("acme", "account=le")
	acme.setNodeProperty("acmedomain0", "pbs.example.org")
	acme.setNodeProperty("http-proxy", "http://proxy.example.org:3128")

	consent := "Authorised use **only**.\nEverything is logged."
	config := nodeConfigConfig(t, h, map[string]any{
		"email_from":        "pbs@example.org",
		"task_log_max_days": 30,
		"consent_text":      consent,
		"description":       "Primary PBS\n\nIn rack 4.",
		"location":          map[string]any{"name": "Vienna", "latitude": decimal(t, "48.2"), "longitude": decimal(t, "16.37")},
	})
	inst := h.create(t, "pbs_node_config", config)

	put := fake.lastCall(t, "PUT /nodes/localhost/config").form
	if put.Get("digest") == "" || put.Get("email-from") != "pbs@example.org" || put.Get("task-log-max-days") != "30" ||
		put.Get("location") != "latitude=48.2,longitude=16.37,name=Vienna" || len(put["delete"]) != 0 {
		t.Fatalf("PUT = %v", put)
	}
	if decoded, _ := base64.StdEncoding.DecodeString(put.Get("consent-text")); string(decoded) != consent {
		t.Fatalf("consent-text sent as %q", put.Get("consent-text"))
	}
	for key, want := range map[string]string{
		"acme": "account=le", "acmedomain0": "pbs.example.org", "http-proxy": "http://proxy.example.org:3128",
		"description": "Primary PBS\n\nIn rack 4.\n", "location": "name=Vienna,latitude=48.2,longitude=16.37",
	} {
		if got, _ := acme.nodeProperty(key); got != want {
			t.Errorf("node.cfg %s = %q, want %q", key, got, want)
		}
	}
	// PBS's forms — a line break after the notes, its own order of the
	// location's keys, its float — are no change.
	if stringAt(t, inst.state, "description") != "Primary PBS\n\nIn rack 4." || stringAt(t, inst.state, "consent_text") != consent ||
		!isNullAt(t, inst.state, "http_proxy") || stringAt(t, inst.state, "id") != "localhost" {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)
	inst = h.refresh(t, inst)
	requireEmptyPlan(t, h, inst, config)

	// A setting the configuration leaves out may change: nothing to plan.
	acme.setNodeProperty("default-lang", "de")
	inst = h.refresh(t, inst)
	requireEmptyPlan(t, h, inst, config)

	// A managed setting changed outside Terraform shows.
	acme.setNodeProperty("email-from", "someone@example.org")
	inst = h.refresh(t, inst)
	if stringAt(t, inst.state, "email_from") != "someone@example.org" {
		t.Fatalf("refreshed state = %s", inst.state)
	}

	// Removing a setting deletes it; one PBS holds the same in its own form
	// is not sent; a digest conflict is retried.
	acme.staleNodes = 1
	config = nodeConfigConfig(t, h, map[string]any{
		"task_log_max_days": 7,
		"consent_text":      consent,
		"description":       "Primary PBS\n\nIn rack 4.\n",
		"location":          map[string]any{"name": "Vienna", "latitude": decimal(t, "48.2"), "longitude": decimal(t, "16.37")},
	})
	inst = h.update(t, inst, config)
	put = fake.lastCall(t, "PUT /nodes/localhost/config").form
	if strings.Join(put["delete"], ",") != "email-from" || put.Get("task-log-max-days") != "7" || put.Has("description") ||
		put.Has("location") || put.Has("consent-text") {
		t.Fatalf("PUT = %v", put)
	}
	if _, set := acme.nodeProperty("email-from"); set {
		t.Fatal("email-from is still set")
	}
	requireEmptyPlan(t, h, inst, config)

	// Destroying deletes what the resource managed, and leaves the rest.
	h.destroy(t, inst)
	put = fake.lastCall(t, "PUT /nodes/localhost/config").form
	if got := strings.Join(put["delete"], ","); got != "consent-text,description,location,task-log-max-days" || put.Get("digest") == "" {
		t.Fatalf("destroy deleted %q", got)
	}
	for _, key := range []string{"acme", "acmedomain0", "http-proxy", "default-lang"} {
		if _, set := acme.nodeProperty(key); !set {
			t.Errorf("destroy deleted %s", key)
		}
	}
}

// A configuration that sets nothing manages nothing: no write, and no plan
// whatever the node holds.
func TestNodeConfigResourceManagesNothing(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	acme.setNodeProperty("email-from", "pbs@example.org")
	config := nodeConfigConfig(t, h, map[string]any{})
	inst := h.create(t, "pbs_node_config", config)
	if fake.count("PUT /nodes/localhost/config") != 0 {
		t.Fatal("an empty configuration wrote node.cfg")
	}
	acme.setNodeProperty("description", "changed\n")
	inst = h.refresh(t, inst)
	requireEmptyPlan(t, h, inst, config)
	h.destroy(t, inst)
	if fake.count("PUT /nodes/localhost/config") != 0 {
		t.Fatal("destroying an empty configuration wrote node.cfg")
	}
}

// An import manages every setting the node has, so that the plan shows the
// ones the configuration leaves out as deleted.
func TestNodeConfigResourceImport(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	acme.setNodeProperty("acme", "account=le")
	acme.setNodeProperty("http-proxy", "http://proxy.example.org:3128")
	acme.setNodeProperty("task-log-max-days", "14")
	acme.setNodeProperty("ciphers-tls-1.3", "TLS_AES_256_GCM_SHA384")
	acme.setNodeProperty("consent-text", base64.StdEncoding.EncodeToString([]byte("Be nice.")))
	acme.setNodeProperty("location", "name=Graz,latitude=47.07,longitude=15.44")

	inst := h.importByID(t, "pbs_node_config", "localhost")
	if stringAt(t, inst.state, "http_proxy") != "http://proxy.example.org:3128" || int64At(t, inst.state, "task_log_max_days") != 14 ||
		stringAt(t, inst.state, "consent_text") != "Be nice." || stringAt(t, inst.state, "location", "name") != "Graz" ||
		stringAt(t, inst.state, "description") != fakeNodeDescription || !isNullAt(t, inst.state, "email_from") {
		t.Fatalf("imported state = %s", inst.state)
	}
	full := nodeConfigConfig(t, h, map[string]any{
		"http_proxy":        "http://proxy.example.org:3128",
		"task_log_max_days": 14,
		"ciphers_tls_1_3":   "TLS_AES_256_GCM_SHA384",
		"consent_text":      "Be nice.",
		"description":       "PBS for cluster1",
		"location":          map[string]any{"name": "Graz", "latitude": decimal(t, "47.07"), "longitude": decimal(t, "15.44")},
	})
	inst = h.importByIdentity(t, "pbs_node_config", map[string]any{"node": "localhost"})
	puts := fake.count("PUT /nodes/localhost/config")
	inst = h.update(t, inst, full)
	if fake.count("PUT /nodes/localhost/config") != puts {
		t.Fatal("recording the configuration after an import wrote node.cfg")
	}
	requireEmptyPlan(t, h, inst, full)

	// Leaving settings out after the import deletes them.
	reimported := h.importByID(t, "pbs_node_config", "localhost")
	h.update(t, reimported, nodeConfigConfig(t, h, map[string]any{"http_proxy": "http://proxy.example.org:3128"}))
	if got := strings.Join(fake.lastCall(t, "PUT /nodes/localhost/config").form["delete"], ","); got !=
		"ciphers-tls-1.3,consent-text,description,location,task-log-max-days" {
		t.Fatalf("deleted %q", got)
	}
	if _, set := acme.nodeProperty("acme"); !set {
		t.Fatal("the ACME settings went too")
	}

	acme.setNodeProperty("consent-text", "not base64!")
	resp := h.importResource(t, "pbs_node_config", "localhost", nil)
	requireProtocolWarningContaining(t, resp.Diagnostics, "not base64")
	requireProtocolErrorContaining(t, h.importResource(t, "pbs_node_config", "pbs_1", nil).Diagnostics, "by the node's name")
}

func TestNodeConfigResourceLocationNeedsPBS421(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /version", http.StatusOK, `{"data":{"release":"0","repoid":"0123456789abcdef","version":"4.2"}}`)
	newFakeACME(t, fake)
	h := newProtocolHarness(t, fake)
	planned := h.plan(t, "pbs_node_config", nil, nodeConfigConfig(t, h, map[string]any{
		"location": map[string]any{"latitude": 48.2, "longitude": 16.37},
	}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "needs PBS 4.2.1")
	planned = h.plan(t, "pbs_node_config", nil, nodeConfigConfig(t, h, map[string]any{"email_from": "pbs@example.org"}))
	requireNoProtocolErrors(t, planned.Diagnostics)
}

func TestNodeConfigResourceValidation(t *testing.T) {
	h, _, _ := newACMEHarness(t)
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"http_proxy": "https://proxy.example.org"}, "HTTP proxy"},
		{map[string]any{"http_proxy": "http://proxy.example.org:3128/path"}, "HTTP proxy"},
		{map[string]any{"email_from": "x"}, "length"},
		{map[string]any{"email_from": " pbs@example.org"}, "white space"},
		{map[string]any{"default_lang": "ko"}, "value must be one of"},
		{map[string]any{"ciphers_tls_1_2": "ECDHE-RSA-AES256-GCM-SHA384 "}, "cipher list"},
		{map[string]any{"ciphers_tls_1_3": "TLS_AES_256_GCM_SHA384;x"}, "cipher list"},
		{map[string]any{"task_log_max_days": -1}, "between"},
		{map[string]any{"description": "a\r\nb"}, "control characters"},
		{map[string]any{"description": ""}, "length"},
		{map[string]any{"consent_text": strings.Repeat("x", maxConsentText+1)}, "length"},
		{map[string]any{"location": map[string]any{"name": "Vienna, AT", "latitude": 48.2, "longitude": 16.37}}, "commas"},
		{map[string]any{"location": map[string]any{"latitude": 91, "longitude": 16.37}}, "between"},
		{map[string]any{"location": map[string]any{"latitude": 48.2}}, "longitude"},
	} {
		requireProtocolErrorContaining(t, h.validateResource(t, "pbs_node_config", nodeConfigConfig(t, h, tc.attrs)), tc.want)
	}
	for _, ok := range []map[string]any{
		{"http_proxy": "proxy.example.org:3128"},
		{"http_proxy": "http://user:secret@[2001:db8::1]:8080"},
		{"default_lang": "pt_BR"},
		{"description": "tab\tseparated\nlines"},
		{"ciphers_tls_1_2": "HIGH:!aNULL:!MD5"},
	} {
		requireNoProtocolErrors(t, h.validateResource(t, "pbs_node_config", nodeConfigConfig(t, h, ok)))
	}
}

// PBS's errors reach the user, and a write that fails leaves no state.
func TestNodeConfigResourceRefusedWrite(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	// PBS checks the whole file on every write: a broken ACME domain left
	// by someone else fails any change.
	acme.setNodeProperty("acmedomain0", "pbs.example.org")
	acme.setNodeProperty("acmedomain1", "PBS.example.org")
	config := nodeConfigConfig(t, h, map[string]any{"email_from": "pbs@example.org"})
	planned := h.plan(t, "pbs_node_config", nil, config)
	applied := h.apply(t, "pbs_node_config", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "duplicate domain")
	if !h.decodeResource(t, "pbs_node_config", applied.NewState).IsNull() {
		t.Fatal("a refused create recorded state")
	}
	if got, _ := acme.nodeProperty("email-from"); got != "" || !slices.Contains(acme.fakeACMEDomains(), "1:PBS.example.org") {
		t.Fatal("the refused write changed node.cfg")
	}
}

// Notes whose every line holds a tab pass older PBS only with a line break
// at the end, which the provider sends.
func TestNodeConfigResourceTabbedDescription(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	config := nodeConfigConfig(t, h, map[string]any{"description": "Owner:\tbackup team"})
	inst := h.create(t, "pbs_node_config", config)
	if got := fake.lastCall(t, "PUT /nodes/localhost/config").form.Get("description"); got != "Owner:\tbackup team\n" {
		t.Fatalf("description sent as %q", got)
	}
	if got, _ := acme.nodeProperty("description"); got != "Owner:\tbackup team\n" {
		t.Fatalf("description stored as %q", got)
	}
	requireEmptyPlan(t, h, inst, config)
}

// Consent text that is not base64 — which the login page cannot show — is
// read as none, so that the configured text is written encoded.
func TestNodeConfigResourceRewritesPlainConsentText(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	config := nodeConfigConfig(t, h, map[string]any{"consent_text": "Authorised use only"})
	inst := h.create(t, "pbs_node_config", config)
	acme.setNodeProperty("consent-text", "Authorised use only")
	read := h.read(t, inst)
	requireProtocolWarningContaining(t, read.Diagnostics, "not base64")
	inst.state = h.decodeResource(t, "pbs_node_config", read.NewState)
	if !isNullAt(t, inst.state, "consent_text") {
		t.Fatalf("refreshed state = %s", inst.state)
	}
	inst = h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /nodes/localhost/config").form.Get("consent-text"); got != base64.StdEncoding.EncodeToString([]byte("Authorised use only")) {
		t.Fatalf("consent-text sent as %q", got)
	}
	requireEmptyPlan(t, h, inst, config)
}

// Secrets never show in validation errors.
func TestNodeSecretsStayOutOfValidationErrors(t *testing.T) {
	h, _, _ := newACMEHarness(t)
	for _, proxy := range []string{"https://user:s3cret@proxy.example.org:3128", "http://user:s3cret@proxy.example.org:3128\n"} {
		diags := h.validateResource(t, "pbs_node_config", nodeConfigConfig(t, h, map[string]any{"http_proxy": proxy}))
		requireProtocolErrorContaining(t, diags, "HTTP proxy")
		for _, d := range diags {
			if strings.Contains(d.Detail, "s3cret") {
				t.Errorf("the error shows the proxy's password: %s", d.Detail)
			}
		}
	}
	diags := h.validateResource(t, "pbs_subscription", h.resourceValue(t, "pbs_subscription", map[string]any{"key": "pbsc-0a1b2c3d4e\n"}))
	requireProtocolErrorContaining(t, diags, "subscription key")
	for _, d := range diags {
		if strings.Contains(d.Detail, "0a1b2c3d4e") {
			t.Errorf("the error shows the key: %s", d.Detail)
		}
	}
}

func TestNodeConfigResourceWarnsAboutSecurityLevels(t *testing.T) {
	h, _, _ := newACMEHarness(t)
	diags := h.validateResource(t, "pbs_node_config", nodeConfigConfig(t, h, map[string]any{"ciphers_tls_1_2": "HIGH:!aNULL@SECLEVEL=3"}))
	requireNoProtocolErrors(t, diags)
	requireProtocolWarningContaining(t, diags, "security level to 3")
	diags = h.validateResource(t, "pbs_node_config", nodeConfigConfig(t, h, map[string]any{"ciphers_tls_1_2": "HIGH:!aNULL@SECLEVEL=2"}))
	if len(diags) != 0 {
		t.Fatalf("diagnostics for the default level: %v", diags)
	}
}
