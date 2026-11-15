package provider

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func TestNodeConfigDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &nodeConfigDataSource{})
}

// Every setting of node.cfg, in the form an import of pbs_node_config
// reads it: the consent text decoded, the notes with PBS's line break at
// the end, the location as an object; the ACME settings of the same file
// stay out, and the proxy, which may hold a password, is sensitive.
func TestNodeConfigDataSourceReadsEverySetting(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	d := &nodeConfigDataSource{data: fake.configured(t)}
	consent := "Authorised use **only**.\nEverything is logged."
	for key, value := range map[string]string{
		"http-proxy":        "http://user:secret@proxy.example.org:3128",
		"email-from":        "pbs@example.org",
		"task-log-max-days": "30",
		"default-lang":      "de",
		"ciphers-tls-1.2":   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
		"ciphers-tls-1.3":   "TLS_AES_256_GCM_SHA384",
		"consent-text":      base64.StdEncoding.EncodeToString([]byte(consent)),
		"description":       "Line one\n\tTabbed\n",
		"location":          "name=Vienna,latitude=48.2,longitude=16.37",
		"acme":              "account=default",
		"acmedomain0":       "pbs.example.org",
	} {
		acme.setNodeProperty(key, value)
	}

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	requireNoWarnings(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node":              "localhost",
		"http_proxy":        "http://user:secret@proxy.example.org:3128",
		"email_from":        "pbs@example.org",
		"task_log_max_days": 30,
		"default_lang":      "de",
		"ciphers_tls_1_2":   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
		"ciphers_tls_1_3":   "TLS_AES_256_GCM_SHA384",
		"consent_text":      consent,
		"description":       "Line one\n\tTabbed\n",
		"location":          map[string]any{"name": "Vienna", "latitude": 48.2, "longitude": 16.37},
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
	if state := resp.State.Raw.String(); strings.Contains(state, "account=default") || strings.Contains(state, "pbs.example.org") {
		t.Errorf("the ACME settings are in the state: %s", state)
	}
	if !dataSourceSchema(t, d).Attributes["http_proxy"].IsSensitive() {
		t.Error("http_proxy is not sensitive")
	}
}

// A node without settings — PBS reads a missing node.cfg as an empty one —
// has every attribute null but node, and a location without a name has a
// null name.
func TestNodeConfigDataSourceReadsUnsetSettingsAsNull(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	d := &nodeConfigDataSource{data: fake.configured(t)}
	acme.setNodeProperty("description", "")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	if want := dataSourceValue(t, d, map[string]any{"node": "localhost"}); !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}

	acme.setNodeProperty("location", "latitude=-33.87,longitude=151.21")
	resp = readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node":     "localhost",
		"location": map[string]any{"latitude": -33.87, "longitude": 151.21},
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// Consent text that is not base64 — written to node.cfg by hand — reads as
// none, with a warning, and the other settings are read all the same.
func TestNodeConfigDataSourceWarnsAboutPlainConsentText(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	d := &nodeConfigDataSource{data: fake.configured(t)}
	acme.setNodeProperty("consent-text", "Authorised use only")
	acme.setNodeProperty("email-from", "pbs@example.org")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	requireWarningContaining(t, resp.Diagnostics, "not base64")
	requireWarningContaining(t, resp.Diagnostics, "pbs_node_config writes its consent_text encoded")
	want := dataSourceValue(t, d, map[string]any{
		"node":        "localhost",
		"email_from":  "pbs@example.org",
		"description": fakeNodeDescription,
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// A location the provider cannot parse fails the read, as it fails the
// resource's.
func TestNodeConfigDataSourceRefusesAnUnreadableLocation(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	d := &nodeConfigDataSource{data: fake.configured(t)}
	acme.setNodeProperty("location", "latitude=abc,longitude=16.37")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, "Unexpected PBS node configuration")
	requireErrorContaining(t, resp.Diagnostics, "latitude=abc")
}

// A token without Sys.Audit on /system gets 403, and the error says what is
// missing.
func TestNodeConfigDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	d := &nodeConfigDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/config", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, "Unable to read the settings of the PBS node")
	requireErrorContaining(t, resp.Diagnostics, "Sys.Audit on /system")
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}

// Read the way Terraform reads it, through the protocol: it shows the
// settings pbs_node_config leaves alone as well as those it manages, and
// node takes only a node name.
func TestNodeConfigDataSourceThroughTheProtocol(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	h.create(t, "pbs_node_config", nodeConfigConfig(t, h, map[string]any{"email_from": "pbs@example.org"}))
	acme.setNodeProperty("default-lang", "fr")

	state := h.readDataSource(t, "pbs_node_config", h.dataSourceValue(t, "pbs_node_config", nil))
	if stringAt(t, state, "node") != "localhost" || stringAt(t, state, "email_from") != "pbs@example.org" ||
		stringAt(t, state, "default_lang") != "fr" || stringAt(t, state, "description") != fakeNodeDescription ||
		!isNullAt(t, state, "location") || !isNullAt(t, state, "http_proxy") {
		t.Fatalf("state = %s", state)
	}

	diags := dataSourceConfigDiagnostics(t, h, "pbs_node_config",
		h.dataSourceValue(t, "pbs_node_config", map[string]any{"node": "local host"}))
	requireProtocolErrorContaining(t, diags, "must be a node name")
}
