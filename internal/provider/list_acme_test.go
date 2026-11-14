package provider

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// generatedConfigWith is a generated configuration with the attributes
// attrs set, as a user fills in what the generated file leaves out. It works
// on a copy: tftypes hands out an object's own map of attributes.
func generatedConfigWith(t *testing.T, config tftypes.Value, attrs map[string]any) tftypes.Value {
	t.Helper()
	values := harnessObjectAttributes(t, config.Copy())
	attributeTypes := config.Type().(tftypes.Object).AttributeTypes
	for name, value := range attrs {
		values[name] = tfValue(t, attributeTypes[name], value)
	}
	return tftypes.NewValue(config.Type(), values)
}

// fakeACMEAccountProps are an account as PBS stores it after registering it
// at a CA that returns contacts, such as Pebble.
func fakeACMEAccountProps(directory, tos string, location int, contacts ...string) fakeProperties {
	var mailto []string
	for _, c := range contacts {
		mailto = append(mailto, "mailto:"+c)
	}
	return fakeProperties{
		"directory": directory,
		"location":  fmt.Sprintf("https://ca.test/acme/acct/%d", location),
		"tos":       tos,
		"contact":   mailto,
		"status":    "valid",
	}
}

func TestACMEAccountListResource(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	// The fake lists accounts in reverse name order, as PBS answers in the
	// order of its directory.
	acme.addAccount("default", fakeACMEAccountProps(pbsclient.DefaultACMEDirectory, fakeToS[pbsclient.DefaultACMEDirectory], 1, "ops@pbs.test"))
	acme.addAccount("staging", fakeACMEAccountProps(pbsclient.ACMEStagingDirectory, "", 2, "ops@pbs.test", "oncall@pbs.test"))
	acme.addAccount("pebble", fakeACMEAccountProps("https://pebble.test:14000/dir", fakeToS["https://pebble.test:14000/dir"], 3, "tfacc@pbs.test"))

	// Without resources, the list costs one call and names every account.
	results := h.listedObjects(t, "pbs_acme_account", listRequest{})
	if got, want := listedIdentities(t, results, "name"), []string{"default", "pebble", "staging"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	if results[1].displayName != "pebble" {
		t.Fatalf("display name %q", results[1].displayName)
	}
	if !results[0].resource.IsNull() || fake.count("GET /config/acme/account/default") != 0 {
		t.Fatal("a list without resources read the accounts")
	}

	// With resources, each is what importing it gives — tos_url included,
	// which only an import reads from PBS — and the configuration generated
	// from it plans nothing.
	results = h.listedObjects(t, "pbs_acme_account", listRequest{includeResource: true})
	if len(results) != 3 {
		t.Fatalf("listed %d accounts with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_acme_account", result)
	}
	if got := stringAt(t, results[0].resource, "tos_url"); got != fakeToS[pbsclient.DefaultACMEDirectory] {
		t.Fatalf("tos_url %q", got)
	}
	if !isNullAt(t, results[2].resource, "tos_url") || stringAt(t, results[2].resource, "contact") != "ops@pbs.test,oncall@pbs.test" ||
		stringAt(t, results[2].resource, "directory") != pbsclient.ACMEStagingDirectory {
		t.Fatalf("listed staging account: %s", results[2].resource)
	}

	if got := h.listedObjects(t, "pbs_acme_account", listRequest{limit: 1}); len(got) != 1 {
		t.Fatalf("a limit of 1 listed %d", len(got))
	}
}

// A CA that returns no contacts — Let's Encrypt since June 2025 — leaves
// contact null after an import, so the generated configuration lacks a
// required attribute until the user fills it in; then it plans an update of
// the contact alone.
func TestACMEAccountListResourceWithoutContacts(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	acme.addAccount("default", fakeACMEAccountProps(pbsclient.DefaultACMEDirectory, fakeToS[pbsclient.DefaultACMEDirectory], 1))

	results := h.listedObjects(t, "pbs_acme_account", listRequest{includeResource: true})
	if len(results) != 1 {
		t.Fatalf("listed %d accounts", len(results))
	}
	generated := h.planGenerated(t, "pbs_acme_account", results[0])
	if !isNullAt(t, generated.config, "contact") {
		t.Fatalf("generated contact %s", valueAt(t, generated.config, "contact"))
	}
	requireProtocolErrorContaining(t, generated.validation, "Missing Configuration for Required Attribute")

	filled := generatedConfigWith(t, generated.config, map[string]any{"contact": "ops@pbs.test"})
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_acme_account", filled))
	plan := h.plan(t, "pbs_acme_account", generated.imported, filled)
	requireNoProtocolErrors(t, plan.Diagnostics)
	if len(plan.RequiresReplace) > 0 {
		t.Fatalf("filling in contact replaces the account: %v", plan.RequiresReplace)
	}
	planned := h.decodeResource(t, "pbs_acme_account", plan.PlannedState)
	if stringAt(t, planned, "contact") != "ops@pbs.test" || stringAt(t, planned, "tos_url") != fakeToS[pbsclient.DefaultACMEDirectory] {
		t.Fatalf("planned %s", planned)
	}
}

// An account deactivated between the listing and its read is left out
// without an error, one PBS fails to read with a warning; a failed listing
// fails the list block with the privilege PBS wants.
func TestACMEAccountListResourceAccountGoneOrForbidden(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	acme.addAccount("default", fakeACMEAccountProps(pbsclient.DefaultACMEDirectory, "", 1, "ops@pbs.test"))
	acme.addAccount("gone", fakeACMEAccountProps(pbsclient.DefaultACMEDirectory, "", 2, "ops@pbs.test"))
	acme.addAccount("broken", fakeACMEAccountProps(pbsclient.DefaultACMEDirectory, "", 3, "ops@pbs.test"))
	fake.reply("GET /config/acme/account/gone", http.StatusBadRequest, "acme account 'gone' does not exist")
	fake.reply("GET /config/acme/account/broken", http.StatusInternalServerError, "unable to parse account file")
	var listed []string
	warned := false
	for _, result := range h.listResources(t, "pbs_acme_account", listRequest{includeResource: true}) {
		requireNoProtocolErrors(t, result.diagnostics)
		if result.identity.IsNull() {
			requireProtocolWarningContaining(t, result.diagnostics, "Left out broken: Unable to read PBS ACME account")
			warned = true
			continue
		}
		listed = append(listed, stringAt(t, result.identity, "name"))
	}
	if !warned || !slices.Equal(listed, []string{"default"}) {
		t.Fatalf("listed %q, warned %v", listed, warned)
	}

	fake.reply("GET /config/acme/account", http.StatusForbidden, "permission check failed")
	all := h.listResources(t, "pbs_acme_account", listRequest{})
	if len(all) != 1 {
		t.Fatalf("got %d results", len(all))
	}
	requireProtocolErrorContaining(t, all[0].diagnostics, "Unable to list PBS ACME accounts")
	requireProtocolErrorContaining(t, all[0].diagnostics, certificatesPrivilege)
}

// listFakeACMEPlugins serves GET /config/acme/plugins as PBS does: every
// plugin with its whole configuration, settings decoded, the built-in
// standalone plugin included, in the order of plugins.cfg — the fake's
// map order, which the list must not rely on.
func listFakeACMEPlugins(a *fakeACME, extra ...map[string]any) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		plugins := []map[string]any{}
		for id := range a.plugins {
			props, _ := a.pluginLocked(id)
			plugins = append(plugins, props)
		}
		standalone, _ := a.pluginLocked(pbsclient.StandaloneACMEPlugin)
		plugins = append(plugins, standalone)
		plugins = append(plugins, extra...)
		writeData(w, plugins, a.pluginDigestLocked())
	}
}

func TestACMEPluginListResource(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	fake.handle("GET /config/acme/plugins", listFakeACMEPlugins(acme))
	acme.addPlugin("cloudflare", fakeProperties{"api": "cf", "data": "CF_Token=secret-token\nCF_Zone_ID=zone"})
	acme.addPlugin("hetzner", fakeProperties{"api": "hetznercloud", "data": "HETZNER_Token=another", "validation-delay": int64(120), "disable": true})

	results := h.listedObjects(t, "pbs_acme_plugin", listRequest{})
	if got, want := listedIdentities(t, results, "id"), []string{"cloudflare", "hetzner", "standalone"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	for i, want := range []string{
		"cloudflare — DNS plugin, API cf",
		"hetzner — DNS plugin, API hetznercloud, disabled",
		"standalone — built-in HTTP-01 plugin",
	} {
		if results[i].displayName != want {
			t.Errorf("display name %q, want %q", results[i].displayName, want)
		}
	}
	if fake.count("GET /config/acme/plugins/cloudflare") != 0 {
		t.Fatal("a list without resources read the plugins")
	}

	results = h.listedObjects(t, "pbs_acme_plugin", listRequest{includeResource: true})
	if len(results) != 3 {
		t.Fatalf("listed %d plugins with resources", len(results))
	}
	// The built-in plugin is what importing it gives, and its generated
	// configuration plans nothing.
	h.requireListedLikeImport(t, "pbs_acme_plugin", results[2])

	// A DNS plugin's settings are sensitive: null in the result and in the
	// generated configuration, which a DNS plugin refuses until they are
	// filled in.
	for i, settings := range []map[string]any{
		{"CF_Token": "secret-token", "CF_Zone_ID": "zone"},
		{"HETZNER_Token": "another"},
	} {
		result := results[i]
		if !isNullAt(t, result.resource, "data") || stringAt(t, result.resource, "type") != pbsclient.DNSACMEPluginType {
			t.Fatalf("listed %s", result.resource)
		}
		generated := h.planGenerated(t, "pbs_acme_plugin", result)
		if got := h.identityValue(t, "pbs_acme_plugin", generated.imported.identity); !got.Equal(result.identity) {
			t.Fatalf("listed identity %s, imported %s", result.identity, got)
		}
		// withoutSensitive changes the attributes of the value it is given.
		wantState := withoutSensitive(t, h.resourceSchema(t, "pbs_acme_plugin").Block, generated.imported.state.Copy())
		if !result.resource.Equal(wantState) {
			t.Fatalf("listed state differs from the imported one\nlisted:   %s\nimported: %s", result.resource, wantState)
		}
		if !isNullAt(t, generated.config, "data") {
			t.Fatalf("generated data %s", valueAt(t, generated.config, "data"))
		}
		requireProtocolErrorContaining(t, generated.validation, "Missing setting of a DNS plugin")
		// Left as it is, it would also plan to remove the settings.
		if planned := h.decodeResource(t, "pbs_acme_plugin", generated.plan.PlannedState); !planned.Equal(wantState) {
			t.Fatalf("the generated configuration plans more than removing data\nplanned: %s\nwant:    %s", planned, wantState)
		}

		// With the settings PBS has, the configuration plans nothing.
		filled := generatedConfigWith(t, generated.config, map[string]any{"data": settings})
		requireNoProtocolErrors(t, h.validateResource(t, "pbs_acme_plugin", filled))
		plan := h.plan(t, "pbs_acme_plugin", generated.imported, filled)
		requireNoProtocolErrors(t, plan.Diagnostics)
		if planned := h.decodeResource(t, "pbs_acme_plugin", plan.PlannedState); !planned.Equal(generated.imported.state) {
			t.Fatalf("the filled-in configuration plans a change\nplanned:  %s\nimported: %s", planned, generated.imported.state)
		}
	}
	if int64At(t, results[1].resource, "validation_delay") != 120 || !boolAt(t, results[1].resource, "disable") {
		t.Fatalf("listed hetzner: %s", results[1].resource)
	}
}

// The "*Error*" placeholder PBS would list for a section it cannot convert —
// which its plugin types do not give, as a defensive case — is left out with
// a warning; a plugin deleted between the listing and its read is left out
// silently.
func TestACMEPluginListResourceUnreadableAndGone(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	unreadable := map[string]any{"plugin": pbsclient.UnreadableACMEPlugin, "type": pbsclient.UnreadableACMEPlugin}
	fake.handle("GET /config/acme/plugins", listFakeACMEPlugins(acme, unreadable))
	acme.addPlugin("cloudflare", fakeProperties{"api": "cf", "data": "CF_Token=secret-token"})
	acme.addPlugin("gone", fakeProperties{"api": "cf", "data": "CF_Token=other"})
	fake.reply("GET /config/acme/plugins/gone", http.StatusNotFound, "no such plugin")

	var listed []string
	warned := false
	for _, result := range h.listResources(t, "pbs_acme_plugin", listRequest{includeResource: true}) {
		requireNoProtocolErrors(t, result.diagnostics)
		if result.identity.IsNull() {
			requireProtocolWarningContaining(t, result.diagnostics, "Left out ACME plugins PBS cannot read")
			warned = true
			continue
		}
		listed = append(listed, stringAt(t, result.identity, "id"))
	}
	if !warned || !slices.Equal(listed, []string{"cloudflare", "standalone"}) {
		t.Fatalf("listed %q, warned %v", listed, warned)
	}
}

// A refused listing fails the list block with the privilege it needs; so
// does a plugins.cfg PBS cannot parse, as after a bad edit by hand, which
// PBS refuses to list at all, with the line at fault.
func TestACMEPluginListResourceListFails(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/acme/plugins", http.StatusForbidden, "permission check failed")
	h := newProtocolHarness(t, fake)
	results := h.listResources(t, "pbs_acme_plugin", listRequest{})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS ACME plugins")
	requireProtocolErrorContaining(t, results[0].diagnostics, certificatesPrivilege)

	const parseFailed = `parsing "/etc/proxmox-backup/acme/plugins.cfg" failed: line 3 - unknown property 'validation'`
	fake.reply("GET /config/acme/plugins", http.StatusBadRequest, parseFailed)
	results = h.listResources(t, "pbs_acme_plugin", listRequest{includeResource: true})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS ACME plugins")
	requireProtocolErrorContaining(t, results[0].diagnostics, parseFailed)
}
