package provider

import (
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// newACMEHarness is a fake PBS with the ACME, node and certificate API and a
// provider signed in to it.
func newACMEHarness(t *testing.T, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeACME) {
	t.Helper()
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	return newProtocolHarness(t, fake, opts...), fake, acme
}

// requireEmptyPlan fails the test when planning config against inst changes
// anything.
func requireEmptyPlan(t *testing.T, h *protocolHarness, inst *resourceInstance, config tftypes.Value) {
	t.Helper()
	replan := h.plan(t, inst.typeName, inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if len(replan.RequiresReplace) > 0 {
		t.Fatalf("plan replaces the resource for %v", replan.RequiresReplace)
	}
	if planned := h.decodeResource(t, inst.typeName, replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan changes %v", diffs)
	}
}

func TestACMESchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, NewACMEAccountResource())
	requireValidResourceSchema(t, NewACMEPluginResource())
	requireValidResourceSchema(t, NewNodeACMEResource())
	requireValidResourceSchema(t, NewNodeCertificateResource())
	requireValidDataSourceSchema(t, NewACMEToSDataSource())
}

func accountConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"name": "le", "contact": "ops@example.org"}
	for k, v := range attrs {
		config[k] = v
	}
	return h.resourceValue(t, "pbs_acme_account", config)
}

func TestACMEAccountResourceLifecycle(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	const tos = "https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf"

	config := accountConfig(t, h, map[string]any{"tos_url": tos})
	planned := h.plan(t, "pbs_acme_account", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	inst := h.create(t, "pbs_acme_account", config)

	registered := fake.lastCall(t, "POST /config/acme/account")
	if registered.form.Get("name") != "le" || registered.form.Get("contact") != "ops@example.org" ||
		registered.form.Get("directory") != pbsclient.DefaultACMEDirectory || registered.form.Get("tos_url") != tos {
		t.Fatalf("POST form = %v", registered.form)
	}
	if stringAt(t, inst.state, "id") != "le" || stringAt(t, inst.state, "directory") != pbsclient.DefaultACMEDirectory ||
		stringAt(t, inst.state, "status") != "valid" || !strings.HasPrefix(stringAt(t, inst.state, "location"), "https://ca.test/acme/acct/") ||
		stringAt(t, inst.state, "tos_url") != tos {
		t.Fatalf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_acme_account", inst.identity), "name"); got != "le" {
		t.Fatalf("identity name = %q", got)
	}
	requireEmptyPlan(t, h, inst, config)

	// The contact changes in place, at the CA.
	config = accountConfig(t, h, map[string]any{"tos_url": tos, "contact": "admin@example.org,ops@example.org"})
	inst = h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /config/acme/account/le").form.Get("contact"); got != "admin@example.org,ops@example.org" {
		t.Fatalf("PUT contact = %q", got)
	}
	if props, _ := acme.account("le"); !slices.Equal(props["contact"].([]string), []string{"mailto:admin@example.org", "mailto:ops@example.org"}) {
		t.Fatalf("CA contacts = %v", props["contact"])
	}
	requireEmptyPlan(t, h, inst, config)

	// The contacts in another order, case and spelling are the same
	// contacts: recorded as configured, without a call.
	config = accountConfig(t, h, map[string]any{"tos_url": tos, "contact": "OPS@example.org, admin@example.org"})
	puts := fake.count("PUT /config/acme/account/le")
	inst = h.update(t, inst, config)
	if got := stringAt(t, inst.state, "contact"); got != "OPS@example.org, admin@example.org" || fake.count("PUT /config/acme/account/le") != puts {
		t.Fatalf("contact = %q after %d PUTs, want it as configured without one", got, fake.count("PUT /config/acme/account/le")-puts)
	}
	requireEmptyPlan(t, h, inst, config)

	// Other addresses are sent without the empty part PBS would turn into
	// an empty contact.
	config = accountConfig(t, h, map[string]any{"tos_url": tos, "contact": "ops@example.org, new@example.org;"})
	inst = h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /config/acme/account/le").form.Get("contact"); got != "ops@example.org,new@example.org" {
		t.Fatalf("PUT contact = %q", got)
	}
	requireEmptyPlan(t, h, inst, config)
	puts = fake.count("PUT /config/acme/account/le")

	// A new terms of service URL is recorded without a call.
	const newToS = "https://letsencrypt.org/documents/LE-SA-v1.9.pdf"
	config = accountConfig(t, h, map[string]any{"tos_url": newToS, "contact": "ops@example.org, new@example.org;"})
	replan := h.plan(t, "pbs_acme_account", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if len(replan.RequiresReplace) > 0 {
		t.Fatalf("a new tos_url replaces the account: %v", replan.RequiresReplace)
	}
	inst = h.update(t, inst, config)
	if fake.count("PUT /config/acme/account/le") != puts || stringAt(t, inst.state, "tos_url") != newToS {
		t.Fatalf("after a new tos_url: %d PUTs, state %s", fake.count("PUT /config/acme/account/le"), inst.state)
	}
	inst = h.refresh(t, inst)
	if stringAt(t, inst.state, "tos_url") != newToS {
		t.Fatalf("refresh reset tos_url to %q", stringAt(t, inst.state, "tos_url"))
	}

	// Leaving tos_url out is recorded too: PBS keeps the URL agreed to.
	config = accountConfig(t, h, map[string]any{"contact": "ops@example.org, new@example.org;"})
	inst = h.update(t, inst, config)
	inst = h.refresh(t, inst)
	requireEmptyPlan(t, h, inst, config)

	// A change made outside Terraform shows, for a CA that returns contacts.
	acme.mu.Lock()
	acme.accounts["le"]["contact"] = []string{"mailto:intruder@example.org"}
	acme.mu.Unlock()
	inst = h.refresh(t, inst)
	if got := stringAt(t, inst.state, "contact"); got != "intruder@example.org" {
		t.Fatalf("contact after a change outside Terraform = %q", got)
	}

	// Destroying deactivates the account, after a warning in the plan.
	destroyPlan := h.plan(t, "pbs_acme_account", inst, tftypes.NewValue(h.resourceType(t, "pbs_acme_account"), nil))
	requireProtocolWarningContaining(t, destroyPlan.Diagnostics, "deactivates it at")
	h.destroy(t, inst)
	if _, exists := acme.account("le"); exists || !slices.Equal(acme.deactivated, []string{"le"}) {
		t.Fatalf("the account was not deactivated: %v", acme.deactivated)
	}
	// It is gone: a refresh drops it, and a destroy again succeeds.
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Fatalf("refresh kept a deactivated account: %s", refreshed.state)
	}
	h.destroy(t, inst)
}

// Let's Encrypt neither keeps nor returns contacts: the configured ones
// stay in state.
func TestACMEAccountResourceWithACAThatForgetsContacts(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	acme.caForgets = true

	config := accountConfig(t, h, map[string]any{"directory": pbsclient.ACMEStagingDirectory, "tos_url": "https://ca.test/tos"})
	inst := h.create(t, "pbs_acme_account", config)
	if stringAt(t, inst.state, "contact") != "ops@example.org" || stringAt(t, inst.state, "directory") != pbsclient.ACMEStagingDirectory {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)
	inst = h.refresh(t, inst)
	requireEmptyPlan(t, h, inst, config)

	config = accountConfig(t, h, map[string]any{"directory": pbsclient.ACMEStagingDirectory, "tos_url": "https://ca.test/tos", "contact": "new@example.org"})
	inst = h.update(t, inst, config)
	if fake.count("PUT /config/acme/account/le") != 1 || stringAt(t, inst.state, "contact") != "new@example.org" {
		t.Fatalf("state = %s", inst.state)
	}

	// A new directory replaces the account, which deactivates the old one.
	replan := h.plan(t, "pbs_acme_account", inst, accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos", "contact": "new@example.org"}))
	requireNoProtocolErrors(t, replan.Diagnostics)
	if len(replan.RequiresReplace) != 1 {
		t.Fatalf("RequiresReplace = %v, want directory", replan.RequiresReplace)
	}
	requireProtocolWarningContaining(t, replan.Diagnostics, "deactivates it at "+pbsclient.ACMEStagingDirectory)

	// After an import, the contacts the CA does not return are unknown
	// until the next apply sends them; tos_url comes from PBS, and leaving
	// it out of the configuration is recorded.
	imported := h.importByID(t, "pbs_acme_account", "le")
	if !isNullAt(t, imported.state, "contact") || stringAt(t, imported.state, "tos_url") != "https://ca.test/tos" {
		t.Fatalf("imported state = %s", imported.state)
	}
	config = accountConfig(t, h, map[string]any{"directory": pbsclient.ACMEStagingDirectory, "contact": "new@example.org"})
	imported = h.update(t, imported, config)
	imported = h.refresh(t, imported)
	requireEmptyPlan(t, h, imported, config)
}

func TestACMEAccountResourceErrors(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	acme.addAccount("taken", fakeProperties{"directory": pbsclient.DefaultACMEDirectory, "location": "https://ca/1", "status": "valid"})

	config := accountConfig(t, h, map[string]any{"name": "taken"})
	planned := h.plan(t, "pbs_acme_account", nil, config)
	applied := h.apply(t, "pbs_acme_account", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Import it to manage it")

	// The CA refuses: the error names the task's reason, and suggests
	// tos_url, which is missing.
	acme.registerFailure = "Error: userActionRequired: Provided account did not agree to the terms of service"
	config = accountConfig(t, h, nil)
	planned = h.plan(t, "pbs_acme_account", nil, config)
	applied = h.apply(t, "pbs_acme_account", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "set tos_url")
	requireProtocolErrorContaining(t, applied.Diagnostics, "did not agree to the terms of service")

	for _, bad := range []string{"", "not an address", "Ops <ops@example.org>", "ops@example.org,,", ",,"} {
		if bad == "ops@example.org,," {
			// Empty parts are left out of what the provider sends.
			requireNoProtocolErrors(t, h.validateResource(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"contact": bad})))
			continue
		}
		requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"contact": bad})), "email addresses")
	}
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"directory": "http://ca.test/dir"})), "https://")
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"name": "-bad"})), "must start with")

	// A deactivation the CA refuses is an error that says how to get rid of
	// the account.
	inst := h.importByID(t, "pbs_acme_account", "taken")
	acme.mu.Lock()
	acme.tasks = map[string]func() string{}
	acme.mu.Unlock()
	acme.fake.handlePrefix("DELETE /config/acme/account/", func(w http.ResponseWriter, _ *http.Request) {
		acme.mu.Lock()
		upid := acme.startTaskLocked("acme-deactivate", "taken", func() string { return "Error: connection refused" })
		acme.mu.Unlock()
		writeData(w, upid, "")
	})
	destroyed := h.apply(t, "pbs_acme_account", inst, tftypes.NewValue(h.resourceType(t, "pbs_acme_account"), nil),
		h.plan(t, "pbs_acme_account", inst, tftypes.NewValue(h.resourceType(t, "pbs_acme_account"), nil)))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "--force")

	// Import by identity.
	byIdentity := h.importByIdentity(t, "pbs_acme_account", map[string]any{"name": "taken"})
	if stringAt(t, byIdentity.state, "location") != "https://ca/1" {
		t.Fatalf("imported state = %s", byIdentity.state)
	}
	resp := h.importResource(t, "pbs_acme_account", "not/valid", nil)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS ACME account by its name")
}

func pluginConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"id": "cloudflare", "api": "cf", "data": map[string]any{"CF_Token": "token-1", "CF_Zone_ID": "zone"}}
	for k, v := range attrs {
		config[k] = v
	}
	return h.resourceValue(t, "pbs_acme_plugin", config)
}

func TestACMEPluginResourceLifecycle(t *testing.T) {
	h, fake, acme := newACMEHarness(t)

	config := pluginConfig(t, h, nil)
	inst := h.create(t, "pbs_acme_plugin", config)
	created := fake.lastCall(t, "POST /config/acme/plugins")
	decoded, _ := base64.StdEncoding.DecodeString(created.form.Get("data"))
	if created.form.Get("type") != "dns" || created.form.Get("api") != "cf" || string(decoded) != "CF_Token=token-1\nCF_Zone_ID=zone" {
		t.Fatalf("POST form = %v, data %q", created.form, decoded)
	}
	for _, name := range []string{"validation-delay", "disable"} {
		if created.form.Has(name) {
			t.Errorf("POST sent the default %s", name)
		}
	}
	if stringAt(t, inst.state, "type") != "dns" || int64At(t, inst.state, "validation_delay") != 30 || boolAt(t, inst.state, "disable") ||
		stringAt(t, inst.state, "data", "CF_Token") != "token-1" {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)

	// A new token and settings away from the defaults, with the digest.
	config = pluginConfig(t, h, map[string]any{
		"data":             map[string]any{"CF_Token": "token-2", "CF_Zone_ID": "zone"},
		"validation_delay": 120,
		"disable":          true,
	})
	inst = h.update(t, inst, config)
	updated := fake.lastCall(t, "PUT /config/acme/plugins/cloudflare")
	decoded, _ = base64.StdEncoding.DecodeString(updated.form.Get("data"))
	if string(decoded) != "CF_Token=token-2\nCF_Zone_ID=zone" || updated.form.Get("validation-delay") != "120" ||
		updated.form.Get("disable") != "true" || updated.form.Get("digest") == "" || updated.form.Has("api") {
		t.Fatalf("PUT form = %v", updated.form)
	}
	requireEmptyPlan(t, h, inst, config)

	// Back to the defaults deletes them; unchanged data is not sent.
	config = pluginConfig(t, h, map[string]any{"data": map[string]any{"CF_Token": "token-2", "CF_Zone_ID": "zone"}})
	inst = h.update(t, inst, config)
	updated = fake.lastCall(t, "PUT /config/acme/plugins/cloudflare")
	if got := strings.Join(updated.form["delete"], ","); got != "disable,validation-delay" || updated.form.Has("data") {
		t.Fatalf("PUT form = %v", updated.form)
	}
	if props, _ := acme.plugin("cloudflare"); props["validation-delay"] != nil || props["disable"] != nil {
		t.Fatalf("plugin = %v", props)
	}

	// Settings changed outside Terraform show as a difference; the web
	// interface's trailing newline does not.
	acme.mu.Lock()
	acme.plugins["cloudflare"]["data"] = "CF_Token=token-2\nCF_Zone_ID=zone\n"
	acme.mu.Unlock()
	inst = h.refresh(t, inst)
	requireEmptyPlan(t, h, inst, config)
	acme.mu.Lock()
	acme.plugins["cloudflare"]["data"] = "CF_Token=rotated\nCF_Zone_ID=zone\n"
	acme.mu.Unlock()
	inst = h.refresh(t, inst)
	if replan := h.plan(t, "pbs_acme_plugin", inst, config); h.decodeResource(t, "pbs_acme_plugin", replan.PlannedState).Equal(inst.state) {
		t.Fatal("a token changed outside Terraform plans nothing")
	}

	// A digest conflict from a writer outside the provider is retried.
	acme.mu.Lock()
	acme.pluginGen++
	acme.mu.Unlock()
	inst = h.update(t, inst, config)

	h.destroy(t, inst)
	if _, exists := acme.plugin("cloudflare"); exists {
		t.Fatal("the plugin still exists")
	}
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Fatal("refresh kept a deleted plugin")
	}
	h.destroy(t, inst)
}

func TestACMEPluginResourceStandalone(t *testing.T) {
	h, fake, _ := newACMEHarness(t)
	config := h.resourceValue(t, "pbs_acme_plugin", map[string]any{"id": "standalone"})

	planned := h.plan(t, "pbs_acme_plugin", nil, config)
	requireProtocolErrorContaining(t, planned.Diagnostics, "must be imported")

	inst := h.importByID(t, "pbs_acme_plugin", "standalone")
	if stringAt(t, inst.state, "type") != "standalone" || !isNullAt(t, inst.state, "api") || !isNullAt(t, inst.state, "data") ||
		int64At(t, inst.state, "validation_delay") != 30 || boolAt(t, inst.state, "disable") {
		t.Fatalf("imported state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)
	h.destroy(t, inst)
	if fake.count("DELETE /config/acme/plugins/standalone") != 0 {
		t.Fatal("destroying the standalone plugin called DELETE")
	}

	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_plugin",
		h.resourceValue(t, "pbs_acme_plugin", map[string]any{"id": "standalone", "api": "cf"})), "has no api")
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_plugin",
		h.resourceValue(t, "pbs_acme_plugin", map[string]any{"id": "standalone", "validation_delay": 10})), "has no validation_delay")
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_acme_plugin",
		h.resourceValue(t, "pbs_acme_plugin", map[string]any{"id": "standalone", "validation_delay": 30, "disable": false})))
}

func TestACMEPluginResourceValidation(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_plugin",
		h.resourceValue(t, "pbs_acme_plugin", map[string]any{"id": "cf"})), "A DNS plugin needs api")
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_plugin",
		h.resourceValue(t, "pbs_acme_plugin", map[string]any{"id": "cf", "api": "cf"})), "A DNS plugin needs data")
	for _, data := range []map[string]any{
		{"CF_Token": "has space"},
		{"CF_Token": "line\nbreak"},
		{"1BAD": "x"},
		{"bad-name": "x"},
		{},
	} {
		if diags := h.validateResource(t, "pbs_acme_plugin", pluginConfig(t, h, map[string]any{"data": data})); len(diags) == 0 {
			t.Errorf("data %v passed validation", data)
		}
	}
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_plugin", pluginConfig(t, h, map[string]any{"validation_delay": 172801})), "172800")
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_plugin", pluginConfig(t, h, map[string]any{"api": "c f"})), "acme.sh DNS API")

	// A plugin that exists already must be imported.
	acme.addPlugin("cloudflare", fakeProperties{"api": "cf", "data": "CF_Token=x"})
	config := pluginConfig(t, h, nil)
	applied := h.apply(t, "pbs_acme_plugin", nil, config, h.plan(t, "pbs_acme_plugin", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "Import it to manage it")
	inst := h.importByIdentity(t, "pbs_acme_plugin", map[string]any{"id": "cloudflare"})
	if stringAt(t, inst.state, "data", "CF_Token") != "x" {
		t.Fatalf("imported state = %s", inst.state)
	}
}

func TestACMEToSDataSource(t *testing.T) {
	h, fake, _ := newACMEHarness(t)

	state := h.readDataSource(t, "pbs_acme_tos", h.dataSourceValue(t, "pbs_acme_tos", map[string]any{}))
	if stringAt(t, state, "directory") != pbsclient.DefaultACMEDirectory || stringAt(t, state, "url") != fakeToS[pbsclient.DefaultACMEDirectory] {
		t.Fatalf("state = %s", state)
	}
	if got := fake.lastCall(t, "GET /config/acme/tos").query.Get("directory"); got != pbsclient.DefaultACMEDirectory {
		t.Fatalf("directory = %q", got)
	}
	state = h.readDataSource(t, "pbs_acme_tos", h.dataSourceValue(t, "pbs_acme_tos", map[string]any{"directory": "https://pebble.test:14000/dir"}))
	if stringAt(t, state, "url") != "data:text/plain,Do%20what%20thou%20wilt" {
		t.Fatalf("state = %s", state)
	}
	state = h.readDataSource(t, "pbs_acme_tos", h.dataSourceValue(t, "pbs_acme_tos", map[string]any{"directory": "https://private.test/dir"}))
	if !isNullAt(t, state, "url") {
		t.Fatalf("state = %s, want no terms of service", state)
	}

	fake.reply("GET /config/acme/tos", http.StatusBadRequest, "error trying to connect: dns error")
	resp := h.readDataSourceResponse(t, "pbs_acme_tos", h.dataSourceValue(t, "pbs_acme_tos", map[string]any{}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "must reach the directory")
}
