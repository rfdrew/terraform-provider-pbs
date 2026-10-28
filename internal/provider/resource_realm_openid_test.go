package provider

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestOpenIDRealmSchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, &openIDRealmResource{})
	requireValidDataSourceSchema(t, &realmsDataSource{})
}

// newRealmHarness is a fake PBS with the realm API and a provider signed in
// to it. version, when set, is what GET /version answers.
func newRealmHarness(t *testing.T, version ...string) (*protocolHarness, *fakePBS, *fakeRealms) {
	t.Helper()
	fake := newFakePBS()
	if len(version) > 0 {
		fake.reply("GET /version", http.StatusOK, version[0])
	}
	realms := newFakeRealms(fake)
	return newProtocolHarness(t, fake), fake, realms
}

// testIssuerURL is an issuer as Authentik names one.
const testIssuerURL = "https://authentik.example.com/application/o/pbs/"

// openIDRealmConfig is the configuration of a realm "authentik", with attrs
// on top of what it needs.
func openIDRealmConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"realm": "authentik", "issuer_url": testIssuerURL, "client_id": "pbs"}
	for k, v := range attrs {
		config[k] = v
	}
	return h.resourceValue(t, "pbs_realm_openid", config)
}

// setStringsAt returns the strings of the set or list at steps, sorted.
func setStringsAt(t *testing.T, v tftypes.Value, steps ...any) []string {
	t.Helper()
	var elements []tftypes.Value
	if err := knownAt(t, v, steps...).As(&elements); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(elements))
	for _, e := range elements {
		var s string
		if err := e.As(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func TestOpenIDRealmResourceLifecycle(t *testing.T) {
	h, fake, realms := newRealmHarness(t)

	// Created with a client key in state: only what differs from PBS's
	// defaults is sent, and username-claim, which only a create takes.
	attrs := map[string]any{
		"client_key":     "first-secret",
		"acr_values":     []string{"silver", "gold"},
		"prompt":         "login",
		"username_claim": "preferred_username",
		"autocreate":     true,
		"comment":        "Authentik",
	}
	config := openIDRealmConfig(t, h, attrs)
	inst := h.create(t, "pbs_realm_openid", config)

	created := fake.lastCall(t, "POST /config/access/openid")
	for name, want := range map[string]string{"realm": "authentik", "issuer-url": testIssuerURL, "client-id": "pbs",
		"client-key": "first-secret", "acr-values": "silver gold", "prompt": "login",
		"username-claim": "preferred_username", "autocreate": "true", "comment": "Authentik"} {
		if got := created.form.Get(name); got != want {
			t.Errorf("POST %s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"scopes", "audiences", "default"} {
		if _, sent := created.form[name]; sent {
			t.Errorf("POST sent %s: %v", name, created.form)
		}
	}
	if stringAt(t, inst.state, "id") != "authentik" || stringAt(t, inst.state, "client_key") != "first-secret" ||
		!slices.Equal(setStringsAt(t, inst.state, "scopes"), []string{"email", "profile"}) ||
		stringAt(t, inst.state, "acr_values", 0) != "silver" || boolAt(t, inst.state, "default") ||
		!isNullAt(t, inst.state, "client_key_wo_version") {
		t.Errorf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_realm_openid", inst.identity), "realm"); got != "authentik" {
		t.Errorf("identity realm = %q", got)
	}
	requireNoPlannedChange(t, h, inst, config)

	// A key changed outside Terraform shows, and the next apply puts it back.
	realms.mu.Lock()
	realms.realms["authentik"]["client-key"] = "changed-outside"
	realms.mu.Unlock()
	inst = h.refresh(t, inst)
	if got := stringAt(t, inst.state, "client_key"); got != "changed-outside" {
		t.Errorf("client_key after a change outside = %q", got)
	}
	inst = h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /config/access/openid/authentik").form; got.Get("client-key") != "first-secret" || len(got) != 1 {
		t.Errorf("PUT form = %v, want only the client key", got)
	}

	// The lists are sent separated by spaces, a set's sorted; the default
	// flag is taken from pam.
	if realms.defaultRealm() != "pam" {
		t.Fatalf("default realm = %q before, want pam", realms.defaultRealm())
	}
	attrs["scopes"] = []string{"profile", "email", "groups"}
	attrs["audiences"] = []string{"pbs-extra"}
	attrs["default"] = true
	delete(attrs, "acr_values")
	config = openIDRealmConfig(t, h, attrs)
	inst = h.update(t, inst, config)
	updated := fake.lastCall(t, "PUT /config/access/openid/authentik")
	for name, want := range map[string]string{"scopes": "email groups profile", "audiences": "pbs-extra", "default": "true",
		"delete": "acr-values"} {
		if got := updated.form.Get(name); got != want {
			t.Errorf("PUT %s = %q, want %q", name, got, want)
		}
	}
	if realms.defaultRealm() != "authentik" || !boolAt(t, inst.state, "default") || !isNullAt(t, inst.state, "acr_values") {
		t.Errorf("default realm = %q, state = %s", realms.defaultRealm(), inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// PBS clears the default flag on any update that leaves it out, so a
	// default realm's update sends it every time.
	attrs["comment"] = "Authentik SSO"
	config = openIDRealmConfig(t, h, attrs)
	inst = h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /config/access/openid/authentik").form; got.Get("default") != "true" || got.Get("comment") != "Authentik SSO" {
		t.Errorf("PUT form = %v", got)
	}
	if realms.defaultRealm() != "authentik" {
		t.Errorf("default realm = %q after an update", realms.defaultRealm())
	}

	// Moving to client_key_wo sends the key once, deletes nothing, and keeps
	// it out of state, also after a refresh.
	delete(attrs, "client_key")
	attrs["client_key_wo"] = "second-secret"
	attrs["client_key_wo_version"] = 1
	config = openIDRealmConfig(t, h, attrs)
	inst = h.update(t, inst, config)
	updated = fake.lastCall(t, "PUT /config/access/openid/authentik")
	if updated.form.Get("client-key") != "second-secret" || updated.form.Has("delete") {
		t.Errorf("PUT form = %v", updated.form)
	}
	if !isNullAt(t, inst.state, "client_key") || !isNullAt(t, inst.state, "client_key_wo") ||
		int64At(t, inst.state, "client_key_wo_version") != 1 {
		t.Errorf("state = %s", inst.state)
	}
	inst = h.refresh(t, inst)
	if !isNullAt(t, inst.state, "client_key") {
		t.Errorf("refresh put the key into state: %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// The key goes only with a new version.
	puts := fake.count("PUT /config/access/openid/authentik")
	attrs["client_key_wo"] = "unsent-secret"
	inst = h.update(t, inst, openIDRealmConfig(t, h, attrs))
	if fake.count("PUT /config/access/openid/authentik") != puts {
		t.Error("a new client_key_wo without a new version was sent")
	}
	attrs["client_key_wo"] = "third-secret"
	attrs["client_key_wo_version"] = 2
	inst = h.update(t, inst, openIDRealmConfig(t, h, attrs))
	if got, _ := realms.realm("authentik"); got["client-key"] != "third-secret" {
		t.Errorf("client key = %v after a new version", got["client-key"])
	}

	// Dropping client_key_wo leaves the key PBS has, and so does the next
	// plan.
	delete(attrs, "client_key_wo")
	delete(attrs, "client_key_wo_version")
	config = openIDRealmConfig(t, h, attrs)
	inst = h.update(t, inst, config)
	if got, _ := realms.realm("authentik"); got["client-key"] != "third-secret" {
		t.Errorf("client key = %v after dropping client_key_wo", got["client-key"])
	}
	inst = h.refresh(t, inst)
	requireNoPlannedChange(t, h, inst, config)

	// Back to the defaults: deleted, not written.
	inst = h.update(t, inst, openIDRealmConfig(t, h, map[string]any{"username_claim": "preferred_username"}))
	updated = fake.lastCall(t, "PUT /config/access/openid/authentik")
	if got := strings.Join(updated.form["delete"], ","); got != "audiences,autocreate,comment,default,prompt,scopes" {
		t.Errorf("delete = %q", got)
	}
	if len(updated.form) != 1 {
		t.Errorf("PUT form = %v, want only deletions", updated.form)
	}
	stored, _ := realms.realm("authentik")
	if len(stored) != 5 || realms.defaultRealm() != "" {
		t.Errorf("stored realm = %v, default realm %q", stored, realms.defaultRealm())
	}

	// client_key again: sent; then removed: deleted from PBS.
	inst = h.update(t, inst, openIDRealmConfig(t, h, map[string]any{"username_claim": "preferred_username", "client_key": "fourth-secret"}))
	if got := fake.lastCall(t, "PUT /config/access/openid/authentik").form.Get("client-key"); got != "fourth-secret" {
		t.Errorf("PUT client-key = %q", got)
	}
	inst = h.update(t, inst, openIDRealmConfig(t, h, map[string]any{"username_claim": "preferred_username"}))
	if got := fake.lastCall(t, "PUT /config/access/openid/authentik").form["delete"]; !slices.Equal(got, []string{"client-key"}) {
		t.Errorf("delete = %v", got)
	}
	if stored, _ := realms.realm("authentik"); stored["client-key"] != nil {
		t.Errorf("client key = %v after removing client_key", stored["client-key"])
	}

	// A new username claim, which PBS cannot change, replaces the realm.
	planned := h.plan(t, "pbs_realm_openid", inst, openIDRealmConfig(t, h, map[string]any{"username_claim": "email"}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 1 || !strings.Contains(planned.RequiresReplace[0].String(), "username_claim") {
		t.Errorf("RequiresReplace = %v", planned.RequiresReplace)
	}

	// A realm deleted outside Terraform is gone from state, and destroying it
	// then is no error.
	realms.mu.Lock()
	delete(realms.realms, "authentik")
	delete(realms.types, "authentik")
	realms.mu.Unlock()
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept a deleted realm: %s", refreshed.state)
	}
	h.destroy(t, inst)
}

// A realm created with client_key_wo sends it in the POST and keeps it out
// of state; one with no key at all is a public client.
func TestOpenIDRealmResourceCreatesWithWriteOnlyKeyOrNone(t *testing.T) {
	h, fake, realms := newRealmHarness(t)

	config := openIDRealmConfig(t, h, map[string]any{"client_key_wo": "wo-secret", "client_key_wo_version": 1})
	inst := h.create(t, "pbs_realm_openid", config)
	if got := fake.lastCall(t, "POST /config/access/openid").form.Get("client-key"); got != "wo-secret" {
		t.Errorf("POST client-key = %q", got)
	}
	if !isNullAt(t, inst.state, "client_key") || int64At(t, inst.state, "client_key_wo_version") != 1 {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)
	h.destroy(t, inst)
	if _, exists := realms.realm("authentik"); exists {
		t.Error("destroy left the realm")
	}

	inst = h.create(t, "pbs_realm_openid", openIDRealmConfig(t, h, nil))
	if _, sent := fake.lastCall(t, "POST /config/access/openid").form["client-key"]; sent {
		t.Error("POST sent a client key")
	}
	if !isNullAt(t, inst.state, "client_key") {
		t.Errorf("state = %s", inst.state)
	}
}

func TestOpenIDRealmResourceImport(t *testing.T) {
	h, _, realms := newRealmHarness(t)
	realms.addRealm("corp", "openid", fakeProperties{"issuer-url": "https://sso.example.com/realms/corp",
		"client-id": "pbs", "client-key": "imported-secret", "scopes": "openid,email;profile email",
		"acr-values": "gold silver", "audiences": "a b", "username-claim": "preferred_username", "default": true})

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_realm_openid", "corp"),
		"identity": h.importByIdentity(t, "pbs_realm_openid", map[string]any{"realm": "corp"}),
	} {
		if stringAt(t, inst.state, "issuer_url") != "https://sso.example.com/realms/corp" ||
			!slices.Equal(setStringsAt(t, inst.state, "scopes"), []string{"email", "openid", "profile"}) ||
			stringAt(t, inst.state, "acr_values", 1) != "silver" ||
			!slices.Equal(setStringsAt(t, inst.state, "audiences"), []string{"a", "b"}) ||
			stringAt(t, inst.state, "username_claim") != "preferred_username" || !boolAt(t, inst.state, "default") ||
			!isNullAt(t, inst.state, "client_key") || !isNullAt(t, inst.state, "client_key_wo_version") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
	}

	// After an import, a configuration with the key sends it once.
	inst := h.importByID(t, "pbs_realm_openid", "corp")
	config := h.resourceValue(t, "pbs_realm_openid", map[string]any{"realm": "corp",
		"issuer_url": "https://sso.example.com/realms/corp", "client_id": "pbs", "client_key": "imported-secret",
		"scopes": []string{"openid", "email", "profile"}, "acr_values": []string{"gold", "silver"},
		"audiences": []string{"a", "b"}, "username_claim": "preferred_username", "default": true})
	inst = h.update(t, inst, config)
	if stringAt(t, inst.state, "client_key") != "imported-secret" {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// Without one, PBS keeps its key.
	inst = h.importByID(t, "pbs_realm_openid", "corp")
	config = h.resourceValue(t, "pbs_realm_openid", map[string]any{"realm": "corp",
		"issuer_url": "https://sso.example.com/realms/corp", "client_id": "pbs",
		"scopes": []string{"openid", "email", "profile"}, "acr_values": []string{"gold", "silver"},
		"audiences": []string{"a", "b"}, "username_claim": "preferred_username", "default": true})
	requireNoPlannedChange(t, h, inst, config)

	resp := h.importResource(t, "pbs_realm_openid", "corp/x", nil)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS OpenID realm by its realm")
}

func TestOpenIDRealmResourceErrors(t *testing.T) {
	h, fake, realms := newRealmHarness(t)

	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"built-in name":     {map[string]any{"realm": "pam"}, "value must be none of"},
		"short name":        {map[string]any{"realm": "a"}, "string length must be between 2 and 32"},
		"issuer with query": {map[string]any{"issuer_url": "https://sso.example.com/?x=1"}, "must be an https:// or http:// URL"},
		"issuer without host": {map[string]any{"issuer_url": "https:///realms/corp"},
			"must be an https:// or http:// URL"},
		"ftp issuer":      {map[string]any{"issuer_url": "ftp://sso.example.com/"}, "must be an https:// or http:// URL"},
		"padded client":   {map[string]any{"client_id": " pbs"}, "must not begin or end with white space"},
		"both keys":       {map[string]any{"client_key": "a", "client_key_wo": "b", "client_key_wo_version": 1}, "cannot be specified when"},
		"version alone":   {map[string]any{"client_key_wo_version": 1}, "client_key_wo"},
		"bad scope":       {map[string]any{"scopes": []string{"email", "-x"}}, "must start with a letter"},
		"no scopes":       {map[string]any{"scopes": []string{}}, "set must contain at least 1 elements"},
		"acr with comma":  {map[string]any{"acr_values": []string{"a,b"}}, "must be non-empty, without white space"},
		"padded acr":      {map[string]any{"acr_values": []string{"gold\u00a0"}}, "must be non-empty, without white space"},
		"null acr":        {map[string]any{"acr_values": []any{"gold", nil}}, "null"},
		"null scope":      {map[string]any{"scopes": []any{"email", nil}}, "null"},
		"null audience":   {map[string]any{"audiences": []any{nil}}, "null"},
		"duplicate acr":   {map[string]any{"acr_values": []string{"a", "a"}}, "duplicate"},
		"long audience":   {map[string]any{"audiences": []string{strings.Repeat("a", 257)}}, "string length must be at most 256"},
		"prompt":          {map[string]any{"prompt": "select account"}, "must start with a letter"},
		"username claim":  {map[string]any{"username_claim": strings.Repeat("a", 65)}, "string length must be between 1 and 64"},
		"comment newline": {map[string]any{"comment": "a\nb"}, "must be a single line"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_realm_openid", openIDRealmConfig(t, h, tc.attrs)), tc.want)
		})
	}

	// A secret that fails validation is not repeated.
	diags := h.validateResource(t, "pbs_realm_openid", openIDRealmConfig(t, h, map[string]any{"client_key": "secret\n"}))
	requireProtocolErrorContaining(t, diags, "the value is not shown")
	for _, d := range diags {
		if strings.Contains(d.Detail, "secret") && !strings.Contains(d.Detail, "is a secret") {
			t.Errorf("diagnostic repeats the key: %s", d.Detail)
		}
	}

	// Creating a realm whose name PBS has, for a realm of any type, fails and
	// advises an import.
	realms.addRealm("authentik", "ldap", fakeProperties{"server1": "ldap.example.com"})
	config := openIDRealmConfig(t, h, nil)
	planned := h.plan(t, "pbs_realm_openid", nil, config)
	applied := h.apply(t, "pbs_realm_openid", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "import it")

	// The API's errors do not repeat the client key.
	fake.reply("POST /config/access/openid", http.StatusBadRequest, "parameter verification failed - 'client-key': value 'leaky-secret' is bad")
	config = openIDRealmConfig(t, h, map[string]any{"realm": "other", "client_key": "leaky-secret"})
	planned = h.plan(t, "pbs_realm_openid", nil, config)
	applied = h.apply(t, "pbs_realm_openid", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to create PBS OpenID realm")
	for _, d := range applied.Diagnostics {
		if strings.Contains(d.Detail, "leaky-secret") {
			t.Errorf("diagnostic repeats the key: %s", d.Detail)
		}
	}
}

// A realm replaced outside Terraform by one of another type leaves state,
// with a warning, and destroying the resource leaves that realm alone.
func TestOpenIDRealmResourceReplacedByAnotherType(t *testing.T) {
	h, _, realms := newRealmHarness(t)
	inst := h.create(t, "pbs_realm_openid", openIDRealmConfig(t, h, nil))

	realms.addRealm("authentik", "ldap", fakeProperties{"server1": "ldap.example.com"})
	resp := h.read(t, inst)
	requireProtocolWarningContaining(t, resp.Diagnostics, "not of type openid")
	if state := h.decodeResource(t, "pbs_realm_openid", resp.NewState); !state.IsNull() {
		t.Errorf("refresh kept the realm: %s", state)
	}

	destroyed := syncDestroyResponse(t, h, inst)
	requireProtocolWarningContaining(t, destroyed.Diagnostics, "so it was not deleted")
	if _, exists := realms.realm("authentik"); !exists {
		t.Error("destroy deleted the LDAP realm")
	}
}

// The delete sends the digest of its read, and reads again when another
// writer changed domains.cfg in between.
func TestOpenIDRealmResourceDeleteRetriesOnDigestConflict(t *testing.T) {
	h, fake, realms := newRealmHarness(t)
	inst := h.create(t, "pbs_realm_openid", openIDRealmConfig(t, h, nil))

	bumped := false
	fake.handle("DELETE /config/access/openid/authentik", func(w http.ResponseWriter, req *http.Request) {
		if !bumped {
			bumped = true
			realms.addRealm("other", "openid", fakeProperties{"issuer-url": testIssuerURL, "client-id": "x"})
		}
		realms.serveOpenIDRealm(w, req)
	})
	h.destroy(t, inst)
	if _, exists := realms.realm("authentik"); exists {
		t.Error("destroy left the realm")
	}
	if got := fake.count("DELETE /config/access/openid/authentik"); got != 2 {
		t.Errorf("DELETE was sent %d times, want 2", got)
	}
	if got := fake.lastCall(t, "DELETE /config/access/openid/authentik").query.Get("digest"); got == "" {
		t.Error("DELETE sent no digest")
	}
}

// audiences needs PBS 4.2.1.
func TestOpenIDRealmResourceNeedsPBS421ForAudiences(t *testing.T) {
	h, _, _ := newRealmHarness(t, `{"data":{"release":"0","repoid":"0123456789abcdef","version":"4.2"}}`)
	planned := h.plan(t, "pbs_realm_openid", nil, openIDRealmConfig(t, h, map[string]any{"audiences": []string{"x"}}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "needs PBS 4.2.1 or newer")
	planned = h.plan(t, "pbs_realm_openid", nil, openIDRealmConfig(t, h, nil))
	requireNoProtocolErrors(t, planned.Diagnostics)
}

func TestRealmsDataSource(t *testing.T) {
	h, _, realms := newRealmHarness(t)
	realms.addRealm("authentik", "openid", fakeProperties{"issuer-url": testIssuerURL, "client-id": "pbs",
		"comment": "SSO", "default": true})
	realms.addRealm("ad", "ad", fakeProperties{"server1": "dc.example.com"})

	state := h.readDataSource(t, "pbs_realms", h.dataSourceValue(t, "pbs_realms", nil))
	if got := listedStrings(t, state, "realms", "realm"); !slices.Equal(got, []string{"ad", "authentik", "pam", "pbs"}) {
		t.Errorf("realms = %v", got)
	}
	if got := listedStrings(t, state, "realms", "type"); !slices.Equal(got, []string{"ad", "openid", "pam", "pbs"}) {
		t.Errorf("types = %v", got)
	}
	if stringAt(t, state, "realms", 1, "comment") != "SSO" || !boolAt(t, state, "realms", 1, "default") ||
		boolAt(t, state, "realms", 2, "default") || !isNullAt(t, state, "realms", 0, "comment") {
		t.Errorf("state = %s", state)
	}
}

// Failed calls are errors that name the privilege they need; a realm whose
// read-back fails is still recorded, tainted after a create.
func TestOpenIDRealmResourceAPIErrors(t *testing.T) {
	h, fake, _ := newRealmHarness(t)
	const route = "GET /config/access/openid/authentik"
	config := openIDRealmConfig(t, h, nil)

	fake.reply(route, http.StatusForbidden, "permission check failed")
	planned := h.plan(t, "pbs_realm_openid", nil, config)
	applied := h.apply(t, "pbs_realm_openid", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "marked tainted")
	requireProtocolErrorContaining(t, applied.Diagnostics, "Sys.Audit on /access/domains")
	if state := h.decodeResource(t, "pbs_realm_openid", applied.NewState); stringAt(t, state, "id") != "authentik" {
		t.Errorf("state after a failed read-back = %s", state)
	}
	fake.handle(route, nil)
	inst := h.refresh(t, &resourceInstance{typeName: "pbs_realm_openid", state: h.decodeResource(t, "pbs_realm_openid", applied.NewState),
		identity: applied.NewIdentity})

	fake.reply(route, http.StatusInternalServerError, "unable to parse domains.cfg")
	requireProtocolErrorContaining(t, h.read(t, inst).Diagnostics, "Unable to read PBS OpenID realm")

	update := openIDRealmConfig(t, h, map[string]any{"comment": "SSO"})
	planned = h.plan(t, "pbs_realm_openid", inst, update)
	applied = h.apply(t, "pbs_realm_openid", inst, update, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "the change was recorded in state")
	fake.handle(route, nil)

	fake.reply("PUT /config/access/openid/authentik", http.StatusForbidden, "permission check failed")
	update = openIDRealmConfig(t, h, map[string]any{"comment": "Other"})
	planned = h.plan(t, "pbs_realm_openid", inst, update)
	applied = h.apply(t, "pbs_realm_openid", inst, update, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Realm.Allocate on /access/domains")

	fake.reply("DELETE /config/access/openid/authentik", http.StatusForbidden, "permission check failed")
	requireProtocolErrorContaining(t, syncDestroyResponse(t, h, inst).Diagnostics, "Unable to delete PBS OpenID realm")

	fake.reply("GET /access/domains", http.StatusInternalServerError, "unable to parse domains.cfg")
	resp := h.readDataSourceResponse(t, "pbs_realms", h.dataSourceValue(t, "pbs_realms", nil))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS realms")
}

// default = true on a create takes the flag from pam, and a flag taken away
// outside Terraform is drift the next apply puts back.
func TestOpenIDRealmResourceDefaultFlag(t *testing.T) {
	h, fake, realms := newRealmHarness(t)
	config := openIDRealmConfig(t, h, map[string]any{"default": true})
	inst := h.create(t, "pbs_realm_openid", config)
	if got := fake.lastCall(t, "POST /config/access/openid").form.Get("default"); got != "true" {
		t.Errorf("POST default = %q", got)
	}
	if realms.defaultRealm() != "authentik" || !boolAt(t, inst.state, "default") {
		t.Errorf("default realm = %q, state = %s", realms.defaultRealm(), inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	realms.addRealm("other", "openid", fakeProperties{"issuer-url": testIssuerURL, "client-id": "x", "default": true})
	inst = h.refresh(t, inst)
	if boolAt(t, inst.state, "default") {
		t.Errorf("state = %s after another realm took the flag", inst.state)
	}
	inst = h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /config/access/openid/authentik").form; len(got) != 1 || got.Get("default") != "true" {
		t.Errorf("PUT form = %v, want only default", got)
	}
	if realms.defaultRealm() != "authentik" {
		t.Errorf("default realm = %q", realms.defaultRealm())
	}
	requireNoPlannedChange(t, h, inst, config)
}

// An empty scope list PBS keeps asks for no scopes but openid, unlike no
// list at all: it reads as an empty set, and the default plans its deletion.
func TestOpenIDRealmResourceEmptyScopes(t *testing.T) {
	h, fake, realms := newRealmHarness(t)
	realms.addRealm("authentik", "openid", fakeProperties{"issuer-url": testIssuerURL, "client-id": "pbs", "scopes": ""})
	inst := h.importByID(t, "pbs_realm_openid", "authentik")
	if lengthAt(t, inst.state, "scopes") != 0 {
		t.Errorf("state = %s", inst.state)
	}
	config := openIDRealmConfig(t, h, nil)
	inst = h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /config/access/openid/authentik").form["delete"]; !slices.Equal(got, []string{"scopes"}) {
		t.Errorf("delete = %v", got)
	}
	requireNoPlannedChange(t, h, inst, config)
}

// A replacement creates the realm without a key the configuration leaves to
// PBS, and the plan says so.
func TestOpenIDRealmResourceWarnsWhenAReplacementDropsTheKey(t *testing.T) {
	h, _, realms := newRealmHarness(t)
	realms.addRealm("authentik", "openid", fakeProperties{"issuer-url": testIssuerURL, "client-id": "pbs",
		"client-key": "kept-by-pbs"})
	inst := h.importByID(t, "pbs_realm_openid", "authentik")

	planned := h.plan(t, "pbs_realm_openid", inst, openIDRealmConfig(t, h, map[string]any{"username_claim": "email"}))
	requireProtocolWarningContaining(t, planned.Diagnostics, "it is lost")
	for _, attrs := range []map[string]any{
		{"username_claim": "email", "client_key": "kept-by-pbs"},
		{"username_claim": "email", "client_key_wo": "kept-by-pbs", "client_key_wo_version": 1},
		{"comment": "no replacement"},
	} {
		planned = h.plan(t, "pbs_realm_openid", inst, openIDRealmConfig(t, h, attrs))
		requireNoProtocolErrors(t, planned.Diagnostics)
		for _, d := range planned.Diagnostics {
			t.Errorf("plan with %v: unexpected diagnostic %s", attrs, d.Summary)
		}
	}
}
