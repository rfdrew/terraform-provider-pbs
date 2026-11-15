package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// External Account Binding and force_destroy of pbs_acme_account, against
// the fake CA, which checks a binding as Pebble does.

// fakeEABKey returns a 32-byte HMAC key, which base64 pads, made from seed.
func fakeEABKey(seed string) []byte {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

// fakeEABKeyStd returns a 35-byte HMAC key whose standard base64 holds "+"
// and "/", so that PBS reads it as standard base64.
func fakeEABKeyStd(seed string) []byte {
	return append([]byte{0xfb, 0xff, 0xbf}, fakeEABKey(seed)...)
}

// eabConfig is accountConfig with a binding: kid, key and version, nil for
// none.
func eabConfig(t *testing.T, h *protocolHarness, kid, key, version any, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"tos_url": "https://ca.test/tos", "eab_kid": kid, "eab_hmac_key_wo": key, "eab_hmac_key_wo_version": version}
	for k, v := range attrs {
		config[k] = v
	}
	return accountConfig(t, h, config)
}

// replacedAttributes names the attributes a plan replaces the resource for.
func replacedAttributes(plan *tfprotov6.PlanResourceChangeResponse) []string {
	var names []string
	for _, p := range plan.RequiresReplace {
		for _, step := range p.Steps() {
			if name, ok := step.(tftypes.AttributeName); ok {
				names = append(names, string(name))
				break
			}
		}
	}
	slices.Sort(names)
	return names
}

// requireReplacedFor fails the test unless plan replaces the resource for
// exactly the attributes want.
func requireReplacedFor(t *testing.T, plan *tfprotov6.PlanResourceChangeResponse, want ...string) {
	t.Helper()
	requireNoProtocolErrors(t, plan.Diagnostics)
	slices.Sort(want)
	if got := replacedAttributes(plan); !slices.Equal(got, want) {
		t.Fatalf("the plan replaces the resource for %q, want %q", got, want)
	}
}

// replaceAccount applies a plan that replaces inst, as Terraform does: it
// plans again without a prior state, destroys inst and creates the new one.
func replaceAccount(t *testing.T, h *protocolHarness, inst *resourceInstance, config tftypes.Value) *resourceInstance {
	t.Helper()
	requireNoProtocolErrors(t, h.plan(t, inst.typeName, nil, config).Diagnostics)
	h.destroy(t, inst)
	return h.create(t, inst.typeName, config)
}

// accountWrites counts the calls the fake received that write accounts:
// registering, updating and deactivating them.
func accountWrites(fake *fakePBS) int {
	n := 0
	for _, route := range fake.routes() {
		if strings.HasPrefix(route, "POST /config/acme/account") || strings.HasPrefix(route, "PUT /config/acme/account/") ||
			strings.HasPrefix(route, "DELETE /config/acme/account/") {
			n++
		}
	}
	return n
}

func TestACMEAccountResourceEABLifecycle(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	key1, key2 := fakeEABKey("tfacc-eab-1"), fakeEABKeyStd("tfacc-eab-2")
	acme.eabKeys["kid-1"], acme.eabKeys["kid-2"] = key1, key2

	// The key as a CA hands it out, padded, and as file() reads it, with a
	// line break: PBS gets it without either.
	padded := base64.URLEncoding.EncodeToString(key1)
	if !strings.HasSuffix(padded, "=") {
		t.Fatalf("the sample key %q is not padded", padded)
	}
	config := eabConfig(t, h, "kid-1", padded+"\n", 1, nil)
	inst := h.create(t, "pbs_acme_account", config)
	registered := fake.lastCall(t, "POST /config/acme/account")
	if registered.form.Get("eab_kid") != "kid-1" || registered.form.Get("eab_hmac_key") != base64.RawURLEncoding.EncodeToString(key1) {
		t.Fatalf("POST form = %v", registered.form)
	}
	if stringAt(t, inst.state, "eab_kid") != "kid-1" || int64At(t, inst.state, "eab_hmac_key_wo_version") != 1 ||
		!isNullAt(t, inst.state, "eab_hmac_key_wo") || boolAt(t, inst.state, "force_destroy") || stringAt(t, inst.state, "status") != "valid" {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)
	inst = h.refresh(t, inst)
	requireEmptyPlan(t, h, inst, config)

	// Another key under the same version goes unnoticed, as for any
	// write-only value.
	requireEmptyPlan(t, h, inst, eabConfig(t, h, "kid-1", base64.RawURLEncoding.EncodeToString(key2), 1, nil))

	// A new version registers a new account, after a warning that the old
	// one goes first.
	replan := h.plan(t, "pbs_acme_account", inst, eabConfig(t, h, "kid-1", padded, 2, nil))
	requireReplacedFor(t, replan, "eab_hmac_key_wo_version")
	requireProtocolWarningContaining(t, replan.Diagnostics, "deactivates it at")
	requireProtocolWarningContaining(t, replan.Diagnostics, "before PBS registers the new one")

	// A new key identifier too: here with a key in standard base64, holding
	// "+" and "/", which PBS reads as such.
	stdKey := base64.StdEncoding.EncodeToString(key2)
	if !strings.ContainsAny(stdKey, "+/") {
		t.Fatalf("the sample key %q holds neither + nor /", stdKey)
	}
	config = eabConfig(t, h, "kid-2", stdKey, 2, nil)
	replan = h.plan(t, "pbs_acme_account", inst, config)
	requireReplacedFor(t, replan, "eab_hmac_key_wo_version", "eab_kid")
	requireProtocolWarningContaining(t, replan.Diagnostics, "before PBS registers the new one")
	location := stringAt(t, inst.state, "location")
	inst = replaceAccount(t, h, inst, config)
	if got := fake.lastCall(t, "POST /config/acme/account").form; got.Get("eab_kid") != "kid-2" || got.Get("eab_hmac_key") != strings.TrimRight(stdKey, "=") {
		t.Fatalf("POST form = %v", got)
	}
	if stringAt(t, inst.state, "eab_kid") != "kid-2" || stringAt(t, inst.state, "location") == location || !slices.Equal(acme.deactivated, []string{"le"}) {
		t.Fatalf("state = %s after deactivating %v", inst.state, acme.deactivated)
	}
	requireEmptyPlan(t, h, inst, config)

	// Leaving the binding out once the account is registered is recorded,
	// without a call: PBS has nothing to change.
	writes := accountWrites(fake)
	config = accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos"})
	replan = h.plan(t, "pbs_acme_account", inst, config)
	requireReplacedFor(t, replan)
	if len(replan.Diagnostics) > 0 {
		t.Fatalf("diagnostics %v", replan.Diagnostics)
	}
	inst = h.update(t, inst, config)
	if accountWrites(fake) != writes || !isNullAt(t, inst.state, "eab_kid") || !isNullAt(t, inst.state, "eab_hmac_key_wo_version") {
		t.Fatalf("after %d writes, state = %s", accountWrites(fake)-writes, inst.state)
	}
	requireEmptyPlan(t, h, inst, config)

	// Setting it again on the registered account is recorded as well, with
	// a warning that nothing changes at the CA; the version alone is only
	// recorded too.
	config = accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos", "eab_kid": "kid-2"})
	replan = h.plan(t, "pbs_acme_account", inst, config)
	requireReplacedFor(t, replan)
	requireProtocolWarningContaining(t, replan.Diagnostics, "External Account Binding only recorded")
	inst = h.update(t, inst, config)
	config = eabConfig(t, h, "kid-2", stdKey, 3, nil)
	replan = h.plan(t, "pbs_acme_account", inst, config)
	requireReplacedFor(t, replan)
	inst = h.update(t, inst, config)
	if accountWrites(fake) != writes || stringAt(t, inst.state, "eab_kid") != "kid-2" || int64At(t, inst.state, "eab_hmac_key_wo_version") != 3 {
		t.Fatalf("after %d writes, state = %s", accountWrites(fake)-writes, inst.state)
	}

	// A contact update makes PBS hold the CA's answer, which Pebble gives
	// without the binding: the configured eab_kid stays.
	config = eabConfig(t, h, "kid-2", stdKey, 3, map[string]any{"contact": "new@example.org"})
	inst = h.update(t, inst, config)
	if props, _ := acme.account("le"); props["eab_kid"] != nil {
		t.Fatalf("the fake CA kept the binding after an update: %v", props)
	}
	inst = h.refresh(t, inst)
	if stringAt(t, inst.state, "eab_kid") != "kid-2" {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)
}

func TestACMEAccountResourceEABValidation(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	key := base64.RawURLEncoding.EncodeToString(fakeEABKey("tfacc-eab-1"))
	acme.eabKeys["kid-1"] = fakeEABKey("tfacc-eab-1")

	// A binding given half cannot register an account.
	planned := h.plan(t, "pbs_acme_account", nil, eabConfig(t, h, "kid-1", nil, nil, nil))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Missing External Account Binding key")
	requireProtocolErrorContaining(t, planned.Diagnostics, "Set eab_hmac_key_wo, with eab_hmac_key_wo_version, or remove eab_kid")
	planned = h.plan(t, "pbs_acme_account", nil, eabConfig(t, h, nil, key, 1, nil))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Missing External Account Binding key identifier")
	// A key still unknown is no error.
	planned = h.plan(t, "pbs_acme_account", nil, eabConfig(t, h, "kid-1", tfUnknown, 1, nil))
	requireNoProtocolErrors(t, planned.Diagnostics)
	// Nor is a key identifier still unknown: it may turn out null.
	planned = h.plan(t, "pbs_acme_account", nil, eabConfig(t, h, tfUnknown, nil, nil, nil))
	requireNoProtocolErrors(t, planned.Diagnostics)

	// An account registered without a binding: a key identifier alone is
	// only recorded, but on a replacement, the plan without a prior state
	// refuses it.
	inst := h.create(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos"}))
	alone := eabConfig(t, h, "kid-1", nil, nil, nil)
	planned = h.plan(t, "pbs_acme_account", inst, alone)
	requireReplacedFor(t, planned)
	requireProtocolWarningContaining(t, planned.Diagnostics, "only recorded")
	moved := eabConfig(t, h, "kid-1", nil, nil, map[string]any{"directory": pbsclient.ACMEStagingDirectory})
	planned = h.plan(t, "pbs_acme_account", inst, moved)
	requireReplacedFor(t, planned, "directory")
	requireProtocolWarningContaining(t, planned.Diagnostics, "deactivates it at")
	requireProtocolErrorContaining(t, h.plan(t, "pbs_acme_account", nil, moved).Diagnostics, "Missing External Account Binding key")

	// The key: what PBS decodes, padding and white space around it aside.
	for _, good := range []string{
		base64.StdEncoding.EncodeToString(fakeEABKeyStd("x")),
		base64.RawStdEncoding.EncodeToString(fakeEABKeyStd("x")),
		base64.URLEncoding.EncodeToString(fakeEABKey("x")),
		" " + key + "\n",
	} {
		requireNoProtocolErrors(t, h.validateResource(t, "pbs_acme_account", eabConfig(t, h, "kid-1", good, 1, nil)))
	}
	for _, bad := range []string{"", "====", "ab+c-d", key[:10] + "\n" + key[10:], "not base64!", "QR"} {
		diags := h.validateResource(t, "pbs_acme_account", eabConfig(t, h, "kid-1", bad, 1, nil))
		requireProtocolErrorContaining(t, diags, "must be the HMAC key as the CA gave it")
		for _, d := range diags {
			if bad != "" && strings.Contains(d.Detail, bad) {
				t.Errorf("the error shows the key %q: %s", bad, d.Detail)
			}
		}
	}
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_acme_account", eabConfig(t, h, "kid-1", tfUnknown, 1, nil)))
	// The key and its version go together.
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_account", eabConfig(t, h, "kid-1", key, nil, nil)), "eab_hmac_key_wo_version")
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acme_account", eabConfig(t, h, "kid-1", nil, 1, nil)), "eab_hmac_key_wo")

	for _, bad := range []string{"", " kid-1", "kid-1\n"} {
		if diags := h.validateResource(t, "pbs_acme_account", eabConfig(t, h, bad, key, 1, nil)); len(diags) == 0 {
			t.Errorf("eab_kid %q passed validation", bad)
		}
	}
}

func TestACMEAccountResourceEABErrors(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	key := fakeEABKey("tfacc-eab-1")
	acme.eabKeys["kid-1"] = key
	encoded := base64.RawURLEncoding.EncodeToString(key)
	register := func(config tftypes.Value) *tfprotov6.ApplyResourceChangeResponse {
		t.Helper()
		planned := h.plan(t, "pbs_acme_account", nil, config)
		requireNoProtocolErrors(t, planned.Diagnostics)
		return h.apply(t, "pbs_acme_account", nil, config, planned)
	}

	// A CA that requires a binding: the error says how to give one.
	acme.eabRequired = true
	applied := register(accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos"}))
	requireProtocolErrorContaining(t, applied.Diagnostics, "This CA requires External Account Binding: set eab_kid and eab_hmac_key_wo")
	requireProtocolErrorContaining(t, applied.Diagnostics, "externalAccountRequired")

	// A binding the CA refuses: an unknown key identifier, a wrong key.
	applied = register(eabConfig(t, h, "kid-unknown", encoded, 1, nil))
	requireProtocolErrorContaining(t, applied.Diagnostics, "The CA refused the External Account Binding: check eab_kid and eab_hmac_key_wo")
	requireProtocolErrorContaining(t, applied.Diagnostics, "not known to the ACME server")
	applied = register(eabConfig(t, h, "kid-1", base64.RawURLEncoding.EncodeToString(fakeEABKey("wrong")), 1, nil))
	requireProtocolErrorContaining(t, applied.Diagnostics, "The CA refused the External Account Binding")
	requireProtocolErrorContaining(t, applied.Diagnostics, "verification error")
	if _, exists := acme.account("le"); exists {
		t.Fatal("a refused binding registered the account")
	}

	// The key never shows in an error.
	acme.registerFailures = []string{"urn:ietf:params:acme:error:malformed: external account binding key " + encoded + " is not valid"}
	applied = register(eabConfig(t, h, "kid-1", encoded, 1, nil))
	requireProtocolErrorContaining(t, applied.Diagnostics, "The CA refused the External Account Binding")
	for _, d := range applied.Diagnostics {
		if strings.Contains(d.Summary+d.Detail, encoded) {
			t.Fatalf("the error shows the key: %s", d.Detail)
		}
	}

	// The CA refused the account key PBS generated: the next attempt, with
	// a new key, sends the binding again.
	posts := fake.count("POST /config/acme/account")
	acme.registerFailures = []string{fakeKeyRefused}
	inst := h.create(t, "pbs_acme_account", eabConfig(t, h, "kid-1", encoded, 1, nil))
	if got := fake.count("POST /config/acme/account") - posts; got != 2 {
		t.Fatalf("%d registrations, want 2", got)
	}
	if got := fake.lastCall(t, "POST /config/acme/account").form; got.Get("eab_kid") != "kid-1" || got.Get("eab_hmac_key") != encoded {
		t.Fatalf("POST form = %v", got)
	}
	if stringAt(t, inst.state, "eab_kid") != "kid-1" {
		t.Fatalf("state = %s", inst.state)
	}
}

func TestACMEAccountResourceImportEAB(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	echoed := fakeACMEAccountProps("https://ca.test/dir", "https://ca.test/tos", 1, "ops@example.org")
	echoed["eab_kid"] = "kid-1"
	acme.addAccount("echoed", echoed)
	acme.addAccount("plain", fakeACMEAccountProps("https://ca.test/dir", "https://ca.test/tos", 2, "ops@example.org"))
	acme.addAccount("odd", fakeACMEAccountProps("https://ca.test/dir", "https://ca.test/tos", 3, "ops@example.org"))
	fake.handle("GET /config/acme/account/odd", func(w http.ResponseWriter, _ *http.Request) {
		writeData(w, map[string]any{"directory": "https://ca.test/dir", "location": "https://ca.test/acme/acct/3",
			"account": map[string]any{"status": "valid", "externalAccountBinding": map[string]any{"protected": "not a header"}}}, "")
	})

	// The binding the CA echoed names the key identifier; an account without
	// one, or with one that cannot be read, has none.
	inst := h.importByID(t, "pbs_acme_account", "echoed")
	if stringAt(t, inst.state, "eab_kid") != "kid-1" || !isNullAt(t, inst.state, "eab_hmac_key_wo_version") || boolAt(t, inst.state, "force_destroy") {
		t.Fatalf("imported state = %s", inst.state)
	}
	for _, name := range []string{"plain", "odd"} {
		if imported := h.importByID(t, "pbs_acme_account", name); !isNullAt(t, imported.state, "eab_kid") {
			t.Fatalf("imported %s: %s", name, imported.state)
		}
	}

	// The configuration of the import plans nothing; adding the key and a
	// version where state has none is only recorded, without a call.
	base := map[string]any{"name": "echoed", "directory": "https://ca.test/dir"}
	config := eabConfig(t, h, "kid-1", nil, nil, base)
	requireEmptyPlan(t, h, inst, config)
	writes := accountWrites(fake)
	config = eabConfig(t, h, "kid-1", base64.RawURLEncoding.EncodeToString(fakeEABKey("k")), 1, base)
	planned := h.plan(t, "pbs_acme_account", inst, config)
	requireReplacedFor(t, planned)
	if len(planned.Diagnostics) > 0 {
		t.Fatalf("diagnostics %v", planned.Diagnostics)
	}
	inst = h.update(t, inst, config)
	if accountWrites(fake) != writes || int64At(t, inst.state, "eab_hmac_key_wo_version") != 1 {
		t.Fatalf("after %d writes, state = %s", accountWrites(fake)-writes, inst.state)
	}

	// An account whose binding the CA dropped since, after a contact update,
	// or never echoed: the key identifier set in the configuration is only
	// recorded, with a warning.
	acme.eabNotEchoed = true
	acme.eabKeys["kid-2"] = fakeEABKey("tfacc-eab-2")
	h.create(t, "pbs_acme_account", eabConfig(t, h, "kid-2", base64.RawURLEncoding.EncodeToString(fakeEABKey("tfacc-eab-2")), 1, map[string]any{"name": "silent"}))
	if props, _ := acme.account("silent"); props["eab_kid"] != nil {
		t.Fatalf("the fake CA echoed the binding: %v", props)
	}
	imported := h.importByID(t, "pbs_acme_account", "silent")
	if !isNullAt(t, imported.state, "eab_kid") {
		t.Fatalf("imported state = %s", imported.state)
	}
	config = eabConfig(t, h, "kid-2", nil, nil, map[string]any{"name": "silent"})
	planned = h.plan(t, "pbs_acme_account", imported, config)
	requireReplacedFor(t, planned)
	requireProtocolWarningContaining(t, planned.Diagnostics, "only recorded")
	writes = accountWrites(fake)
	imported = h.update(t, imported, config)
	if accountWrites(fake) != writes || stringAt(t, imported.state, "eab_kid") != "kid-2" {
		t.Fatalf("after %d writes, state = %s", accountWrites(fake)-writes, imported.state)
	}
	requireEmptyPlan(t, h, imported, config)
}

// fakeAccountGone is how PBS reports Pebble's refusal of a request of an
// account it does not know.
const fakeAccountGone = "urn:ietf:params:acme:error:accountDoesNotExist: Account https://ca.test/acme/acct/1 not found."

func TestACMEAccountResourceForceDestroy(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	null := tftypes.NewValue(h.resourceType(t, "pbs_acme_account"), nil)
	config := accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos"})
	inst := h.create(t, "pbs_acme_account", config)
	if boolAt(t, inst.state, "force_destroy") {
		t.Fatalf("state = %s", inst.state)
	}

	// The CA no longer knows the account: destroying fails, says that
	// nothing is left at the CA, and how to go on; PBS keeps the account.
	acme.refuseDeactivation = fakeAccountGone
	destroyed := h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "PBS could not deactivate the account")
	var detail string
	for _, d := range destroyed.Diagnostics {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			detail = d.Detail
		}
	}
	gone, advice, reason := strings.Index(detail, "nothing is left behind at the CA"), strings.Index(detail, "set force_destroy = true"),
		strings.Index(detail, "accountDoesNotExist: Account")
	if gone < 0 || advice < gone || reason < advice || !strings.Contains(detail, "--force") {
		t.Fatalf("detail %q: want the CA's state, then the advice, then the error", detail)
	}
	if _, exists := acme.account("le"); !exists || len(acme.deactivated) != 0 {
		t.Fatalf("the account went: %v", acme.deactivated)
	}
	if query := fake.lastCall(t, "DELETE /config/acme/account/le").query; query.Has("force") {
		t.Fatalf("DELETE query = %v, want no force", query)
	}

	// force_destroy is recorded without a call.
	writes := accountWrites(fake)
	config = accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos", "force_destroy": true})
	inst = h.update(t, inst, config)
	if accountWrites(fake) != writes || !boolAt(t, inst.state, "force_destroy") {
		t.Fatalf("after %d writes, state = %s", accountWrites(fake)-writes, inst.state)
	}
	requireEmptyPlan(t, h, inst, config)

	// Destroying now removes the account, with a warning that names the CA's
	// answer and what PBS keeps.
	planned := h.plan(t, "pbs_acme_account", inst, null)
	requireProtocolWarningContaining(t, planned.Diagnostics, "force_destroy is set in state")
	destroyed = h.apply(t, "pbs_acme_account", inst, null, planned)
	requireNoProtocolErrors(t, destroyed.Diagnostics)
	requireProtocolWarningContaining(t, destroyed.Diagnostics, "removed although the CA refused")
	requireProtocolWarningContaining(t, destroyed.Diagnostics, fakeAccountGone)
	requireProtocolWarningContaining(t, destroyed.Diagnostics, "/etc/proxmox-backup/acme/accounts/_deactivated_le_<n>")
	if fake.lastCall(t, "DELETE /config/acme/account/le").query.Get("force") != "true" || !slices.Equal(acme.deactivated, []string{"le"}) {
		t.Fatalf("deactivated %v", acme.deactivated)
	}
	// Gone from PBS, destroying again succeeds, force or not.
	h.destroy(t, inst)

	// A CA that deactivates the account: no warning, with force_destroy too.
	acme.refuseDeactivation = ""
	inst = h.create(t, "pbs_acme_account", config)
	destroyed = h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	for _, d := range destroyed.Diagnostics {
		t.Errorf("destroying warned: %s: %s", d.Summary, d.Detail)
	}

	// Another refusal, without force_destroy: the advice, without saying
	// that nothing is left at the CA.
	acme.refuseDeactivation = "urn:ietf:params:acme:error:serverInternal: the database is down"
	inst = h.create(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"name": "other", "tos_url": "https://ca.test/tos"}))
	destroyed = h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "set force_destroy = true")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "the database is down")
	for _, d := range destroyed.Diagnostics {
		if strings.Contains(d.Detail, "nothing is left behind") {
			t.Fatalf("detail %q says the CA forgot the account", d.Detail)
		}
	}

	// A CA's refusal that says "does not exist" is no missing account.
	acme.refuseDeactivation = "urn:ietf:params:acme:error:accountDoesNotExist: account does not exist"
	destroyed = h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "PBS could not deactivate the account")
	if _, exists := acme.account("other"); !exists {
		t.Fatal("the account went")
	}
}

// requireNoDetail fails when a diagnostic's detail says one of wrong.
func requireNoDetail(t *testing.T, diags []*tfprotov6.Diagnostic, wrong ...string) {
	t.Helper()
	for _, d := range diags {
		for _, w := range wrong {
			if strings.Contains(d.Detail, w) {
				t.Fatalf("detail %q says %q", d.Detail, w)
			}
		}
	}
}

// A deactivation that fails on PBS's own file of the account, after the
// CA's answer, points to the file. Without force, the CA has deactivated
// the account, and destroying again needs force_destroy; with it,
// force_destroy cannot get past the failure.
func TestACMEAccountResourceDestroyFileFailure(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	null := tftypes.NewValue(h.resourceType(t, "pbs_acme_account"), nil)
	inst := h.create(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos"}))
	requireKept := func() {
		t.Helper()
		if _, exists := acme.account("le"); !exists || len(acme.deactivated) != 0 {
			t.Fatalf("the account went: %v", acme.deactivated)
		}
	}

	// The CA deactivates the account; PBS then finds no free name for its
	// file, and keeps it.
	acme.renameFailure = fakeNoFreeSlot("le")
	destroyed := h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "The CA has deactivated the account, but PBS could not record that")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "Remove old _deactivated_le_<n> files")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "then set force_destroy = true")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, fakeNoFreeSlot("le"))
	requireNoDetail(t, destroyed.Diagnostics, "does not get past", "could not deactivate the account at", "nothing is left behind")
	requireKept()
	if query := fake.lastCall(t, "DELETE /config/acme/account/le").query; query.Has("force") {
		t.Fatalf("DELETE query = %v, want no force", query)
	}
	inst = h.refresh(t, inst)
	if status := stringAt(t, inst.state, "status"); status != "deactivated" {
		t.Fatalf("status = %q, want the CA's deactivation", status)
	}

	// With force_destroy, PBS passes over the CA's refusal of the account it
	// deactivated, and fails the same way.
	inst = h.update(t, inst, accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos", "force_destroy": true}))
	acme.refuseDeactivation = "urn:ietf:params:acme:error:unauthorized: account is deactivated"
	destroyed = h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "PBS failed on its own copy of the account")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "force_destroy does not get past this")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "Remove old _deactivated_le_<n> files")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, fakeNoFreeSlot("le"))
	requireNoDetail(t, destroyed.Diagnostics, "set force_destroy = true", "could not deactivate the account at", "nothing is left behind")
	requireKept()
	if fake.lastCall(t, "DELETE /config/acme/account/le").query.Get("force") != "true" {
		t.Fatal("DELETE without force")
	}

	// Once old files are removed, destroying removes the account.
	acme.renameFailure = ""
	destroyed = h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	requireNoProtocolErrors(t, destroyed.Diagnostics)
	requireProtocolWarningContaining(t, destroyed.Diagnostics, "account is deactivated")
	if !slices.Equal(acme.deactivated, []string{"le"}) {
		t.Fatalf("deactivated %v", acme.deactivated)
	}
}

// A deactivation the CA accepts, but whose answer PBS cannot save, as on a
// full file system: PBS keeps the account, with the status it had, and the
// error says that the CA has deactivated it. With force_destroy, as the
// error advises, PBS passes over the CA's refusal of the deactivated
// account, and destroying succeeds with a warning.
func TestACMEAccountResourceDestroySaveFailure(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	null := tftypes.NewValue(h.resourceType(t, "pbs_acme_account"), nil)
	inst := h.create(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos"}))

	acme.saveFailure = "write failed: No space left on device"
	destroyed := h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "The CA has deactivated the account, but PBS could not record that")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "Free space on the file system of /etc/proxmox-backup/acme/accounts")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "then set force_destroy = true")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, acme.saveFailure)
	requireNoDetail(t, destroyed.Diagnostics, "does not get past", "could not deactivate the account at")
	if _, exists := acme.account("le"); !exists || len(acme.deactivated) != 0 {
		t.Fatalf("the account went: %v", acme.deactivated)
	}
	inst = h.refresh(t, inst)
	if status := stringAt(t, inst.state, "status"); status != "valid" {
		t.Fatalf("status = %q, want the one PBS kept", status)
	}

	inst = h.update(t, inst, accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos", "force_destroy": true}))
	acme.saveFailure = ""
	acme.refuseDeactivation = "urn:ietf:params:acme:error:unauthorized: account is deactivated"
	destroyed = h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	requireNoProtocolErrors(t, destroyed.Diagnostics)
	requireProtocolWarningContaining(t, destroyed.Diagnostics, "removed although the CA refused")
	requireProtocolWarningContaining(t, destroyed.Diagnostics, "account is deactivated")
	if fake.lastCall(t, "DELETE /config/acme/account/le").query.Get("force") != "true" || !slices.Equal(acme.deactivated, []string{"le"}) {
		t.Fatalf("deactivated %v", acme.deactivated)
	}
}

// The advice on a failed deactivation follows where it failed: at the CA;
// reading PBS's own file of the account, before PBS asks the CA, which
// force cannot get past; or recording the CA's answer in that file, after
// the CA has deactivated the account, which needs force to destroy again
// unless force was set already, and which force cannot get past then.
func TestACMEAccountDeactivationErrorDetail(t *testing.T) {
	plain := acmeAccountModel{Name: types.StringValue("le"), Directory: types.StringValue("https://ca.test/dir"), ForceDestroy: types.BoolValue(false)}
	forced := plain
	forced.ForceDestroy = types.BoolValue(true)
	const (
		read     = "PBS could not read its own copy of the account, /etc/proxmox-backup/acme/accounts/le"
		recorded = "The CA has deactivated the account, but PBS could not record that"
		file     = "PBS failed on its own copy of the account"
		noForce  = "force_destroy does not get past this"
		atCA     = "PBS could not deactivate the account at https://ca.test/dir"
		advice   = "set force_destroy = true"
		forgets  = "nothing is left behind at the CA"
		slots    = "Remove old _deactivated_le_<n> files"
		space    = "Free space on the file system"
		readOnly = "writable again"
		other    = "Fix on PBS what the error names"
	)
	for _, tc := range []struct {
		name  string
		state acmeAccountModel
		exit  string
		want  []string
	}{
		{"CA refusal", plain, "urn:ietf:params:acme:error:serverInternal: the database is down", []string{atCA, advice}},
		{"CA refusal that mentions a write", plain, "urn:ietf:params:acme:error:serverInternal: write failed: No space left on device", []string{atCA, advice}},
		{"CA forgot the account", plain, fakeAccountGone, []string{atCA, forgets, advice}},
		// Before PBS asks the CA, with force or without.
		{"parse, PBS 4.2", plain, `failed to parse acme account from "/etc/proxmox-backup/acme/accounts/le" - EOF while parsing a value at line 1 column 0`, []string{read, noForce}},
		{"parse, PBS 4.0", plain, `failed to parse acme account from '/etc/proxmox-backup/acme/accounts/le' - EOF while parsing a value at line 1 column 0`, []string{read, noForce}},
		{"parse, forced", forced, `failed to parse acme account from "/etc/proxmox-backup/acme/accounts/le" - EOF while parsing a value at line 1 column 0`, []string{read, noForce}},
		{"load", plain, `failed to load acme account from "/etc/proxmox-backup/acme/accounts/le" - EACCES: Permission denied`, []string{read, noForce}},
		// After the CA deactivated the account, without force.
		{"no free slot", plain, fakeNoFreeSlot("le"), []string{recorded, slots, advice}},
		{"rename", plain, `failed to move account path "/etc/proxmox-backup/acme/accounts/le" to "/etc/proxmox-backup/acme/accounts/_deactivated_le_0" - EROFS: Read-only file system`, []string{recorded, readOnly, advice}},
		{"serialize", plain, `failed to serialize acme account to "/etc/proxmox-backup/acme/accounts/le": key must be a string`, []string{recorded, other, advice}},
		{"mkstemp", plain, `mkstemp "/etc/proxmox-backup/acme/accounts/le.tmp_XXXXXX" failed: EROFS: Read-only file system`, []string{recorded, readOnly, advice}},
		{"fchown", plain, `fchown "/etc/proxmox-backup/acme/accounts/le.tmp_a1B2c3" failed: EPERM: Operation not permitted`, []string{recorded, other, advice}},
		{"write", plain, "write failed: No space left on device (os error 28)", []string{recorded, space, advice}},
		{"fsync", plain, "fsync failed: EIO: I/O error", []string{recorded, other, advice}},
		{"atomic rename", plain, `Atomic rename failed for file "/etc/proxmox-backup/acme/accounts/le" - EIO: I/O error`, []string{recorded, other, advice}},
		{"fsync of the directory", plain, `fsync of directory "/etc/proxmox-backup/acme/accounts" failed - EIO: I/O error`, []string{recorded, other, advice}},
		// With force, past the CA's answer.
		{"no free slot, forced", forced, fakeNoFreeSlot("le"), []string{file, noForce, slots}},
		{"write, forced", forced, "write failed: No space left on device (os error 28)", []string{file, noForce, space}},
		{"mkstemp, forced", forced, `mkstemp "/etc/proxmox-backup/acme/accounts/le.tmp_XXXXXX" failed: EROFS: Read-only file system`, []string{file, noForce, readOnly}},
		{"forced, another failure", forced, "something else", []string{file, noForce, other}},
	} {
		detail := acmeDeactivationErrorDetail(nil, tc.state, &pbsclient.TaskError{ExitStatus: tc.exit})
		for _, hint := range []string{read, recorded, file, noForce, atCA, advice, forgets, slots, space, readOnly, other} {
			if got := strings.Contains(detail, hint); got != slices.Contains(tc.want, hint) {
				t.Errorf("%s: detail %q, hint %q: %v", tc.name, detail, hint, got)
			}
		}
		if !strings.Contains(detail, tc.exit) {
			t.Errorf("%s: detail %q leaves out the task's error", tc.name, detail)
		}
	}
}

// The advice on a failed registration follows the CA's answer and whether
// the registration carried a binding.
func TestACMEAccountErrorDetailEAB(t *testing.T) {
	withKid := acmeAccountModel{Directory: types.StringValue("https://ca.test/dir"), ToSURL: types.StringValue("https://ca.test/tos"), EABKid: types.StringValue("kid-1")}
	withoutKid := withKid
	withoutKid.EABKid = types.StringNull()
	const (
		required = "requires External Account Binding: set eab_kid"
		refused  = "refused the External Account Binding"
		decoding = "could not decode eab_hmac_key_wo"
	)
	for _, tc := range []struct {
		name string
		plan acmeAccountModel
		exit string
		want string
	}{
		{"required", withoutKid, fakeEABRequired, required},
		{"required, with a binding", withKid, fakeEABRequired, ""},
		{"unknown kid", withKid, fakeEABUnknownKid, refused},
		{"wrong key", withKid, fakeEABBadMAC, refused},
		{"unauthorized without a binding", withoutKid, "urn:ietf:params:acme:error:unauthorized: account is not valid", ""},
		{"malformed binding", withKid, `urn:ietf:params:acme:error:malformed: the "kid" field is missing from the external account binding`, refused},
		{"another malformed request", withKid, "urn:ietf:params:acme:error:malformed: contact email has invalid domain", ""},
		{"padding", withKid, fakeBase64Padding, decoding},
		{"symbol", withKid, fakeBase64Other, decoding},
		{"symbol without a binding", withoutKid, fakeBase64Other, ""},
		{"the base64 crate's own text", withKid, "Invalid symbol 10, offset 12.", ""},
		{"a CA's answer about base64", withKid, "urn:ietf:params:acme:error:malformed: illegal base64 data at input byte 4", ""},
	} {
		detail := acmeAccountErrorDetail(nil, tc.plan, true, &pbsclient.TaskError{ExitStatus: tc.exit})
		for _, hint := range []string{required, refused, decoding} {
			if got := strings.Contains(detail, hint); got != (hint == tc.want) {
				t.Errorf("%s: detail %q, hint %q: %v", tc.name, detail, hint, got)
			}
		}
		if !strings.Contains(detail, tc.exit) {
			t.Errorf("%s: detail %q leaves out the task's error", tc.name, detail)
		}
	}
}
