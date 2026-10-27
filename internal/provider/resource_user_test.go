package provider

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestAccessResourceSchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, &userResource{})
	requireValidResourceSchema(t, &apiTokenResource{})
	requireValidResourceSchema(t, &aclResource{})
}

// newUserHarness is a fake PBS with the access API and a provider signed in
// to it, with the API token unless opts say otherwise.
func newUserHarness(t *testing.T, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeAccess) {
	t.Helper()
	fake := newFakePBS()
	access := newFakeAccess(fake)
	return newProtocolHarness(t, fake, opts...), fake, access
}

func TestUserResourceLifecycle(t *testing.T) {
	h, fake, access := newUserHarness(t)
	access.addACL(pbsclient.ACLEntry{Path: "/", UGID: "bob@pbs", UGIDType: "user", RoleID: "Audit"})

	config := h.resourceValue(t, "pbs_user", map[string]any{
		"userid":              "alice@pbs",
		"comment":             "Backups",
		"firstname":           "Alice",
		"email":               "alice@example.com",
		"password_wo":         "first-password",
		"password_wo_version": 1,
	})
	inst := h.create(t, "pbs_user", config)

	created := fake.lastCall(t, "POST /access/users")
	if got := created.form.Get("password"); got != "first-password" {
		t.Errorf("POST password = %q, want the configured one", got)
	}
	for _, name := range []string{"enable", "expire", "lastname"} {
		if _, sent := created.form[name]; sent {
			t.Errorf("POST sent %s, which is at PBS's default: %v", name, created.form)
		}
	}
	if got := access.password("alice@pbs"); got != "first-password" {
		t.Errorf("stored password = %q", got)
	}
	if got := stringAt(t, inst.state, "id"); got != "alice@pbs" {
		t.Errorf("id = %q", got)
	}
	if !boolAt(t, inst.state, "enable") || int64At(t, inst.state, "expire") != 0 || !isNullAt(t, inst.state, "lastname") {
		t.Errorf("state = %s, want PBS's defaults for what is left out", inst.state)
	}
	if !isNullAt(t, inst.state, "password_wo") || int64At(t, inst.state, "password_wo_version") != 1 {
		t.Errorf("state = %s, want no password and its version", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_user", inst.identity), "userid"); got != "alice@pbs" {
		t.Errorf("identity userid = %q", got)
	}

	// A plan against the unchanged configuration changes nothing.
	replan := h.plan(t, "pbs_user", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_user", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	// Dropping firstname and email deletes them, changing comment sends it,
	// and an expiry is set; the password is not sent again.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_user", map[string]any{
		"userid":              "alice@pbs",
		"comment":             "Backup operator",
		"expire":              4102444800,
		"password_wo":         "first-password",
		"password_wo_version": 1,
	}))
	updated := fake.lastCall(t, "PUT /access/users/alice@pbs")
	if got := strings.Join(updated.form["delete"], ","); got != "email,firstname" {
		t.Errorf("delete = %q, want email,firstname", got)
	}
	if updated.form.Get("comment") != "Backup operator" || updated.form.Get("expire") != "4102444800" {
		t.Errorf("PUT form = %v", updated.form)
	}
	if _, sent := updated.form["password"]; sent || fake.count("PUT /access/password") != 0 {
		t.Error("an unchanged password_wo_version sent the password again")
	}
	if !isNullAt(t, inst.state, "firstname") || int64At(t, inst.state, "expire") != 4102444800 {
		t.Errorf("state after update = %s", inst.state)
	}

	// Leaving expire out resets it with 0, which PBS cannot delete.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_user", map[string]any{"userid": "alice@pbs", "comment": "Backup operator"}))
	if got := fake.lastCall(t, "PUT /access/users/alice@pbs").form; got.Get("expire") != "0" || len(got["delete"]) != 0 {
		t.Errorf("PUT form = %v, want expire=0 and nothing deleted", got)
	}
	if !isNullAt(t, inst.state, "password_wo_version") {
		t.Errorf("password_wo_version = %s, want null once removed", valueAt(t, inst.state, "password_wo_version"))
	}
	if got := access.password("alice@pbs"); got != "first-password" {
		t.Errorf("removing password_wo changed the password to %q", got)
	}

	// Destroying removes the user's own ACL entries, which PBS would keep,
	// and nobody else's.
	access.addACL(pbsclient.ACLEntry{Path: "/datastore/store1", UGID: "alice@pbs", UGIDType: "user", RoleID: "DatastoreBackup"})
	access.addACL(pbsclient.ACLEntry{Path: "/", UGID: "alice@pbs", UGIDType: "user", RoleID: "Audit"})
	h.destroy(t, inst)
	if _, exists := access.user("alice@pbs"); exists {
		t.Error("the user still exists")
	}
	if got := access.aclEntries(); !slices.Equal(got, []string{"/|bob@pbs|Audit|true"}) {
		t.Errorf("ACL entries after destroy = %v, want only bob's", got)
	}
}

// The resource identity names the user, and both import forms read it back
// in full.
func TestUserResourceImport(t *testing.T) {
	h, _, access := newUserHarness(t)
	enabled := false
	access.addUser(pbsclient.User{UserID: "carol@pam", Comment: "Host account", Validity: pbsclient.Validity{Enable: &enabled}})

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_user", "carol@pam"),
		"identity": h.importByIdentity(t, "pbs_user", map[string]any{"userid": "carol@pam"}),
	} {
		if stringAt(t, inst.state, "comment") != "Host account" || boolAt(t, inst.state, "enable") ||
			!isNullAt(t, inst.state, "password_wo_version") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
	}

	resp := h.importResource(t, "pbs_user", "carol", nil)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS user by its user ID")
}

func TestUserResourceRefreshRemovesAMissingUser(t *testing.T) {
	h, _, _ := newUserHarness(t)
	inst := h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{"userid": "dave@pbs"}))
	h.destroy(t, inst)
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Fatalf("refresh = %s, want the user removed from state", refreshed.state)
	}
}

func TestUserResourceExistingUser(t *testing.T) {
	h, _, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: "erin@pbs"})
	config := h.resourceValue(t, "pbs_user", map[string]any{"userid": "erin@pbs"})
	planned := h.plan(t, "pbs_user", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, "pbs_user", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "already has a user")
	requireProtocolErrorContaining(t, applied.Diagnostics, "import it")
}

// A user deleted outside Terraform still has its ACL entries removed on
// destroy, and the missing user is no error.
func TestUserResourceDestroyAfterOutsideDeletion(t *testing.T) {
	h, fake, access := newUserHarness(t)
	inst := h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{"userid": "frank@pbs"}))
	fake.reply("DELETE /access/users/frank@pbs", http.StatusBadRequest, "user 'frank@pbs' does not exist.")
	access.addACL(pbsclient.ACLEntry{Path: "/datastore/store1", UGID: "frank@pbs", UGIDType: "user", RoleID: "DatastoreReader"})

	h.destroy(t, inst)
	if got := access.aclEntries(); len(got) != 0 {
		t.Errorf("ACL entries after destroy = %v, want none", got)
	}
}

func TestUserResourceValidation(t *testing.T) {
	h, _, _ := newUserHarness(t)

	diags := h.validateResource(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "grace@pam", "password_wo": "long-enough", "password_wo_version": 1,
	}))
	requireProtocolErrorContaining(t, diags, "PBS stores passwords only for users of the \"pbs\" realm")

	diags = h.validateResource(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "grace@pbs", "password_wo": "long-enough",
	}))
	requireProtocolErrorContaining(t, diags, "password_wo_version")

	diags = h.validateResource(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "grace@pbs", "password_wo_version": 1,
	}))
	requireProtocolErrorContaining(t, diags, "password_wo")

	diags = h.validateResource(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "grace@pbs", "password_wo": "short", "password_wo_version": 1,
	}))
	requireProtocolErrorContaining(t, diags, "length must be between 8 and 64")

	for _, comment := range []string{" padded", "two\nlines", ""} {
		diags = h.validateResource(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{"userid": "grace@pbs", "comment": comment}))
		requireProtocolErrorContaining(t, diags, "comment")
	}
	diags = h.validateResource(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{"userid": "grace@pbs", "firstname": "G"}))
	requireProtocolErrorContaining(t, diags, "firstname")
	diags = h.validateResource(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{"userid": "grace"}))
	requireProtocolErrorContaining(t, diags, "must be a user ID")
}

// With an API token, PBS refuses password changes, so the plan does.
func TestUserResourcePasswordChangeWithTokenFailsAtPlan(t *testing.T) {
	h, fake, _ := newUserHarness(t)
	inst := h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "heidi@pbs", "password_wo": "first-password", "password_wo_version": 1,
	}))

	planned := h.plan(t, "pbs_user", inst, h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "heidi@pbs", "password_wo": "second-password", "password_wo_version": 2,
	}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Cannot change the password with an API token")
	requireProtocolErrorContaining(t, planned.Diagnostics, "PUT /access/password")
	if fake.count("PUT /access/password") != 0 {
		t.Error("the plan called PBS")
	}

	// Removing the password asks for no change, and is fine with a token.
	removed := h.plan(t, "pbs_user", inst, h.resourceValue(t, "pbs_user", map[string]any{"userid": "heidi@pbs"}))
	requireNoProtocolErrors(t, removed.Diagnostics)
}

// Signed in with a password, the provider changes a password through PUT
// /access/password, confirming with its own.
func TestUserResourcePasswordChangeWithPassword(t *testing.T) {
	h, fake, access := newUserHarness(t, withPasswordSignIn())
	inst := h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "ivan@pbs", "password_wo": "first-password", "password_wo_version": 1,
	}))

	inst = h.update(t, inst, h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "ivan@pbs", "password_wo": "second-password", "password_wo_version": 2,
	}))
	call := fake.lastCall(t, "PUT /access/password")
	if call.form.Get("userid") != "ivan@pbs" || call.form.Get("password") != "second-password" ||
		call.form.Get("confirmation-password") != fakePassword {
		t.Errorf("PUT /access/password form = %v", call.form)
	}
	if got := access.password("ivan@pbs"); got != "second-password" {
		t.Errorf("password = %q, want the new one", got)
	}
	if fake.count("PUT /access/users/ivan@pbs") != 0 {
		t.Error("an unchanged user was updated as well")
	}
	if got := int64At(t, inst.state, "password_wo_version"); got != 2 {
		t.Errorf("password_wo_version = %d, want 2", got)
	}
}

// A failed password change keeps the old version in state, so that the next
// apply tries again, and keeps the other changes.
func TestUserResourceFailedPasswordChangeKeepsTheVersion(t *testing.T) {
	h, fake, _ := newUserHarness(t, withPasswordSignIn())
	inst := h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "judy@pbs", "password_wo": "first-password", "password_wo_version": 1,
	}))
	fake.reply("PUT /access/password", http.StatusUnauthorized, "authentication failed - invalid credentials")

	config := h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "judy@pbs", "comment": "Changed", "password_wo": "second-password", "password_wo_version": 2,
	})
	planned := h.plan(t, "pbs_user", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, "pbs_user", inst, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to change the PBS user's password")
	state := h.decodeResource(t, "pbs_user", applied.NewState)
	if int64At(t, state, "password_wo_version") != 1 || stringAt(t, state, "comment") != "Changed" {
		t.Errorf("state = %s, want the old version and the new comment", state)
	}
	for _, d := range applied.Diagnostics {
		if strings.Contains(d.Detail, "second-password") {
			t.Errorf("the error quotes the new password: %s", d.Detail)
		}
	}
}

// Changing the password of the user the provider signs in as works, with a
// warning that the provider's own password is stale afterwards.
func TestUserResourceWarnsAboutTheProvidersOwnPassword(t *testing.T) {
	h, _, access := newUserHarness(t, withPasswordSignIn())
	access.addUser(pbsclient.User{UserID: fakeUsername})
	inst := h.importByID(t, "pbs_user", fakeUsername)
	planned := h.plan(t, "pbs_user", inst, h.resourceValue(t, "pbs_user", map[string]any{
		"userid": fakeUsername, "password_wo": "rotated-password", "password_wo_version": 1,
	}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "Changing the provider's own password")
}

func TestUserResourceExplainsAMissingPrivilege(t *testing.T) {
	h, fake, _ := newUserHarness(t)
	fake.reply("POST /access/users", http.StatusForbidden, "permission check failed")
	config := h.resourceValue(t, "pbs_user", map[string]any{"userid": "ken@pbs"})
	planned := h.plan(t, "pbs_user", nil, config)
	applied := h.apply(t, "pbs_user", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, userModifyPrivilege)
	requireProtocolErrorContaining(t, applied.Diagnostics, "An API token has no privileges of its own")
}

// Without Sys.Audit on /access/acl, PBS would hide the user's entries, so
// destroying the user fails rather than leave them behind.
func TestUserResourceDestroyNeedsToSeeTheACL(t *testing.T) {
	h, fake, access := newUserHarness(t)
	inst := h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{"userid": "lena@pbs"}))
	access.addACL(pbsclient.ACLEntry{Path: "/", UGID: "lena@pbs", UGIDType: "user", RoleID: "Audit"})
	access.hideACL = true

	planned := h.plan(t, "pbs_user", inst, tftypes.NewValue(h.resourceType(t, "pbs_user"), nil))
	applied := h.apply(t, "pbs_user", inst, tftypes.NewValue(h.resourceType(t, "pbs_user"), nil), planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "lacks "+aclReadPrivilege)
	if _, exists := access.user("lena@pbs"); !exists || fake.count("DELETE /access/users/lena@pbs") != 0 {
		t.Error("the user was deleted with its ACL entries hidden")
	}
}

// A changed user ID replaces the user, which gets its password at creation:
// with an API token, a new password version is fine then.
func TestUserResourceReplacementSetsThePasswordWithAToken(t *testing.T) {
	h, _, access := newUserHarness(t)
	inst := h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "mike@pbs", "password_wo": "first-password", "password_wo_version": 1,
	}))
	config := h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "mike2@pbs", "password_wo": "second-password", "password_wo_version": 2,
	})
	planned := h.plan(t, "pbs_user", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) == 0 {
		t.Fatal("changing userid does not replace the user")
	}
	h.destroy(t, inst)
	h.create(t, "pbs_user", config)
	if got := access.password("mike2@pbs"); got != "second-password" {
		t.Errorf("password = %q", got)
	}
}

// A password changed before the read-back failed stays recorded, so that the
// next apply does not send it again.
func TestUserResourceKeepsAChangedPasswordWhenTheReadBackFails(t *testing.T) {
	h, fake, access := newUserHarness(t, withPasswordSignIn())
	inst := h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "nina@pbs", "password_wo": "first-password", "password_wo_version": 1,
	}))
	config := h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "nina@pbs", "password_wo": "second-password", "password_wo_version": 2,
	})
	planned := h.plan(t, "pbs_user", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	fake.reply("GET /access/users/nina@pbs", http.StatusInternalServerError, "something broke")

	applied := h.apply(t, "pbs_user", inst, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to read PBS user back after update")
	if got := int64At(t, h.decodeResource(t, "pbs_user", applied.NewState), "password_wo_version"); got != 2 {
		t.Errorf("password_wo_version = %d, want 2: the password was changed", got)
	}
	if got := access.password("nina@pbs"); got != "second-password" {
		t.Errorf("password = %q", got)
	}
}
