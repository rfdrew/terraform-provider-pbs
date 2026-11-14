package provider

import (
	"net/http"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// newACLHarness is newUserHarness with a user and an API token to grant
// roles to.
func newACLHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeAccess) {
	t.Helper()
	h, fake, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: "pve@pbs"})
	access.addToken(pbsclient.APIToken{TokenID: "pve@pbs!cluster1"}, "secret")
	return h, fake, access
}

func TestACLResourceLifecycle(t *testing.T) {
	h, fake, access := newACLHarness(t)
	const id = "/datastore/store1|pve@pbs!cluster1|DatastoreBackup"
	config := h.resourceValue(t, "pbs_acl", map[string]any{
		"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreBackup",
	})

	planned := h.plan(t, "pbs_acl", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if got := stringAt(t, h.decodeResource(t, "pbs_acl", planned.PlannedState), "id"); got != id {
		t.Errorf("planned id = %q, want it known at plan time", got)
	}

	inst := h.create(t, "pbs_acl", config)
	if got := access.aclEntries(); !slices.Equal(got, []string{id + "|true"}) {
		t.Errorf("ACL = %v", got)
	}
	granted := fake.lastCall(t, "PUT /access/acl")
	if granted.form.Get("auth-id") != "pve@pbs!cluster1" || granted.form.Get("propagate") != "true" || granted.form.Get("digest") == "" {
		t.Errorf("PUT form = %v, want the grant with the digest it was checked against", granted.form)
	}
	if got := fake.lastCall(t, "GET /access/acl").query; got.Get("path") != "/datastore/store1" || got.Get("exact") != "1" {
		t.Errorf("GET query = %v", got)
	}
	identity := h.identityValue(t, "pbs_acl", inst.identity)
	if stringAt(t, identity, "path") != "/datastore/store1" || stringAt(t, identity, "auth_id") != "pve@pbs!cluster1" ||
		stringAt(t, identity, "role") != "DatastoreBackup" {
		t.Errorf("identity = %s", identity)
	}

	// propagate changes in place.
	changed := h.resourceValue(t, "pbs_acl", map[string]any{
		"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreBackup", "propagate": false,
	})
	replan := h.plan(t, "pbs_acl", inst, changed)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if len(replan.RequiresReplace) != 0 {
		t.Errorf("changing propagate replaces the entry: %v", replan.RequiresReplace)
	}
	inst = h.update(t, inst, changed)
	if got := access.aclEntries(); !slices.Equal(got, []string{id + "|false"}) {
		t.Errorf("ACL after update = %v", got)
	}

	// The role is part of the entry's ID.
	replace := h.plan(t, "pbs_acl", inst, h.resourceValue(t, "pbs_acl", map[string]any{
		"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreReader",
	}))
	requireNoProtocolErrors(t, replace.Diagnostics)
	if len(replace.RequiresReplace) == 0 {
		t.Error("changing the role does not replace the entry")
	}

	h.destroy(t, inst)
	if got := access.aclEntries(); len(got) != 0 {
		t.Errorf("ACL after destroy = %v", got)
	}
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh after destroy = %s, want the entry removed", refreshed.state)
	}
}

// Granting a role that is already granted would take the entry over without
// a word, so it fails; nothing is written.
func TestACLResourceExistingEntry(t *testing.T) {
	h, fake, access := newACLHarness(t)
	access.addACL(pbsclient.ACLEntry{Path: "/", UGID: "pve@pbs", UGIDType: "user", RoleID: "Audit"})
	config := h.resourceValue(t, "pbs_acl", map[string]any{"path": "/", "auth_id": "pve@pbs", "role": "Audit"})
	planned := h.plan(t, "pbs_acl", nil, config)
	applied := h.apply(t, "pbs_acl", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "already has the role Audit on /")
	requireProtocolErrorContaining(t, applied.Diagnostics, `"/|pve@pbs|Audit"`)
	if fake.count("PUT /access/acl") != 0 {
		t.Error("the existing entry was written")
	}

	// Another role on the same path, or the same role on another, is a
	// separate entry.
	h.create(t, "pbs_acl", h.resourceValue(t, "pbs_acl", map[string]any{"path": "/", "auth_id": "pve@pbs", "role": "DatastoreAudit"}))
	h.create(t, "pbs_acl", h.resourceValue(t, "pbs_acl", map[string]any{"path": "/system", "auth_id": "pve@pbs", "role": "Audit"}))
	if got := len(access.aclEntries()); got != 3 {
		t.Errorf("ACL has %d entries, want 3", got)
	}
}

// Another client writing acl.cfg between the check and the grant makes PBS
// refuse the grant; the provider checks again and retries.
func TestACLResourceRetriesADigestConflict(t *testing.T) {
	h, fake, access := newACLHarness(t)
	first := true
	fake.handle("PUT /access/acl", func(w http.ResponseWriter, req *http.Request) {
		if first {
			first = false
			access.touchACL()
		}
		access.updateACL(w, req)
	})

	h.create(t, "pbs_acl", h.resourceValue(t, "pbs_acl", map[string]any{"path": "/", "auth_id": "pve@pbs", "role": "Audit"}))
	if got := fake.count("PUT /access/acl"); got != 2 {
		t.Errorf("PUT /access/acl was called %d times, want 2: refused, then retried", got)
	}
	if got := fake.count("GET /access/acl"); got != 2 {
		t.Errorf("GET /access/acl was called %d times, want 2: the retry reads the new digest", got)
	}
	if got := access.aclEntries(); !slices.Equal(got, []string{"/|pve@pbs|Audit|true"}) {
		t.Errorf("ACL = %v", got)
	}
}

func TestACLResourceForAMissingUser(t *testing.T) {
	h, _, _ := newACLHarness(t)
	for authID, want := range map[string]string{"nobody@pbs": "no such user.", "pve@pbs!nope": "no such API token."} {
		config := h.resourceValue(t, "pbs_acl", map[string]any{"path": "/", "auth_id": authID, "role": "Audit"})
		planned := h.plan(t, "pbs_acl", nil, config)
		applied := h.apply(t, "pbs_acl", nil, config, planned)
		requireProtocolErrorContaining(t, applied.Diagnostics, "PBS has no user or API token \""+authID+"\"")
		requireProtocolErrorContaining(t, applied.Diagnostics, want)
	}
}

func TestACLResourceImport(t *testing.T) {
	h, _, access := newACLHarness(t)
	propagate := false
	access.addACL(pbsclient.ACLEntry{Path: "/datastore/store1", UGID: "pve@pbs!cluster1", UGIDType: "user", RoleID: "DatastoreBackup", Propagate: &propagate})

	for name, inst := range map[string]*resourceInstance{
		"id": h.importByID(t, "pbs_acl", "/datastore/store1|pve@pbs!cluster1|DatastoreBackup"),
		"identity": h.importByIdentity(t, "pbs_acl", map[string]any{
			"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreBackup",
		}),
	} {
		if stringAt(t, inst.state, "id") != "/datastore/store1|pve@pbs!cluster1|DatastoreBackup" || boolAt(t, inst.state, "propagate") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
	}

	// An entry that does not exist imports as nothing, which Terraform
	// reports.
	resp := h.importResource(t, "pbs_acl", "/|pve@pbs|Admin", nil)
	requireNoProtocolErrors(t, resp.Diagnostics)
	if refreshed := h.refresh(t, &resourceInstance{typeName: "pbs_acl", state: h.decodeResource(t, "pbs_acl", resp.ImportedResources[0].State)}); !refreshed.state.IsNull() {
		t.Errorf("import of a missing entry = %s", refreshed.state)
	}

	for _, bad := range []string{"/datastore/store1", "/|pve@pbs", "/|pve@pbs|Superuser", "no-slash|pve@pbs|Admin", "/|pve|Admin"} {
		resp := h.importResource(t, "pbs_acl", bad, nil)
		requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS ACL entry by <path>|<user or token ID>|<role>")
	}
}

func TestACLResourceValidation(t *testing.T) {
	h, _, _ := newACLHarness(t)
	for _, tc := range []struct {
		path, authID, role, wantAttribute string
	}{
		{"/datastore/", "pve@pbs", "Admin", "path"},
		{"datastore", "pve@pbs", "Admin", "path"},
		{"/", "pve", "Admin", "auth_id"},
		{"/", "pve@pbs!", "Admin", "auth_id"},
		{"/", "pve@pbs!a!b", "Admin", "auth_id"},
		{"/", "pve@pbs", "PVEVMAdmin", "role"},
		{"/", "root@pam", "Admin", "must not be root@pam"},
	} {
		diags := h.validateResource(t, "pbs_acl", h.resourceValue(t, "pbs_acl", map[string]any{
			"path": tc.path, "auth_id": tc.authID, "role": tc.role,
		}))
		requireProtocolErrorContaining(t, diags, tc.wantAttribute)
	}
	// root@pam's tokens take entries as any token does, and a value known
	// only at apply time is checked then.
	for _, authID := range []any{"root@pam!ci", "pam@pbs", tfUnknown} {
		diags := h.validateResource(t, "pbs_acl", h.resourceValue(t, "pbs_acl", map[string]any{
			"path": "/", "auth_id": authID, "role": "Admin",
		}))
		requireNoProtocolErrors(t, diags)
	}
}

// PBS takes an entry for root@pam and never stores it, so without the
// validation the entry would read as gone after every apply and be created
// again by the next.
func TestACLResourceRefusesRootPAM(t *testing.T) {
	h, fake, access := newACLHarness(t)
	config := h.resourceValue(t, "pbs_acl", map[string]any{"path": "/", "auth_id": "root@pam", "role": "Admin"})
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_acl", config), "PBS stores no ACL entry for it")

	// What the validation prevents, through plan and apply alone.
	planned := h.plan(t, "pbs_acl", nil, config)
	applied := h.apply(t, "pbs_acl", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	if fake.count("PUT /access/acl") != 1 || len(access.aclEntries()) != 0 {
		t.Fatalf("PUT /access/acl was called %d times, ACL = %v, want one grant that PBS does not store",
			fake.count("PUT /access/acl"), access.aclEntries())
	}
	inst := &resourceInstance{typeName: "pbs_acl", state: h.decodeResource(t, "pbs_acl", applied.NewState), identity: applied.NewIdentity}
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh = %s, want the entry gone", refreshed.state)
	}
}

// setHideACL takes the Admin role away from the fake's token and user, as
// fakeAccess.hideACL describes.
func setHideACL(access *fakeAccess) {
	access.mu.Lock()
	defer access.mu.Unlock()
	access.hideACL = true
}

// Without Sys.Audit on /access/acl, PBS shows an API token no ACL entry, so
// an entry it does not list may exist all the same: refresh and import fail
// with the reason, and the state keeps the entry, rather than drop it and
// plan to create it again, which PBS would refuse.
func TestACLResourceRefreshWithoutAudit(t *testing.T) {
	h, fake, access := newACLHarness(t)
	access.addACL(pbsclient.ACLEntry{Path: "/datastore/store1", UGID: "pve@pbs!cluster1", UGIDType: "user", RoleID: "DatastoreBackup"})
	inst := h.importByID(t, "pbs_acl", "/datastore/store1|pve@pbs!cluster1|DatastoreBackup")
	setHideACL(access)

	before := fake.count("GET /access/permissions")
	resp := h.read(t, inst)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to read PBS ACL entry")
	requireProtocolErrorContaining(t, resp.Diagnostics, "without "+aclReadPrivilege+", PBS shows a user signed in with "+
		"its password only the ACL entries of its own API tokens, and an API token none at all")
	requireProtocolErrorContaining(t, resp.Diagnostics, "The entry stays in state as it was")
	requireProtocolErrorContaining(t, resp.Diagnostics, `grant Admin on /access/acl to "`+fakeTokenID+`" and to its user`)
	if got := h.decodeResource(t, "pbs_acl", resp.NewState); !got.Equal(inst.state) {
		t.Errorf("state after the failed refresh = %s, want %s", got, inst.state)
	}
	if got := fake.count("GET /access/permissions") - before; got != 1 {
		t.Errorf("GET /access/permissions was called %d times, want 1", got)
	}

	// Importing an entry the provider cannot see fails the same way, for
	// one that exists and one that does not, instead of Terraform's
	// "Cannot import non-existent remote object".
	for _, id := range []string{"/datastore/store1|pve@pbs!cluster1|DatastoreBackup", "/|pve@pbs|Admin"} {
		imported := h.importResource(t, "pbs_acl", id, nil)
		requireNoProtocolErrors(t, imported.Diagnostics)
		resp := h.read(t, &resourceInstance{
			typeName: "pbs_acl",
			state:    h.decodeResource(t, "pbs_acl", imported.ImportedResources[0].State),
			identity: imported.ImportedResources[0].Identity,
		})
		requireProtocolErrorContaining(t, resp.Diagnostics, "The entry is not imported.")
		requireProtocolErrorContaining(t, resp.Diagnostics, aclReadPrivilege)
	}

	// The check failing is an error too, and keeps the state.
	fake.reply("GET /access/permissions", http.StatusInternalServerError, "something broke")
	resp = h.read(t, inst)
	requireProtocolErrorContaining(t, resp.Diagnostics, "reads its own privileges on /access/acl to tell whether the entry is gone")
	requireProtocolErrorContaining(t, resp.Diagnostics, "something broke")
	if got := h.decodeResource(t, "pbs_acl", resp.NewState); !got.Equal(inst.state) {
		t.Errorf("state after the failed check = %s, want %s", got, inst.state)
	}
}

// Without Admin on /access/acl, PBS lets a user signed in with its password
// see and change the entries of its own API tokens, so pbs_acl manages them
// as usual, without asking PBS for privileges, and a refresh drops one that
// is gone. Entries of anyone else it refuses with a 400, which the error
// turns into the privilege that is missing.
func TestACLResourceOwnTokenWithoutAudit(t *testing.T) {
	h, fake, access := newUserHarness(t, withPasswordSignIn())
	ownToken := fakeUsername + "!other"
	access.addUser(pbsclient.User{UserID: fakeUsername})
	access.addToken(pbsclient.APIToken{TokenID: ownToken}, "secret")
	access.addUser(pbsclient.User{UserID: "pve@pbs"})
	access.addToken(pbsclient.APIToken{TokenID: "pve@pbs!cluster1"}, "secret")
	setHideACL(access)
	entry := func(path, role string, extra map[string]any) tftypes.Value {
		attrs := map[string]any{"path": path, "auth_id": ownToken, "role": role}
		for k, v := range extra {
			attrs[k] = v
		}
		return h.resourceValue(t, "pbs_acl", attrs)
	}

	inst := h.create(t, "pbs_acl", entry("/datastore/store1", "DatastoreBackup", nil))
	if refreshed := h.refresh(t, inst); refreshed.state.IsNull() || !boolAt(t, refreshed.state, "propagate") {
		t.Fatalf("refresh = %s", refreshed.state)
	}
	inst = h.update(t, inst, entry("/datastore/store1", "DatastoreBackup", map[string]any{"propagate": false}))
	if got := access.aclEntries(); !slices.Equal(got, []string{"/datastore/store1|" + ownToken + "|DatastoreBackup|false"}) {
		t.Fatalf("ACL after update = %v", got)
	}
	// The check for an existing entry sees the token's entries.
	planned := h.plan(t, "pbs_acl", nil, entry("/datastore/store1", "DatastoreBackup", nil))
	applied := h.apply(t, "pbs_acl", nil, entry("/datastore/store1", "DatastoreBackup", nil), planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "already has the role DatastoreBackup")
	h.destroy(t, inst)
	if got := access.aclEntries(); len(got) != 0 {
		t.Fatalf("ACL after destroy = %v", got)
	}
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Fatalf("refresh after destroy = %s, want the entry gone", refreshed.state)
	}

	// So do the roles NoAccess displaces.
	reader := h.create(t, "pbs_acl", entry("/datastore/store2", "DatastoreReader", nil))
	planned = h.plan(t, "pbs_acl", nil, entry("/datastore/store2", "NoAccess", nil))
	applied = h.apply(t, "pbs_acl", nil, entry("/datastore/store2", "NoAccess", nil), planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "removed its roles DatastoreReader there")
	if refreshed := h.refresh(t, reader); !refreshed.state.IsNull() {
		t.Fatalf("the displaced entry is still in state: %s", refreshed.state)
	}
	if n := fake.count("GET /access/permissions"); n != 0 {
		t.Errorf("GET /access/permissions was called %d times, want none for the user's own tokens", n)
	}

	for authID, refusal := range map[string]string{
		fakeUsername:       "Unprivileged users can only set ACL items for API tokens.",
		"pve@pbs":          "Unprivileged users can only set ACL items for API tokens.",
		"pve@pbs!cluster1": "Unprivileged users can only set ACL items for their own API tokens.",
	} {
		config := h.resourceValue(t, "pbs_acl", map[string]any{"path": "/datastore/store1", "auth_id": authID, "role": "DatastoreBackup"})
		planned := h.plan(t, "pbs_acl", nil, config)
		applied := h.apply(t, "pbs_acl", nil, config, planned)
		requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to create PBS ACL entry")
		requireProtocolErrorContaining(t, applied.Diagnostics, `"`+fakeUsername+`" lacks `+aclModifyPrivilege+", which only the Admin role grants")
		requireProtocolErrorContaining(t, applied.Diagnostics, refusal)
	}
	if got := access.aclEntries(); !slices.Equal(got, []string{"/datastore/store2|" + ownToken + "|NoAccess|true"}) {
		t.Errorf("ACL = %v, want only the token's NoAccess", got)
	}
}

// Without Permissions.Modify on /access/acl, PBS refuses every change an
// API token makes with a 400 "Unprivileged API tokens can't set ACL items.",
// which the errors of update and delete turn into the privilege that is
// missing.
func TestACLResourceChangesWithoutPermissionsModify(t *testing.T) {
	h, _, access := newACLHarness(t)
	inst := h.create(t, "pbs_acl", h.resourceValue(t, "pbs_acl", map[string]any{
		"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreBackup",
	}))
	setHideACL(access)

	changed := h.resourceValue(t, "pbs_acl", map[string]any{
		"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreBackup", "propagate": false,
	})
	planned := h.plan(t, "pbs_acl", inst, changed)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, "pbs_acl", inst, changed, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to update PBS ACL entry")
	requireProtocolErrorContaining(t, applied.Diagnostics, `"`+fakeTokenID+`" lacks `+aclModifyPrivilege)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unprivileged API tokens can't set ACL items.")

	null := tftypes.NewValue(h.resourceType(t, "pbs_acl"), nil)
	planned = h.plan(t, "pbs_acl", inst, null)
	applied = h.apply(t, "pbs_acl", inst, null, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to delete PBS ACL entry")
	requireProtocolErrorContaining(t, applied.Diagnostics, "an API token none at all")
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unprivileged API tokens can't set ACL items.")
	if got := access.aclEntries(); !slices.Equal(got, []string{"/datastore/store1|pve@pbs!cluster1|DatastoreBackup|true"}) {
		t.Errorf("ACL = %v, want the entry unchanged", got)
	}
}

// A user name may contain the separator; the path and the role never do.
func TestSplitACLID(t *testing.T) {
	for id, want := range map[string][3]string{
		"/|alice@pbs|Admin":                          {"/", "alice@pbs", "Admin"},
		"/datastore/s1|a|b@pbs!t|DatastoreBackup":    {"/datastore/s1", "a|b@pbs!t", "DatastoreBackup"},
		"/remote/r1/store|x@ldap|RemoteSyncOperator": {"/remote/r1/store", "x@ldap", "RemoteSyncOperator"},
	} {
		path, authID, role, ok := splitACLID(id)
		if !ok || [3]string{path, authID, role} != want {
			t.Errorf("splitACLID(%q) = %q, %q, %q, %v, want %q", id, path, authID, role, ok, want)
		}
		if aclID(path, authID, role) != id {
			t.Errorf("aclID does not invert splitACLID for %q", id)
		}
	}
	for _, id := range []string{"", "/", "/|alice@pbs"} {
		if _, _, _, ok := splitACLID(id); ok {
			t.Errorf("splitACLID(%q) succeeded", id)
		}
	}
}

// NoAccess and the other roles of one user or token on one path exclude each
// other in PBS; granting one removes the others, and the provider says so.
func TestACLResourceNoAccessDisplacesOtherRoles(t *testing.T) {
	h, _, access := newACLHarness(t)
	backup := h.create(t, "pbs_acl", h.resourceValue(t, "pbs_acl", map[string]any{
		"path": "/datastore/store1", "auth_id": "pve@pbs", "role": "DatastoreBackup",
	}))
	h.create(t, "pbs_acl", h.resourceValue(t, "pbs_acl", map[string]any{
		"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreReader",
	}))

	config := h.resourceValue(t, "pbs_acl", map[string]any{"path": "/datastore/store1", "auth_id": "pve@pbs", "role": "NoAccess"})
	planned := h.plan(t, "pbs_acl", nil, config)
	applied := h.apply(t, "pbs_acl", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "removed its roles DatastoreBackup there")
	if got := access.aclEntries(); !slices.Equal(got, []string{
		"/datastore/store1|pve@pbs!cluster1|DatastoreReader|true", "/datastore/store1|pve@pbs|NoAccess|true",
	}) {
		t.Errorf("ACL = %v, want the user's other role gone and the token's kept", got)
	}
	if refreshed := h.refresh(t, backup); !refreshed.state.IsNull() {
		t.Errorf("the displaced entry is still in state: %s", refreshed.state)
	}

	// Granting another role removes NoAccess in turn.
	config = h.resourceValue(t, "pbs_acl", map[string]any{"path": "/datastore/store1", "auth_id": "pve@pbs", "role": "DatastoreAudit"})
	planned = h.plan(t, "pbs_acl", nil, config)
	applied = h.apply(t, "pbs_acl", nil, config, planned)
	requireProtocolWarningContaining(t, applied.Diagnostics, "removed its roles NoAccess there")
}
