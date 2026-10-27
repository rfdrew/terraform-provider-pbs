package provider

import (
	"net/http"
	"slices"
	"testing"

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
	} {
		diags := h.validateResource(t, "pbs_acl", h.resourceValue(t, "pbs_acl", map[string]any{
			"path": tc.path, "auth_id": tc.authID, "role": tc.role,
		}))
		requireProtocolErrorContaining(t, diags, tc.wantAttribute)
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
