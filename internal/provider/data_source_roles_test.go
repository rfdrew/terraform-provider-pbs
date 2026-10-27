package provider

import (
	"net/http"
	"testing"
)

func TestRolesDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &rolesDataSource{})
}

// The roles keep the order PBS lists them in rather than an alphabetical one,
// as the schema promises; and a role without privileges, NoAccess, has an
// empty list.
func TestRolesDataSourceListsTheRolesInPBSOrder(t *testing.T) {
	fake := newFakePBS()
	newFakeAccess(fake)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_roles", h.dataSourceValue(t, "pbs_roles", map[string]any{}))
	want := h.dataSourceValue(t, "pbs_roles", map[string]any{
		"roles": []any{
			map[string]any{
				"roleid":     "Admin",
				"comment":    "Administrator",
				"privileges": []string{"Datastore.Allocate", "Datastore.Audit", "Permissions.Modify", "Sys.Audit"},
			},
			map[string]any{
				"roleid":     "NoAccess",
				"comment":    "Disable Access - overrides other roles.",
				"privileges": []string{},
			},
			map[string]any{
				"roleid":     "DatastoreBackup",
				"comment":    "Datastore Backup User (only backup and restore owned backups)",
				"privileges": []string{"Datastore.Backup"},
			},
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
}

// A role without a comment has a null one rather than "", and one PBS lists
// without privileges, or with null for them, an empty list rather than null,
// so that contains() works on every role.
func TestRolesDataSourceWithoutCommentOrPrivileges(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/roles", http.StatusOK, `{"data":[
		{"roleid":"Audit","privs":["Datastore.Audit","Sys.Audit"]},
		{"roleid":"NoAccess","comment":"Disable Access - overrides other roles."},
		{"roleid":"TapeAudit","privs":null}]}`)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_roles", h.dataSourceValue(t, "pbs_roles", map[string]any{}))
	want := h.dataSourceValue(t, "pbs_roles", map[string]any{
		"roles": []any{
			map[string]any{"roleid": "Audit", "privileges": []string{"Datastore.Audit", "Sys.Audit"}},
			map[string]any{"roleid": "NoAccess", "comment": "Disable Access - overrides other roles.", "privileges": []string{}},
			map[string]any{"roleid": "TapeAudit", "privileges": []string{}},
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
}

// No roles at all is an empty list, not null.
func TestRolesDataSourceEmptyListIsNotNull(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/roles", http.StatusOK, `{"data":[]}`)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_roles", h.dataSourceValue(t, "pbs_roles", map[string]any{}))
	if isNullAt(t, state, "roles") {
		t.Fatal("roles is null, want an empty list")
	}
	if n := lengthAt(t, state, "roles"); n != 0 {
		t.Errorf("%d roles, want none", n)
	}
}

func TestRolesDataSourceReportsErrors(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/roles", http.StatusInternalServerError, "something broke")
	h := newProtocolHarness(t, fake)

	resp := h.readDataSourceResponse(t, "pbs_roles", h.dataSourceValue(t, "pbs_roles", map[string]any{}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS roles")
	requireProtocolErrorContaining(t, resp.Diagnostics, "something broke")
}
