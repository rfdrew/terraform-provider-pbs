package provider

import (
	"net/http"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestUsersDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &usersDataSource{})
}

// The data source does not rely on the order PBS lists users in. The answer
// here is unsorted on purpose, so that the test sees the data source sort
// them by user ID: a list that changes order between reads would show as a
// change on every plan.
func TestUsersDataSourceListsUsersSortedByID(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/users", http.StatusOK, `{"data":[
		{"userid":"root@pam","email":"root@example.com"},
		{"userid":"alice@pbs","comment":"Backup operator","firstname":"Alice","lastname":"Liddell","enable":false,"expire":1893456000},
		{"userid":"a@example.com@pbs","email":"a@example.com"}]}`)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_users", h.dataSourceValue(t, "pbs_users", map[string]any{}))
	want := h.dataSourceValue(t, "pbs_users", map[string]any{
		"users": []any{
			map[string]any{"userid": "a@example.com@pbs", "email": "a@example.com", "enable": true, "expire": 0},
			map[string]any{
				"userid":    "alice@pbs",
				"comment":   "Backup operator",
				"firstname": "Alice",
				"lastname":  "Liddell",
				"enable":    false,
				"expire":    1893456000,
			},
			map[string]any{"userid": "root@pam", "email": "root@example.com", "enable": true, "expire": 0},
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
	// The users' tokens are of no use here, so the data source does not ask
	// PBS for them.
	if query := fake.lastCall(t, "GET /access/users").query; len(query) != 0 {
		t.Errorf("query = %v, want none", query)
	}
}

// The realm is the part of a user ID after the last "@": a user name may
// contain "@" itself, so a@example.com@pbs is in the realm pbs and
// svc@pbs@ldap is not.
func TestUsersDataSourceFiltersByRealm(t *testing.T) {
	fake := newFakePBS()
	access := newFakeAccess(fake)
	for _, id := range []string{"root@pam", "alice@pbs", "svc@pbs@ldap", "a@example.com@pbs", "backup@pam", "carol@pbs-old"} {
		access.addUser(pbsclient.User{UserID: id})
	}
	h := newProtocolHarness(t, fake)

	for realm, want := range map[string][]string{
		"pbs":  {"a@example.com@pbs", "alice@pbs"},
		"pam":  {"backup@pam", "root@pam"},
		"ldap": {"svc@pbs@ldap"},
	} {
		t.Run(realm, func(t *testing.T) {
			state := h.readDataSource(t, "pbs_users", h.dataSourceValue(t, "pbs_users", map[string]any{"realm": realm}))
			if got := listedStrings(t, state, "users", "userid"); !slices.Equal(got, want) {
				t.Errorf("users = %v, want %v", got, want)
			}
			if got := stringAt(t, state, "realm"); got != realm {
				t.Errorf("realm = %q, want %q", got, realm)
			}
		})
	}
}

// No users is an empty list, not null, so that length() and for expressions
// work on it without a null check.
func TestUsersDataSourceEmptyListIsNotNull(t *testing.T) {
	for name, tc := range map[string]struct {
		body   string
		config map[string]any
	}{
		"PBS lists none":      {body: `{"data":[]}`, config: map[string]any{}},
		"none in the realm":   {body: `{"data":[{"userid":"root@pam"}]}`, config: map[string]any{"realm": "pbs"}},
		"PBS answers no data": {body: `{"data":null}`, config: map[string]any{}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /access/users", http.StatusOK, tc.body)
			h := newProtocolHarness(t, fake)

			state := h.readDataSource(t, "pbs_users", h.dataSourceValue(t, "pbs_users", tc.config))
			if isNullAt(t, state, "users") {
				t.Fatal("users is null, want an empty list")
			}
			if n := lengthAt(t, state, "users"); n != 0 {
				t.Errorf("%d users, want none", n)
			}
		})
	}
}

func TestUsersDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/users", http.StatusForbidden, "permission check failed")
	h := newProtocolHarness(t, fake)

	resp := h.readDataSourceResponse(t, "pbs_users", h.dataSourceValue(t, "pbs_users", map[string]any{}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS users")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /access/users")
}

// A realm is a bare name; "@pbs" is a mistake that would otherwise match
// nothing and read as a server without users.
func TestUsersDataSourceRejectsAnInvalidRealm(t *testing.T) {
	fake := newFakePBS()
	h := newProtocolHarness(t, fake)

	diags := dataSourceConfigDiagnostics(t, h, "pbs_users", h.dataSourceValue(t, "pbs_users", map[string]any{"realm": "@pbs"}))
	requireProtocolErrorContaining(t, diags, "must be a realm name")
}

// listedStrings returns the string attribute attr of every element of the
// list attribute list of v, in order.
func listedStrings(t *testing.T, v tftypes.Value, list, attr string) []string {
	t.Helper()
	n := lengthAt(t, v, list)
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, stringAt(t, v, list, i, attr))
	}
	return out
}
