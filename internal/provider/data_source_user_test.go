package provider

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestUserDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &userDataSource{})
}

func TestUserDataSourceReadsAUser(t *testing.T) {
	fake := newFakePBS()
	access := newFakeAccess(fake)
	disabled, expire := false, int64(1893456000)
	access.addUser(pbsclient.User{
		UserID:    "alice@pbs",
		Comment:   "Backup operator",
		Email:     "alice@example.com",
		Firstname: "Alice",
		Lastname:  "Liddell",
		Validity:  pbsclient.Validity{Enable: &disabled, Expire: &expire},
	})
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_user", h.dataSourceValue(t, "pbs_user", map[string]any{"userid": "alice@pbs"}))
	want := h.dataSourceValue(t, "pbs_user", map[string]any{
		"userid":    "alice@pbs",
		"comment":   "Backup operator",
		"email":     "alice@example.com",
		"firstname": "Alice",
		"lastname":  "Liddell",
		"enable":    false,
		"expire":    1893456000,
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
}

// PBS leaves out the properties a user does not have, and enable and expire
// at their defaults. The missing texts read as null rather than "", and the
// account as enabled without an expiry, which is what PBS means by leaving
// them out.
func TestUserDataSourceDefaults(t *testing.T) {
	fake := newFakePBS()
	access := newFakeAccess(fake)
	access.addUser(pbsclient.User{UserID: "bob@pbs"})
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_user", h.dataSourceValue(t, "pbs_user", map[string]any{"userid": "bob@pbs"}))
	want := h.dataSourceValue(t, "pbs_user", map[string]any{"userid": "bob@pbs", "enable": true, "expire": 0})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
}

// A user name may itself contain "@", as an email address does; the user ID
// must still reach PBS whole, as one path segment.
func TestUserDataSourceUserNameWithAt(t *testing.T) {
	fake := newFakePBS()
	access := newFakeAccess(fake)
	access.addUser(pbsclient.User{UserID: "a@example.com@pbs", Email: "a@example.com"})
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_user", h.dataSourceValue(t, "pbs_user", map[string]any{"userid": "a@example.com@pbs"}))
	if got := stringAt(t, state, "email"); got != "a@example.com" {
		t.Errorf("email = %q, want a@example.com", got)
	}
	fake.lastCall(t, "GET /access/users/a@example.com@pbs")
}

// A user that does not exist is an error on userid, not an empty result: a
// data source that silently reads nothing would hide a typo.
func TestUserDataSourceMissingUser(t *testing.T) {
	fake := newFakePBS()
	newFakeAccess(fake)
	h := newProtocolHarness(t, fake)

	resp := h.readDataSourceResponse(t, "pbs_user", h.dataSourceValue(t, "pbs_user", map[string]any{"userid": "nobody@pbs"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS user not found")
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS has no user "nobody@pbs"`)
	requireProtocolErrorOn(t, resp.Diagnostics, tftypes.NewAttributePath().WithAttributeName("userid"))
}

// Reading another user without Sys.Audit on /access/users is 403, and the
// error says which privilege is missing.
func TestUserDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/users/alice@pbs", http.StatusForbidden, "permission check failed")
	h := newProtocolHarness(t, fake)

	resp := h.readDataSourceResponse(t, "pbs_user", h.dataSourceValue(t, "pbs_user", map[string]any{"userid": "alice@pbs"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to read PBS user")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /access/users")
	requireProtocolErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}

// A user ID without a realm is refused when the configuration is validated,
// before any request, with a message that says what a user ID looks like.
func TestUserDataSourceRejectsAUserIDWithoutRealm(t *testing.T) {
	fake := newFakePBS()
	h := newProtocolHarness(t, fake)

	diags := dataSourceConfigDiagnostics(t, h, "pbs_user", h.dataSourceValue(t, "pbs_user", map[string]any{"userid": "alice"}))
	requireProtocolErrorContaining(t, diags, "must be a user ID")
}

// requireProtocolErrorOn fails the test unless an error is attached to the
// attribute at want, which is what makes Terraform point at the offending
// line of the configuration.
func requireProtocolErrorOn(t *testing.T, diags []*tfprotov6.Diagnostic, want *tftypes.AttributePath) {
	t.Helper()
	var got []string
	for _, d := range diags {
		if d.Severity == tfprotov6.DiagnosticSeverityError && d.Attribute != nil && d.Attribute.Equal(want) {
			return
		}
		got = append(got, fmt.Sprintf("%s on %v: %s: %s", d.Severity, d.Attribute, d.Summary, d.Detail))
	}
	t.Fatalf("expected an error on %s, got %v", want, got)
}
