package provider

import (
	"net/http"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestAPITokensDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &apiTokensDataSource{})
}

// With userid, the data source reads that user's tokens only, through the
// user's own token list rather than every user's.
func TestAPITokensDataSourceListsTheTokensOfOneUser(t *testing.T) {
	fake := newFakePBS()
	access := newFakeAccess(fake)
	access.addUser(pbsclient.User{UserID: "pve@pbs"})
	access.addUser(pbsclient.User{UserID: "alice@pbs"})
	disabled, expire := false, int64(1893456000)
	access.addToken(pbsclient.APIToken{
		TokenID:  "pve@pbs!cluster2",
		Validity: pbsclient.Validity{Enable: &disabled, Expire: &expire},
	}, "00000000-0000-4000-8000-000000000002")
	access.addToken(pbsclient.APIToken{TokenID: "pve@pbs!cluster1", Comment: "PVE cluster 1"}, "00000000-0000-4000-8000-000000000001")
	access.addToken(pbsclient.APIToken{TokenID: "alice@pbs!ci"}, "00000000-0000-4000-8000-000000000003")
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_api_tokens", h.dataSourceValue(t, "pbs_api_tokens", map[string]any{"userid": "pve@pbs"}))
	want := h.dataSourceValue(t, "pbs_api_tokens", map[string]any{
		"userid": "pve@pbs",
		"tokens": []any{
			map[string]any{
				"tokenid":    "pve@pbs!cluster1",
				"userid":     "pve@pbs",
				"token_name": "cluster1",
				"comment":    "PVE cluster 1",
				"enable":     true,
				"expire":     0,
			},
			map[string]any{
				"tokenid":    "pve@pbs!cluster2",
				"userid":     "pve@pbs",
				"token_name": "cluster2",
				"enable":     false,
				"expire":     1893456000,
			},
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
	fake.lastCall(t, "GET /access/users/pve@pbs/token")
	if n := fake.count("GET /access/users"); n != 0 {
		t.Errorf("GET /access/users was called %d times, want none", n)
	}
}

// Without userid, the data source reads every user with their tokens in one
// call. The answer is unsorted on purpose, across users and within one, so
// that the test sees the data source sort the tokens by token ID; and a user
// name with "@" in it shows that userid and token_name are split at the "!",
// not at an "@".
func TestAPITokensDataSourceListsEveryUsersTokens(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/users", http.StatusOK, `{"data":[
		{"userid":"root@pam","tokens":[{"tokenid":"root@pam!monitoring","comment":"Prometheus"}]},
		{"userid":"pve@pbs","tokens":[{"tokenid":"pve@pbs!cluster2","enable":false},{"tokenid":"pve@pbs!cluster1","expire":1893456000}]},
		{"userid":"alice@pbs"},
		{"userid":"a@example.com@pbs","tokens":[{"tokenid":"a@example.com@pbs!laptop"}]}]}`)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_api_tokens", h.dataSourceValue(t, "pbs_api_tokens", map[string]any{}))
	want := h.dataSourceValue(t, "pbs_api_tokens", map[string]any{
		"tokens": []any{
			map[string]any{
				"tokenid":    "a@example.com@pbs!laptop",
				"userid":     "a@example.com@pbs",
				"token_name": "laptop",
				"enable":     true,
				"expire":     0,
			},
			map[string]any{
				"tokenid":    "pve@pbs!cluster1",
				"userid":     "pve@pbs",
				"token_name": "cluster1",
				"enable":     true,
				"expire":     1893456000,
			},
			map[string]any{
				"tokenid":    "pve@pbs!cluster2",
				"userid":     "pve@pbs",
				"token_name": "cluster2",
				"enable":     false,
				"expire":     0,
			},
			map[string]any{
				"tokenid":    "root@pam!monitoring",
				"userid":     "root@pam",
				"token_name": "monitoring",
				"comment":    "Prometheus",
				"enable":     true,
				"expire":     0,
			},
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
	if got := fake.lastCall(t, "GET /access/users").query.Get("include_tokens"); got != "1" {
		t.Errorf("include_tokens = %q, want 1", got)
	}
}

// A user without tokens has an empty list, not null, so that length() and
// for expressions work on it without a null check.
func TestAPITokensDataSourceEmptyListIsNotNull(t *testing.T) {
	for name, config := range map[string]map[string]any{
		"one user":   {"userid": "pve@pbs"},
		"every user": {},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			access := newFakeAccess(fake)
			access.addUser(pbsclient.User{UserID: "pve@pbs"})
			h := newProtocolHarness(t, fake)

			state := h.readDataSource(t, "pbs_api_tokens", h.dataSourceValue(t, "pbs_api_tokens", config))
			if isNullAt(t, state, "tokens") {
				t.Fatal("tokens is null, want an empty list")
			}
			if n := lengthAt(t, state, "tokens"); n != 0 {
				t.Errorf("%d tokens, want none", n)
			}
		})
	}
}

// The tokens of a user that does not exist are an error, with PBS's reason,
// rather than an empty list that would hide a typo in userid.
func TestAPITokensDataSourceMissingUser(t *testing.T) {
	fake := newFakePBS()
	newFakeAccess(fake)
	h := newProtocolHarness(t, fake)

	resp := h.readDataSourceResponse(t, "pbs_api_tokens", h.dataSourceValue(t, "pbs_api_tokens", map[string]any{"userid": "nobody@pbs"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS API tokens")
	requireProtocolErrorContaining(t, resp.Diagnostics, "no such user 'nobody@pbs'")
}

// Both ways of listing tokens explain a 403 with the privilege it needs.
func TestAPITokensDataSourceExplainsAMissingPrivilege(t *testing.T) {
	for name, tc := range map[string]struct {
		route  string
		config map[string]any
	}{
		"one user":   {route: "GET /access/users/alice@pbs/token", config: map[string]any{"userid": "alice@pbs"}},
		"every user": {route: "GET /access/users", config: map[string]any{}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(tc.route, http.StatusForbidden, "permission check failed")
			h := newProtocolHarness(t, fake)

			resp := h.readDataSourceResponse(t, "pbs_api_tokens", h.dataSourceValue(t, "pbs_api_tokens", tc.config))
			requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS API tokens")
			requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /access/users")
		})
	}
}
