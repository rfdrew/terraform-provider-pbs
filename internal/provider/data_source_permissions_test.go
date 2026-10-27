package provider

import (
	"net/http"
	"net/url"
	"testing"
)

func TestPermissionsDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &permissionsDataSource{})
}

// Without auth_id and path, PBS answers the caller's own privileges on every
// path, so the data source sends neither parameter rather than an empty one,
// which would be a different question.
func TestPermissionsDataSourceReadsTheCallersPrivileges(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/permissions", http.StatusOK, `{"data":{
		"/":{"Sys.Audit":false},
		"/datastore/store1":{"Datastore.Audit":true,"Datastore.Backup":true}}}`)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_permissions", h.dataSourceValue(t, "pbs_permissions", map[string]any{}))
	want := h.dataSourceValue(t, "pbs_permissions", map[string]any{
		"permissions": map[string]any{
			"/":                 map[string]any{"Sys.Audit": false},
			"/datastore/store1": map[string]any{"Datastore.Audit": true, "Datastore.Backup": true},
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
	if query := fake.lastCall(t, "GET /access/permissions").query; len(query) != 0 {
		t.Errorf("query = %v, want none", query)
	}
}

// auth_id and path go to PBS as auth-id and path, and are kept in the state
// as configured.
func TestPermissionsDataSourceForATokenOnAPath(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/permissions", http.StatusOK, `{"data":{"/datastore/store1":{"Datastore.Backup":true}}}`)
	h := newProtocolHarness(t, fake)

	config := map[string]any{"auth_id": "pve@pbs!cluster1", "path": "/datastore/store1"}
	state := h.readDataSource(t, "pbs_permissions", h.dataSourceValue(t, "pbs_permissions", config))
	want := h.dataSourceValue(t, "pbs_permissions", map[string]any{
		"auth_id":     "pve@pbs!cluster1",
		"path":        "/datastore/store1",
		"permissions": map[string]any{"/datastore/store1": map[string]any{"Datastore.Backup": true}},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
	wantQuery := url.Values{"auth-id": {"pve@pbs!cluster1"}, "path": {"/datastore/store1"}}
	if got := fake.lastCall(t, "GET /access/permissions").query; got.Encode() != wantQuery.Encode() {
		t.Errorf("query = %v, want %v", got, wantQuery)
	}
}

// Each filter is sent on its own, without an empty value for the other.
func TestPermissionsDataSourceSendsOnlyTheFiltersSet(t *testing.T) {
	for name, tc := range map[string]struct {
		config map[string]any
		query  url.Values
	}{
		"auth_id only": {config: map[string]any{"auth_id": "alice@pbs"}, query: url.Values{"auth-id": {"alice@pbs"}}},
		"path only":    {config: map[string]any{"path": "/datastore/store1"}, query: url.Values{"path": {"/datastore/store1"}}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /access/permissions", http.StatusOK, `{"data":{}}`)
			h := newProtocolHarness(t, fake)

			h.readDataSource(t, "pbs_permissions", h.dataSourceValue(t, "pbs_permissions", tc.config))
			if got := fake.lastCall(t, "GET /access/permissions").query; got.Encode() != tc.query.Encode() {
				t.Errorf("query = %v, want %v", got, tc.query)
			}
		})
	}
}

// Where the user or token has no privilege, PBS answers an empty map for the
// path or no path at all. Either way the result is a map, not null, so that
// lookup() works on it, as the schema tells users to test.
func TestPermissionsDataSourceWithoutPrivileges(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want map[string]any
	}{
		"empty map for the path": {body: `{"data":{"/datastore/store1":{}}}`, want: map[string]any{"/datastore/store1": map[string]any{}}},
		"no path":                {body: `{"data":{}}`, want: map[string]any{}},
		"no data":                {body: `{"data":null}`, want: map[string]any{}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /access/permissions", http.StatusOK, tc.body)
			h := newProtocolHarness(t, fake)

			config := map[string]any{"auth_id": "pve@pbs!cluster1", "path": "/datastore/store1"}
			state := h.readDataSource(t, "pbs_permissions", h.dataSourceValue(t, "pbs_permissions", config))
			want := h.dataSourceValue(t, "pbs_permissions", map[string]any{
				"auth_id":     "pve@pbs!cluster1",
				"path":        "/datastore/store1",
				"permissions": tc.want,
			})
			if !state.Equal(want) {
				t.Errorf("state = %s, want %s", state, want)
			}
		})
	}
}

// Asking about another user or token without Sys.Audit on /access is 403,
// and the error says which privilege is missing.
func TestPermissionsDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/permissions", http.StatusForbidden, "permission check failed")
	h := newProtocolHarness(t, fake)

	resp := h.readDataSourceResponse(t, "pbs_permissions", h.dataSourceValue(t, "pbs_permissions", map[string]any{"auth_id": "alice@pbs"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to read PBS permissions")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /access")
	requireProtocolErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}
