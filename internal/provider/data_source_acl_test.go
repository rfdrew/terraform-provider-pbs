package provider

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestACLDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &aclDataSource{})
}

// newACLFixture serves an ACL whose entries come back out of order — the fake
// lists them as they were added — so that the tests see the data source sort
// them.
func newACLFixture(t *testing.T) (*fakePBS, *protocolHarness) {
	t.Helper()
	fake := newFakePBS()
	access := newFakeAccess(fake)
	noPropagate := false
	for _, e := range []pbsclient.ACLEntry{
		{Path: "/datastore/store2", UGID: "alice@pbs", RoleID: "DatastoreBackup"},
		{Path: "/datastore/store1", UGID: "pve@pbs!cluster1", RoleID: "DatastoreBackup"},
		{Path: "/datastore/store1/ns1", UGID: "pve@pbs!cluster1", RoleID: "DatastoreAudit"},
		{Path: "/datastore/store1", UGID: "alice@pbs", RoleID: "DatastoreReader", Propagate: &noPropagate},
		{Path: "/", UGID: "admin@pbs", RoleID: "Admin"},
		{Path: "/datastore/store1", UGID: "alice@pbs", RoleID: "DatastoreAudit"},
	} {
		e.UGIDType = "user"
		access.addACL(e)
	}
	return fake, newProtocolHarness(t, fake)
}

func TestACLDataSourceListsEveryEntrySorted(t *testing.T) {
	fake, h := newACLFixture(t)

	state := h.readDataSource(t, "pbs_acl", h.dataSourceValue(t, "pbs_acl", map[string]any{}))
	entry := func(path, authID, role string, propagate bool) map[string]any {
		return map[string]any{"path": path, "auth_id": authID, "role": role, "propagate": propagate}
	}
	want := h.dataSourceValue(t, "pbs_acl", map[string]any{
		"entries": []any{
			entry("/", "admin@pbs", "Admin", true),
			entry("/datastore/store1", "alice@pbs", "DatastoreAudit", true),
			entry("/datastore/store1", "alice@pbs", "DatastoreReader", false),
			entry("/datastore/store1", "pve@pbs!cluster1", "DatastoreBackup", true),
			entry("/datastore/store1/ns1", "pve@pbs!cluster1", "DatastoreAudit", true),
			entry("/datastore/store2", "alice@pbs", "DatastoreBackup", true),
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
	if query := fake.lastCall(t, "GET /access/acl").query; len(query) != 0 {
		t.Errorf("query = %v, want none", query)
	}
}

// path and exact are PBS's own filters and go into the query, exact only
// when it is true; auth_id is not one PBS has, so the data source filters
// by it itself.
func TestACLDataSourceFilters(t *testing.T) {
	for name, tc := range map[string]struct {
		config map[string]any
		query  url.Values
		want   []string
	}{
		"path": {
			config: map[string]any{"path": "/datastore/store1"},
			query:  url.Values{"path": {"/datastore/store1"}},
			want: []string{
				"/datastore/store1|alice@pbs|DatastoreAudit|true",
				"/datastore/store1|alice@pbs|DatastoreReader|false",
				"/datastore/store1|pve@pbs!cluster1|DatastoreBackup|true",
				"/datastore/store1/ns1|pve@pbs!cluster1|DatastoreAudit|true",
			},
		},
		"exact path": {
			config: map[string]any{"path": "/datastore/store1", "exact": true},
			query:  url.Values{"path": {"/datastore/store1"}, "exact": {"1"}},
			want: []string{
				"/datastore/store1|alice@pbs|DatastoreAudit|true",
				"/datastore/store1|alice@pbs|DatastoreReader|false",
				"/datastore/store1|pve@pbs!cluster1|DatastoreBackup|true",
			},
		},
		"exact false": {
			config: map[string]any{"path": "/datastore/store1", "exact": false},
			query:  url.Values{"path": {"/datastore/store1"}},
			want: []string{
				"/datastore/store1|alice@pbs|DatastoreAudit|true",
				"/datastore/store1|alice@pbs|DatastoreReader|false",
				"/datastore/store1|pve@pbs!cluster1|DatastoreBackup|true",
				"/datastore/store1/ns1|pve@pbs!cluster1|DatastoreAudit|true",
			},
		},
		"user": {
			config: map[string]any{"auth_id": "alice@pbs"},
			query:  url.Values{},
			want: []string{
				"/datastore/store1|alice@pbs|DatastoreAudit|true",
				"/datastore/store1|alice@pbs|DatastoreReader|false",
				"/datastore/store2|alice@pbs|DatastoreBackup|true",
			},
		},
		"token on an exact path": {
			config: map[string]any{"path": "/datastore/store1", "exact": true, "auth_id": "pve@pbs!cluster1"},
			query:  url.Values{"path": {"/datastore/store1"}, "exact": {"1"}},
			want:   []string{"/datastore/store1|pve@pbs!cluster1|DatastoreBackup|true"},
		},
		"no match": {
			config: map[string]any{"path": "/datastore/store3"},
			query:  url.Values{"path": {"/datastore/store3"}},
			want:   []string{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake, h := newACLFixture(t)

			state := h.readDataSource(t, "pbs_acl", h.dataSourceValue(t, "pbs_acl", tc.config))
			if got := aclEntriesIn(t, state); !slices.Equal(got, tc.want) {
				t.Errorf("entries = %v, want %v", got, tc.want)
			}
			if got := fake.lastCall(t, "GET /access/acl").query; got.Encode() != tc.query.Encode() {
				t.Errorf("query = %v, want %v", got, tc.query)
			}
			// The filters are kept as configured.
			for _, attr := range []string{"path", "exact", "auth_id"} {
				if got, want := isNullAt(t, state, attr), tc.config[attr] == nil; got != want {
					t.Errorf("%s is null: %t, want %t", attr, got, want)
				}
			}
		})
	}
}

// PBS leaves out propagate when it is true, its default, as the client
// expects; the entry must then read as propagating.
func TestACLDataSourcePropagateDefaultsToTrue(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/acl", http.StatusOK, `{"data":[
		{"path":"/datastore/store1","ugid":"alice@pbs","ugid_type":"user","roleid":"DatastoreReader"},
		{"path":"/datastore/store1","ugid":"bob@pbs","ugid_type":"user","roleid":"DatastoreReader","propagate":false},
		{"path":"/datastore/store1","ugid":"carol@pbs","ugid_type":"user","roleid":"DatastoreReader","propagate":true}],
		"digest":"0123"}`)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_acl", h.dataSourceValue(t, "pbs_acl", map[string]any{}))
	want := []string{
		"/datastore/store1|alice@pbs|DatastoreReader|true",
		"/datastore/store1|bob@pbs|DatastoreReader|false",
		"/datastore/store1|carol@pbs|DatastoreReader|true",
	}
	if got := aclEntriesIn(t, state); !slices.Equal(got, want) {
		t.Errorf("entries = %v, want %v", got, want)
	}
}

// exact narrows path, so on its own it means nothing; the configuration is
// refused before anything is read.
func TestACLDataSourceExactRequiresPath(t *testing.T) {
	fake, h := newACLFixture(t)

	diags := dataSourceConfigDiagnostics(t, h, "pbs_acl", h.dataSourceValue(t, "pbs_acl", map[string]any{"exact": true}))
	requireProtocolErrorContaining(t, diags, `Attribute "path" must be specified when "exact" is specified`)
	if n := fake.count("GET /access/acl"); n != 0 {
		t.Errorf("GET /access/acl was called %d times, want none", n)
	}
}

func TestACLDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/acl", http.StatusForbidden, "permission check failed")
	h := newProtocolHarness(t, fake)

	resp := h.readDataSourceResponse(t, "pbs_acl", h.dataSourceValue(t, "pbs_acl", map[string]any{}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to read PBS ACL entries")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /access/acl")
}

// aclEntriesIn returns the entries of a pbs_acl state as
// "path|auth_id|role|propagate", in order: shorter to compare than objects,
// and the order is part of what the tests check.
func aclEntriesIn(t *testing.T, state tftypes.Value) []string {
	t.Helper()
	n := lengthAt(t, state, "entries")
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, stringAt(t, state, "entries", i, "path")+"|"+
			stringAt(t, state, "entries", i, "auth_id")+"|"+
			stringAt(t, state, "entries", i, "role")+"|"+
			strconv.FormatBool(boolAt(t, state, "entries", i, "propagate")))
	}
	return out
}

// dataSourceConfigDiagnostics runs ValidateDataResourceConfig, the attribute
// and configuration validators Terraform runs before it reads a data source,
// and returns its diagnostics; h.readDataSource fails the test on them
// instead.
func dataSourceConfigDiagnostics(t *testing.T, h *protocolHarness, typeName string, config tftypes.Value) []*tfprotov6.Diagnostic {
	t.Helper()
	resp, err := h.server.ValidateDataResourceConfig(context.Background(), &tfprotov6.ValidateDataResourceConfigRequest{
		TypeName: typeName,
		Config:   dynamicValue(t, config),
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Diagnostics
}
