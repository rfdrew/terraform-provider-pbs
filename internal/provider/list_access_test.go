package provider

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestAPITokenListResource(t *testing.T) {
	h, fake, access := newACLHarness(t)
	access.addUser(pbsclient.User{UserID: "alice@pbs"})
	access.addToken(pbsclient.APIToken{TokenID: "alice@pbs!backup", Comment: "Nightly backups"}, "secret")
	h.create(t, "pbs_api_token", h.resourceValue(t, "pbs_api_token", map[string]any{
		"userid": "pve@pbs", "token_name": "ci", "comment": "CI pipeline", "expire": 4102444800, "enable": false,
	}))

	// Without resources, the list costs one call and names every token.
	before := len(fake.routes())
	results := h.listedObjects(t, "pbs_api_token", listRequest{})
	if got, want := listedIdentities(t, results, "tokenid"), []string{"alice@pbs!backup", "pve@pbs!ci", "pve@pbs!cluster1"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	if got := fake.routes()[before:]; !slices.Equal(got, []string{"GET /access/users"}) || fake.lastCall(t, "GET /access/users").query.Get("include_tokens") != "1" {
		t.Fatalf("calls %q, query %v", got, fake.lastCall(t, "GET /access/users").query)
	}
	if results[0].displayName != "alice@pbs!backup — Nightly backups" || results[2].displayName != "pve@pbs!cluster1" {
		t.Fatalf("display names %q, %q", results[0].displayName, results[2].displayName)
	}
	if !results[0].resource.IsNull() {
		t.Fatal("a list without resources included them")
	}

	// userid lists one user's tokens, with the call for them.
	results = h.listedObjects(t, "pbs_api_token", listRequest{config: map[string]any{"userid": "pve@pbs"}})
	if got, want := listedIdentities(t, results, "tokenid"), []string{"pve@pbs!ci", "pve@pbs!cluster1"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q for pve@pbs, want %q", got, want)
	}
	if fake.count("GET /access/users/pve@pbs/token") != 1 {
		t.Fatalf("calls: %q", fake.routes())
	}
	// A user without tokens, or none at all, has none to list.
	if got := h.listedObjects(t, "pbs_api_token", listRequest{config: map[string]any{"userid": "nobody@pbs"}}); len(got) != 0 {
		t.Fatalf("listed %d tokens of a missing user", len(got))
	}

	// With resources, each is what importing it gives — without a secret,
	// which PBS never shows again — and the configuration generated from
	// it plans nothing.
	results = h.listedObjects(t, "pbs_api_token", listRequest{includeResource: true})
	if len(results) != 3 {
		t.Fatalf("listed %d tokens with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_api_token", result)
		if !isNullAt(t, result.resource, "value") || !isNullAt(t, result.resource, "regenerate") {
			t.Fatalf("listed token %s with a secret or regenerate: %s", result.displayName, result.resource)
		}
	}
	if boolAt(t, results[1].resource, "enable") || int64At(t, results[1].resource, "expire") != 4102444800 ||
		stringAt(t, results[1].resource, "comment") != "CI pipeline" {
		t.Fatalf("listed state: %s", results[1].resource)
	}

	if got := h.listedObjects(t, "pbs_api_token", listRequest{limit: 1}); len(got) != 1 {
		t.Fatalf("a limit of 1 listed %d", len(got))
	}
}

// A failed listing fails the list block, with the privilege it needs.
func TestAPITokenListResourceListFails(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/users", 500, "user.cfg is broken")
	fake.reply("GET /access/users/pve@pbs/token", 403, "permission check failed")
	h := newProtocolHarness(t, fake)
	results := h.listResources(t, "pbs_api_token", listRequest{})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS API tokens")
	results = h.listResources(t, "pbs_api_token", listRequest{config: map[string]any{"userid": "pve@pbs"}})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, userReadPrivilege)
}

func TestAPITokenListResourceValidation(t *testing.T) {
	h, _, _ := newACLHarness(t)
	requireProtocolErrorContaining(t, listConfigDiagnostics(t, h, "pbs_api_token", map[string]any{"userid": "not a user"}),
		"must be a user ID")
}

func TestACLListResource(t *testing.T) {
	h, fake, access := newACLHarness(t)
	access.addUser(pbsclient.User{UserID: "alice@pbs"})
	access.addACL(pbsclient.ACLEntry{Path: "/", UGID: "alice@pbs", UGIDType: "user", RoleID: "Audit"})
	// A group's entry, which PBS keeps when acl.cfg is edited by hand.
	access.addACL(pbsclient.ACLEntry{Path: "/datastore/store1", UGID: "admins", UGIDType: "group", RoleID: "Admin"})
	for _, entry := range []map[string]any{
		{"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreBackup"},
		{"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreAudit", "propagate": false},
		{"path": "/datastore/store1", "auth_id": "pve@pbs", "role": "DatastoreBackup"},
		{"path": "/datastore/store1/ns1", "auth_id": "pve@pbs!cluster1", "role": "DatastoreReader"},
	} {
		h.create(t, "pbs_acl", h.resourceValue(t, "pbs_acl", entry))
	}

	// Every role of a user or token on a path is one result, ordered by
	// path, then user or token, then role.
	before := len(fake.routes())
	results := h.listedObjects(t, "pbs_acl", listRequest{})
	want := []string{
		"Audit on / for alice@pbs",
		"DatastoreBackup on /datastore/store1 for pve@pbs",
		"DatastoreAudit on /datastore/store1 for pve@pbs!cluster1",
		"DatastoreBackup on /datastore/store1 for pve@pbs!cluster1",
		"DatastoreReader on /datastore/store1/ns1 for pve@pbs!cluster1",
	}
	if got := resultDisplayNames(results); !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	if got := fake.routes()[before:]; !slices.Equal(got, []string{"GET /access/acl"}) || len(fake.lastCall(t, "GET /access/acl").query) != 0 {
		t.Fatalf("calls %q", got)
	}
	if stringAt(t, results[2].identity, "path") != "/datastore/store1" || stringAt(t, results[2].identity, "auth_id") != "pve@pbs!cluster1" ||
		stringAt(t, results[2].identity, "role") != "DatastoreAudit" {
		t.Fatalf("identity %s", results[2].identity)
	}

	// path selects the entries on exactly that path; auth_id those of one
	// user or token, not its tokens'.
	results = h.listedObjects(t, "pbs_acl", listRequest{config: map[string]any{"path": "/datastore/store1"}})
	if got := listedIdentities(t, results, "role"); !slices.Equal(got, []string{"DatastoreBackup", "DatastoreAudit", "DatastoreBackup"}) {
		t.Fatalf("listed %q on /datastore/store1", got)
	}
	if query := fake.lastCall(t, "GET /access/acl").query; query.Get("path") != "/datastore/store1" || query.Get("exact") != "1" {
		t.Fatalf("query %v", query)
	}
	results = h.listedObjects(t, "pbs_acl", listRequest{config: map[string]any{"auth_id": "pve@pbs"}})
	if got := resultDisplayNames(results); !slices.Equal(got, []string{"DatastoreBackup on /datastore/store1 for pve@pbs"}) {
		t.Fatalf("listed %q for pve@pbs", got)
	}
	results = h.listedObjects(t, "pbs_acl", listRequest{config: map[string]any{"path": "/datastore/store1", "auth_id": "pve@pbs!cluster1"}})
	if got := listedIdentities(t, results, "role"); !slices.Equal(got, []string{"DatastoreAudit", "DatastoreBackup"}) {
		t.Fatalf("listed %q", got)
	}
	if got := h.listedObjects(t, "pbs_acl", listRequest{config: map[string]any{"path": "/remote"}}); len(got) != 0 {
		t.Fatalf("listed %d entries on a path without any", len(got))
	}

	// With resources, each is what importing it gives, and the
	// configuration generated from it plans nothing.
	results = h.listedObjects(t, "pbs_acl", listRequest{includeResource: true})
	if len(results) != len(want) {
		t.Fatalf("listed %d entries with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_acl", result)
	}
	if boolAt(t, results[2].resource, "propagate") || !boolAt(t, results[3].resource, "propagate") {
		t.Fatalf("listed states: %s, %s", results[2].resource, results[3].resource)
	}
}

// Without Sys.Audit on /access/acl, PBS shows a user signed in with its
// password only the entries of its own tokens, not even its own, and so
// does the list.
func TestACLListResourceWithoutAudit(t *testing.T) {
	h, _, access := newUserHarness(t, withPasswordSignIn())
	access.addUser(pbsclient.User{UserID: fakeUsername})
	access.addToken(pbsclient.APIToken{TokenID: fakeUsername + "!other"}, "secret")
	access.addACL(pbsclient.ACLEntry{Path: "/", UGID: "pve@pbs!cluster1", UGIDType: "user", RoleID: "Audit"})
	access.addACL(pbsclient.ACLEntry{Path: "/", UGID: fakeUsername, UGIDType: "user", RoleID: "Audit"})
	access.addACL(pbsclient.ACLEntry{Path: "/", UGID: fakeUsername + "!other", UGIDType: "user", RoleID: "Audit"})
	access.mu.Lock()
	access.hideACL = true
	access.mu.Unlock()
	results := h.listedObjects(t, "pbs_acl", listRequest{includeResource: true})
	if got := listedIdentities(t, results, "auth_id"); !slices.Equal(got, []string{fakeUsername + "!other"}) {
		t.Fatalf("listed %q", got)
	}
	h.requireListedLikeImport(t, "pbs_acl", results[0])
}

// An entry that goes between the listing and its read is left out without
// an error.
func TestACLListResourceEntryGone(t *testing.T) {
	h, fake, access := newACLHarness(t)
	access.addACL(pbsclient.ACLEntry{Path: "/", UGID: "pve@pbs", UGIDType: "user", RoleID: "Audit"})
	access.addACL(pbsclient.ACLEntry{Path: "/system", UGID: "pve@pbs", UGIDType: "user", RoleID: "Audit"})
	// The full list has both; the read of / finds nothing.
	fake.handle("GET /access/acl", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("path") == "/" {
			writeData(w, []pbsclient.ACLEntry{}, "")
			return
		}
		access.readACL(w, req)
	})
	results := h.listedObjects(t, "pbs_acl", listRequest{includeResource: true})
	if got := listedIdentities(t, results, "path"); !slices.Equal(got, []string{"/system"}) {
		t.Fatalf("listed %q", got)
	}
}

func TestACLListResourceValidation(t *testing.T) {
	h, _, _ := newACLHarness(t)
	for want, config := range map[string]map[string]any{
		"must be / or a path": {"path": "/datastore/"},
		"must be a user ID":   {"auth_id": "nobody"},
	} {
		requireProtocolErrorContaining(t, listConfigDiagnostics(t, h, "pbs_acl", config), want)
	}
}

// resultDisplayNames returns the display name of each result, in order.
func resultDisplayNames(results []listedResult) []string {
	names := make([]string, len(results))
	for i, result := range results {
		names[i] = result.displayName
	}
	return names
}

// listConfigDiagnostics validates the configuration of a list block, as
// `terraform validate` and `terraform query` do, and returns the
// diagnostics.
func listConfigDiagnostics(t *testing.T, h *protocolHarness, typeName string, attrs map[string]any) []*tfprotov6.Diagnostic {
	t.Helper()
	config := tfValue(t, h.listSchema(t, typeName).ValueType(), attrs)
	resp, err := h.listServer(t).ValidateListResourceConfig(context.Background(), &tfprotov6.ValidateListResourceConfigRequest{
		TypeName: typeName,
		Config:   dynamicValue(t, config),
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Diagnostics
}
