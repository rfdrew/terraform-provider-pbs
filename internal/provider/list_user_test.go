package provider

import (
	"slices"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestUserListResource(t *testing.T) {
	h, fake, access := newUserHarness(t)
	// PBS lists users in the order of its hash map, not by name.
	access.addUser(pbsclient.User{UserID: "root@pam", Comment: "Superuser"})
	h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "zed@pbs", "comment": "Backup operator", "email": "zed@example.com", "firstname": "Zed",
	}))
	h.create(t, "pbs_user", h.resourceValue(t, "pbs_user", map[string]any{
		"userid": "alice@pbs", "expire": 4102444800, "enable": false,
	}))

	// Without resources, the list costs one call and names every user.
	before := fake.count("GET /access/users/alice@pbs")
	results := h.listedObjects(t, "pbs_user", listRequest{})
	if got, want := listedIdentities(t, results, "userid"), []string{"alice@pbs", "root@pam", "zed@pbs"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	if results[2].displayName != "zed@pbs — Backup operator" || results[0].displayName != "alice@pbs" {
		t.Fatalf("display names %q, %q", results[0].displayName, results[2].displayName)
	}
	if !results[0].resource.IsNull() || fake.count("GET /access/users/alice@pbs") != before {
		t.Fatal("a list without resources read the users")
	}

	// realm selects one realm.
	results = h.listedObjects(t, "pbs_user", listRequest{config: map[string]any{"realm": "pbs"}})
	if got, want := listedIdentities(t, results, "userid"), []string{"alice@pbs", "zed@pbs"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q in realm pbs, want %q", got, want)
	}

	// With resources, each is what importing it gives, and the configuration
	// generated from it plans nothing.
	results = h.listedObjects(t, "pbs_user", listRequest{includeResource: true})
	if len(results) != 3 {
		t.Fatalf("listed %d users with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_user", result)
	}
	if stringAt(t, results[2].resource, "email") != "zed@example.com" || boolAt(t, results[0].resource, "enable") {
		t.Fatalf("listed states: %s, %s", results[2].resource, results[0].resource)
	}

	// The limit Terraform sends bounds the results.
	if got := h.listedObjects(t, "pbs_user", listRequest{limit: 2}); len(got) != 2 {
		t.Fatalf("a limit of 2 listed %d", len(got))
	}
}

// A user that disappears between the listing and its read is left out
// without an error.
func TestUserListResourceUserGone(t *testing.T) {
	h, fake, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: "alice@pbs"})
	access.addUser(pbsclient.User{UserID: "bob@pbs"})
	fake.reply("GET /access/users/alice@pbs", 400, "no such user 'alice@pbs'")
	results := h.listedObjects(t, "pbs_user", listRequest{includeResource: true})
	if got := listedIdentities(t, results, "userid"); !slices.Equal(got, []string{"bob@pbs"}) {
		t.Fatalf("listed %q", got)
	}
}

// A user PBS will not show is left out with a warning, and the others are
// still listed.
func TestUserListResourceUnreadableUser(t *testing.T) {
	h, fake, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: "alice@pbs"})
	access.addUser(pbsclient.User{UserID: "bob@pbs"})
	fake.reply("GET /access/users/alice@pbs", 500, "internal error")
	all := h.listResources(t, "pbs_user", listRequest{includeResource: true})
	var listed []string
	warned := false
	for _, result := range all {
		requireNoProtocolErrors(t, result.diagnostics)
		if result.identity.IsNull() {
			requireProtocolWarningContaining(t, result.diagnostics, "Left out alice@pbs")
			warned = true
			continue
		}
		listed = append(listed, stringAt(t, result.identity, "userid"))
	}
	if !warned || !slices.Equal(listed, []string{"bob@pbs"}) {
		t.Fatalf("listed %q, warned %v", listed, warned)
	}
}

// A failed listing fails the list block.
func TestUserListResourceListFails(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/users", 403, "permission check failed")
	h := newProtocolHarness(t, fake)
	results := h.listResources(t, "pbs_user", listRequest{})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS users")
}
