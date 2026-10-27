package provider

import (
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestAPITokenResourceLifecycle(t *testing.T) {
	h, fake, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: "pve@pbs"})

	config := h.resourceValue(t, "pbs_api_token", map[string]any{
		"userid": "pve@pbs", "token_name": "cluster1", "comment": "PVE cluster",
	})

	// The token ID is known at plan time, for ACL entries that refer to it;
	// the secret is not.
	planned := h.plan(t, "pbs_api_token", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	plannedState := h.decodeResource(t, "pbs_api_token", planned.PlannedState)
	if stringAt(t, plannedState, "tokenid") != "pve@pbs!cluster1" || stringAt(t, plannedState, "id") != "pve@pbs!cluster1" {
		t.Errorf("planned = %s, want the token ID known", plannedState)
	}
	if !isUnknownAt(t, plannedState, "value") {
		t.Error("the secret is known at plan time")
	}

	inst := h.create(t, "pbs_api_token", config)
	_, secret, exists := access.token("pve@pbs!cluster1")
	if !exists || stringAt(t, inst.state, "value") != secret {
		t.Fatalf("state = %s, want the secret PBS created", inst.state)
	}
	created := fake.lastCall(t, "POST /access/users/pve@pbs/token/cluster1")
	if created.form.Get("comment") != "PVE cluster" || len(created.form) != 1 {
		t.Errorf("POST form = %v, want only the comment", created.form)
	}
	if !boolAt(t, inst.state, "enable") || int64At(t, inst.state, "expire") != 0 {
		t.Errorf("state = %s, want PBS's defaults", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_api_token", inst.identity), "tokenid"); got != "pve@pbs!cluster1" {
		t.Errorf("identity tokenid = %q", got)
	}

	// Removing the comment deletes it and keeps the secret.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_api_token", map[string]any{
		"userid": "pve@pbs", "token_name": "cluster1", "enable": false,
	}))
	updated := fake.lastCall(t, "PUT /access/users/pve@pbs/token/cluster1")
	if got := strings.Join(updated.form["delete"], ","); got != "comment" || updated.form.Get("enable") != "false" {
		t.Errorf("PUT form = %v", updated.form)
	}
	if _, sent := updated.form["regenerate"]; sent {
		t.Error("an update regenerated the secret")
	}
	if stringAt(t, inst.state, "value") != secret || boolAt(t, inst.state, "enable") {
		t.Errorf("state after update = %s", inst.state)
	}

	// Destroying deletes the token, and PBS its ACL entries.
	access.addACL(pbsclient.ACLEntry{Path: "/datastore/store1", UGID: "pve@pbs!cluster1", UGIDType: "user", RoleID: "DatastoreBackup"})
	h.destroy(t, inst)
	if _, _, exists := access.token("pve@pbs!cluster1"); exists {
		t.Error("the token still exists")
	}
	if got := access.aclEntries(); len(got) != 0 {
		t.Errorf("ACL entries = %v, want the token's gone", got)
	}
}

// Changing regenerate has PBS replace the secret; the plan says the secret
// changes, and removing regenerate changes nothing.
func TestAPITokenResourceRegenerate(t *testing.T) {
	h, fake, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: "pve@pbs"})
	inst := h.create(t, "pbs_api_token", h.resourceValue(t, "pbs_api_token", map[string]any{
		"userid": "pve@pbs", "token_name": "cluster1", "regenerate": "2026-10",
	}))
	first := stringAt(t, inst.state, "value")

	config := h.resourceValue(t, "pbs_api_token", map[string]any{
		"userid": "pve@pbs", "token_name": "cluster1", "regenerate": "2026-11",
	})
	planned := h.plan(t, "pbs_api_token", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if !isUnknownAt(t, h.decodeResource(t, "pbs_api_token", planned.PlannedState), "value") {
		t.Error("a plan that regenerates the secret keeps the old one")
	}
	inst = h.update(t, inst, config)
	_, secret, _ := access.token("pve@pbs!cluster1")
	if got := stringAt(t, inst.state, "value"); got == first || got != secret {
		t.Errorf("value = %q, want the new secret %q", got, secret)
	}
	if got := fake.lastCall(t, "PUT /access/users/pve@pbs/token/cluster1").form.Get("regenerate"); got != "1" {
		t.Errorf("regenerate = %q", got)
	}

	// Removing regenerate keeps the secret.
	puts := fake.count("PUT /access/users/pve@pbs/token/cluster1")
	inst = h.update(t, inst, h.resourceValue(t, "pbs_api_token", map[string]any{"userid": "pve@pbs", "token_name": "cluster1"}))
	if fake.count("PUT /access/users/pve@pbs/token/cluster1") != puts || stringAt(t, inst.state, "value") != secret {
		t.Error("removing regenerate changed the token")
	}
}

// An imported token has no secret until regenerate changes.
func TestAPITokenResourceImport(t *testing.T) {
	h, _, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: "pve@pbs"})
	access.addToken(pbsclient.APIToken{TokenID: "pve@pbs!old", Comment: "Imported"}, "secret-from-before")

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_api_token", "pve@pbs!old"),
		"identity": h.importByIdentity(t, "pbs_api_token", map[string]any{"tokenid": "pve@pbs!old"}),
	} {
		if stringAt(t, inst.state, "userid") != "pve@pbs" || stringAt(t, inst.state, "token_name") != "old" ||
			stringAt(t, inst.state, "comment") != "Imported" || !isNullAt(t, inst.state, "value") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
	}

	inst := h.importByID(t, "pbs_api_token", "pve@pbs!old")
	inst = h.update(t, inst, h.resourceValue(t, "pbs_api_token", map[string]any{
		"userid": "pve@pbs", "token_name": "old", "comment": "Imported", "regenerate": "1",
	}))
	if _, secret, _ := access.token("pve@pbs!old"); stringAt(t, inst.state, "value") != secret {
		t.Errorf("value = %s, want the regenerated secret", valueAt(t, inst.state, "value"))
	}

	for _, bad := range []string{"pve@pbs", "pve@pbs!", "pve!token", "pve@pbs!bad name"} {
		resp := h.importResource(t, "pbs_api_token", bad, nil)
		requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS API token by its token ID")
	}
}

// A token that is gone, with its user or on its own, leaves state, and its
// deletion is no error.
func TestAPITokenResourceGoneOutsideTerraform(t *testing.T) {
	h, fake, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: "pve@pbs"})
	inst := h.create(t, "pbs_api_token", h.resourceValue(t, "pbs_api_token", map[string]any{"userid": "pve@pbs", "token_name": "t1"}))

	access.mu.Lock()
	access.removeTokenLocked("pve@pbs!t1")
	access.mu.Unlock()

	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Fatalf("refresh = %s, want the token removed", refreshed.state)
	}
	h.destroy(t, inst)
	if got := fake.lastCall(t, "DELETE /access/users/pve@pbs/token/t1"); got.route == "" {
		t.Error("destroy did not try to delete the token")
	}
}

func TestAPITokenResourceErrors(t *testing.T) {
	h, _, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: "pve@pbs"})
	access.addToken(pbsclient.APIToken{TokenID: "pve@pbs!taken"}, "secret")

	config := h.resourceValue(t, "pbs_api_token", map[string]any{"userid": "pve@pbs", "token_name": "taken"})
	planned := h.plan(t, "pbs_api_token", nil, config)
	applied := h.apply(t, "pbs_api_token", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "already has an API token")

	config = h.resourceValue(t, "pbs_api_token", map[string]any{"userid": "nobody@pbs", "token_name": "t"})
	planned = h.plan(t, "pbs_api_token", nil, config)
	applied = h.apply(t, "pbs_api_token", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "no such user")

	diags := h.validateResource(t, "pbs_api_token", h.resourceValue(t, "pbs_api_token", map[string]any{
		"userid": "pve@pbs", "token_name": strings.Repeat("t", 60),
	}))
	requireProtocolErrorContaining(t, diags, "Token ID too long")
	diags = h.validateResource(t, "pbs_api_token", h.resourceValue(t, "pbs_api_token", map[string]any{
		"userid": "pve@pbs", "token_name": "-dash",
	}))
	requireProtocolErrorContaining(t, diags, "token_name")
}

func TestRegenerates(t *testing.T) {
	one, two := types.StringValue("1"), types.StringValue("2")
	for _, tc := range []struct {
		plan, prior types.String
		want        bool
	}{
		{types.StringNull(), types.StringNull(), false},
		{types.StringNull(), one, false},
		{one, one, false},
		{one, types.StringNull(), true},
		{two, one, true},
		{types.StringUnknown(), one, true},
	} {
		if got := regenerates(tc.plan, tc.prior); got != tc.want {
			t.Errorf("regenerates(%s, %s) = %v, want %v", tc.plan, tc.prior, got, tc.want)
		}
	}
	if !slices.Equal(apiTokenDeletable, []string{"comment"}) {
		t.Errorf("deletable = %v", apiTokenDeletable)
	}
}

// Managing the token the provider signs in with: regenerating it warns and
// carries on with the new secret; disabling or destroying it warns.
func TestAPITokenResourceProvidersOwnToken(t *testing.T) {
	h, fake, access := newUserHarness(t)
	access.addUser(pbsclient.User{UserID: fakeUsername})
	access.addToken(pbsclient.APIToken{TokenID: fakeTokenID}, fakeTokenSecret)
	inst := h.importByID(t, "pbs_api_token", fakeTokenID)

	config := h.resourceValue(t, "pbs_api_token", map[string]any{"userid": fakeUsername, "token_name": "acc", "regenerate": "1"})
	planned := h.plan(t, "pbs_api_token", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "Regenerating the provider's own API token")
	applied := h.apply(t, "pbs_api_token", inst, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	inst = &resourceInstance{typeName: "pbs_api_token", state: h.decodeResource(t, "pbs_api_token", applied.NewState), identity: applied.NewIdentity}
	if got := stringAt(t, inst.state, "value"); got == fakeTokenSecret || got != fake.tokenSecret {
		t.Errorf("value = %q, want the regenerated secret the fake now accepts", got)
	}
	// The provider signs in with the new secret from now on.
	h.refresh(t, inst)

	disabled := h.plan(t, "pbs_api_token", inst, h.resourceValue(t, "pbs_api_token", map[string]any{
		"userid": fakeUsername, "token_name": "acc", "regenerate": "1", "enable": false,
	}))
	requireProtocolWarningContaining(t, disabled.Diagnostics, "Disabling the provider's own API token")
	destroyed := h.plan(t, "pbs_api_token", inst, tftypes.NewValue(h.resourceType(t, "pbs_api_token"), nil))
	requireProtocolWarningContaining(t, destroyed.Diagnostics, "Destroying the provider's own API token")
}
