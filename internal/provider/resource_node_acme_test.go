package provider

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func nodeACMEConfig(t *testing.T, h *protocolHarness, account string, domains ...map[string]any) tftypes.Value {
	t.Helper()
	elements := make([]any, 0, len(domains))
	for _, d := range domains {
		elements = append(elements, d)
	}
	return h.resourceValue(t, "pbs_node_acme", map[string]any{"account": account, "domains": elements})
}

func TestNodeACMEResourceLifecycle(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	// Settings made before Terraform: a domain the resource replaces.
	acme.setNodeProperty("acmedomain3", "old.example.org")

	config := nodeACMEConfig(t, h, "le",
		map[string]any{"domain": "pbs.example.org", "plugin": "cloudflare"},
		map[string]any{"domain": "backup.example.org"},
	)
	planned := h.plan(t, "pbs_node_acme", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if got := stringAt(t, h.decodeResource(t, "pbs_node_acme", planned.PlannedState), "node"); got != "localhost" {
		t.Fatalf("planned node = %q, want the provider's", got)
	}
	applied := h.apply(t, "pbs_node_acme", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "old.example.org")
	inst := &resourceInstance{typeName: "pbs_node_acme", state: h.decodeResource(t, "pbs_node_acme", applied.NewState), identity: applied.NewIdentity}

	// New domains take the free slots from the lowest, the old domain's slot
	// is emptied, and the node's other settings stay.
	if got := acme.fakeACMEDomains(); !slices.Equal(got, []string{"0:backup.example.org", "1:pbs.example.org,plugin=cloudflare"}) {
		t.Fatalf("slots = %v", got)
	}
	if got, _ := acme.nodeProperty("acme"); got != "account=le" {
		t.Fatalf("acme = %q", got)
	}
	if got, _ := acme.nodeProperty("description"); got != fakeNodeDescription {
		t.Fatalf("description = %q", got)
	}
	if fake.lastCall(t, "PUT /nodes/localhost/config").form.Get("digest") == "" {
		t.Fatal("the PUT carried no digest")
	}
	if stringAt(t, inst.state, "id") != "localhost" || lengthAt(t, inst.state, "domains") != 2 ||
		stringAt(t, h.identityValue(t, "pbs_node_acme", inst.identity), "node") != "localhost" {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)

	// The same domains in another order change nothing.
	reordered := nodeACMEConfig(t, h, "le",
		map[string]any{"domain": "backup.example.org"},
		map[string]any{"domain": "pbs.example.org", "plugin": "cloudflare"},
	)
	requireEmptyPlan(t, h, inst, reordered)

	// A domain that stays keeps its slot; the one that goes frees its slot
	// for the new one; a changed plugin rewrites the slot in place.
	puts := fake.count("PUT /nodes/localhost/config")
	inst = h.update(t, inst, nodeACMEConfig(t, h, "staging",
		map[string]any{"domain": "pbs.example.org", "plugin": "cloudflare", "alias": "validation.example.net"},
		map[string]any{"domain": "www.example.org"},
		map[string]any{"domain": "third.example.org"},
	))
	if fake.count("PUT /nodes/localhost/config") != puts+1 {
		t.Fatal("the update took more than one PUT")
	}
	if got := acme.fakeACMEDomains(); !slices.Equal(got, []string{
		"0:third.example.org", "1:pbs.example.org,alias=validation.example.net,plugin=cloudflare", "2:www.example.org",
	}) {
		t.Fatalf("slots = %v", got)
	}
	if got, _ := acme.nodeProperty("acme"); got != "account=staging" {
		t.Fatalf("acme = %q", got)
	}

	// A change outside Terraform shows; a digest conflict is retried.
	acme.setNodeProperty("acmedomain4", "intruder.example.org")
	inst = h.refresh(t, inst)
	if lengthAt(t, inst.state, "domains") != 4 {
		t.Fatalf("refreshed state = %s", inst.state)
	}
	acme.staleNodes = 1
	config = nodeACMEConfig(t, h, "staging", map[string]any{"domain": "pbs.example.org"})
	inst = h.update(t, inst, config)
	if got := acme.fakeACMEDomains(); !slices.Equal(got, []string{"1:pbs.example.org"}) {
		t.Fatalf("slots = %v", got)
	}
	requireEmptyPlan(t, h, inst, config)

	// Destroying removes the account and every domain, nothing else.
	h.destroy(t, inst)
	if _, set := acme.nodeProperty("acme"); set || len(acme.fakeACMEDomains()) != 0 {
		t.Fatalf("ACME settings left: %v", acme.fakeACMEDomains())
	}
	if got, _ := acme.nodeProperty("description"); got != fakeNodeDescription {
		t.Fatalf("description = %q", got)
	}
	if got := strings.Join(fake.lastCall(t, "PUT /nodes/localhost/config").form["delete"], ","); got != "acme,acmedomain1" {
		t.Fatalf("delete = %q", got)
	}
	// Nothing left to remove: no PUT.
	puts = fake.count("PUT /nodes/localhost/config")
	h.destroy(t, inst)
	if fake.count("PUT /nodes/localhost/config") != puts {
		t.Fatal("destroying settings that are gone called PUT")
	}

	// A node without ACME settings reads as none.
	refreshed := h.refresh(t, inst)
	if !isNullAt(t, refreshed.state, "account") || !isNullAt(t, refreshed.state, "domains") {
		t.Fatalf("refreshed state = %s", refreshed.state)
	}
}

func TestNodeACMEResourceImport(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	acme.setNodeProperty("acme", "account=le")
	acme.setNodeProperty("acmedomain2", "domain=pbs.example.org,plugin=cloudflare")

	inst := h.importByID(t, "pbs_node_acme", "localhost")
	config := nodeACMEConfig(t, h, "le", map[string]any{"domain": "pbs.example.org", "plugin": "cloudflare"})
	requireEmptyPlan(t, h, inst, config)
	inst = h.importByIdentity(t, "pbs_node_acme", map[string]any{"node": "localhost"})
	requireEmptyPlan(t, h, inst, config)

	resp := h.importResource(t, "pbs_node_acme", "not a node", nil)
	requireProtocolErrorContaining(t, resp.Diagnostics, "by the node's name")

	acme.setNodeProperty("acmedomain0", `"broken`)
	read := h.read(t, inst)
	requireProtocolErrorContaining(t, read.Diagnostics, "acmedomain0")
}

func TestNodeACMEResourceValidation(t *testing.T) {
	h, _, _ := newACMEHarness(t)
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_node_acme", nodeACMEConfig(t, h, "le",
		map[string]any{"domain": "pbs.example.org"}, map[string]any{"domain": "PBS.example.org", "plugin": "cloudflare"})), "more than once")
	var six []map[string]any
	for _, name := range []string{"a", "b", "c", "d", "e", "f"} {
		six = append(six, map[string]any{"domain": name + ".example.org"})
	}
	if diags := h.validateResource(t, "pbs_node_acme", nodeACMEConfig(t, h, "le", six...)); len(diags) == 0 {
		t.Fatal("six domains passed validation")
	}
	for _, bad := range []map[string]any{
		{"domain": "-bad.example.org"},
		{"domain": "pbs.example.org", "alias": "bad..example.net"},
		{"domain": "pbs.example.org", "plugin": "-cf"},
	} {
		if diags := h.validateResource(t, "pbs_node_acme", nodeACMEConfig(t, h, "le", bad)); len(diags) == 0 {
			t.Errorf("%v passed validation", bad)
		}
	}
	if diags := h.validateResource(t, "pbs_node_acme", nodeACMEConfig(t, h, "le")); len(diags) == 0 {
		t.Error("no domains passed validation")
	}
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_node_acme", h.resourceValue(t, "pbs_node_acme", map[string]any{
		"node": "-bad", "account": "le", "domains": []any{map[string]any{"domain": "pbs.example.org"}},
	})), "node name")
}

// The slot mapping keeps every domain that stays where it is.
func TestNodeACMEChanges(t *testing.T) {
	current := pbsclient.NodeConfig{ACME: "account=le", ACMEDomains: [pbsclient.MaxACMEDomains]string{
		"", "b.example.org", `"broken`, "A.example.org,plugin=old", "c.example.org",
	}}
	planned := map[string]pbsclient.ACMEDomain{
		"a.example.org": {Domain: "a.example.org", Plugin: "new"},
		"b.example.org": {Domain: "b.example.org"},
		"d.example.org": {Domain: "d.example.org"},
		"e.example.org": {Domain: "e.example.org"},
	}
	params, replaced, err := nodeACMEChanges(current, "le", planned)
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{
		"acmedomain0": {"d.example.org"},
		"acmedomain2": {"e.example.org"},
		"acmedomain3": {"a.example.org,plugin=new"},
		"delete":      {"acmedomain4"},
	}
	if params.Encode() != want.Encode() || !slices.Equal(replaced, []string{"c.example.org"}) {
		t.Fatalf("nodeACMEChanges() = %v, %v", params, replaced)
	}

	// Nothing to do.
	params, _, err = nodeACMEChanges(pbsclient.NodeConfig{ACME: "account=le", ACMEDomains: [pbsclient.MaxACMEDomains]string{"b.example.org"}},
		"le", map[string]pbsclient.ACMEDomain{"b.example.org": {Domain: "b.example.org"}})
	if err != nil || len(params) != 0 {
		t.Fatalf("nodeACMEChanges() = %v, %v, want nothing", params, err)
	}

	six := map[string]pbsclient.ACMEDomain{}
	for _, name := range []string{"a", "b", "c", "d", "e", "f"} {
		six[name] = pbsclient.ACMEDomain{Domain: name}
	}
	if _, _, err := nodeACMEChanges(pbsclient.NodeConfig{}, "le", six); err == nil {
		t.Fatal("nodeACMEChanges() placed six domains in five slots")
	}
}
