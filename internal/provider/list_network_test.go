package provider

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// newNetworkListHarness serves a node with a bridge, a bond with a VLAN
// interface on it, an alias and an interface of a type PBS does not know,
// physical NICs, one of them on DHCP, and the provider signed in with a
// token.
func newNetworkListHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeNetwork) {
	t.Helper()
	fake := newFakePBS()
	network := newFakeNetwork(fake, "localhost", "eno1", "eno2", "eno3", "eno4")
	mtu, tag := int64(9000), int64(20)
	network.add(&fakeIface{Name: "vmbr0", Type: "bridge", Autostart: true, Method: "static", CIDR: "192.0.2.10/24",
		Gateway: "192.0.2.1", Method6: "manual", BridgePorts: []string{"eno1"}, Comments: "Management\nsecond line",
		Options: []string{"bridge-stp off"}})
	network.add(&fakeIface{Name: "bond0", Type: "bond", Autostart: true, Method: "manual", Method6: "manual",
		Slaves: []string{"eno2", "eno3"}, BondMode: "active-backup", BondPrimary: "eno2", MTU: &mtu})
	network.add(&fakeIface{Name: "bond0.20", Type: "vlan", Autostart: true, Method: "static", CIDR: "198.51.100.2/24",
		Method6: "manual", VLANID: &tag, VLANRawDevice: "bond0"})
	network.add(&fakeIface{Name: "eno4", Type: "eth", Autostart: true, Method: "dhcp", Method6: "manual"})
	network.add(&fakeIface{Name: "vmbr0:1", Type: "alias", Method: "static", CIDR: "192.0.2.11/24"})
	network.add(&fakeIface{Name: "wg0", Type: "unknown", Method: "manual"})
	return newProtocolHarness(t, fake), fake, network
}

func TestNetworkInterfaceListResource(t *testing.T) {
	h, fake, _ := newNetworkListHarness(t)

	// The types the resource manages, sorted by name; the alias and the
	// interface of an unknown type are left out.
	results := h.listedObjects(t, "pbs_network_interface", listRequest{})
	if got, want := listedIdentities(t, results, "name"), []string{"bond0", "bond0.20", "eno1", "eno2", "eno3", "eno4", "vmbr0"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	for _, result := range results {
		if node := stringAt(t, result.identity, "node"); node != "localhost" {
			t.Fatalf("listed node %q", node)
		}
	}
	if results[6].displayName != "vmbr0 (bridge) — Management" || results[2].displayName != "eno1 (eth)" {
		t.Fatalf("display names %q, %q", results[6].displayName, results[2].displayName)
	}
	if fake.count("GET /nodes/localhost/network/vmbr0") != 0 {
		t.Fatal("a list without resources read the interfaces")
	}

	// type selects one type.
	results = h.listedObjects(t, "pbs_network_interface", listRequest{config: map[string]any{"type": "eth"}})
	if got, want := listedIdentities(t, results, "name"), []string{"eno1", "eno2", "eno3", "eno4"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q of type eth, want %q", got, want)
	}

	// With resources, each is what importing it gives, and the generated
	// configuration plans nothing — but for eno4's, below.
	results = h.listedObjects(t, "pbs_network_interface", listRequest{includeResource: true})
	if len(results) != 7 {
		t.Fatalf("listed %d interfaces with resources", len(results))
	}
	for _, result := range results {
		if stringAt(t, result.identity, "name") == "eno4" {
			continue
		}
		h.requireListedLikeImport(t, "pbs_network_interface", result)
	}
	if stringAt(t, results[0].resource, "bond_primary") != "eno2" || int64At(t, results[1].resource, "vlan_id") != 20 ||
		stringAt(t, results[6].resource, "comments") != "Management\nsecond line" || boolAt(t, results[3].resource, "autostart") {
		t.Fatalf("listed states: %s, %s, %s, %s", results[0].resource, results[1].resource, results[6].resource, results[3].resource)
	}

	if got := h.listedObjects(t, "pbs_network_interface", listRequest{limit: 3}); len(got) != 3 {
		t.Fatalf("a limit of 3 listed %d", len(got))
	}
}

// A physical interface on DHCP gets method = "dhcp" in the generated
// configuration, which the resource refuses for type eth; without the
// line, the import plans nothing and keeps DHCP.
func TestNetworkInterfaceListResourcePhysicalDHCP(t *testing.T) {
	h, _, _ := newNetworkListHarness(t)
	results := h.listedObjects(t, "pbs_network_interface", listRequest{config: map[string]any{"type": "eth"}, includeResource: true})
	result := results[3]
	if stringAt(t, result.identity, "name") != "eno4" {
		t.Fatalf("listed %s", result.identity)
	}
	generated := h.planGenerated(t, "pbs_network_interface", result)
	if !result.resource.Equal(generated.imported.state) {
		t.Fatalf("listed state differs from the imported one\nlisted:   %s\nimported: %s", result.resource, generated.imported.state)
	}
	if stringAt(t, generated.config, "method") != networkMethodDHCP {
		t.Fatalf("generated method %s", valueAt(t, generated.config, "method"))
	}
	requireProtocolErrorContaining(t, generated.validation, "DHCP on a physical interface")

	withoutMethod := generatedConfigWith(t, generated.config, map[string]any{"method": nil})
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_network_interface", withoutMethod))
	plan := h.plan(t, "pbs_network_interface", generated.imported, withoutMethod)
	requireNoProtocolErrors(t, plan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_network_interface", plan.PlannedState); !planned.Equal(generated.imported.state) {
		t.Fatalf("the configuration without method plans a change\nplanned:  %s\nimported: %s", planned, generated.imported.state)
	}
}

// While changes are pending, PBS lists the pending configuration, and the
// list says so.
func TestNetworkInterfaceListResourcePendingChanges(t *testing.T) {
	h, _, network := newNetworkListHarness(t)
	network.edit("vmbr0", func(i *fakeIface) { i.Comments = "Pending comment" })
	all := h.listResources(t, "pbs_network_interface", listRequest{config: map[string]any{"type": "bridge"}, includeResource: true})
	if len(all) != 2 || !all[0].identity.IsNull() {
		t.Fatalf("got %d results, the first %s", len(all), all[0].identity)
	}
	requireNoProtocolErrors(t, all[0].diagnostics)
	requireProtocolWarningContaining(t, all[0].diagnostics, "Network changes are pending")
	requireProtocolWarningContaining(t, all[0].diagnostics, "#Pending comment")
	if all[1].displayName != "vmbr0 (bridge) — Pending comment" || stringAt(t, all[1].resource, "comments") != "Pending comment" {
		t.Fatalf("listed %q: %s", all[1].displayName, all[1].resource)
	}
	h.requireListedLikeImport(t, "pbs_network_interface", all[1])
}

// node selects the node, which the results name as given; an interface
// that disappears between the listing and its read is left out; a failed
// listing fails the list block.
func TestNetworkInterfaceListResourceNodeAndErrors(t *testing.T) {
	fake := newFakePBS()
	network := newFakeNetwork(fake, "pbs1", "eno1")
	network.add(&fakeIface{Name: "vmbr9", Type: "bridge", Autostart: true, Method: "manual", Method6: "manual"})
	h := newProtocolHarness(t, fake)
	fake.reply("GET /nodes/pbs1/network/vmbr9", http.StatusBadRequest, "interface 'vmbr9' does not exist.")

	results := h.listedObjects(t, "pbs_network_interface", listRequest{config: map[string]any{"node": "pbs1"}, includeResource: true})
	if got := listedIdentities(t, results, "name"); !slices.Equal(got, []string{"eno1"}) {
		t.Fatalf("listed %q", got)
	}
	if node := stringAt(t, results[0].identity, "node"); node != "pbs1" {
		t.Fatalf("listed node %q", node)
	}
	h.requireListedLikeImport(t, "pbs_network_interface", results[0])

	fake.reply("GET /nodes/pbs1/network", http.StatusBadRequest, "line 7: unknown iface option auto")
	all := h.listResources(t, "pbs_network_interface", listRequest{config: map[string]any{"node": "pbs1"}})
	if len(all) != 1 {
		t.Fatalf("got %d results", len(all))
	}
	requireProtocolErrorContaining(t, all[0].diagnostics, "Unable to list the PBS network interfaces")
	requireProtocolErrorContaining(t, all[0].diagnostics, "releases before 4.2.7 do not know the method auto")
}

// validateListBlockConfig runs ValidateListResourceConfig on a list block's
// configuration.
func validateListBlockConfig(t *testing.T, h *protocolHarness, typeName string, attrs map[string]any) []*tfprotov6.Diagnostic {
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

// The filters are checked as the attributes they select by are; unknown
// values pass.
func TestNodeListResourceFilterValidation(t *testing.T) {
	h, _, _ := newNetworkListHarness(t)
	for _, typeName := range []string{"pbs_network_interface", "pbs_apt_repository", "pbs_apt_standard_repository"} {
		requireProtocolErrorContaining(t, validateListBlockConfig(t, h, typeName, map[string]any{"node": "not a node"}), "must be a node name")
		requireNoProtocolErrors(t, validateListBlockConfig(t, h, typeName, map[string]any{"node": tfUnknown}))
		requireNoProtocolErrors(t, validateListBlockConfig(t, h, typeName, map[string]any{"node": "pbs1"}))
	}
	requireProtocolErrorContaining(t, validateListBlockConfig(t, h, "pbs_network_interface", map[string]any{"type": "alias"}), "value must be one of")
	requireNoProtocolErrors(t, validateListBlockConfig(t, h, "pbs_network_interface", map[string]any{"type": tfUnknown}))
}
