package provider

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// newNetworkHarness serves a node with the physical NICs eno1, eno2 and
// eno3, signed in as root@pam with a password unless asToken.
func newNetworkHarness(t *testing.T, asToken bool, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeNetwork) {
	t.Helper()
	fake := newFakePBS()
	fake.username = "root@pam"
	network := newFakeNetwork(fake, "localhost", "eno1", "eno2", "eno3")
	if !asToken {
		opts = append(opts, withPasswordSignIn())
	}
	return newProtocolHarness(t, fake, opts...), fake, network
}

// fakePBS408 makes the fake answer as PBS 4.0.22.
const fakeVersion4022 = `{"data":{"release":"22","repoid":"fbe006cdd","version":"4.0"}}`

func TestNetworkResourceSchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, NewNetworkInterfaceResource())
	requireValidResourceSchema(t, NewNetworkApplyResource())
}

func TestNetworkInterfaceBridgeLifecycle(t *testing.T) {
	h, fake, network := newNetworkHarness(t, false)
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{
		"name": "vmbr1", "type": "bridge", "cidr": "198.51.100.2/24", "gateway": "198.51.100.1",
		"comments": "Backup network\n\nsecond paragraph", "mtu": 9000, "bridge_ports": []any{"eno2", "eno1"},
		"bridge_vlan_aware": true,
	})
	// eno1 and eno2 must take the bridge's MTU.
	network.add(&fakeIface{Name: "eno1", Type: "eth", Method: "manual", MTU: ptr(int64(9000))})
	network.add(&fakeIface{Name: "eno2", Type: "eth", Method: "manual", MTU: ptr(int64(9000))})

	inst := h.create(t, "pbs_network_interface", config)
	post := fake.lastCall(t, "POST /nodes/localhost/network").form
	if post.Get("iface") != "vmbr1" || post.Get("type") != "bridge" || post.Get("bridge_ports") != "eno1,eno2" ||
		post.Get("bridge_vlan_aware") != "true" || post.Get("method") != "static" || post.Get("method6") != "manual" ||
		post.Get("autostart") != "true" || post.Get("mtu") != "9000" || post.Has("digest") {
		t.Fatalf("POST = %v", post)
	}
	if stringAt(t, inst.state, "id") != "localhost/vmbr1" || stringAt(t, inst.state, "method") != "static" ||
		stringAt(t, inst.state, "method6") != "manual" || lengthAt(t, inst.state, "options") != 0 ||
		!isNullAt(t, inst.state, "bond_mode") || !boolAt(t, inst.state, "bridge_vlan_aware") {
		t.Fatalf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_network_interface", inst.identity), "name"); got != "vmbr1" {
		t.Fatalf("identity name = %q", got)
	}
	if !network.pendingChanges() || network.runningInterface("vmbr1") != nil {
		t.Fatal("the bridge should be pending, not running")
	}
	requireEmptyPlan(t, h, inst, config)

	// Changing: the gateway goes, IPv6 comes, the comment changes. The
	// IPv4 method follows the address and is never sent.
	config = h.resourceValue(t, "pbs_network_interface", map[string]any{
		"name": "vmbr1", "type": "bridge", "cidr": "198.51.100.2/24", "cidr6": "2001:db8::2/64",
		"comments": "Backup network", "mtu": 9000, "bridge_ports": []any{"eno1"},
	})
	inst = h.update(t, inst, config)
	put := fake.lastCall(t, "PUT /nodes/localhost/network/vmbr1").form
	if put.Get("digest") == "" || put.Has("method") || put.Get("method6") != "static" || put.Get("cidr6") != "2001:db8::2/64" ||
		put.Get("bridge_ports") != "eno1" || strings.Join(put["delete"], ",") != "bridge_vlan_aware,gateway" {
		t.Fatalf("PUT = %v", put)
	}
	requireEmptyPlan(t, h, inst, config)

	// Drift outside Terraform shows.
	network.edit("vmbr1", func(i *fakeIface) { i.Comments = "changed in the web interface" })
	inst = h.refresh(t, inst)
	if stringAt(t, inst.state, "comments") != "changed in the web interface" {
		t.Fatalf("state = %s", inst.state)
	}
	inst = h.update(t, inst, config)

	// Import by id and by identity.
	imported := h.importByID(t, "pbs_network_interface", "localhost/vmbr1")
	requireEmptyPlan(t, h, imported, config)
	imported = h.importByIdentity(t, "pbs_network_interface", map[string]any{"node": "localhost", "name": "vmbr1"})
	requireEmptyPlan(t, h, imported, config)

	h.destroy(t, inst)
	if network.get("vmbr1") != nil {
		t.Fatal("vmbr1 is still configured")
	}
	if del := fake.lastCall(t, "DELETE /nodes/localhost/network/vmbr1"); del.query.Get("digest") == "" {
		t.Fatalf("DELETE = %v", del.query)
	}
}

func TestNetworkInterfaceCreateNeedsRootPam(t *testing.T) {
	h, fake, network := newNetworkHarness(t, true)
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge"})
	// The plan fails, as Terraform keeps only the errors of the create it
	// plans for a forced replacement.
	planned := h.plan(t, "pbs_network_interface", nil, config)
	requireProtocolErrorContaining(t, planned.Diagnostics, "Creating a network interface needs root@pam")
	requireProtocolErrorContaining(t, planned.Diagnostics, "proxmox-backup-manager network create")
	// Should PBS refuse all the same, the error says why.
	fake.username = "admin@pbs"
	adminHarness := newProtocolHarness(t, fake, withPasswordSignIn())
	applied := adminHarness.apply(t, "pbs_network_interface", nil, config, &tfprotov6.PlanResourceChangeResponse{
		PlannedState: dynamicValue(t, h.decodeResource(t, "pbs_network_interface", planned.PlannedState))})
	requireProtocolErrorContaining(t, applied.Diagnostics, "PBS lets only root@pam, signed in with a password, create a network interface")
	if network.get("vmbr1") != nil {
		t.Fatal("vmbr1 was created")
	}

	// A token may take over a physical interface.
	inst := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "eno3", "type": "eth", "comments": "spare"}))
	if stringAt(t, inst.state, "comments") != "spare" {
		t.Fatalf("state = %s", inst.state)
	}
}

func TestNetworkInterfaceBond(t *testing.T) {
	h, fake, network := newNetworkHarness(t, false)
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{
		"name": "bond0", "type": "bond", "slaves": []any{"eno2", "eno1"}, "bond_mode": "active-backup",
		"bond_primary": "eno2",
	})
	inst := h.create(t, "pbs_network_interface", config)
	post := fake.lastCall(t, "POST /nodes/localhost/network").form
	if post.Get("slaves") != "eno2,eno1" || post.Get("bond_mode") != "active-backup" || post.Get("bond-primary") != "eno2" {
		t.Fatalf("POST = %v", post)
	}
	if got := network.get("bond0").Slaves; !slices.Equal(got, []string{"eno2", "eno1"}) {
		t.Fatalf("slaves = %v", got)
	}
	requireEmptyPlan(t, h, inst, config)

	// LACP with a hash policy: the mode goes along, the primary goes.
	config = h.resourceValue(t, "pbs_network_interface", map[string]any{
		"name": "bond0", "type": "bond", "slaves": []any{"eno2", "eno1"}, "bond_mode": "802.3ad",
		"bond_xmit_hash_policy": "layer3+4",
	})
	inst = h.update(t, inst, config)
	put := fake.lastCall(t, "PUT /nodes/localhost/network/bond0").form
	if put.Get("bond_mode") != "802.3ad" || put.Get("bond_xmit_hash_policy") != "layer3+4" || strings.Join(put["delete"], ",") != "bond-primary" {
		t.Fatalf("PUT = %v", put)
	}
	requireEmptyPlan(t, h, inst, config)

	// The default mode, and no slaves.
	config = h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "bond0", "type": "bond"})
	inst = h.update(t, inst, config)
	if stringAt(t, inst.state, "bond_mode") != "balance-rr" || !isNullAt(t, inst.state, "slaves") {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)

	// A slave that is not physical is PBS's to refuse.
	bridge := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr9", "type": "bridge"}))
	planned := h.plan(t, "pbs_network_interface", inst, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "bond0", "type": "bond", "slaves": []any{"vmbr9"}}))
	applied := h.apply(t, "pbs_network_interface", inst, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "bond0", "type": "bond", "slaves": []any{"vmbr9"}}), planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "wrong interface type on slave 'vmbr9'")
	h.destroy(t, bridge)
	h.destroy(t, inst)
}

func TestNetworkInterfaceVLAN(t *testing.T) {
	h, fake, network := newNetworkHarness(t, false)
	bridge := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge"}))

	// The name gives tag and device.
	named := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1.20", "type": "vlan", "cidr": "203.0.113.2/24"})
	inst := h.create(t, "pbs_network_interface", named)
	post := fake.lastCall(t, "POST /nodes/localhost/network").form
	if post.Has("vlan-id") || post.Has("vlan-raw-device") {
		t.Fatalf("POST = %v", post)
	}
	if !isNullAt(t, inst.state, "vlan_id") || !isNullAt(t, inst.state, "vlan_raw_device") {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, named)
	h.destroy(t, inst)

	// Another name needs both; removing the tag replaces the interface.
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "storage", "type": "vlan", "vlan_id": 30, "vlan_raw_device": "vmbr1"})
	inst = h.create(t, "pbs_network_interface", config)
	if got := network.get("storage"); got.VLANID == nil || *got.VLANID != 30 || got.VLANRawDevice != "vmbr1" {
		t.Fatalf("storage = %+v", got)
	}
	config = h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "storage", "type": "vlan", "vlan_id": 31, "vlan_raw_device": "vmbr1"})
	inst = h.update(t, inst, config)
	if put := fake.lastCall(t, "PUT /nodes/localhost/network/storage").form; put.Get("vlan-id") != "31" || put.Has("vlan-raw-device") {
		t.Fatalf("PUT = %v", put)
	}
	// Adding a tag to a name that gives it is an update; PBS cannot remove
	// the tag or the device, so removing either alone replaces the
	// interface.
	both := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1.20", "type": "vlan", "vlan_id": 20, "vlan_raw_device": "vmbr1"})
	tagged := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1.20", "type": "vlan"}))
	planned := h.plan(t, "pbs_network_interface", tagged, both)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 0 {
		t.Fatalf("RequiresReplace = %v", planned.RequiresReplace)
	}
	tagged = h.update(t, tagged, both)
	for removed, config := range map[string]map[string]any{
		"vlan_id":         {"name": "vmbr1.20", "type": "vlan", "vlan_raw_device": "vmbr1"},
		"vlan_raw_device": {"name": "vmbr1.20", "type": "vlan", "vlan_id": 20},
	} {
		planned := h.plan(t, "pbs_network_interface", tagged, h.resourceValue(t, "pbs_network_interface", config))
		requireNoProtocolErrors(t, planned.Diagnostics)
		if len(planned.RequiresReplace) != 1 || planned.RequiresReplace[0].String() != tftypes.NewAttributePath().WithAttributeName(removed).String() {
			t.Fatalf("removing %s: RequiresReplace = %v", removed, planned.RequiresReplace)
		}
	}
	h.destroy(t, tagged)
	// PBS checks the device a name gives on every change.
	network.mu.Lock()
	network.pending = slices.DeleteFunc(network.pending, func(i *fakeIface) bool { return i.Name == "vmbr1" })
	network.pending = append(network.pending, &fakeIface{Name: "eno9.5", Type: "vlan", Method: "manual"})
	network.mu.Unlock()
	imported := h.importByID(t, "pbs_network_interface", "localhost/eno9.5")
	planned = h.plan(t, "pbs_network_interface", imported, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "eno9.5", "type": "vlan", "comments": "x"}))
	applied := h.apply(t, "pbs_network_interface", imported, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "eno9.5", "type": "vlan", "comments": "x"}), planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "vlan-raw-device eno9 does not exist")
	network.mu.Lock()
	network.pending = slices.DeleteFunc(network.pending, func(i *fakeIface) bool { return i.Name == "eno9.5" })
	network.pending = append(network.pending, &fakeIface{Name: "vmbr1", Type: "bridge", Method: "manual"})
	network.mu.Unlock()
	h.destroy(t, inst)
	h.destroy(t, bridge)
}

func TestNetworkInterfaceValidation(t *testing.T) {
	h, _, _ := newNetworkHarness(t, false)
	for _, tc := range []struct {
		name   string
		config map[string]any
		want   string
	}{
		{"static without address", map[string]any{"name": "vmbr1", "type": "bridge", "method": "static"}, "Static method without an address"},
		{"dhcp with address", map[string]any{"name": "vmbr1", "type": "bridge", "method": "dhcp", "cidr": "192.0.2.1/24"}, "Address with another method than static"},
		{"dhcp6 with address", map[string]any{"name": "vmbr1", "type": "bridge", "method6": "auto", "cidr6": "2001:db8::1/64"}, "Address with another method than static"},
		{"dhcp on eth", map[string]any{"name": "eno1", "type": "eth", "method": "dhcp"}, "DHCP on a physical interface"},
		{"ports of a bond", map[string]any{"name": "bond0", "type": "bond", "bridge_ports": []any{"eno1"}}, "only for interfaces of type \"bridge\""},
		{"vlan tag on a bridge", map[string]any{"name": "vmbr1", "type": "bridge", "vlan_id": 5}, "only for interfaces of type \"vlan\""},
		{"bridge with a VLAN name", map[string]any{"name": "vmbr0.5", "type": "bridge"}, "Name of a VLAN interface"},
		{"vlan without tag", map[string]any{"name": "storage", "type": "vlan", "vlan_raw_device": "eno1"}, "Missing VLAN tag"},
		{"vlan without device", map[string]any{"name": "vlan5", "type": "vlan"}, "Missing VLAN device"},
		{"vlan tag differs", map[string]any{"name": "eno1.5", "type": "vlan", "vlan_id": 6}, "VLAN tag differs from the name"},
		{"vlan device differs", map[string]any{"name": "eno1.5", "type": "vlan", "vlan_raw_device": "eno2"}, "VLAN device differs from the name"},
		{"primary without active-backup", map[string]any{"name": "bond0", "type": "bond", "slaves": []any{"eno1"}, "bond_primary": "eno1"}, "Bond primary without active-backup"},
		{"primary not a slave", map[string]any{"name": "bond0", "type": "bond", "bond_mode": "active-backup", "slaves": []any{"eno1"}, "bond_primary": "eno2"}, "Bond primary is not a slave"},
		{"hash policy of balance-rr", map[string]any{"name": "bond0", "type": "bond", "bond_xmit_hash_policy": "layer2"}, "Transmit hash policy of another bond mode"},
		{"comments with padding", map[string]any{"name": "vmbr1", "type": "bridge", "comments": "a \nb"}, "no line may begin or end with white space"},
		{"comments ending in a line break", map[string]any{"name": "vmbr1", "type": "bridge", "comments": "a\n"}, "must not begin or end with a line"},
		{"IPv6 as cidr", map[string]any{"name": "vmbr1", "type": "bridge", "cidr": "2001:db8::1/64"}, "Invalid IPv4 address"},
		{"no prefix", map[string]any{"name": "vmbr1", "type": "bridge", "cidr": "192.0.2.1"}, "Invalid IPv4 address"},
		{"lo", map[string]any{"name": "lo", "type": "eth"}, "lo"},
		{"long name", map[string]any{"name": "abcdefghijklmnop", "type": "bridge"}, "length"},
		{"small mtu", map[string]any{"name": "vmbr1", "type": "bridge", "mtu": 60}, "68"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := h.validateResource(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface", tc.config))
			requireProtocolErrorContaining(t, diags, tc.want)
		})
	}

	diags := h.validateResource(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "vmbr1", "type": "bridge", "cidr": "192.0.2.10/24", "gateway": "198.51.100.1"}))
	requireNoProtocolErrors(t, diags)
	requireProtocolWarningContaining(t, diags, "Gateway outside the interface's network")
}

// Taking over a physical interface sets what the configuration says,
// removes what it leaves out with a warning, keeps the lines PBS does not
// interpret, and destroying it resets it.
func TestNetworkInterfaceTakeOverPhysical(t *testing.T) {
	h, fake, network := newNetworkHarness(t, true)
	network.add(&fakeIface{Name: "eno1", Type: "eth", Method: "manual", Method6: "manual", MTU: ptr(int64(9000)),
		Comments: "uplink", Options: []string{"post-up ethtool -K eno1 tso off"}})
	network.add(&fakeIface{Name: "vmbr0", Type: "bridge", Autostart: true, Method: "static", CIDR: "192.0.2.10/24",
		Gateway: "192.0.2.1", BridgePorts: []string{"eno1"}, MTU: ptr(int64(9000))})

	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno1", "type": "eth", "autostart": false, "comments": "Uplink of vmbr0"})
	// The plan reads the interface: it settles the methods and shows what
	// the takeover removes.
	planned := h.plan(t, "pbs_network_interface", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "mtu 9000 removed")
	if got := stringAt(t, h.decodeResource(t, "pbs_network_interface", planned.PlannedState), "method"); got != "manual" {
		t.Fatalf("planned method = %q", got)
	}
	applied := h.apply(t, "pbs_network_interface", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "mtu 9000 removed")
	inst := &resourceInstance{typeName: "pbs_network_interface", state: h.decodeResource(t, "pbs_network_interface", applied.NewState), identity: applied.NewIdentity}
	if fake.count("POST /nodes/localhost/network") != 0 {
		t.Fatal("a takeover must not create")
	}
	eno1 := network.get("eno1")
	if eno1.MTU != nil || eno1.Comments != "Uplink of vmbr0" || !slices.Equal(eno1.Options, []string{"post-up ethtool -K eno1 tso off"}) {
		t.Fatalf("eno1 = %+v", eno1)
	}
	if got := valueAt(t, inst.state, "options"); got.String() == "" || lengthAt(t, inst.state, "options") != 1 {
		t.Fatalf("options = %s", got)
	}
	requireEmptyPlan(t, h, inst, config)

	// Destroying resets it, keeping the stanza vmbr0 needs.
	h.destroy(t, inst)
	eno1 = network.get("eno1")
	if eno1 == nil || eno1.Comments != "" || eno1.Method != "manual" || eno1.Autostart || len(eno1.Options) != 1 {
		t.Fatalf("eno1 = %+v", eno1)
	}
	if put := fake.lastCall(t, "PUT /nodes/localhost/network/eno1").form; strings.Join(put["delete"], ",") !=
		"autostart,cidr,cidr6,comments,comments6,gateway,gateway6,method6,mtu" {
		t.Fatalf("PUT = %v", put)
	}

	// An interface the node does not have cannot be taken over.
	planned = h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno9", "type": "eth"}))
	applied = h.apply(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno9", "type": "eth"}), planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "has no interface eno9")
}

// PBS's PUT turns IPv4 DHCP into manual, so the provider refuses to let it.
func TestNetworkInterfaceDHCP(t *testing.T) {
	h, _, network := newNetworkHarness(t, false)
	network.add(&fakeIface{Name: "eno1", Type: "eth", Autostart: true, Method: "dhcp", Method6: "auto"})

	// A takeover that would drop DHCP fails in the plan.
	planned := h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno1", "type": "eth"}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "has the IPv4 method \"dhcp\"")
	if network.get("eno1").Method != "dhcp" {
		t.Fatal("eno1 changed")
	}

	// Saying so explicitly gives it up, and keeps IPv6 auto on 4.2.8.
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno1", "type": "eth", "method": "manual"})
	inst := h.create(t, "pbs_network_interface", config)
	if got := network.get("eno1"); got.Method != "manual" || got.Method6 != "auto" {
		t.Fatalf("eno1 = %+v", got)
	}
	if stringAt(t, inst.state, "method6") != "auto" {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)

	// A new bridge may use DHCP; changing it afterwards replaces it.
	config = h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge", "method": "dhcp"})
	bridge := h.create(t, "pbs_network_interface", config)
	if network.get("vmbr1").Method != "dhcp" {
		t.Fatal("vmbr1 lost DHCP")
	}
	requireEmptyPlan(t, h, bridge, config)
	changed := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge", "method": "dhcp", "comments": "x"})
	planned = h.plan(t, "pbs_network_interface", bridge, changed)
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "by replacing the interface")
	if len(planned.RequiresReplace) != 1 || planned.RequiresReplace[0].String() != tftypes.NewAttributePath().WithAttributeName("comments").String() {
		t.Fatalf("RequiresReplace = %v", planned.RequiresReplace)
	}
	// Terraform then deletes it and plans a create: PBS keeps DHCP.
	h.destroy(t, bridge)
	bridge = h.create(t, "pbs_network_interface", changed)
	if got := network.get("vmbr1"); got.Method != "dhcp" || got.Comments != "x" {
		t.Fatalf("vmbr1 = %+v", got)
	}
	// Leaving the method out keeps DHCP, and fails the plan of a change.
	planned = h.plan(t, "pbs_network_interface", bridge, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "vmbr1", "type": "bridge", "comments": "y"}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "PBS cannot change an interface with this IPv4 method")
	requireProtocolErrorContaining(t, planned.Diagnostics, "Set `method = \"dhcp\"` in the configuration")
	// Giving it up is fine.
	h.update(t, bridge, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "vmbr1", "type": "bridge", "method": "manual", "comments": "x"}))
	if network.get("vmbr1").Method != "manual" {
		t.Fatal("vmbr1 should be manual")
	}
}

// Before 4.1.7 PBS turns IPv6 DHCP and SLAAC into manual on any change.
func TestNetworkInterfaceIPv6MethodsOnOldPBS(t *testing.T) {
	fake := newFakePBS()
	fake.username = "root@pam"
	fake.reply("GET /version", http.StatusOK, fakeVersion4022)
	network := newFakeNetwork(fake, "localhost", "eno1")
	network.keepMethod6 = false
	h := newProtocolHarness(t, fake, withPasswordSignIn())

	diags := h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "vmbr1", "type": "bridge", "method6": "dhcp"})).Diagnostics
	requireProtocolErrorContaining(t, diags, "needs PBS 4.1.7 or newer")
	diags = h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "vmbr1", "type": "bridge", "method6": "auto"})).Diagnostics
	requireProtocolErrorContaining(t, diags, "needs PBS 4.2.7 or newer")

	network.add(&fakeIface{Name: "eno1", Type: "eth", Method: "manual", Method6: "dhcp"})
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno1", "type": "eth"})
	planned := h.plan(t, "pbs_network_interface", nil, config)
	requireProtocolErrorContaining(t, planned.Diagnostics, "PBS before 4.1.7")

	// Imported, the method shows, and a change fails the plan.
	inst := h.importByID(t, "pbs_network_interface", "localhost/eno1")
	if stringAt(t, inst.state, "method6") != "dhcp" {
		t.Fatalf("state = %s", inst.state)
	}
	diags = h.plan(t, "pbs_network_interface", inst, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "eno1", "type": "eth", "autostart": false, "comments": "x"})).Diagnostics
	requireProtocolErrorContaining(t, diags, "PBS cannot change an interface with this IPv6 method")
}

func TestNetworkInterfaceErrors(t *testing.T) {
	h, _, network := newNetworkHarness(t, false)
	network.add(&fakeIface{Name: "vmbr0", Type: "bridge", Method: "static", CIDR: "192.0.2.10/24", Gateway: "192.0.2.1"})

	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge", "cidr": "198.51.100.2/24", "gateway": "198.51.100.1"})
	planned := h.plan(t, "pbs_network_interface", nil, config)
	applied := h.apply(t, "pbs_network_interface", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "one default gateway per address family")

	config = h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr0", "type": "bridge"})
	planned = h.plan(t, "pbs_network_interface", nil, config)
	applied = h.apply(t, "pbs_network_interface", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Import it")

	// A bridge port that is in use cannot be deleted.
	port := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "bond0", "type": "bond", "slaves": []any{"eno1"}}))
	network.edit("vmbr0", func(i *fakeIface) { i.BridgePorts = []string{"bond0"} })
	planned = h.plan(t, "pbs_network_interface", port, tftypes.NewValue(h.resourceType(t, "pbs_network_interface"), nil))
	applied = h.apply(t, "pbs_network_interface", port, tftypes.NewValue(h.resourceType(t, "pbs_network_interface"), nil), planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "unable to find port 'bond0'")

	// An interface removed outside Terraform leaves the state.
	network.edit("vmbr0", func(i *fakeIface) { i.BridgePorts = nil })
	network.mu.Lock()
	network.pending = slices.DeleteFunc(network.pending, func(i *fakeIface) bool { return i.Name == "bond0" })
	network.mu.Unlock()
	if gone := h.refresh(t, port); !gone.state.IsNull() {
		t.Fatalf("state = %s", gone.state)
	}
}

func TestNetworkApplyLifecycle(t *testing.T) {
	h, fake, network := newNetworkHarness(t, true)
	network.edit("eno1", func(i *fakeIface) { i.Autostart = true })

	// Creating applies what is pending.
	config := h.resourceValue(t, "pbs_network_apply", map[string]any{"triggers": map[string]any{"eno1": "1"}})
	inst := h.create(t, "pbs_network_apply", config)
	if network.pendingChanges() || network.reloads != 1 || network.runningInterface("eno1") == nil || !network.runningInterface("eno1").Autostart {
		t.Fatalf("pending = %v, reloads = %d", network.pendingChanges(), network.reloads)
	}
	if stringAt(t, inst.state, "id") != "localhost" || !isNullAt(t, inst.state, "pending_changes") {
		t.Fatalf("state = %s", inst.state)
	}
	if fake.count("PUT /nodes/localhost/network") != 1 {
		t.Fatalf("routes = %v", fake.routes())
	}
	requireEmptyPlan(t, h, inst, config)

	// Changes made elsewhere show on refresh and plan an apply, with a
	// warning that quotes them.
	network.edit("eno1", func(i *fakeIface) { i.Comments = "made in the web interface" })
	inst = h.refresh(t, inst)
	if !strings.Contains(stringAt(t, inst.state, "pending_changes"), "#made in the web interface") {
		t.Fatalf("state = %s", inst.state)
	}
	planned := h.plan(t, "pbs_network_apply", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "#made in the web interface")
	if !isUnknownAt(t, h.decodeResource(t, "pbs_network_apply", planned.PlannedState), "pending_changes") {
		t.Fatal("pending changes should plan an apply")
	}
	inst = h.update(t, inst, config)
	if network.pendingChanges() || network.reloads != 2 {
		t.Fatalf("pending = %v, reloads = %d", network.pendingChanges(), network.reloads)
	}
	requireEmptyPlan(t, h, inst, config)

	// Changed triggers apply again, even with nothing pending.
	config = h.resourceValue(t, "pbs_network_apply", map[string]any{"triggers": map[string]any{"eno1": "2"}})
	inst = h.update(t, inst, config)
	if network.reloads != 3 {
		t.Fatalf("reloads = %d", network.reloads)
	}

	// Destroying changes nothing, and warns when changes stay pending.
	network.edit("eno1", func(i *fakeIface) { i.Comments = "pending" })
	inst = h.refresh(t, inst)
	planned = h.plan(t, "pbs_network_apply", inst, tftypes.NewValue(h.resourceType(t, "pbs_network_apply"), nil))
	requireProtocolWarningContaining(t, planned.Diagnostics, "they stay pending")
	h.destroy(t, inst)
	if network.reloads != 3 || !network.pendingChanges() {
		t.Fatalf("reloads = %d", network.reloads)
	}
}

func TestNetworkApplyErrors(t *testing.T) {
	h, _, network := newNetworkHarness(t, true)
	config := h.resourceValue(t, "pbs_network_apply", map[string]any{})

	network.ifupdown2 = false
	planned := h.plan(t, "pbs_network_apply", nil, config)
	applied := h.apply(t, "pbs_network_apply", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Install ifupdown2")

	network.ifupdown2 = true
	network.reloadError = "error: vmbr1: cmd '/sbin/ip link set dev vmbr1 mtu 9000' failed"
	network.edit("eno1", func(i *fakeIface) { i.Comments = "x" })
	planned = h.plan(t, "pbs_network_apply", nil, config)
	applied = h.apply(t, "pbs_network_apply", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "PBS keeps no copy of the previous one")
	requireProtocolErrorContaining(t, applied.Diagnostics, "vmbr1 mtu 9000")
	if network.pendingChanges() {
		t.Fatal("PBS moves the file before ifreload")
	}

	// Without /etc/network/interfaces, PBS cannot show the changes, and
	// the resource applies them all the same.
	network.reloadError = ""
	inst := h.create(t, "pbs_network_apply", config)
	network.mu.Lock()
	network.hasRunningFile = false
	network.mu.Unlock()
	network.edit("eno1", func(i *fakeIface) { i.Comments = "y" })
	read := h.read(t, inst)
	requireProtocolWarningContaining(t, read.Diagnostics, "PBS cannot show the pending network changes")
	inst.state = h.decodeResource(t, "pbs_network_apply", read.NewState)
	inst = h.update(t, inst, config)
	if network.pendingChanges() || !isNullAt(t, inst.state, "pending_changes") {
		t.Fatalf("the changes should be applied; state = %s", inst.state)
	}
}

// The whole flow: an interface, then the apply that its triggers order
// after it.
func TestNetworkInterfaceAndApply(t *testing.T) {
	h, _, network := newNetworkHarness(t, false)
	bridge := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "vmbr1", "type": "bridge", "cidr": "198.51.100.2/24"}))
	h.create(t, "pbs_network_apply", h.resourceValue(t, "pbs_network_apply", map[string]any{"triggers": map[string]any{"vmbr1": stringAt(t, bridge.state, "id")}}))
	if network.runningInterface("vmbr1") == nil || network.pendingChanges() {
		t.Fatal("vmbr1 should be running")
	}
	// Reading after the reload, nothing changes.
	refreshed := h.refresh(t, bridge)
	if !refreshed.state.Equal(bridge.state) {
		diffs, _ := refreshed.state.Diff(bridge.state)
		t.Fatalf("refresh changed %v", diffs)
	}
}

func ptr[T any](v T) *T { return &v }

// networkTransport wraps the fake: it can fail the polls of tasks, as a
// node does while a reload rebuilds the path to it or once a reload cut it
// off, answer them as running, fail the reads that follow a write, and
// change an interface outside Terraform right before the first change of an
// interface arrives.
type networkTransport struct {
	fake        *fakePBS
	network     *fakeNetwork
	cutOff      bool
	failPolls   int
	running     bool
	failReads   bool
	interfering func()

	mu      sync.Mutex
	written bool
}

func (n *networkTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	unreachable := errors.New("dial tcp 192.0.2.10:8007: connect: no route to host")
	if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/tasks/") {
		switch {
		case n.cutOff:
			return nil, unreachable
		case n.failPolls > 0:
			n.failPolls--
			return nil, unreachable
		case n.running:
			rec := httptest.NewRecorder()
			writeData(rec, map[string]any{"status": "running"}, "")
			return rec.Result(), nil
		}
	}
	if req.Method == http.MethodGet && n.failReads && n.written && strings.Contains(req.URL.Path, "/network") {
		rec := httptest.NewRecorder()
		writeFakeResponse(rec, http.StatusInternalServerError, "temporarily unavailable")
		return rec.Result(), nil
	}
	if req.Method != http.MethodGet && strings.Contains(req.URL.Path, "/network") {
		n.written = true
	}
	if req.Method == http.MethodPut && strings.Contains(req.URL.Path, "/network/") && n.interfering != nil {
		interfere := n.interfering
		n.interfering = nil
		interfere()
	}
	return n.fake.RoundTrip(req)
}

func TestNetworkApplyLosesContact(t *testing.T) {
	fake := newFakePBS()
	network := newFakeNetwork(fake, "localhost", "eno1")
	transport := &networkTransport{fake: fake, network: network, cutOff: true}
	h := newProtocolHarness(t, fake, withTransport(transport), withTaskTimeout("1s"))

	config := h.resourceValue(t, "pbs_network_apply", map[string]any{})
	planned := h.plan(t, "pbs_network_apply", nil, config)
	applied := h.apply(t, "pbs_network_apply", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "lost contact with it while waiting for the task")
	requireProtocolErrorContaining(t, applied.Diagnostics, "UPID:localhost:")
}

// A change made elsewhere between the read and the write is a digest
// conflict, which the resource reads anew and retries.
func TestNetworkInterfaceRetriesOnDigestConflict(t *testing.T) {
	fake := newFakePBS()
	fake.username = "root@pam"
	network := newFakeNetwork(fake, "localhost", "eno1")
	transport := &networkTransport{fake: fake, network: network}
	h := newProtocolHarness(t, fake, withPasswordSignIn(), withTransport(transport))

	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge"})
	inst := h.create(t, "pbs_network_interface", config)
	transport.interfering = func() { network.edit("eno1", func(i *fakeIface) { i.Comments = "edited meanwhile" }) }
	config = h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge", "comments": "changed"})
	h.update(t, inst, config)
	if fake.count("PUT /nodes/localhost/network/vmbr1") != 2 {
		t.Fatalf("routes = %v", fake.routes())
	}
	if network.get("vmbr1").Comments != "changed" || network.get("eno1").Comments != "edited meanwhile" {
		t.Fatal("both changes should be kept")
	}
}

// A reload that makes the node unreachable for a while is waited out.
func TestNetworkApplyWaitsOutAnOutage(t *testing.T) {
	fake := newFakePBS()
	network := newFakeNetwork(fake, "localhost", "eno1")
	transport := &networkTransport{fake: fake, network: network, failPolls: 2}
	h := newProtocolHarness(t, fake, withTransport(transport))
	network.edit("eno1", func(i *fakeIface) { i.Comments = "x" })
	h.create(t, "pbs_network_apply", h.resourceValue(t, "pbs_network_apply", map[string]any{}))
	if network.pendingChanges() || network.reloads != 1 {
		t.Fatalf("pending = %v, reloads = %d", network.pendingChanges(), network.reloads)
	}
}

func TestNetworkApplyTaskTimeout(t *testing.T) {
	fake := newFakePBS()
	network := newFakeNetwork(fake, "localhost", "eno1")
	transport := &networkTransport{fake: fake, network: network, running: true}
	h := newProtocolHarness(t, fake, withTransport(transport), withTaskTimeout("1s"))
	config := h.resourceValue(t, "pbs_network_apply", map[string]any{})
	applied := h.apply(t, "pbs_network_apply", nil, config, h.plan(t, "pbs_network_apply", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "is still running")
}

// Reads that fail after a write leave the planned values in state, with a
// warning, and the next refresh reads them.
func TestNetworkReadBackFailures(t *testing.T) {
	fake := newFakePBS()
	fake.username = "root@pam"
	network := newFakeNetwork(fake, "localhost", "eno1")
	transport := &networkTransport{fake: fake, network: network, failReads: true}
	h := newProtocolHarness(t, fake, withPasswordSignIn(), withTransport(transport))

	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge", "comments": "x"})
	planned := h.plan(t, "pbs_network_interface", nil, config)
	applied := h.apply(t, "pbs_network_interface", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "Unable to read the PBS network interface back")
	inst := &resourceInstance{typeName: "pbs_network_interface", state: h.decodeResource(t, "pbs_network_interface", applied.NewState), identity: applied.NewIdentity}
	requireAppliedCompatible(t, h.decodeResource(t, "pbs_network_interface", planned.PlannedState), inst.state)
	if lengthAt(t, inst.state, "options") != 0 || stringAt(t, inst.state, "method") != "manual" {
		t.Fatalf("state = %s", inst.state)
	}

	applyConfig := h.resourceValue(t, "pbs_network_apply", map[string]any{})
	applied = h.apply(t, "pbs_network_apply", nil, applyConfig, h.plan(t, "pbs_network_apply", nil, applyConfig))
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "Unable to read the PBS network configuration back")
	if !isNullAt(t, h.decodeResource(t, "pbs_network_apply", applied.NewState), "pending_changes") {
		t.Fatal("pending_changes should be null")
	}

	transport.mu.Lock()
	transport.failReads = false
	transport.mu.Unlock()
	inst = h.refresh(t, inst)
	requireEmptyPlan(t, h, inst, config)
}

// A takeover shows in the plan what it changes, and refuses to remove
// addresses the configuration does not give up.
func TestNetworkInterfaceTakeOverAddresses(t *testing.T) {
	h, _, network := newNetworkHarness(t, true)
	// As the PBS installer leaves the management interface.
	network.add(&fakeIface{Name: "eno1", Type: "eth", Autostart: true, Method: "static", CIDR: "192.0.2.10/24",
		Gateway: "192.0.2.1", Method6: "static", CIDR6: "2001:db8::10/64"})
	network.add(&fakeIface{Name: "eno2", Type: "eth", Method: "manual"})

	planned := h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno1", "type": "eth", "mtu": 9000}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "cidr 192.0.2.10/24 removed, gateway 192.0.2.1 removed")
	requireProtocolErrorContaining(t, planned.Diagnostics, "Import the interface")
	planned = h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "eno1", "type": "eth", "method": "manual", "mtu": 9000}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "cidr6 2001:db8::10/64 removed")

	// Giving them up explicitly, the plan warns.
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno1", "type": "eth", "method": "manual", "method6": "manual"})
	planned = h.plan(t, "pbs_network_interface", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "cidr 192.0.2.10/24 removed")
	inst := h.create(t, "pbs_network_interface", config)
	if got := network.get("eno1"); got.CIDR != "" || got.Gateway != "" || got.CIDR6 != "" || got.Method != "manual" {
		t.Fatalf("eno1 = %+v", got)
	}

	// Keeping them is no change.
	kept := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno1", "type": "eth",
		"cidr": "192.0.2.10/24", "gateway": "192.0.2.1", "comments": "Management"})
	h.destroy(t, inst)
	network.edit("eno1", func(i *fakeIface) {
		i.Method, i.CIDR, i.Gateway, i.Method6, i.CIDR6 = "static", "192.0.2.10/24", "192.0.2.1", "static", "2001:db8::10/64"
	})
	planned = h.plan(t, "pbs_network_interface", nil, kept)
	requireProtocolErrorContaining(t, planned.Diagnostics, "cidr6 2001:db8::10/64 removed")

	// A NIC without an auto line gets one, by default, with a warning.
	planned = h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno2", "type": "eth"}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "autostart turned on")

	// The node does not have it.
	planned = h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno7", "type": "eth"}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "has no interface eno7")
}

// Destroying an interface with addresses warns that they go.
func TestNetworkInterfaceDestroyWarns(t *testing.T) {
	h, _, network := newNetworkHarness(t, false)
	network.add(&fakeIface{Name: "eno1", Type: "eth", Autostart: true, Method: "static", CIDR: "192.0.2.10/24"})
	bridge := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge", "cidr": "198.51.100.2/24"}))
	nic := h.importByID(t, "pbs_network_interface", "localhost/eno1")

	null := tftypes.NewValue(h.resourceType(t, "pbs_network_interface"), nil)
	diags := h.plan(t, "pbs_network_interface", bridge, null).Diagnostics
	requireProtocolWarningContaining(t, diags, "deletes it from the pending configuration, and with it 198.51.100.2/24")
	requireProtocolWarningContaining(t, diags, "removed block")
	diags = h.plan(t, "pbs_network_interface", nic, null).Diagnostics
	requireProtocolWarningContaining(t, diags, "resets it to method manual, removing 192.0.2.10/24")

	// Without addresses, nothing to warn about.
	plain := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr2", "type": "bridge"}))
	if diags := h.plan(t, "pbs_network_interface", plain, null).Diagnostics; len(diags) != 0 {
		t.Fatalf("diagnostics = %v", diags)
	}
}

// A replacement deletes before it creates: with a token, the plan fails;
// with root@pam, it warns about the lines the new interface will not have.
func TestNetworkInterfaceReplacement(t *testing.T) {
	h, _, network := newNetworkHarness(t, true)
	network.add(&fakeIface{Name: "vmbr1", Type: "bridge", Method: "manual", Options: []string{"bridge-stp off"}})
	inst := h.importByID(t, "pbs_network_interface", "localhost/vmbr1")
	diags := h.plan(t, "pbs_network_interface", inst, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bond"})).Diagnostics
	requireProtocolErrorContaining(t, diags, "Replacing a network interface needs root@pam")
	requireProtocolWarningContaining(t, diags, "bridge-stp off")

	h, _, network = newNetworkHarness(t, false)
	network.add(&fakeIface{Name: "vmbr1", Type: "bridge", Method: "manual", Options: []string{"bridge-stp off"}})
	inst = h.importByID(t, "pbs_network_interface", "localhost/vmbr1")
	diags = h.plan(t, "pbs_network_interface", inst, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr9", "type": "bridge"})).Diagnostics
	requireNoProtocolErrors(t, diags)
	requireProtocolWarningContaining(t, diags, "bridge-stp off")
}

// A bond the configuration gives no mode is planned with PBS's default,
// also when it has another one.
func TestNetworkInterfaceBondModeDefault(t *testing.T) {
	h, _, _ := newNetworkHarness(t, false)
	inst := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "bond0", "type": "bond", "slaves": []any{"eno1", "eno2"}, "bond_mode": "802.3ad"}))
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "bond0", "type": "bond", "slaves": []any{"eno1", "eno2"}})
	planned := h.plan(t, "pbs_network_interface", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if got := stringAt(t, h.decodeResource(t, "pbs_network_interface", planned.PlannedState), "bond_mode"); got != "balance-rr" {
		t.Fatalf("planned bond_mode = %q", got)
	}
	// The slaves' order is the configuration's.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "bond0", "type": "bond", "slaves": []any{"eno2", "eno1"}}))
	if got := stringAt(t, inst.state, "slaves", 0); got != "eno2" {
		t.Fatalf("state = %s", inst.state)
	}
}

// Values unknown when planning stay unknown, and validation copes with
// them.
func TestNetworkInterfaceUnknownValues(t *testing.T) {
	h, _, _ := newNetworkHarness(t, false)
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge", "method": tfUnknown, "method6": tfUnknown})
	planned := h.plan(t, "pbs_network_interface", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	plannedState := h.decodeResource(t, "pbs_network_interface", planned.PlannedState)
	requirePlanValid(t, h.resourceSchema(t, "pbs_network_interface").Block, tftypes.NewValue(h.resourceType(t, "pbs_network_interface"), nil), config, plannedState)
	if !isUnknownAt(t, plannedState, "method") || !isUnknownAt(t, plannedState, "method6") {
		t.Fatalf("planned = %s", plannedState)
	}

	requireNoProtocolErrors(t, h.validateResource(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "bond0", "type": "bond", "slaves": []any{tfUnknown, "eno2"}, "bond_mode": "active-backup", "bond_primary": "eno1"})))
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "bond0", "type": "bond", "slaves": []any{tfUnknown, "bond0"}})), "Bond slave is the bond")
}

func TestNetworkInterfaceVLANTagRange(t *testing.T) {
	h, _, _ := newNetworkHarness(t, false)
	for _, name := range []string{"eno1.4095", "vlan0", "eno1.0"} {
		diags := h.validateResource(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface",
			map[string]any{"name": name, "type": "vlan", "vlan_raw_device": "eno1"}))
		requireProtocolErrorContaining(t, diags, "VLAN tag out of range")
	}
}

// Removing all ports of a bridge deletes them, and IPv6 comments make PBS
// write an inet6 stanza and keep them.
func TestNetworkInterfaceBridgePortsAndComments6(t *testing.T) {
	h, fake, network := newNetworkHarness(t, false)
	inst := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "vmbr1", "type": "bridge", "bridge_ports": []any{"eno1"}, "comments6": "IPv6\nside"}))
	if got := network.get("vmbr1"); got.Comments6 != "IPv6\nside" || stringAt(t, inst.state, "method6") != "manual" {
		t.Fatalf("vmbr1 = %+v, state = %s", got, inst.state)
	}
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge"})
	inst = h.update(t, inst, config)
	put := fake.lastCall(t, "PUT /nodes/localhost/network/vmbr1").form
	if strings.Join(put["delete"], ",") != "bridge_ports,comments6" {
		t.Fatalf("PUT = %v", put)
	}
	if !isNullAt(t, inst.state, "bridge_ports") || !isNullAt(t, inst.state, "comments6") {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)
}

// Creating the apply resource warns about changes already pending.
func TestNetworkApplyCreateWarnsAboutPendingChanges(t *testing.T) {
	h, _, network := newNetworkHarness(t, true)
	config := h.resourceValue(t, "pbs_network_apply", map[string]any{})
	if diags := h.plan(t, "pbs_network_apply", nil, config).Diagnostics; len(diags) != 0 {
		t.Fatalf("diagnostics = %v", diags)
	}
	network.edit("eno1", func(i *fakeIface) { i.Comments = "left in the web interface" })
	requireProtocolWarningContaining(t, h.plan(t, "pbs_network_apply", nil, config).Diagnostics, "#left in the web interface")
}

// Updating an interface whose configured method is not known yet fails
// the plan: whether the change replaces it depends on the method.
func TestNetworkInterfaceUnknownMethodOnUpdate(t *testing.T) {
	h, _, _ := newNetworkHarness(t, false)
	inst := h.create(t, "pbs_network_interface", h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "vmbr1", "type": "bridge"}))
	diags := h.plan(t, "pbs_network_interface", inst, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "vmbr1", "type": "bridge", "method": tfUnknown, "comments": "x"})).Diagnostics
	requireProtocolErrorContaining(t, diags, "IPv4 method unknown when planning")
}

// The takeover refusal names the method the configuration can set.
func TestNetworkInterfaceTakeOverAdvice(t *testing.T) {
	h, _, network := newNetworkHarness(t, true)
	network.add(&fakeIface{Name: "eno1", Type: "eth", Method: "static", CIDR: "192.0.2.10/24", Gateway: "192.0.2.1"})
	diags := h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface",
		map[string]any{"name": "eno1", "type": "eth", "cidr": "192.0.2.10/24"})).Diagnostics
	requireProtocolErrorContaining(t, diags, "gateway 192.0.2.1 removed")
	requireProtocolErrorContaining(t, diags, `set method = "static"`)
}

// A plan that cannot read the interface it takes over fails, rather than
// leaving the methods to an apply-time plan that might read them.
func TestNetworkInterfaceTakeOverReadFailure(t *testing.T) {
	h, fake, _ := newNetworkHarness(t, true)
	fake.reply("GET /nodes/localhost/network/eno1", http.StatusInternalServerError, "temporarily unavailable")
	diags := h.plan(t, "pbs_network_interface", nil, h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno1", "type": "eth"})).Diagnostics
	requireProtocolErrorContaining(t, diags, "Unable to read the PBS network interface")
}

// Resetting a physical interface keeps an IPv6 method PBS keeps, so that
// taking the same NIC over again plans as before.
func TestNetworkInterfaceResetKeepsSelfConfiguringIPv6(t *testing.T) {
	h, fake, network := newNetworkHarness(t, true)
	network.add(&fakeIface{Name: "eno1", Type: "eth", Method: "manual", Method6: "auto", Comments: "x"})
	config := h.resourceValue(t, "pbs_network_interface", map[string]any{"name": "eno1", "type": "eth", "comments": "y"})
	inst := h.create(t, "pbs_network_interface", config)
	if stringAt(t, inst.state, "method6") != "auto" {
		t.Fatalf("state = %s", inst.state)
	}
	h.destroy(t, inst)
	if put := fake.lastCall(t, "PUT /nodes/localhost/network/eno1").form; slices.Contains(put["delete"], "method6") {
		t.Fatalf("PUT = %v", put)
	}
	if got := network.get("eno1"); got.Method6 != "auto" || got.Comments != "" {
		t.Fatalf("eno1 = %+v", got)
	}
	again := h.plan(t, "pbs_network_interface", nil, config)
	requireNoProtocolErrors(t, again.Diagnostics)
	if got := stringAt(t, h.decodeResource(t, "pbs_network_interface", again.PlannedState), "method6"); got != "auto" {
		t.Fatalf("planned method6 = %q", got)
	}
}
