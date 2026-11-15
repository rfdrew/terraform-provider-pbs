package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestNetworkInterfacesDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &networkInterfacesDataSource{})
}

const fakeNetworkDigest = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"

// fakeNetworkJSON is what PBS 4.2.8 answers for a host with a VLAN-aware
// bridge on an LACP bond, a VLAN on the bond, a NIC the file does not name,
// and a comment written through the API but not applied: the file's digest
// and the name again as iface on every interface, keys in snake_case and
// kebab-case, what is not set left out, and the diff next to data.
const fakeNetworkJSON = `{"data":[
 {"active":true,"autostart":true,"bond_mode":"802.3ad","bond_xmit_hash_policy":"layer3+4","digest":"` + fakeNetworkDigest + `",
  "iface":"bond0","method":"manual","mtu":9000,"name":"bond0","options":["bond-miimon 100"],"slaves":["eno1","eno2"],"type":"bond"},
 {"active":true,"altnames":["enp1s0f0"],"autostart":true,"digest":"` + fakeNetworkDigest + `","iface":"eno1","method":"manual",
  "name":"eno1","type":"eth"},
 {"active":true,"altnames":["enp1s0f1"],"autostart":true,"digest":"` + fakeNetworkDigest + `","iface":"eno2","method":"manual",
  "name":"eno2","type":"eth"},
 {"active":false,"autostart":false,"digest":"` + fakeNetworkDigest + `","iface":"eno3","method":"manual","name":"eno3","type":"eth"},
 {"active":true,"autostart":true,"cidr":"198.51.100.5/24","comments":"Backup network","digest":"` + fakeNetworkDigest + `",
  "iface":"vlan20","method":"static","name":"vlan20","type":"vlan","vlan-id":20,"vlan-raw-device":"bond0"},
 {"active":true,"autostart":true,"bridge_ports":["bond0"],"bridge_vlan_aware":true,"cidr":"192.0.2.10/24","cidr6":"2001:db8::10/64",
  "comments":"Management\nDo not change","comments6":"IPv6 uplink","digest":"` + fakeNetworkDigest + `","gateway":"192.0.2.1",
  "gateway6":"2001:db8::1","iface":"vmbr0","method":"static","method6":"static","name":"vmbr0",
  "options":["bridge-stp off","bridge-fd 0"],"options6":["accept_ra 2"],"type":"bridge"}],
"changes":"` + fakeNetworkChangesJSON + `"}`

const (
	fakeNetworkChangesJSON = `--- /etc/network/interfaces\t2026-10-30 09:12:44.000000000 +0000\n` +
		`+++ /etc/network/interfaces.new\t2026-11-02 08:01:13.123456789 +0000\n@@ -24,3 +24,4 @@\n` +
		` iface vlan20 inet static\n \taddress 198.51.100.5/24\n \tvlan-id 20\n+#Backup network\n`
	fakeNetworkChanges = "--- /etc/network/interfaces\t2026-10-30 09:12:44.000000000 +0000\n" +
		"+++ /etc/network/interfaces.new\t2026-11-02 08:01:13.123456789 +0000\n@@ -24,3 +24,4 @@\n" +
		" iface vlan20 inet static\n \taddress 198.51.100.5/24\n \tvlan-id 20\n+#Backup network\n"
)

// wantNetworkInterface is an interface as the state has it: attrs, with the
// lists it leaves out empty and the rest null.
func wantNetworkInterface(attrs map[string]any) map[string]any {
	for _, list := range []string{"bridge_ports", "slaves", "options", "options6", "altnames"} {
		if _, ok := attrs[list]; !ok {
			attrs[list] = []string{}
		}
	}
	return attrs
}

// The data source reports every interface as PBS lists it, on the node the
// configuration names, with the digest and the pending changes.
func TestNetworkInterfacesDataSourceReadsTheInterfaces(t *testing.T) {
	fake := newFakePBS()
	d := &networkInterfacesDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/pbs1/network", http.StatusOK, fakeNetworkJSON)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{"node": "pbs1"}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node": "pbs1",
		"interfaces": []any{
			wantNetworkInterface(map[string]any{"name": "bond0", "type": "bond", "active": true, "autostart": true,
				"method": "manual", "mtu": 9000, "options": []string{"bond-miimon 100"}, "slaves": []string{"eno1", "eno2"},
				"bond_mode": "802.3ad", "bond_xmit_hash_policy": "layer3+4"}),
			wantNetworkInterface(map[string]any{"name": "eno1", "type": "eth", "active": true, "autostart": true,
				"method": "manual", "altnames": []string{"enp1s0f0"}}),
			wantNetworkInterface(map[string]any{"name": "eno2", "type": "eth", "active": true, "autostart": true,
				"method": "manual", "altnames": []string{"enp1s0f1"}}),
			wantNetworkInterface(map[string]any{"name": "eno3", "type": "eth", "active": false, "autostart": false,
				"method": "manual"}),
			wantNetworkInterface(map[string]any{"name": "vlan20", "type": "vlan", "active": true, "autostart": true,
				"method": "static", "cidr": "198.51.100.5/24", "comments": "Backup network", "vlan_id": 20,
				"vlan_raw_device": "bond0"}),
			wantNetworkInterface(map[string]any{"name": "vmbr0", "type": "bridge", "active": true, "autostart": true,
				"method": "static", "method6": "static", "cidr": "192.0.2.10/24", "gateway": "192.0.2.1",
				"cidr6": "2001:db8::10/64", "gateway6": "2001:db8::1", "bridge_ports": []string{"bond0"},
				"bridge_vlan_aware": true, "comments": "Management\nDo not change", "comments6": "IPv6 uplink",
				"options": []string{"bridge-stp off", "bridge-fd 0"}, "options6": []string{"accept_ra 2"}}),
		},
		"digest":          fakeNetworkDigest,
		"pending_changes": fakeNetworkChanges,
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// A node without interfaces has no digest; PBS may leave things out or send
// null for them, and its order is no promise.
func TestNetworkInterfacesDataSourceEdgeCases(t *testing.T) {
	const digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for _, tc := range []struct {
		name string
		body string
		want map[string]any
	}{
		{
			name: "no interfaces",
			body: `{"data":[]}`,
			want: map[string]any{"node": "localhost", "interfaces": []any{}},
		},
		{
			name: "null data, empty changes",
			body: `{"data":null,"changes":""}`,
			want: map[string]any{"node": "localhost", "interfaces": []any{}},
		},
		{
			name: "unsorted, with nulls",
			body: `{"data":[
 {"active":false,"autostart":true,"bridge_ports":[],"bridge_vlan_aware":null,"cidr":null,"comments":null,"digest":"` + digest + `",
  "iface":"vmbr1","method":"manual","mtu":null,"name":"vmbr1","options":null,"altnames":null,"type":"bridge"},
 {"active":true,"autostart":true,"bond-primary":"enp6s0","bond_mode":"active-backup","digest":"` + digest + `","iface":"bond1",
  "name":"bond1","slaves":["enp5s0","enp6s0"],"type":"bond","vlan-id":null},
 {"active":true,"autostart":false,"digest":"` + digest + `","iface":"eth0","method":"manual","name":"eth0","type":"eth"}],
"changes":null}`,
			want: map[string]any{
				"node": "localhost",
				"interfaces": []any{
					wantNetworkInterface(map[string]any{"name": "bond1", "type": "bond", "active": true, "autostart": true,
						"slaves": []string{"enp5s0", "enp6s0"}, "bond_mode": "active-backup", "bond_primary": "enp6s0"}),
					wantNetworkInterface(map[string]any{"name": "eth0", "type": "eth", "active": true, "autostart": false,
						"method": "manual"}),
					wantNetworkInterface(map[string]any{"name": "vmbr1", "type": "bridge", "active": false, "autostart": true,
						"method": "manual"}),
				},
				"digest": digest,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			d := &networkInterfacesDataSource{data: fake.configured(t)}
			fake.reply("GET /nodes/localhost/network", http.StatusOK, tc.body)

			resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
			requireNoErrors(t, resp.Diagnostics)
			if want := dataSourceValue(t, d, tc.want); !resp.State.Raw.Equal(want) {
				t.Errorf("state = %s, want %s", resp.State.Raw, want)
			}
		})
	}
}

// A token without Sys.Audit on the interfaces gets 403, and the error says
// what is missing.
func TestNetworkInterfacesDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	d := &networkInterfacesDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/network", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, "Unable to read the PBS network interfaces")
	requireErrorContaining(t, resp.Diagnostics, "Sys.Audit on /system/network/interfaces")
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}

// Before PBS 4.2.7 a stanza with the method auto fails the whole listing;
// the error says why and what to do, and other failures go through as they
// are.
func TestNetworkInterfacesDataSourceExplainsTheMethodAuto(t *testing.T) {
	fake := newFakePBS()
	d := &networkInterfacesDataSource{data: fake.configured(t)}
	fake.replies("GET /nodes/localhost/network", http.StatusBadRequest,
		"line 12: unknown iface option auto", "could not obtain ip link output")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, "line 12: unknown iface option auto")
	requireErrorContaining(t, resp.Diagnostics, "Upgrade PBS to 4.2.7 or later")

	resp = readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, "could not obtain ip link output")
	for _, e := range resp.Diagnostics.Errors() {
		if strings.Contains(e.Detail(), "4.2.7") {
			t.Errorf("error %q has the advice for the method auto", e.Detail())
		}
	}
}

func TestNetworkInterfaceDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &networkInterfaceDataSource{})
}

// fakeNetworkInterfaceJSON is what PBS 4.2.8 answers for vmbr0 of
// fakeNetworkJSON on its own: the same object, with the digest inside data
// but without iface.
const fakeNetworkInterfaceJSON = `{"data":
 {"active":true,"autostart":true,"bridge_ports":["bond0"],"bridge_vlan_aware":true,"cidr":"192.0.2.10/24","cidr6":"2001:db8::10/64",
  "comments":"Management\nDo not change","comments6":"IPv6 uplink","digest":"` + fakeNetworkDigest + `","gateway":"192.0.2.1",
  "gateway6":"2001:db8::1","method":"static","method6":"static","name":"vmbr0",
  "options":["bridge-stp off","bridge-fd 0"],"options6":["accept_ra 2"],"type":"bridge"}}`

// One interface reads with the attributes the list has for it, on the node
// the configuration names, with the digest.
func TestNetworkInterfaceDataSourceReadsTheInterface(t *testing.T) {
	fake := newFakePBS()
	d := &networkInterfaceDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/pbs1/network/vmbr0", http.StatusOK, fakeNetworkInterfaceJSON)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{"node": "pbs1", "name": "vmbr0"}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, wantNetworkInterface(map[string]any{
		"node": "pbs1", "name": "vmbr0", "type": "bridge", "active": true, "autostart": true,
		"method": "static", "method6": "static", "cidr": "192.0.2.10/24", "gateway": "192.0.2.1",
		"cidr6": "2001:db8::10/64", "gateway6": "2001:db8::1", "bridge_ports": []string{"bond0"},
		"bridge_vlan_aware": true, "comments": "Management\nDo not change", "comments6": "IPv6 uplink",
		"options": []string{"bridge-stp off", "bridge-fd 0"}, "options6": []string{"accept_ra 2"},
		"digest": fakeNetworkDigest,
	}))
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// Through the protocol, against a node with eno1 to eno3 and nothing but lo
// in its file: lo, which the list leaves out; a NIC the file does not name;
// the pending configuration, with the list's digest; and a read where the
// list fails, as PBS cannot diff a pending file without the running one.
func TestNetworkInterfaceDataSourceThroughTheProtocol(t *testing.T) {
	h, _, network := newNetworkHarness(t, true)
	read := func(name string) tftypes.Value {
		t.Helper()
		return h.readDataSource(t, "pbs_network_interface", h.dataSourceValue(t, "pbs_network_interface",
			map[string]any{"name": name}))
	}

	lo := read("lo")
	if stringAt(t, lo, "node") != "localhost" || stringAt(t, lo, "name") != "lo" || stringAt(t, lo, "type") != "loopback" ||
		stringAt(t, lo, "method") != "loopback" || len(stringAt(t, lo, "digest")) != 64 {
		t.Fatalf("lo = %s", lo)
	}

	eno3 := read("eno3")
	if stringAt(t, eno3, "type") != "eth" || stringAt(t, eno3, "method") != "manual" || boolAt(t, eno3, "autostart") ||
		!isNullAt(t, eno3, "cidr") || lengthAt(t, eno3, "bridge_ports") != 0 {
		t.Fatalf("eno3 = %s", eno3)
	}

	network.edit("eno1", func(i *fakeIface) { i.MTU = ptr(int64(9000)) })
	eno1 := read("eno1")
	list := h.readDataSource(t, "pbs_network_interfaces", h.dataSourceValue(t, "pbs_network_interfaces", nil))
	if int64At(t, eno1, "mtu") != 9000 || stringAt(t, eno1, "digest") != stringAt(t, list, "digest") ||
		stringAt(t, eno1, "digest") == stringAt(t, lo, "digest") {
		t.Fatalf("eno1 = %s, list = %s", eno1, list)
	}

	network.mu.Lock()
	network.hasRunningFile = false
	network.mu.Unlock()
	failed := h.readDataSourceResponse(t, "pbs_network_interfaces", h.dataSourceValue(t, "pbs_network_interfaces", nil))
	requireProtocolErrorContaining(t, failed.Diagnostics, "diff failed")
	if eno1 = read("eno1"); int64At(t, eno1, "mtu") != 9000 {
		t.Fatalf("eno1 = %s", eno1)
	}
}

// A name PBS does not have fails on name, saying where PBS looked; one PBS
// would refuse in its path fails validation before any request.
func TestNetworkInterfaceDataSourceNames(t *testing.T) {
	h, fake, _ := newNetworkHarness(t, true)
	resp := h.readDataSourceResponse(t, "pbs_network_interface",
		h.dataSourceValue(t, "pbs_network_interface", map[string]any{"name": "tfacc9"}))
	requireProtocolErrorOn(t, resp.Diagnostics, tftypes.NewAttributePath().WithAttributeName("name"))
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS has no network interface "tfacc9" on node "localhost"`)
	requireProtocolErrorContaining(t, resp.Diagnostics, "alternative names")
	requireProtocolErrorContaining(t, resp.Diagnostics, "interface 'tfacc9' does not exist.")

	reads := fake.count("GET /nodes/localhost/network/eth0:1")
	for name, want := range map[string]string{
		"eth0:1":                "must be an interface name",
		strings.Repeat("a", 16): "string length must be between 1 and 15",
		"":                      "string length must be between 1 and 15",
	} {
		diags := dataSourceConfigDiagnostics(t, h, "pbs_network_interface",
			h.dataSourceValue(t, "pbs_network_interface", map[string]any{"name": name}))
		requireProtocolErrorContaining(t, diags, want)
	}
	if fake.count("GET /nodes/localhost/network/eth0:1") != reads {
		t.Fatal("validation sent a request")
	}
}

// A token without Sys.Audit on the interface gets 403, and the error names
// the privilege on that interface — for the data source and for a refresh
// of pbs_network_interface alike.
func TestNetworkInterfaceDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	d := &networkInterfaceDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/network/vmbr0", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{"name": "vmbr0"}))
	requireErrorContaining(t, resp.Diagnostics, "Unable to read the PBS network interface")
	requireErrorContaining(t, resp.Diagnostics, "Sys.Audit on /system/network/interfaces/vmbr0")
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")

	h, fake, _ := newNetworkHarness(t, true)
	inst := h.importByID(t, "pbs_network_interface", "localhost/eno1")
	fake.reply("GET /nodes/localhost/network/eno1", http.StatusForbidden, "permission check failed")
	requireProtocolErrorContaining(t, h.read(t, inst).Diagnostics, "Sys.Audit on /system/network/interfaces/eno1")
}

// Before PBS 4.2.7 a stanza with the method auto fails every read; the
// error says why and what to do.
func TestNetworkInterfaceDataSourceExplainsTheMethodAuto(t *testing.T) {
	fake := newFakePBS()
	d := &networkInterfaceDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/network/eno1", http.StatusBadRequest, "line 7: unknown iface option auto")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{"name": "eno1"}))
	requireErrorContaining(t, resp.Diagnostics, "line 7: unknown iface option auto")
	requireErrorContaining(t, resp.Diagnostics, "Upgrade PBS to 4.2.7 or later")
}

// --- acceptance --------------------------------------------------------------

// Every stand lists something different — its own NICs, a container's veth
// —, so the test checks what holds everywhere: the interfaces PBS lists,
// sorted, without lo, and the digest of the file. A stand that cannot list
// them at all — no ip binary, a pending file without the original, an inet6
// auto stanza before PBS 4.2.7 — is skipped.
func TestAccNetworkInterfacesDataSource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	interfaces, _, err := client.NetworkInterfaces(context.Background(), client.Node())
	if err != nil {
		for _, environmental := range []string{"unknown iface option", "could not obtain ip link output",
			"ip link returned non-zero exit code", "could not deserialize ip link output", "diff failed",
			"failed to execute diff"} {
			if strings.Contains(err.Error(), environmental) {
				t.Skipf("the stand cannot list its network interfaces: %v", err)
			}
		}
		t.Fatal(err)
	}

	const name = "data.pbs_network_interfaces.this"
	checks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr(name, "node", client.Node()),
		acc.TestCheckResourceAttr(name, "interfaces.#", strconv.Itoa(len(interfaces))),
		testAccCheckNetworkInterfacesSorted(name),
	}
	if len(interfaces) > 0 {
		checks = append(checks,
			acc.TestMatchResourceAttr(name, "digest", regexp.MustCompile(`^[0-9a-f]{64}$`)),
			acc.TestCheckResourceAttrSet(name, "interfaces.0.name"),
			acc.TestMatchResourceAttr(name, "interfaces.0.type", regexp.MustCompile(`^(eth|bridge|bond|vlan|alias|unknown)$`)),
			acc.TestMatchResourceAttr(name, "interfaces.0.active", regexp.MustCompile(`^(true|false)$`)),
			acc.TestMatchResourceAttr(name, "interfaces.0.autostart", regexp.MustCompile(`^(true|false)$`)),
		)
	} else {
		checks = append(checks, acc.TestCheckNoResourceAttr(name, "digest"))
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				Config: providerConfig + `
data "pbs_network_interfaces" "this" {}
`,
				Check: acc.ComposeAggregateTestCheckFunc(checks...),
			},
		},
	})
}

// testAccCheckNetworkInterfacesSorted checks that the interfaces are sorted
// by name and that lo, which PBS leaves out, is not among them.
func testAccCheckNetworkInterfacesSorted(name string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s not found in state", name)
		}
		count, err := strconv.Atoi(rs.Primary.Attributes["interfaces.#"])
		if err != nil {
			return fmt.Errorf("interfaces.# = %q: %w", rs.Primary.Attributes["interfaces.#"], err)
		}
		previous := ""
		for i := range count {
			current := rs.Primary.Attributes[fmt.Sprintf("interfaces.%d.name", i)]
			if current == "lo" {
				return fmt.Errorf("interfaces.%d is lo, which PBS leaves out", i)
			}
			if i > 0 && current <= previous {
				return fmt.Errorf("interfaces.%d.name = %q follows %q: not sorted by name", i, current, previous)
			}
			previous = current
		}
		return nil
	}
}

// One interface at a time, on every stand: lo, which the parser adds where
// the file does not name it — neither active nor autostart is checked, as
// they depend on whether and how the file names it —; the first interface
// the list has, compared with it where the stand can list them; the first
// NIC of the network tests, where the stand has them; and a name nothing
// has. The stand is probed with a read of lo rather than with the list,
// which fails where PBS cannot diff a pending file, and a stand that cannot
// read its network configuration at all — no ip binary, an inet6 auto
// stanza before PBS 4.2.7 — is skipped.
func TestAccNetworkInterfaceDataSource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.NetworkInterface(ctx, client.Node(), "lo"); err != nil {
		for _, environmental := range []string{"unknown iface option", "could not obtain ip link output",
			"ip link returned non-zero exit code", "could not deserialize ip link output"} {
			if strings.Contains(err.Error(), environmental) {
				t.Skipf("the stand cannot read its network configuration: %v", err)
			}
		}
		t.Fatal(err)
	}

	config := providerConfig + `
data "pbs_network_interface" "lo" {
  name = "lo"
}
`
	const lo = "data.pbs_network_interface.lo"
	checks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr(lo, "node", client.Node()),
		acc.TestCheckResourceAttr(lo, "name", "lo"),
		acc.TestCheckResourceAttr(lo, "type", "loopback"),
		acc.TestCheckResourceAttr(lo, "method", "loopback"),
		acc.TestMatchResourceAttr(lo, "digest", regexp.MustCompile(`^[0-9a-f]{64}$`)),
	}
	// PBS cannot read an alias on its own.
	if interfaces, _, err := client.NetworkInterfaces(ctx, client.Node()); err == nil {
		for _, iface := range interfaces {
			if iface.Type == "alias" {
				continue
			}
			const listed = "data.pbs_network_interface.listed"
			config += fmt.Sprintf(`
data "pbs_network_interface" "listed" {
  name = %q
}
`, iface.Name)
			checks = append(checks,
				acc.TestCheckResourceAttr(listed, "type", iface.Type),
				acc.TestCheckResourceAttr(listed, "autostart", strconv.FormatBool(iface.Autostart)),
				acc.TestCheckResourceAttr(listed, "digest", iface.Digest),
			)
			if iface.Method == "" {
				checks = append(checks, acc.TestCheckNoResourceAttr(listed, "method"))
			} else {
				checks = append(checks, acc.TestCheckResourceAttr(listed, "method", iface.Method))
			}
			break
		}
	}
	if nic, _, _ := strings.Cut(os.Getenv(envAccNetworkNICs), ","); nic != "" {
		const veth = "data.pbs_network_interface.veth"
		config += fmt.Sprintf(`
data "pbs_network_interface" "veth" {
  name = %q
}
`, nic)
		checks = append(checks,
			acc.TestCheckResourceAttr(veth, "name", nic),
			acc.TestCheckResourceAttr(veth, "type", "eth"),
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				Config: config,
				Check:  acc.ComposeAggregateTestCheckFunc(checks...),
			},
			{
				Config: providerConfig + `
data "pbs_network_interface" "missing" {
  name = "tfaccmissing0"
}
`,
				ExpectError: regexp.MustCompile(`PBS has no network interface`),
			},
		},
	})
}
