package pbsclient

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

// testNetworkJSON is what PBS 4.2.8 answers for a host with a bridge on a
// VLAN-aware bond and changes pending: the digest of the file on every
// interface, the name again as iface, keys in snake_case and kebab-case,
// what is not set left out, and the diff next to data.
const testNetworkJSON = `{"data":[
 {"active":true,"autostart":true,"bond_mode":"active-backup","bond-primary":"eno1","bond_xmit_hash_policy":"layer2+3",
  "digest":"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b","iface":"bond0","method":"manual",
  "mtu":9000,"name":"bond0","options":["bond-miimon 100"],"slaves":["eno1","eno2"],"type":"bond"},
 {"active":false,"altnames":["enp3s0"],"autostart":false,"digest":"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
  "iface":"eno3","method":"manual","name":"eno3","type":"eth"},
 {"active":true,"autostart":true,"cidr":"198.51.100.5/24","digest":"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
  "iface":"vlan20","method":"static","name":"vlan20","type":"vlan","vlan-id":20,"vlan-raw-device":"bond0"},
 {"active":true,"autostart":true,"bridge_ports":["bond0"],"bridge_vlan_aware":true,"cidr6":"2001:db8::10/64",
  "comments":"Management","digest":"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b","iface":"vmbr0",
  "method6":"static","name":"vmbr0","options6":["accept_ra 2"],"type":"bridge"}],
"changes":"--- /etc/network/interfaces\n+++ /etc/network/interfaces.new\n@@ -1 +1 @@\n-auto eno3\n"}`

func TestNetworkInterfacesDecodesTheMixedKeysAndTheChanges(t *testing.T) {
	const route = "GET /nodes/pbs1/network"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, testNetworkJSON)
	c := fake.client(t)

	interfaces, changes, err := c.NetworkInterfaces(context.Background(), "pbs1")
	if err != nil {
		t.Fatal(err)
	}
	if changes != "--- /etc/network/interfaces\n+++ /etc/network/interfaces.new\n@@ -1 +1 @@\n-auto eno3\n" {
		t.Errorf("changes = %q", changes)
	}
	if len(interfaces) != 4 {
		t.Fatalf("NetworkInterfaces() = %+v", interfaces)
	}
	mtu, vlanID, vlanAware := int64(9000), int64(20), true
	const digest = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
	want := []NetworkInterface{
		{Name: "bond0", Type: "bond", Active: true, Autostart: true, Method: "manual", MTU: &mtu,
			Options: []string{"bond-miimon 100"}, Slaves: []string{"eno1", "eno2"}, BondMode: "active-backup",
			BondPrimary: "eno1", BondXmitHashPolicy: "layer2+3", Digest: digest},
		{Name: "eno3", Type: "eth", Method: "manual", AltNames: []string{"enp3s0"}, Digest: digest},
		{Name: "vlan20", Type: "vlan", Active: true, Autostart: true, Method: "static", CIDR: "198.51.100.5/24",
			VLANID: &vlanID, VLANRawDevice: "bond0", Digest: digest},
		{Name: "vmbr0", Type: "bridge", Active: true, Autostart: true, Method6: "static", CIDR6: "2001:db8::10/64",
			Options6: []string{"accept_ra 2"}, Comments: "Management", BridgePorts: []string{"bond0"},
			BridgeVLANAware: &vlanAware, Digest: digest},
	}
	if !reflect.DeepEqual(interfaces, want) {
		t.Errorf("NetworkInterfaces() = %+v, want %+v", interfaces, want)
	}
	// PBS refuses any parameter but the node, which is in the path.
	if call := fake.lastCall(t, route); len(call.query) != 0 {
		t.Errorf("query = %v, want none", call.query)
	}
}

// Without pending changes PBS sends nothing next to data.
func TestNetworkInterfacesWithoutChanges(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/network", http.StatusOK, `{"data":[]}`)
	c := fake.client(t)

	interfaces, changes, err := c.NetworkInterfaces(context.Background(), c.Node())
	if err != nil || len(interfaces) != 0 || changes != "" {
		t.Errorf("NetworkInterfaces() = %+v, %q, %v", interfaces, changes, err)
	}
}

func TestNetworkInterfacesReportsErrors(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/network", http.StatusBadRequest, "line 12: unknown iface option auto")
	c := fake.client(t)

	interfaces, changes, err := c.NetworkInterfaces(context.Background(), c.Node())
	if err == nil || interfaces != nil || changes != "" {
		t.Fatalf("NetworkInterfaces() = %+v, %q, %v, want an error", interfaces, changes, err)
	}
	if apiErr, ok := asError(err); !ok || apiErr.StatusCode != http.StatusBadRequest || apiErr.Message != "line 12: unknown iface option auto" {
		t.Errorf("err = %v", err)
	}
}
