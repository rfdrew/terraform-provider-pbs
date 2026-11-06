package pbsclient

import "context"

// The node's network configuration is /etc/network/interfaces, in
// ifupdown2's format. What PBS 4 does when it lists it, read in its source
// (src/api2/node/network.rs) and in the proxmox-network-api crate it uses
// (src/config/mod.rs, parser.rs, helper.rs, api_types.rs):
//
//   - GET /nodes/{node}/network parses /etc/network/interfaces.new when it
//     exists — what the API wrote and nobody applied yet —, otherwise
//     /etc/network/interfaces; a missing file is an empty one. So while
//     changes are pending, it lists the pending configuration, not the
//     running one.
//   - It merges what `ip -details -json link show` reports: whether an
//     interface is up, its alternative names, and the physical NICs the
//     file does not name, which it adds as type eth, method manual, without
//     autostart. A container's veth named eth0 counts as physical. It leaves
//     out the loopback interface, lo, and lists the others sorted by name.
//   - It adds the SHA-256 of the file it parsed, in hexadecimal, to every
//     interface as "digest" — not next to data —, and the name again as
//     "iface". When interfaces.new exists and differs from the running file,
//     "diff -b -u" of the two goes next to data as "changes".
//   - Keys are mixed: bridge_ports, bridge_vlan_aware, bond_mode and
//     bond_xmit_hash_policy are snake_case, vlan-id, vlan-raw-device and
//     bond-primary kebab-case. What is not set is left out, empty lists
//     included.
//   - It takes no filter: unlike Proxmox VE's, it refuses a type parameter.
//   - Errors are 400 with plain text: a parse error of the file, "line <N>:
//     ...", or the outer message of a failed `ip` or `diff`, such as "could
//     not obtain ip link output". Before PBS 4.2.7, which moved to
//     proxmox-network-api 1.0.6, the parser does not know the method auto,
//     and a stanza such as "iface eth0 inet6 auto" fails the whole call with
//     "line <N>: unknown iface option auto".
//   - It needs Sys.Audit on /system/network/interfaces.

// NetworkInterface is one interface of GET /nodes/{node}/network.
type NetworkInterface struct {
	Name string `json:"name"`
	// Type is "loopback", "eth", "bridge", "bond", "vlan", "alias" or
	// "unknown".
	Type string `json:"type"`
	// Active is whether ip link reports the interface up.
	Active bool `json:"active"`
	// Autostart is whether the file has an "auto" line for the interface;
	// "allow-hotplug" does not count.
	Autostart bool `json:"autostart"`
	// Method and Method6 are the methods of the inet and inet6 stanzas:
	// "manual", "static", "dhcp", "loopback" or, from PBS 4.2.7, "auto";
	// empty without a stanza.
	Method   string `json:"method,omitempty"`
	Method6  string `json:"method6,omitempty"`
	CIDR     string `json:"cidr,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	CIDR6    string `json:"cidr6,omitempty"`
	Gateway6 string `json:"gateway6,omitempty"`
	MTU      *int64 `json:"mtu,omitempty"`
	// Options and Options6 are the attribute lines of the stanzas PBS does
	// not know, verbatim.
	Options  []string `json:"options,omitempty"`
	Options6 []string `json:"options6,omitempty"`
	// Comments and Comments6 are the comment lines of the stanzas, without
	// their #, one per line.
	Comments           string   `json:"comments,omitempty"`
	Comments6          string   `json:"comments6,omitempty"`
	BridgePorts        []string `json:"bridge_ports,omitempty"`
	BridgeVLANAware    *bool    `json:"bridge_vlan_aware,omitempty"`
	VLANID             *int64   `json:"vlan-id,omitempty"`
	VLANRawDevice      string   `json:"vlan-raw-device,omitempty"`
	Slaves             []string `json:"slaves,omitempty"`
	BondMode           string   `json:"bond_mode,omitempty"`
	BondPrimary        string   `json:"bond-primary,omitempty"`
	BondXmitHashPolicy string   `json:"bond_xmit_hash_policy,omitempty"`
	// AltNames are the alternative names ip link reports.
	AltNames []string `json:"altnames,omitempty"`
	// Digest is the SHA-256 of the file PBS parsed, the same on every
	// interface.
	Digest string `json:"digest"`
}

// NetworkInterfaces lists the network interfaces of a node, in the order
// PBS sends them, and the diff of the changes pending in
// /etc/network/interfaces.new, or "" when there are none. It needs
// Sys.Audit on /system/network/interfaces.
func (c *Client) NetworkInterfaces(ctx context.Context, node string) ([]NetworkInterface, string, error) {
	var interfaces []NetworkInterface
	env, err := c.Get(ctx, Path("nodes", node, "network"), nil, &interfaces)
	if err != nil {
		return nil, "", err
	}
	return interfaces, env.Changes, nil
}
