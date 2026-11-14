package pbsclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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

// Changing the configuration. What PBS 4 does, read in
// src/api2/node/network.rs (unchanged from 4.0.22 to 4.2.10 but for the
// IPv6 method, below) and proxmox-network-api's writer (src/config/mod.rs):
//
//   - POST /nodes/{node}/network creates a bridge, a bond or a VLAN
//     interface — no other type ("creating network interface type 'Eth' is
//     not supported") —, PUT and DELETE /nodes/{node}/network/{iface} change
//     and remove one. All three write /etc/network/interfaces.new, parsed
//     from itself or from /etc/network/interfaces, and nothing takes effect
//     before PUT /nodes/{node}/network reloads the network. They hold
//     /var/lock/pve-network.lck; PUT and DELETE take the digest of the file
//     they parsed, which GET /nodes/{node}/network/{iface} sends inside data.
//   - The permission is Sys.Modify on /system/network/interfaces/{iface},
//     but the server expands {iface} from the path alone: POST carries the
//     name in its body, so PBS refuses it with 403 to everyone but root@pam,
//     the superuser, whatever the ACL. A token may change and delete an
//     existing interface, and reload.
//   - Every write checks the whole file first: a port or slave used by two
//     interfaces, a bond slave that is not a physical (eth) interface or
//     does not exist, a bridge port that does not exist, a child's MTU above
//     its parent's. A second interface with a gateway of the same family is
//     refused ("Default IPv4 gateway already exists on interface 'x'").
//   - PUT sets the IPv4 method to static when the interface has an address
//     or gateway and to manual otherwise, whatever it was or the call asks:
//     a DHCP interface becomes manual on any change. The IPv6 method becomes
//     static with an address or gateway; otherwise PBS 4.1.7 and later keep
//     it, and older releases set it to manual as well.
//   - Reloading spawns the task "srvreload" (worker ID "networking"), which
//     renames interfaces.new over interfaces and runs `ifreload -a`. Before
//     that, PBS checks that /usr/share/ifupdown2 exists ("ifupdown2 is not
//     installed."). A failed ifreload fails the task with "ifreload failed:
//     ..." after the rename: PBS keeps no copy of the previous file.
//   - DELETE /nodes/{node}/network removes interfaces.new, dropping every
//     pending change.

// NetworkInterface reads one interface, from the pending configuration
// while changes are pending, with the digest of the file in Digest. It
// needs Sys.Audit on /system/network/interfaces/{iface}; a missing
// interface is IsNotFound ("interface 'x' does not exist.").
func (c *Client) NetworkInterface(ctx context.Context, node, name string) (NetworkInterface, error) {
	var iface NetworkInterface
	_, err := c.Get(ctx, Path("nodes", node, "network", name), nil, &iface)
	return iface, err
}

// CreateNetworkInterface creates a bridge, bond or VLAN interface in the
// pending configuration. params carry iface and type besides the
// properties. Only root@pam may: see above.
func (c *Client) CreateNetworkInterface(ctx context.Context, node string, params url.Values) error {
	_, err := c.Post(ctx, Path("nodes", node, "network"), params, nil)
	return err
}

// UpdateNetworkInterface changes an interface in the pending configuration.
// Callers hold WithConfigLock(ConfigNetwork) and pass the digest.
func (c *Client) UpdateNetworkInterface(ctx context.Context, node, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("nodes", node, "network", name), params, nil)
	return err
}

// DeleteNetworkInterface removes an interface from the pending
// configuration. A physical interface PBS then lists again, as it lists
// every NIC the file does not name.
func (c *Client) DeleteNetworkInterface(ctx context.Context, node, name, digest string) error {
	var params url.Values
	if digest != "" {
		params = url.Values{DigestParam: {digest}}
	}
	_, err := c.Delete(ctx, Path("nodes", node, "network", name), params, nil)
	return err
}

// NetworkChanges returns the diff of the changes pending in
// /etc/network/interfaces.new, or "" when there are none.
func (c *Client) NetworkChanges(ctx context.Context, node string) (string, error) {
	_, changes, err := c.NetworkInterfaces(ctx, node)
	return changes, err
}

// ReloadNetwork starts the task that applies the pending configuration and
// returns its UPID; WaitTask waits for it. It needs Sys.Modify on
// /system/network/interfaces.
func (c *Client) ReloadNetwork(ctx context.Context, node string) (UPID, error) {
	env, err := c.Put(ctx, Path("nodes", node, "network"), nil, nil)
	if err != nil {
		return UPID{}, err
	}
	upid, ok := UPIDFromData(env.Data)
	if !ok {
		return UPID{}, fmt.Errorf("PUT %s: PBS answered %s instead of the task ID of the reload", Path("nodes", node, "network"), truncate(string(env.Data), 256))
	}
	return upid, nil
}

// RevertNetwork drops every pending change by removing
// /etc/network/interfaces.new. It needs Sys.Modify on
// /system/network/interfaces.
func (c *Client) RevertNetwork(ctx context.Context, node string) error {
	_, err := c.Delete(ctx, Path("nodes", node, "network"), nil, nil)
	return err
}

// IsIfupdown2Missing reports whether PBS refused to reload the network
// because the node has no ifupdown2, which applies the changes.
func IsIfupdown2Missing(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest && strings.Contains(apiErr.Message, "ifupdown2 is not installed")
}

// IsDuplicateGateway reports whether PBS refused a gateway because another
// interface has one of the same family: "Default IPv4 gateway already
// exists on interface 'x'".
func IsDuplicateGateway(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest && strings.HasPrefix(apiErr.Message, "Default IPv")
}

// IsNetworkDiffFailed reports whether listing the interfaces failed because
// PBS could not compare the pending configuration with the running one — on
// a node without /etc/network/interfaces, diff exits with 2 — rather than
// because it could not parse either.
func IsNetworkDiffFailed(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest &&
		(strings.HasPrefix(apiErr.Message, "diff failed:") || strings.HasPrefix(apiErr.Message, "failed to execute diff"))
}

// IsTransportError reports whether err is a failure to reach PBS at all —
// a refused or dropped connection, a request that timed out, a TLS
// failure —, which net/http reports as a *url.Error, rather than an answer
// from PBS or a cancelled operation.
func IsTransportError(err error) bool {
	var urlErr *url.Error
	return errors.As(err, &urlErr) && !errors.Is(err, context.Canceled)
}

// IsUnreachable reports whether a call did not reach PBS: a transport
// error, or a reverse proxy in front of PBS answering 502, 503 or 504
// because PBS did not answer it.
func IsUnreachable(err error) bool {
	if IsTransportError(err) {
		return true
	}
	apiErr, ok := asError(err)
	return ok && (apiErr.StatusCode == http.StatusBadGateway || apiErr.StatusCode == http.StatusServiceUnavailable ||
		apiErr.StatusCode == http.StatusGatewayTimeout)
}
