package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &networkInterfaceDataSource{}
	_ datasource.DataSourceWithConfigure = &networkInterfaceDataSource{}
	_ datasource.DataSource              = &networkInterfacesDataSource{}
	_ datasource.DataSourceWithConfigure = &networkInterfacesDataSource{}
)

// networkReadPrivilege is what listing a node's network interfaces needs.
const networkReadPrivilege = "Sys.Audit on /system/network/interfaces"

// NewNetworkInterfaceDataSource returns the pbs_network_interface data
// source.
func NewNetworkInterfaceDataSource() datasource.DataSource { return &networkInterfaceDataSource{} }

// NewNetworkInterfacesDataSource returns the pbs_network_interfaces data
// source.
func NewNetworkInterfacesDataSource() datasource.DataSource { return &networkInterfacesDataSource{} }

type networkInterfaceDataSource struct {
	data *providerData
}

type networkInterfacesDataSource struct {
	data *providerData
}

// networkInterfaceDataSourceModel is an interface as the
// pbs_network_interface data source reports it: as pbs_network_interfaces
// lists it, with the node and the digest PBS sends with it.
type networkInterfaceDataSourceModel struct {
	Node types.String `tfsdk:"node"`
	networkInterfaceDataModel
	Digest types.String `tfsdk:"digest"`
}

type networkInterfacesDataSourceModel struct {
	Node           types.String                `tfsdk:"node"`
	Interfaces     []networkInterfaceDataModel `tfsdk:"interfaces"`
	Digest         types.String                `tfsdk:"digest"`
	PendingChanges types.String                `tfsdk:"pending_changes"`
}

// networkInterfaceDataModel is an interface as the pbs_network_interface
// and pbs_network_interfaces data sources report it.
type networkInterfaceDataModel struct {
	Name               types.String `tfsdk:"name"`
	Type               types.String `tfsdk:"type"`
	Active             types.Bool   `tfsdk:"active"`
	Autostart          types.Bool   `tfsdk:"autostart"`
	Method             types.String `tfsdk:"method"`
	Method6            types.String `tfsdk:"method6"`
	CIDR               types.String `tfsdk:"cidr"`
	Gateway            types.String `tfsdk:"gateway"`
	CIDR6              types.String `tfsdk:"cidr6"`
	Gateway6           types.String `tfsdk:"gateway6"`
	MTU                types.Int64  `tfsdk:"mtu"`
	BridgePorts        types.List   `tfsdk:"bridge_ports"`
	BridgeVLANAware    types.Bool   `tfsdk:"bridge_vlan_aware"`
	VLANID             types.Int64  `tfsdk:"vlan_id"`
	VLANRawDevice      types.String `tfsdk:"vlan_raw_device"`
	Slaves             types.List   `tfsdk:"slaves"`
	BondMode           types.String `tfsdk:"bond_mode"`
	BondPrimary        types.String `tfsdk:"bond_primary"`
	BondXmitHashPolicy types.String `tfsdk:"bond_xmit_hash_policy"`
	Comments           types.String `tfsdk:"comments"`
	Comments6          types.String `tfsdk:"comments6"`
	Options            types.List   `tfsdk:"options"`
	Options6           types.List   `tfsdk:"options6"`
	AltNames           types.List   `tfsdk:"altnames"`
}

// networkInterfaceDataAttributes are the attributes of a network interface
// in a data source, all computed but the name when it is the lookup key, as
// in pbs_network_interface. That one reads lo too, which the list leaves
// out, and no alias, whose name PBS does not take in a path.
func networkInterfaceDataAttributes(nameRequired bool) map[string]schema.Attribute {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	computedBool := func(description string) schema.BoolAttribute {
		return schema.BoolAttribute{Computed: true, MarkdownDescription: description}
	}
	computedInt64 := func(description string) schema.Int64Attribute {
		return schema.Int64Attribute{Computed: true, MarkdownDescription: description}
	}
	computedList := func(description string) schema.ListAttribute {
		return schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: description}
	}
	name := schema.Attribute(computedString("Name of the interface, such as `eno1`, `bond0` or `vmbr0`."))
	typeText := "Type of the interface: `eth` for a physical NIC, `bridge`, `bond`, `vlan`, `alias` for a name such as " +
		"`eth0:1`, or `unknown` for one PBS cannot place, such as a virtual interface the file names."
	activeText := "Whether the interface is up, as `ip link` reports it; false for an interface of the file the node " +
		"does not have."
	autostartText := "Whether the file brings the interface up at boot, with an `auto` line; `allow-hotplug` does not " +
		"count."
	if nameRequired {
		name = schema.StringAttribute{
			Required: true,
			MarkdownDescription: "Name of the interface to read, such as `vmbr0` or `eno1`, as the file or, for a " +
				"physical NIC the file does not name, `ip link` names it — not an alternative name; `lo` reads the " +
				"loopback interface, which `pbs_network_interfaces` leaves out.",
			Validators: networkInterfaceNameValidators(),
		}
		typeText = "Type of the interface: `loopback` for `lo`, `eth` for a physical NIC, `bridge`, `bond`, `vlan`, " +
			"or `unknown` for one PBS cannot place, such as a virtual interface the file names."
		activeText += " Always false for `lo`, which PBS never reports up."
		autostartText += " True for `lo` when the file has `auto lo` or does not name `lo` at all, as PBS then adds it " +
			"itself."
	}
	return map[string]schema.Attribute{
		"name":      name,
		"type":      computedString(typeText),
		"active":    computedBool(activeText),
		"autostart": computedBool(autostartText),
		"method": computedString("Method of the interface's `inet` (IPv4) stanza: `static`, `dhcp`, " +
			"`manual`, `loopback` or, from PBS 4.2.7, `auto`; null without one."),
		"method6": computedString("Method of the interface's `inet6` (IPv6) stanza, one of the same; " +
			"null without one."),
		"cidr": computedString("IPv4 address with its prefix length, such as `192.0.2.10/24`; PBS " +
			"converts an `address` with a `netmask`. Null when unset."),
		"gateway":  computedString("IPv4 gateway; null when unset."),
		"cidr6":    computedString("IPv6 address with its prefix length, such as `2001:db8::10/64`; null when unset."),
		"gateway6": computedString("IPv6 gateway; null when unset."),
		"mtu":      computedInt64("MTU, in bytes; null when the file does not set one."),
		"bridge_ports": computedList("Ports of a bridge, from its `bridge-ports` line; empty for other " +
			"interfaces and for `bridge-ports none`."),
		"bridge_vlan_aware": computedBool("Whether a bridge is VLAN-aware, from its " +
			"`bridge-vlan-aware` line; null without one."),
		"vlan_id": computedInt64("VLAN tag of a VLAN interface, from its `vlan-id` line; null without " +
			"one. PBS does not take it from a name such as `eno1.10`."),
		"vlan_raw_device": computedString("Interface a VLAN interface runs on, from its " +
			"`vlan-raw-device` line; null without one."),
		"slaves": computedList("Interfaces of a bond, from its `bond-slaves` line; empty for other " +
			"interfaces."),
		"bond_mode": computedString("Mode of a bond: `balance-rr`, `active-backup`, `balance-xor`, " +
			"`broadcast`, `802.3ad`, `balance-tlb` or `balance-alb`; null when unset."),
		"bond_primary": computedString("Primary interface of a bond, from its `bond-primary` line; " +
			"null when unset."),
		"bond_xmit_hash_policy": computedString("Transmit hash policy of a bond: `layer2`, " +
			"`layer2+3` or `layer3+4`; null when unset."),
		"comments": computedString("Comment lines of the `inet` stanza, without their `#`, one per " +
			"line; null without any."),
		"comments6": computedString("Comment lines of an `inet6` stanza, without their `#`, one " +
			"per line; null without any."),
		"options": computedList("Lines of the `inet` stanza PBS does not interpret, such as " +
			"`post-up` commands, verbatim."),
		"options6": computedList("Lines of an `inet6` stanza PBS does not interpret, verbatim."),
		"altnames": computedList("Alternative names of the interface, as `ip link` reports them."),
	}
}

// networkInterfaceData is iface as the data sources report it.
func networkInterfaceData(iface pbsclient.NetworkInterface, diags *diag.Diagnostics) networkInterfaceDataModel {
	return networkInterfaceDataModel{
		Name:               types.StringValue(iface.Name),
		Type:               types.StringValue(iface.Type),
		Active:             types.BoolValue(iface.Active),
		Autostart:          types.BoolValue(iface.Autostart),
		Method:             stringOrNull(iface.Method),
		Method6:            stringOrNull(iface.Method6),
		CIDR:               stringOrNull(iface.CIDR),
		Gateway:            stringOrNull(iface.Gateway),
		CIDR6:              stringOrNull(iface.CIDR6),
		Gateway6:           stringOrNull(iface.Gateway6),
		MTU:                int64OrNull(iface.MTU),
		BridgePorts:        stringListOf(iface.BridgePorts, diags),
		BridgeVLANAware:    types.BoolPointerValue(iface.BridgeVLANAware),
		VLANID:             int64OrNull(iface.VLANID),
		VLANRawDevice:      stringOrNull(iface.VLANRawDevice),
		Slaves:             stringListOf(iface.Slaves, diags),
		BondMode:           stringOrNull(iface.BondMode),
		BondPrimary:        stringOrNull(iface.BondPrimary),
		BondXmitHashPolicy: stringOrNull(iface.BondXmitHashPolicy),
		Comments:           stringOrNull(iface.Comments),
		Comments6:          stringOrNull(iface.Comments6),
		Options:            stringListOf(iface.Options, diags),
		Options6:           stringListOf(iface.Options6, diags),
		AltNames:           stringListOf(iface.AltNames, diags),
	}
}

// The pbs_network_interface data source reads one interface with
// GET /nodes/{node}/network/{iface}, which every PBS 4 release has. What PBS
// does there, read in its source (src/api2/node/network.rs, read_interface,
// proxmox-backup 7c86c5ad5, after 4.2.11; proxmox-network-api's
// src/config/mod.rs and parser.rs, proxmox 601a11e6):
//
//   - It parses the same configuration as the list — interfaces.new while
//     it exists, otherwise interfaces —, merged with ip link alike, and
//     looks the interface up by the name the file gives it or, for a
//     physical NIC the file does not name, ip link does. An alternative
//     name, like a name nothing has, is "interface 'x' does not exist.".
//   - The parser always has lo: when the file does not name it, it adds lo
//     after merging ip link, as type loopback, method loopback, with
//     autostart and never active. Unlike the list, the call returns it.
//   - It answers the Interface object a list item is, with the digest
//     inside data but without iface, and never runs diff: there are no
//     pending changes to show, and none to fail on.
//   - iface takes a safe ID of 1 to 15 characters, so an alias such as
//     eth0:1 cannot be read on its own.
//   - It needs Sys.Audit on /system/network/interfaces/{iface}, which an
//     entry on /system/network/interfaces grants too when it propagates.

func (d *networkInterfaceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_interface"
}

func (d *networkInterfaceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attributes := networkInterfaceDataAttributes(true)
	attributes["node"] = schema.StringAttribute{
		Optional:            true,
		Computed:            true,
		MarkdownDescription: "Node to read: `localhost` or the node's host name. Defaults to the provider's `node`.",
		Validators: []validator.String{
			stringvalidator.LengthBetween(1, 63),
			stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
		},
	}
	attributes["digest"] = schema.StringAttribute{
		Computed: true,
		MarkdownDescription: "SHA-256 digest of the configuration file PBS read, in hexadecimal — " +
			"`/etc/network/interfaces.new` while changes are pending, otherwise `/etc/network/interfaces` —, as " +
			"`pbs_network_interfaces` reports it; it changes whenever the file does.",
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads one network interface of a Proxmox Backup Server node, with the attributes " +
			"`pbs_network_interfaces` lists: an interface of `/etc/network/interfaces`, the loopback interface " +
			"`lo`, or a physical NIC the file does not name, which PBS reports as type `eth`, method `manual`, " +
			"without autostart. PBS looks the interface up by that name, not by an alternative name, and cannot " +
			"read an alias such as `eth0:1` on its own; `pbs_network_interfaces` lists it. To manage an " +
			"interface, use `pbs_network_interface`.\n\n" +
			"Needs `" + networkInterfaceReadPrivilege + "`, which an ACL entry on `/system/network/interfaces` " +
			"grants too when it propagates; `pbs_network_interfaces` needs `" + networkReadPrivilege + "`.\n\n" +
			"~> **Pending changes.** While `/etc/network/interfaces.new` holds changes made through the API or " +
			"the web interface and not applied yet, PBS reads the interface from it, so the data source shows its " +
			"pending configuration, not the one the node runs; `pending_changes` of `pbs_network_interfaces` " +
			"shows the difference. A bridge, bond, VLAN or other virtual interface removed only there reads as " +
			"missing, although the node runs it until the change is applied. A physical NIC whose stanza was " +
			"removed reads as one the file does not name — type `eth`, method `manual`, without autostart —, and " +
			"`lo` as PBS adds it itself, with autostart. Reading one interface does not compare the two files, so " +
			"it works where the list fails with `diff failed`, as when `/etc/network/interfaces` is missing.\n\n" +
			"~> PBS releases before 4.2.7 cannot parse the method `auto`: a stanza such as " +
			"`iface eth0 inet6 auto` makes reading fail with `unknown iface option auto`.",
		Attributes: attributes,
	}
}

func (d *networkInterfaceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *networkInterfaceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config networkInterfaceDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	name := config.Name.ValueString()
	iface, err := d.data.client.NetworkInterface(ctx, node, name)
	if pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS network interface not found",
			fmt.Sprintf("PBS has no network interface %q on node %q: its network configuration — "+
				"/etc/network/interfaces.new while changes are pending, otherwise /etc/network/interfaces — does "+
				"not name it, and it is no physical NIC ip link reports. PBS does not look interfaces up by their "+
				"alternative names. %s", name, node, err))
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS network interface",
			networkErrorDetailFor(d.data.client, networkInterfacePrivilege(networkInterfaceReadPrivilege, name), err))
		return
	}
	model := networkInterfaceDataSourceModel{
		Node:                      types.StringValue(node),
		networkInterfaceDataModel: networkInterfaceData(iface, &resp.Diagnostics),
		Digest:                    stringOrNull(iface.Digest),
	}
	model.Name = types.StringValue(name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (d *networkInterfacesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_interfaces"
}

func (d *networkInterfacesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the network interfaces of a Proxmox Backup Server node, as the Network " +
			"Interfaces panel of its web interface shows them: the interfaces of `/etc/network/interfaces`, with " +
			"whether each is up, and the physical NICs the file does not name, which PBS lists as type `eth`, " +
			"method `manual`, without autostart — in a Docker container without the file, typically just the " +
			"container's `eth0`. PBS leaves out the loopback interface, `lo`. To manage an interface, use " +
			"`pbs_network_interface`, and `pbs_network_apply` to apply the changes.\n\n" +
			"Needs `" + networkReadPrivilege + "`.\n\n" +
			"~> **Pending changes.** While `/etc/network/interfaces.new` holds changes made through the API or " +
			"the web interface and not applied yet, PBS lists that pending configuration, not the one the node " +
			"runs; `pending_changes` then shows the difference.\n\n" +
			"~> PBS releases before 4.2.7 cannot parse the method `auto`: a stanza such as " +
			"`iface eth0 inet6 auto` makes reading fail with `unknown iface option auto`.",
		Attributes: map[string]schema.Attribute{
			"node": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Node to read: `localhost` or the node's host name. Defaults to the provider's `node`.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 63),
					stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
				},
			},
			"interfaces": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The interfaces, sorted by name.",
				NestedObject:        schema.NestedAttributeObject{Attributes: networkInterfaceDataAttributes(false)},
			},
			"digest": computedString("SHA-256 digest of the configuration file PBS read, in hexadecimal: " +
				"`/etc/network/interfaces.new` while changes are pending, otherwise `/etc/network/interfaces`. It " +
				"changes whenever the file does. Null when PBS lists no interface."),
			"pending_changes": computedString("Changes written to `/etc/network/interfaces.new` and not " +
				"applied yet — with Apply Configuration in the web interface —, as the unified diff from " +
				"`/etc/network/interfaces` PBS shows; null when none are pending."),
		},
	}
}

func (d *networkInterfacesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *networkInterfacesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config networkInterfacesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	interfaces, changes, err := d.data.client.NetworkInterfaces(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS network interfaces", networkErrorDetail(d.data.client, err))
		return
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Name < interfaces[j].Name })

	model := networkInterfacesDataSourceModel{
		Node:           types.StringValue(node),
		Interfaces:     []networkInterfaceDataModel{},
		Digest:         types.StringNull(),
		PendingChanges: stringOrNull(changes),
	}
	// PBS adds the file's digest to every interface rather than next to
	// them, so a node without interfaces has none.
	if len(interfaces) > 0 {
		model.Digest = stringOrNull(interfaces[0].Digest)
	}
	for _, iface := range interfaces {
		model.Interfaces = append(model.Interfaces, networkInterfaceData(iface, &resp.Diagnostics))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// networkInterfacePrivilege is privilege, one of the per-interface ones,
// on the interface name.
func networkInterfacePrivilege(privilege, name string) string {
	return strings.Replace(privilege, "<name>", name, 1)
}

// networkErrorDetail is apiErrorDetail for listing the network interfaces,
// with advice when PBS cannot parse its own configuration file.
func networkErrorDetail(client *pbsclient.Client, err error) string {
	return networkErrorDetailFor(client, networkReadPrivilege, err)
}

// networkErrorDetailFor is networkErrorDetail for a call that needs
// privilege, such as reading one interface, which needs Sys.Audit on that
// interface only.
func networkErrorDetailFor(client *pbsclient.Client, privilege string, err error) string {
	detail := apiErrorDetail(client, privilege, err)
	if strings.Contains(err.Error(), "unknown iface option auto") {
		// network-api before 1.0.6, in PBS before 4.2.7, has no method auto.
		detail = "PBS could not parse the node's network configuration: releases before 4.2.7 do not know the " +
			"method auto, as in `iface eth0 inet6 auto`, and then list no interface at all. Upgrade PBS to 4.2.7 " +
			"or later, or give that stanza another method, such as manual, in the file the line number refers " +
			"to: /etc/network/interfaces.new while changes are pending, otherwise /etc/network/interfaces. " + detail
	}
	return detail
}
