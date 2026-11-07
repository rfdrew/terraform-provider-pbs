package provider

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                   = &networkInterfaceResource{}
	_ resource.ResourceWithConfigure      = &networkInterfaceResource{}
	_ resource.ResourceWithIdentity       = &networkInterfaceResource{}
	_ resource.ResourceWithImportState    = &networkInterfaceResource{}
	_ resource.ResourceWithModifyPlan     = &networkInterfaceResource{}
	_ resource.ResourceWithValidateConfig = &networkInterfaceResource{}
)

// NewNetworkInterfaceResource returns the pbs_network_interface resource.
func NewNetworkInterfaceResource() resource.Resource { return &networkInterfaceResource{} }

type networkInterfaceResource struct {
	data *providerData
}

type networkInterfaceModel struct {
	ID                 types.String `tfsdk:"id"`
	Node               types.String `tfsdk:"node"`
	Name               types.String `tfsdk:"name"`
	Type               types.String `tfsdk:"type"`
	Autostart          types.Bool   `tfsdk:"autostart"`
	Method             types.String `tfsdk:"method"`
	CIDR               types.String `tfsdk:"cidr"`
	Gateway            types.String `tfsdk:"gateway"`
	Method6            types.String `tfsdk:"method6"`
	CIDR6              types.String `tfsdk:"cidr6"`
	Gateway6           types.String `tfsdk:"gateway6"`
	MTU                types.Int64  `tfsdk:"mtu"`
	Comments           types.String `tfsdk:"comments"`
	Comments6          types.String `tfsdk:"comments6"`
	BridgePorts        types.Set    `tfsdk:"bridge_ports"`
	BridgeVLANAware    types.Bool   `tfsdk:"bridge_vlan_aware"`
	VLANID             types.Int64  `tfsdk:"vlan_id"`
	VLANRawDevice      types.String `tfsdk:"vlan_raw_device"`
	Slaves             types.List   `tfsdk:"slaves"`
	BondMode           types.String `tfsdk:"bond_mode"`
	BondPrimary        types.String `tfsdk:"bond_primary"`
	BondXmitHashPolicy types.String `tfsdk:"bond_xmit_hash_policy"`
	Options            types.List   `tfsdk:"options"`
	Options6           types.List   `tfsdk:"options6"`
}

// Interface types the resource manages. PBS creates bridges, bonds and VLAN
// interfaces; a physical interface (eth) exists or does not, and the
// resource takes it over.
const (
	networkTypeBridge = "bridge"
	networkTypeBond   = "bond"
	networkTypeVLAN   = "vlan"
	networkTypeEth    = "eth"
)

// Methods of an address family.
const (
	networkMethodManual = "manual"
	networkMethodStatic = "static"
	networkMethodDHCP   = "dhcp"
	networkMethodAuto   = "auto"
)

// defaultBondMode is what PBS writes for a bond without a mode.
const defaultBondMode = "balance-rr"

// Bond modes, and those that take a primary and a transmit hash policy.
var (
	bondModes             = []string{"balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"}
	bondModesWithPrimary  = []string{"active-backup"}
	bondModesWithXmitHash = []string{"802.3ad", "balance-xor"}
)

// networkInterfaceDeletable are the properties PUT accepts in delete, as
// PBS's DeletableProperty names them. vlan-id, vlan-raw-device and bond_mode
// cannot be deleted.
var networkInterfaceDeletable = []string{
	"cidr", "cidr6", "gateway", "gateway6", "method", "method6", "comments", "comments6", "mtu", "autostart",
	"bridge_ports", "bridge_vlan_aware", "slaves", "bond-primary", "bond_xmit_hash_policy",
}

// IPv6 methods other than manual and static that need a newer PBS: before
// 4.1.7 a change of an interface turns its IPv6 method into manual, and
// before 4.2.7 PBS does not know the method auto at all.
var (
	pbs417 = pbsRelease{4, 1, 7}
	pbs427 = pbsRelease{4, 2, 7}
)

func (r *networkInterfaceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_interface"
}

func (r *networkInterfaceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	interfaceList := func() []validator.String {
		return append(networkInterfaceNameValidators(), stringvalidator.NoneOf("lo"))
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a network interface of a Proxmox Backup Server node in " +
			"`/etc/network/interfaces`: a Linux bridge, a bond or a VLAN interface, which the resource creates, " +
			"or a physical interface (`eth`), which it takes over.\n\n" +
			"!> **A wrong network setting cuts the node off, from Terraform and from you.** Changing the address, " +
			"gateway, ports or MTU of the interface the provider reaches PBS through — or of one it runs on — " +
			"can leave the node unreachable once the change is applied, and PBS keeps no copy of the previous " +
			"configuration and does not roll back. Have the node's console at hand before changing interfaces it " +
			"is reached through, and read the guide _Managing the network of a PBS node_.\n\n" +
			"**Changes are pending until applied.** PBS writes every change to `/etc/network/interfaces.new`, and " +
			"none takes effect until the network is reloaded — with `pbs_network_apply`, or Apply Configuration " +
			"in the web interface — or, from PBS 4.0.8, the node boots. The resource describes that file, pending " +
			"changes included: while changes are pending, PBS reports the pending configuration, not the one the " +
			"node runs.\n\n" +
			"**Creating needs root@pam.** PBS refuses to create an interface for every user but `root@pam` — an " +
			"API token, even root@pam's, and any other user get `permission check failed`, whatever their ACL — " +
			"so a configuration that creates — or replaces — bridges, bonds or VLAN interfaces needs the provider to " +
			"sign in with `username = \"root@pam\"` and its `password`, and the plan fails otherwise. That is " +
			"impossible when root@pam has two-factor authentication, which the provider cannot complete: create the " +
			"interface on the node then — in the web " +
			"interface, or with `proxmox-backup-manager network create` — and import it. Changing, deleting and " +
			"reading existing interfaces, and taking over a physical one, need `" + networkInterfaceModifyPrivilege +
			"` and `" + networkInterfaceReadPrivilege + "`, which an API token may have.\n\n" +
			"**A physical interface cannot be created or removed.** Creating the resource takes it over: it sets " +
			"what the configuration sets, autostart included, which defaults to `true`, and removes the comments " +
			"and MTU the configuration leaves out, with a warning in the plan. The plan refuses a takeover that " +
			"would remove addresses or gateways, unless the configuration sets `method` (or `method6`) explicitly: " +
			"import the interface instead, and write its settings into the configuration. Destroying the resource " +
			"resets the interface to what PBS lists for a NIC the file does not configure: method `manual`, no " +
			"addresses, comments or MTU, no autostart — PBS 4.1.7 and later keep an IPv6 method `dhcp` or `auto`. " +
			"To stop managing an interface and leave it as it is — the one the node is reached through above all " +
			"—, remove it from the state instead (a `removed` block with " +
			"`destroy = false`, or `terraform state rm`). Lines of a stanza PBS does not interpret, such as `post-up` " +
			"commands or `bridge-stp off`, are kept through every change; `options` and `options6` show them.\n\n" +
			"**Changes to several interfaces** are written one at a time, ports and slaves before the bridges and " +
			"bonds that use them, and PBS checks the whole pending configuration at every write. So some changes " +
			"take two applies, as the guide describes: removing a bond together with the bridge port it is, moving " +
			"a NIC from a bridge into a new bond, raising the MTU of a bridge and its ports. Keep the network apply " +
			"out of the first one, so that the node never runs the state in between.\n\n" +
			"**IPv4 DHCP.** PBS's API keeps only `static` and `manual` for IPv4: it turns any other IPv4 method, such " +
			"as `dhcp`, into `manual` whenever it changes an interface. So a change of a bridge, bond or VLAN " +
			"interface whose configuration sets `method = \"dhcp\"` replaces it — deletes it from the pending " +
			"configuration and creates it anew, which needs root@pam and drops its `options` —, and the plan refuses " +
			"to change an interface that has an IPv4 method other than `static` and `manual` when the configuration " +
			"leaves `method` out, as it does to keep DHCP on a physical interface.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "`<node>/<name>`, such as `localhost/vmbr1`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"node": nodeAttributeDescribed("Node whose interface to manage: `localhost`, which every PBS answers to, " +
				"or the node's host name. Defaults to the provider's `node`. Both name the same node: manage each " +
				"interface with one resource only. Changing it replaces the resource."),
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Name of the interface, up to 15 characters: an existing NIC's, such as `eno1`, " +
					"for `eth`, or a new one, such as `vmbr1` or `bond0`. A VLAN interface named `<device>.<tag>`, " +
					"such as `bond0.20`, or `vlan<tag>`, such as `vlan20`, takes its tag (and device) from the name, " +
					"as PBS and ifupdown2 do; bridges and bonds must not have such names. Changing it replaces " +
					"the resource.",
				Validators:    append(networkInterfaceNameValidators(), stringvalidator.NoneOf("lo")),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"type": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Type of the interface: `bridge`, `bond` or `vlan`, which the resource creates, " +
					"or `eth`, a physical interface the node has, which it takes over. Changing it replaces the resource.",
				Validators:    []validator.String{stringvalidator.OneOf(networkTypeBridge, networkTypeBond, networkTypeVLAN, networkTypeEth)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"autostart": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				MarkdownDescription: "Whether the node brings the interface up at boot and when the network is " +
					"reloaded (an `auto` line). Defaults to `true`: `ifreload -a`, which applies the changes, " +
					"configures only such interfaces — and brings each of them in line with the file, removing " +
					"addresses the file does not list, such as ones added by hand.",
			},
			"method": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "IPv4 method: `static` with an address or gateway, `manual` without, or " +
					"`dhcp`, for a bridge, bond or VLAN interface only, which then has to be replaced to change (see " +
					"above). Left out, it follows from `cidr` and `gateway`; an existing interface keeps another method " +
					"it has, such as `dhcp`, which the plan then refuses to change, and a new one gets `manual`.",
				Validators: []validator.String{
					stringvalidator.OneOf(networkMethodManual, networkMethodStatic, networkMethodDHCP),
				},
			},
			"cidr": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "IPv4 address with its prefix length, such as `192.0.2.10/24`.",
				Validators:          []validator.String{interfaceAddressValidator{}},
			},
			"gateway": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "IPv4 default gateway, such as `192.0.2.1`. PBS allows one IPv4 gateway in " +
					"the whole configuration and refuses a second.",
				Validators: []validator.String{gatewayValidator{}},
			},
			"method6": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "IPv6 method: `static` with an address or gateway, `manual` without, `dhcp` " +
					"(PBS 4.1.7 and later) or `auto` — SLAAC, from router advertisements (PBS 4.2.7 and later). Left " +
					"out, it follows from `cidr6` and `gateway6`, and keeps `dhcp` or `auto` for an interface that " +
					"has it. Older PBS releases turn `dhcp` and `auto` into `manual` on any change of an interface, " +
					"and those before 4.2.7 cannot read a configuration with `auto` at all.",
				Validators: []validator.String{
					stringvalidator.OneOf(networkMethodManual, networkMethodStatic, networkMethodDHCP, networkMethodAuto),
				},
			},
			"cidr6": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "IPv6 address with its prefix length, such as `2001:db8::10/64`.",
				Validators:          []validator.String{interfaceAddressValidator{ipv6: true}},
			},
			"gateway6": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "IPv6 default gateway, such as `2001:db8::1` or `fe80::1`. PBS allows one " +
					"IPv6 gateway in the whole configuration.",
				Validators: []validator.String{gatewayValidator{ipv6: true}},
			},
			"mtu": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "MTU in bytes, 68 to 65535. Left out, the file sets none and the kernel's " +
					"default applies — 1500 for Ethernet. PBS refuses a port or slave whose MTU is larger than its " +
					"bridge's or bond's, counting a bridge without an MTU as 1500; a bond without one takes any. To " +
					"raise the MTU of a bridge and its ports, raise the bridge's in one apply and the ports' in the next.",
				Validators: []validator.Int64{int64validator.Between(68, 65535)},
			},
			"comments": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Comment of the interface, shown in the web interface; several lines are fine. " +
					"PBS writes each as a `#` line of the IPv4 stanza and reads it back trimmed, so no line may " +
					"begin or end with white space.",
				Validators: []validator.String{networkCommentsCheck},
			},
			"comments6": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Comment of the IPv6 stanza, which PBS keeps apart; it makes PBS write an " +
					"`inet6` stanza even when `method6` is `manual`.",
				Validators: []validator.String{networkCommentsCheck},
			},
			"bridge_ports": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				MarkdownDescription: "Ports of a bridge, such as `[\"eno1\"]` or a bond; left out, the bridge has " +
					"none (`bridge-ports none`). PBS refuses ports that do not exist and ports another bridge or " +
					"bond uses. Only for `bridge`.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(interfaceList()...),
				},
			},
			"bridge_vlan_aware": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether a bridge is VLAN-aware. Defaults to `false`. Only for `bridge`.",
			},
			"vlan_id": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Tag of a VLAN interface, 1 to 4094. Required unless the name gives it " +
					"(`<device>.<tag>` or `vlan<tag>`), and then, if set, the same. PBS cannot remove it, so " +
					"removing it replaces the resource. Only for `vlan`.",
				Validators:    []validator.Int64{int64validator.Between(1, 4094)},
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplaceIf(removedInt64, "Removing the VLAN tag replaces the interface: PBS cannot remove it.", "Removing the VLAN tag replaces the interface: PBS cannot remove it.")},
			},
			"vlan_raw_device": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Interface a VLAN interface runs on, such as `bond0`, which must exist. " +
					"Required unless the name gives it (`<device>.<tag>`), and then, if set, the same. PBS cannot " +
					"remove it, so removing it replaces the resource. Only for `vlan`.",
				Validators:    interfaceList(),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIf(removedString, "Removing the VLAN device replaces the interface: PBS cannot remove it.", "Removing the VLAN device replaces the interface: PBS cannot remove it.")},
			},
			"slaves": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				MarkdownDescription: "Physical interfaces of a bond, in order; left out, the bond has none " +
					"(`bond-slaves none`). PBS refuses slaves that are not physical (`eth`) interfaces of the " +
					"node and slaves another bridge or bond uses. Only for `bond`.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.NoNullValues(),
					listvalidator.UniqueValues(),
					listvalidator.ValueStringsAre(interfaceList()...),
				},
			},
			"bond_mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Mode of a bond: `balance-rr`, `active-backup`, `balance-xor`, `broadcast`, " +
					"`802.3ad` (LACP), `balance-tlb` or `balance-alb`. Defaults to `balance-rr`, as PBS does. Only " +
					"for `bond`.",
				Validators: []validator.String{stringvalidator.OneOf(bondModes...)},
			},
			"bond_primary": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Slave an `active-backup` bond prefers, one of `slaves`. Only with " +
					"`bond_mode = \"active-backup\"`.",
				Validators: networkInterfaceNameValidators(),
			},
			"bond_xmit_hash_policy": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Transmit hash policy of an `802.3ad` or `balance-xor` bond: `layer2`, " +
					"`layer2+3` or `layer3+4`. Left out, the kernel's default (`layer2`) applies.",
				Validators: []validator.String{stringvalidator.OneOf("layer2", "layer2+3", "layer3+4")},
			},
			"options": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				MarkdownDescription: "Lines of the IPv4 stanza PBS does not interpret, such as `bridge-stp off` " +
					"or `post-up` commands, verbatim. The resource neither sets nor removes them, and PBS keeps them " +
					"through every change, but a replacement creates the interface without them.",
				// PBS keeps them through every change the resource makes.
				PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
			},
			"options6": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Lines of the IPv6 stanza PBS does not interpret, verbatim.",
				PlanModifiers:       []planmodifier.List{listplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

// removedString and removedInt64 require replacement when a value the state
// has is removed from the configuration: PBS cannot delete it.
func removedString(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
	resp.RequiresReplace = !req.StateValue.IsNull() && req.PlanValue.IsNull()
}

func removedInt64(_ context.Context, req planmodifier.Int64Request, resp *int64planmodifier.RequiresReplaceIfFuncResponse) {
	resp.RequiresReplace = !req.StateValue.IsNull() && req.PlanValue.IsNull()
}

func (r *networkInterfaceResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(
		identityAttribute{"node", "Node name, such as `localhost`."},
		identityAttribute{"name", "Interface name, such as `vmbr1`."},
	)
}

func (r *networkInterfaceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// known reports whether a value is neither null nor unknown.
func known(v attr.Value) bool { return !v.IsNull() && !v.IsUnknown() }

func (r *networkInterfaceResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m networkInterfaceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Type.IsUnknown() || m.Name.IsUnknown() {
		return
	}
	typ, name := m.Type.ValueString(), m.Name.ValueString()

	// Attributes of other types.
	only := func(p string, v attr.Value, want string) {
		if !v.IsNull() && typ != want && !m.Type.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root(p), "Attribute of another interface type",
				fmt.Sprintf("%s is only for interfaces of type %q, and %s is a %q.", p, want, name, typ))
		}
	}
	only("bridge_ports", m.BridgePorts, networkTypeBridge)
	if known(m.BridgeVLANAware) && m.BridgeVLANAware.ValueBool() {
		only("bridge_vlan_aware", m.BridgeVLANAware, networkTypeBridge)
	}
	only("slaves", m.Slaves, networkTypeBond)
	only("bond_mode", m.BondMode, networkTypeBond)
	only("bond_primary", m.BondPrimary, networkTypeBond)
	only("bond_xmit_hash_policy", m.BondXmitHashPolicy, networkTypeBond)
	only("vlan_id", m.VLANID, networkTypeVLAN)
	only("vlan_raw_device", m.VLANRawDevice, networkTypeVLAN)

	if !m.Name.IsNull() {
		switch typ {
		case networkTypeBridge, networkTypeBond:
			if looksLikeVLAN(name) {
				resp.Diagnostics.AddAttributeError(path.Root("name"), "Name of a VLAN interface",
					fmt.Sprintf("PBS and ifupdown2 take a name such as %q — <device>.<tag> or vlan<tag> — for a VLAN "+
						"interface. Give the %s another name.", name, typ))
			}
		case networkTypeVLAN:
			validateVLANName(m, resp)
		}
	}

	// Ports and slaves.
	if known(m.BridgePorts) {
		for _, port := range sortedStrings(m.BridgePorts.Elements()) {
			if port == name {
				resp.Diagnostics.AddAttributeError(path.Root("bridge_ports"), "Bridge port is the bridge",
					fmt.Sprintf("%s cannot be a port of itself.", name))
			}
		}
	}
	// Elements may be unknown, such as the names of other interfaces.
	slaves := stringsOf(m.Slaves)
	allSlavesKnown := known(m.Slaves) && len(slaves) == len(m.Slaves.Elements())
	if known(m.Slaves) {
		if slices.Contains(slaves, name) {
			resp.Diagnostics.AddAttributeError(path.Root("slaves"), "Bond slave is the bond",
				fmt.Sprintf("%s cannot be a slave of itself.", name))
		}
	}

	// Bond options PBS takes only with some modes, and then writes only
	// for them.
	mode := defaultBondMode
	if !m.BondMode.IsNull() {
		mode = m.BondMode.ValueString()
	}
	if known(m.BondPrimary) && !m.BondMode.IsUnknown() {
		if !slices.Contains(bondModesWithPrimary, mode) {
			resp.Diagnostics.AddAttributeError(path.Root("bond_primary"), "Bond primary without active-backup",
				fmt.Sprintf("PBS takes a primary slave only for a bond with bond_mode = \"active-backup\", and this "+
					"bond's mode is %q.", mode))
		}
		if allSlavesKnown && !slices.Contains(slaves, m.BondPrimary.ValueString()) {
			resp.Diagnostics.AddAttributeError(path.Root("bond_primary"), "Bond primary is not a slave",
				fmt.Sprintf("The primary slave %q must be one of slaves.", m.BondPrimary.ValueString()))
		}
	}
	if known(m.BondXmitHashPolicy) && !m.BondMode.IsUnknown() && !slices.Contains(bondModesWithXmitHash, mode) {
		resp.Diagnostics.AddAttributeError(path.Root("bond_xmit_hash_policy"), "Transmit hash policy of another bond mode",
			fmt.Sprintf("PBS takes a transmit hash policy only for a bond with bond_mode \"802.3ad\" or "+
				"\"balance-xor\", and this bond's mode is %q.", mode))
	}

	validateMethods(m.Method, m.CIDR, m.Gateway, "method", "cidr", "gateway", &resp.Diagnostics)
	validateMethods(m.Method6, m.CIDR6, m.Gateway6, "method6", "cidr6", "gateway6", &resp.Diagnostics)
	if known(m.Method) && m.Method.ValueString() == networkMethodDHCP && typ == networkTypeEth {
		resp.Diagnostics.AddAttributeError(path.Root("method"), "DHCP on a physical interface",
			"PBS's API turns the IPv4 method dhcp into manual whenever it changes an interface, and the "+
				"resource takes over a physical interface with such a change. Give it a static address, or leave "+
				"this interface out of Terraform.")
	}
	warnGatewayOutsidePrefix(m.CIDR, m.Gateway, "gateway", &resp.Diagnostics)
	warnGatewayOutsidePrefix(m.CIDR6, m.Gateway6, "gateway6", &resp.Diagnostics)
}

// validateVLANName checks that a VLAN interface's name and its tag and
// device agree, and that PBS gets both from one of them.
func validateVLANName(m networkInterfaceModel, resp *resource.ValidateConfigResponse) {
	name := m.Name.ValueString()
	device, tag, hasTag := vlanFromName(name)
	if hasTag && (tag < 1 || tag > 4094) {
		resp.Diagnostics.AddAttributeError(path.Root("name"), "VLAN tag out of range",
			fmt.Sprintf("The name %s gives the VLAN tag %d, and a VLAN tag must be 1 to 4094, or the kernel refuses "+
				"the interface when the change is applied. Choose another name.", name, tag))
	}
	switch {
	case known(m.VLANID) && hasTag && m.VLANID.ValueInt64() != tag:
		resp.Diagnostics.AddAttributeError(path.Root("vlan_id"), "VLAN tag differs from the name",
			fmt.Sprintf("The name %s gives the VLAN tag %d, and vlan_id is %d. Leave vlan_id out, or set it to %d.",
				name, tag, m.VLANID.ValueInt64(), tag))
	case m.VLANID.IsNull() && !hasTag:
		resp.Diagnostics.AddAttributeError(path.Root("vlan_id"), "Missing VLAN tag",
			fmt.Sprintf("The name %s gives no VLAN tag (as <device>.<tag> or vlan<tag> would), so set vlan_id.", name))
	}
	switch {
	case known(m.VLANRawDevice) && device != "" && m.VLANRawDevice.ValueString() != device:
		resp.Diagnostics.AddAttributeError(path.Root("vlan_raw_device"), "VLAN device differs from the name",
			fmt.Sprintf("The name %s gives the device %s, and vlan_raw_device is %s. Leave vlan_raw_device out, or "+
				"set it to %s.", name, device, m.VLANRawDevice.ValueString(), device))
	case m.VLANRawDevice.IsNull() && device == "":
		resp.Diagnostics.AddAttributeError(path.Root("vlan_raw_device"), "Missing VLAN device",
			fmt.Sprintf("The name %s gives no device (as <device>.<tag> would), so set vlan_raw_device.", name))
	case known(m.VLANRawDevice) && m.VLANRawDevice.ValueString() == name:
		resp.Diagnostics.AddAttributeError(path.Root("vlan_raw_device"), "VLAN device is the interface",
			fmt.Sprintf("%s cannot run on itself.", name))
	}
}

// validateMethods checks one address family's method against its address
// and gateway: PBS makes the method static whenever either is set, and
// keeps static only with one of them.
func validateMethods(method, cidr, gateway types.String, methodName, cidrName, gatewayName string, diags *diag.Diagnostics) {
	if !known(method) || cidr.IsUnknown() || gateway.IsUnknown() {
		return
	}
	hasAddress := !cidr.IsNull() || !gateway.IsNull()
	switch m := method.ValueString(); {
	case m == networkMethodStatic && !hasAddress:
		diags.AddAttributeError(path.Root(methodName), "Static method without an address",
			fmt.Sprintf("%s = \"static\" needs %s or %s; without them, leave %s out or set it to \"manual\".",
				methodName, cidrName, gatewayName, methodName))
	case m != networkMethodStatic && hasAddress:
		diags.AddAttributeError(path.Root(methodName), "Address with another method than static",
			fmt.Sprintf("PBS makes the method static whenever %s or %s is set, so %s = %q cannot go with them. "+
				"Leave %s out, or remove the address and gateway.", cidrName, gatewayName, methodName, m, methodName))
	}
}

// warnGatewayOutsidePrefix warns when a gateway is outside the interface's
// own prefix. ifupdown2 adds the default route on-link, so the kernel takes
// it and the reload succeeds, but the route works only if the gateway is on
// the interface's link — as with a /32 address from a hosting provider;
// otherwise it is usually a typo that leaves the node without a working
// default route.
func warnGatewayOutsidePrefix(cidr, gateway types.String, gatewayName string, diags *diag.Diagnostics) {
	if !known(cidr) || !known(gateway) {
		return
	}
	prefix, err := netip.ParsePrefix(cidr.ValueString())
	addr, err2 := netip.ParseAddr(gateway.ValueString())
	if err != nil || err2 != nil || addr.IsLinkLocalUnicast() || prefix.Masked().Contains(addr) {
		return
	}
	diags.AddAttributeWarning(path.Root(gatewayName), "Gateway outside the interface's network",
		fmt.Sprintf("The gateway %s is not in %s, the network of the interface's address. ifupdown2 adds the default "+
			"route as on-link, so applying the change works, but the route works only if the gateway really is on "+
			"this interface's link, as with a /32 address from a hosting provider; otherwise the node loses its "+
			"default route once the change is applied.", addr, prefix.Masked()))
}

func (r *networkInterfaceResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		r.warnDestroy(ctx, req, resp)
		return
	}
	var plan, config networkInterfaceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	var state *networkInterfaceModel
	if !req.State.Raw.IsNull() {
		state = &networkInterfaceModel{}
		resp.Diagnostics.Append(req.State.Get(ctx, state)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Node.IsUnknown() && config.Node.IsNull() && r.data != nil {
		plan.Node = types.StringValue(r.data.client.Node())
	}
	if plan.ID.IsUnknown() && known(plan.Node) && known(plan.Name) {
		plan.ID = types.StringValue(networkInterfaceID(plan.Node.ValueString(), plan.Name.ValueString()))
	}

	// A replacement creates the interface anew, which PBS treats as a
	// create; anything else that differs from the state is an update.
	replacing := state != nil && (!plan.Node.Equal(state.Node) || !plan.Name.Equal(state.Name) || !plan.Type.Equal(state.Type) ||
		(!state.VLANID.IsNull() && plan.VLANID.IsNull()) || (!state.VLANRawDevice.IsNull() && plan.VLANRawDevice.IsNull()))
	var prior *networkInterfaceModel
	if state != nil && !replacing {
		prior = state
	}
	takingOver := (state == nil || replacing) && plan.Type.ValueString() == networkTypeEth

	if config.Method.IsNull() {
		plan.Method = plannedMethod(plan.Method, plan.CIDR, plan.Gateway, prior, false, takingOver)
	}
	if config.Method6.IsNull() {
		plan.Method6 = plannedMethod(plan.Method6, plan.CIDR6, plan.Gateway6, prior, true, takingOver)
	}
	// A bond the configuration gives no mode gets PBS's default, also when
	// it has another one: the attribute defaults to balance-rr.
	if config.BondMode.IsNull() && known(plan.Type) {
		if plan.Type.ValueString() == networkTypeBond {
			plan.BondMode = types.StringValue(defaultBondMode)
		} else {
			plan.BondMode = types.StringNull()
		}
	}

	if r.data != nil {
		r.checkMethodVersions(config, &resp.Diagnostics)
		if takingOver && known(plan.Node) && known(plan.Name) {
			r.planTakeover(ctx, &plan, config, &resp.Diagnostics)
		}
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updating := state != nil && !replacing && !resp.Plan.Raw.Equal(req.State.Raw)
	recreating := false
	if updating && config.Method.IsUnknown() && known(plan.Type) && plan.Type.ValueString() != networkTypeEth {
		// Whether the change replaces the interface depends on the method,
		// and Terraform cannot turn an update into a replacement at apply.
		resp.Diagnostics.AddAttributeError(path.Root("method"), "IPv4 method unknown when planning",
			fmt.Sprintf("Changing %s needs its IPv4 method known when planning: a method other than static and manual "+
				"makes the change a replacement, which Terraform has to know of then. Apply the resource the method "+
				"comes from first (terraform apply -target=...), or set the method directly.", plan.Name.ValueString()))
		return
	}
	if updating {
		recreating = r.checkKeptMethods(plan, config, *state, req, resp)
	}
	if (replacing || recreating) && known(plan.Type) && plan.Type.ValueString() != networkTypeEth {
		if r.data != nil && !r.data.canCreateNetworkInterfaces() {
			resp.Diagnostics.AddError("Replacing a network interface needs root@pam",
				fmt.Sprintf("This plan replaces %s, which deletes it and creates it anew, and PBS lets only root@pam signed "+
					"in with a password create a network interface, whatever the ACL. The provider signs in as %s: the "+
					"delete would go through and the create fail, leaving %s removed from the pending configuration. "+
					"Set the provider's username to \"root@pam\" and its password.%s",
					state.Name.ValueString(), r.data.client.AuthID(), state.Name.ValueString(), noRootAdvice))
		}
	}
	if (replacing || recreating) && state.Type.ValueString() != networkTypeEth {
		if lines := append(stringsOf(state.Options), stringsOf(state.Options6)...); len(lines) > 0 {
			resp.Diagnostics.AddWarning("Replacing a network interface drops lines PBS does not interpret",
				fmt.Sprintf("This plan replaces %s, and PBS creates the new interface without the lines of its stanza it "+
					"does not interpret: %s.", state.Name.ValueString(), strings.Join(lines, "; ")))
		}
	}
	// An error, not a warning: Terraform plans a forced replacement
	// (-replace, replace_triggered_by) as an unchanged update and then as a
	// create, and keeps only the errors of the latter — a warning there would
	// let the delete go through and the create fail.
	if state == nil && known(plan.Type) && plan.Type.ValueString() != networkTypeEth && r.data != nil && !r.data.canCreateNetworkInterfaces() {
		resp.Diagnostics.AddError("Creating a network interface needs root@pam",
			fmt.Sprintf("This plan creates the %s %s — or replaces it, which deletes it and creates it anew —, and PBS "+
				"refuses to create a network interface for anyone but root@pam signed in with a password, whatever the "+
				"ACL: the provider signs in as %s. Set the provider's username to \"root@pam\" and its password.%s",
				plan.Type.ValueString(), plan.Name.ValueString(), r.data.client.AuthID(), noRootAdvice))
	}
}

// noRootAdvice is the way out for configurations that cannot sign in as
// root@pam.
const noRootAdvice = " Where that is impossible — root@pam with two-factor authentication, which the provider cannot " +
	"complete, or only an API token at hand —, create the interface on the node, in the web interface or with " +
	"`proxmox-backup-manager network create`, and import it: changing it needs only Sys.Modify."

// stringsOf returns the known elements of a list of strings.
func stringsOf(list types.List) []string {
	var out []string
	for _, e := range list.Elements() {
		if s, ok := e.(types.String); ok && known(s) {
			out = append(out, s.ValueString())
		}
	}
	return out
}

// canCreateNetworkInterfaces reports whether the provider signs in as the
// only user PBS lets create network interfaces.
func (d *providerData) canCreateNetworkInterfaces() bool {
	return !d.client.UsesAPIToken() && d.client.AuthID() == "root@pam"
}

// plannedMethod fills in an address family's method the configuration
// leaves out: static with an address or gateway, as PBS makes it, otherwise
// a method other than manual and static the interface already has — which
// PBS would drop, so that keeping it shows, and the plan can refuse to drop
// it silently —, otherwise manual. A takeover of a physical interface
// leaves it unknown when there is no address, for planTakeover and Create
// to settle from what the interface has.
func plannedMethod(method, cidr, gateway types.String, prior *networkInterfaceModel, ipv6, takingOver bool) types.String {
	if !method.IsUnknown() {
		return method
	}
	if cidr.IsUnknown() || gateway.IsUnknown() {
		return method
	}
	if !cidr.IsNull() || !gateway.IsNull() {
		return types.StringValue(networkMethodStatic)
	}
	if takingOver {
		return method
	}
	if prior != nil {
		current := prior.Method
		if ipv6 {
			current = prior.Method6
		}
		if known(current) && current.ValueString() != networkMethodManual && current.ValueString() != networkMethodStatic {
			return current
		}
	}
	return types.StringValue(networkMethodManual)
}

// planTakeover reads the physical interface a create takes over, settles
// the methods the configuration leaves out from what it has, and shows in
// the plan what the takeover removes — refusing to remove addresses and
// gateways the configuration does not give up explicitly. Create reads it
// again under the lock and settles the takeover anew.
func (r *networkInterfaceResource) planTakeover(ctx context.Context, plan *networkInterfaceModel, config networkInterfaceModel, diags *diag.Diagnostics) {
	node, name := plan.Node.ValueString(), plan.Name.ValueString()
	iface, err := r.data.client.NetworkInterface(ctx, node, name)
	if pbsclient.IsNotFound(err) {
		diags.AddAttributeError(path.Root("name"), "No such physical interface", noSuchPhysicalInterface(node, name))
		return
	}
	if err != nil {
		// Create could not do without the read either, and leaving the
		// methods unknown would make the plan Terraform makes again at apply
		// differ from this one.
		diags.AddAttributeError(path.Root("name"), "Unable to read the PBS network interface",
			fmt.Sprintf("Taking over %s on node %s needs its current settings. %s", name, node,
				apiErrorDetail(r.data.client, networkInterfaceReadPrivilege, err)))
		return
	}
	var current networkInterfaceModel
	current.fromInterface(node, iface, diags)
	changes, err := settleTakeover(plan, config, current, r.data.version)
	if err != nil {
		diags.AddAttributeError(path.Root("name"), "Unable to take over the PBS network interface", err.Error())
		return
	}
	if len(changes) > 0 {
		diags.AddAttributeWarning(path.Root("name"), "Taking over a physical network interface changes what the configuration leaves out",
			fmt.Sprintf("Taking over %s on node %s changes what the configuration leaves out: %s. The change is "+
				"pending until the network is applied; to keep what %s has, import it and write its settings into "+
				"the configuration.", name, node, strings.Join(changes, ", "), name))
	}
}

// noSuchPhysicalInterface explains a takeover of an interface the node does
// not have.
func noSuchPhysicalInterface(node, name string) string {
	return fmt.Sprintf("Node %s has no interface %s. A physical interface (type eth) cannot be created: the resource "+
		"takes over a NIC the node has, which pbs_network_interfaces lists.", node, name)
}

// settleTakeover checks a takeover of the physical interface current
// against the configuration: it must be a physical interface, the methods
// the configuration leaves out are settled from what it has — PBS turns an
// IPv4 method other than static and manual into manual on any change, and
// before 4.1.7 the IPv6 methods dhcp and auto too, which the takeover
// refuses unless the configuration says so —, and so is giving up its
// addresses and gateways. It fills in plan's unknown methods, refuses a
// known one that no longer fits — the interface changed since the plan —,
// and returns what else the takeover changes, for a warning.
func settleTakeover(plan *networkInterfaceModel, config, current networkInterfaceModel, version pbsclient.Version) ([]string, error) {
	name := plan.Name.ValueString()
	if t := current.Type.ValueString(); t != networkTypeEth {
		return nil, fmt.Errorf("%s is not a physical interface but a %s; PBS reports type eth for a physical NIC", name, t)
	}
	settle := func(method *types.String, want, attribute string) error {
		if method.IsUnknown() {
			*method = types.StringValue(want)
			return nil
		}
		if method.ValueString() != want {
			return fmt.Errorf("%s changed since the plan: its %s is now planned as %q, and the interface calls for %q. "+
				"Plan again", name, attribute, method.ValueString(), want)
		}
		return nil
	}

	if config.Method.IsNull() && config.CIDR.IsNull() && config.Gateway.IsNull() {
		if m := current.Method.ValueString(); m != networkMethodManual && m != networkMethodStatic {
			return nil, fmt.Errorf("%s has the IPv4 method %q, and PBS's API sets the IPv4 method of any interface it "+
				"changes to static or manual, so taking it over would give up %s after the next reload. Set method = "+
				"\"manual\" or an address to do so, or leave this interface out of Terraform", name, m, m)
		}
		if err := settle(&plan.Method, networkMethodManual, "method"); err != nil {
			return nil, err
		}
	}
	if config.Method6.IsNull() && config.CIDR6.IsNull() && config.Gateway6.IsNull() {
		want := networkMethodManual
		switch m := current.Method6.ValueString(); {
		case m == networkMethodManual || m == networkMethodStatic:
		case version.AtLeast(pbs417.major, pbs417.minor, pbs417.release):
			// PBS keeps it, and the PUT does not send method6.
			want = m
		default:
			return nil, fmt.Errorf("%s has the IPv6 method %q, and PBS before 4.1.7 — the server runs %s — sets the IPv6 "+
				"method of any interface it changes to manual, so taking it over would give up %s after the next "+
				"reload. Set method6 = \"manual\" or an IPv6 address to do so, or upgrade PBS", name, m, version, m)
		}
		if err := settle(&plan.Method6, want, "method6"); err != nil {
			return nil, err
		}
	}

	var v4, v6, other []string
	removed := func(into *[]string, label string, configured, had attr.Value) {
		if !configured.IsNull() || had.IsNull() {
			return
		}
		text := had.String()
		switch v := had.(type) {
		case types.String:
			// Comments may span lines; the first is enough to recognise.
			text, _, _ = strings.Cut(v.ValueString(), "\n")
		case types.Int64:
			text = strconv.FormatInt(v.ValueInt64(), 10)
		}
		*into = append(*into, fmt.Sprintf("%s %s removed", label, text))
	}
	removed(&v4, "cidr", config.CIDR, current.CIDR)
	removed(&v4, "gateway", config.Gateway, current.Gateway)
	removed(&v6, "cidr6", config.CIDR6, current.CIDR6)
	removed(&v6, "gateway6", config.Gateway6, current.Gateway6)
	removed(&other, "mtu", config.MTU, current.MTU)
	removed(&other, "comments", config.Comments, current.Comments)
	removed(&other, "comments6", config.Comments6, current.Comments6)
	if config.Autostart.IsNull() && !current.Autostart.ValueBool() {
		other = append(other, "autostart turned on (the default)")
	}
	refuse := func(lost []string, attribute string, cidr, gateway types.String) error {
		// With an address or gateway configured, the method is static.
		method := networkMethodManual
		if !cidr.IsNull() || !gateway.IsNull() {
			method = networkMethodStatic
		}
		return fmt.Errorf("taking over %s would remove what the configuration leaves out: %s. After the next reload the "+
			"node would not have it any more — and if it is reached through %s, it would be cut off. Import the "+
			"interface and write its settings into the configuration (import { to = <address>, id = \"<node>/%s\" }), "+
			"or set %s = %q to give them up", name, strings.Join(lost, ", "), name, name, attribute, method)
	}
	if len(v4) > 0 && config.Method.IsNull() {
		return nil, refuse(v4, "method", config.CIDR, config.Gateway)
	}
	if len(v6) > 0 && config.Method6.IsNull() {
		return nil, refuse(v6, "method6", config.CIDR6, config.Gateway6)
	}
	return append(append(v4, v6...), other...), nil
}

// warnDestroy warns when destroying an interface takes addresses off the
// node: a bridge, bond or VLAN interface is deleted, a physical one reset.
func (r *networkInterfaceResource) warnDestroy(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() {
		return
	}
	var state networkInterfaceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var addresses []string
	for _, v := range []types.String{state.CIDR, state.Gateway, state.CIDR6, state.Gateway6} {
		if known(v) {
			addresses = append(addresses, v.ValueString())
		}
	}
	if len(addresses) == 0 {
		return
	}
	name := state.Name.ValueString()
	what := "deletes it from the pending configuration, and with it"
	if state.Type.ValueString() == networkTypeEth {
		what = "resets it to method manual, removing"
	}
	resp.Diagnostics.AddWarning("Destroying a network interface removes its addresses",
		fmt.Sprintf("Destroying pbs_network_interface %s on node %s %s %s. That takes effect when the network is "+
			"applied — by pbs_network_apply in this run, when its triggers change, by the next reload, or, from PBS "+
			"4.0.8, when the node boots —, and if the node is reached through %s, it is cut off then. To stop managing "+
			"the interface and keep it as it is, remove it from the state instead: a removed block with "+
			"lifecycle { destroy = false }, or terraform state rm.",
			name, state.Node.ValueString(), what, strings.Join(addresses, ", "), name))
}

// checkMethodVersions fails the plan for IPv6 methods the configuration
// sets that the server cannot keep or does not know. One the interface
// already has and the configuration leaves out is checkKeptMethods' to
// judge, only when the plan changes the interface.
func (r *networkInterfaceResource) checkMethodVersions(config networkInterfaceModel, diags *diag.Diagnostics) {
	if !known(config.Method6) {
		return
	}
	switch config.Method6.ValueString() {
	case networkMethodAuto:
		r.data.requireRelease(diags, path.Root("method6"), config.Method6, pbs427)
	case networkMethodDHCP:
		r.data.requireRelease(diags, path.Root("method6"), config.Method6, pbs417)
	}
}

// checkKeptMethods judges an update that PBS would carry out by turning a
// method it cannot keep into manual: any IPv4 method but static and
// manual, and, before PBS 4.1.7, the IPv6 methods dhcp and auto. The same
// holds for switching to such a method, which PBS's PUT cannot do. When the
// configuration sets such an IPv4 method on a bridge, bond or VLAN
// interface, the update becomes a replacement, and it reports true;
// otherwise the plan fails.
func (r *networkInterfaceResource) checkKeptMethods(plan, config, state networkInterfaceModel, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) bool {
	name := plan.Name.ValueString()
	if known(plan.Method) && plan.Method.ValueString() != networkMethodManual && plan.Method.ValueString() != networkMethodStatic {
		m := plan.Method.ValueString()
		if known(config.Method) && plan.Type.ValueString() != networkTypeEth {
			resp.RequiresReplace = append(resp.RequiresReplace, changedAttributes(resp.Plan.Raw, req.State.Raw)...)
			resp.Diagnostics.AddAttributeWarning(path.Root("method"), "Changing an interface with this IPv4 method replaces it",
				fmt.Sprintf("PBS's API sets the IPv4 method of any interface it changes to static or manual, so this plan "+
					"keeps %s's method %q by replacing the interface: deleting it from the pending configuration and "+
					"creating it anew. That needs root@pam, and PBS refuses to delete an interface a bridge uses as a "+
					"port or a bond as a slave.", name, m))
			return true
		}
		advice := "Set `method = \"" + m + "\"` in the configuration to change it by replacing the interface — " +
			"deleting it from the pending configuration and creating it anew, which needs root@pam and drops the lines " +
			"PBS does not interpret (`options`) —, or set `method = \"manual\"` or an address to give up the method."
		if plan.Type.ValueString() == networkTypeEth {
			advice = "PBS cannot create a physical interface anew, so set `method = \"manual\"` or an address to " +
				"give up the method, or leave this interface out of Terraform."
		}
		resp.Diagnostics.AddAttributeError(path.Root("method"), "PBS cannot change an interface with this IPv4 method",
			fmt.Sprintf("%s has the IPv4 method %q, and PBS's API sets the IPv4 method of any interface it changes to "+
				"static or manual: after the next reload, %s would not use %s any more. %s",
				name, m, name, m, advice))
		return false
	}
	if r.data == nil || r.data.version.AtLeast(pbs417.major, pbs417.minor, pbs417.release) || !known(plan.Method6) {
		return false
	}
	if m := plan.Method6.ValueString(); m == networkMethodDHCP || m == networkMethodAuto {
		resp.Diagnostics.AddAttributeError(path.Root("method6"), "PBS cannot change an interface with this IPv6 method",
			fmt.Sprintf("%s has the IPv6 method %q, and PBS before 4.1.7 — the server runs %s — sets the IPv6 method "+
				"of any interface it changes to manual unless it has an IPv6 address. Upgrade PBS, or set "+
				"`method6 = \"manual\"` or an IPv6 address.", name, m, r.data.version))
	}
	return false
}

// changedAttributes returns the attributes whose planned value differs from
// the prior one, which a replacement has to name: Terraform replaces only
// for attributes that change. The computed id and options do not count.
func changedAttributes(plan, prior tftypes.Value) path.Paths {
	var planned, before map[string]tftypes.Value
	if plan.As(&planned) != nil || prior.As(&before) != nil {
		return nil
	}
	var changed path.Paths
	for _, name := range sortedAttributeNames(planned) {
		if name == "id" || name == "options" || name == "options6" {
			continue
		}
		if !planned[name].Equal(before[name]) {
			changed = append(changed, path.Root(name))
		}
	}
	return changed
}

// sortedAttributeNames returns the keys of m, sorted.
func sortedAttributeNames(m map[string]tftypes.Value) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// networkInterfaceID is the resource's id.
func networkInterfaceID(node, name string) string { return node + "/" + name }

// fromInterface records what PBS reports for an interface.
func (m *networkInterfaceModel) fromInterface(node string, iface pbsclient.NetworkInterface, diags *diag.Diagnostics) {
	m.ID = types.StringValue(networkInterfaceID(node, iface.Name))
	m.Node = types.StringValue(node)
	m.Name = types.StringValue(iface.Name)
	m.Type = types.StringValue(iface.Type)
	m.Autostart = types.BoolValue(iface.Autostart)
	m.Method = stringOr(iface.Method, networkMethodManual)
	m.CIDR = stringOrNull(iface.CIDR)
	m.Gateway = stringOrNull(iface.Gateway)
	// Without an inet6 stanza — which PBS leaves out for manual when
	// there is nothing else to write — the IPv6 method is manual.
	m.Method6 = stringOr(iface.Method6, networkMethodManual)
	m.CIDR6 = stringOrNull(iface.CIDR6)
	m.Gateway6 = stringOrNull(iface.Gateway6)
	m.MTU = int64OrNull(iface.MTU)
	m.Comments = stringOrNull(iface.Comments)
	m.Comments6 = stringOrNull(iface.Comments6)
	m.BridgePorts = stringSetOrNull(iface.BridgePorts, diags)
	m.BridgeVLANAware = boolOr(iface.BridgeVLANAware, false)
	m.VLANID = int64OrNull(iface.VLANID)
	m.VLANRawDevice = stringOrNull(iface.VLANRawDevice)
	m.Slaves = types.ListNull(types.StringType)
	if len(iface.Slaves) > 0 {
		m.Slaves = stringListOf(iface.Slaves, diags)
	}
	m.BondMode = stringOrNull(iface.BondMode)
	if iface.Type == networkTypeBond && iface.BondMode == "" {
		m.BondMode = types.StringValue(defaultBondMode)
	}
	m.BondPrimary = stringOrNull(iface.BondPrimary)
	m.BondXmitHashPolicy = stringOrNull(iface.BondXmitHashPolicy)
	m.Options = stringListOf(nonNil(iface.Options), diags)
	m.Options6 = stringListOf(nonNil(iface.Options6), diags)
}

// nonNil is s, or an empty slice for nil, so that a list attribute is empty
// rather than null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// createParams are the parameters of the POST that creates the interface
// plan describes.
func createParams(plan networkInterfaceModel, diags *diag.Diagnostics) url.Values {
	params := url.Values{}
	params.Set("iface", plan.Name.ValueString())
	params.Set("type", plan.Type.ValueString())
	params.Set("autostart", pbsclient.FormatBool(plan.Autostart.ValueBool()))
	params.Set("method", plan.Method.ValueString())
	params.Set("method6", plan.Method6.ValueString())
	set := func(name string, v types.String) {
		if known(v) {
			params.Set(name, v.ValueString())
		}
	}
	set("cidr", plan.CIDR)
	set("gateway", plan.Gateway)
	set("cidr6", plan.CIDR6)
	set("gateway6", plan.Gateway6)
	set("comments", plan.Comments)
	set("comments6", plan.Comments6)
	if known(plan.MTU) {
		params.Set("mtu", strconv.FormatInt(plan.MTU.ValueInt64(), 10))
	}
	switch plan.Type.ValueString() {
	case networkTypeBridge:
		if known(plan.BridgePorts) {
			params.Set("bridge_ports", strings.Join(sortedStrings(plan.BridgePorts.Elements()), ","))
		}
		if plan.BridgeVLANAware.ValueBool() {
			params.Set("bridge_vlan_aware", "true")
		}
	case networkTypeBond:
		params.Set("bond_mode", plan.BondMode.ValueString())
		set("bond-primary", plan.BondPrimary)
		set("bond_xmit_hash_policy", plan.BondXmitHashPolicy)
		if known(plan.Slaves) {
			var slaves []string
			diags.Append(plan.Slaves.ElementsAs(context.Background(), &slaves, false)...)
			params.Set("slaves", strings.Join(slaves, ","))
		}
	case networkTypeVLAN:
		if known(plan.VLANID) {
			params.Set("vlan-id", strconv.FormatInt(plan.VLANID.ValueInt64(), 10))
		}
		set("vlan-raw-device", plan.VLANRawDevice)
	}
	return params
}

// updateParams are the parameters of the PUT that makes the interface
// current — as PBS reports it — what plan describes. PBS sets the IPv4
// method from the address and gateway whatever the call says, so sending it
// only makes sure there is a PUT when nothing else changes, as when an
// interface gives up DHCP. The IPv6 method is sent when it changes; an
// unknown one, of a takeover that keeps the interface's, is not.
func updateParams(plan, current networkInterfaceModel, diags *diag.Diagnostics) url.Values {
	c := newPropertyChanges(diags, networkInterfaceDeletable...)
	if !plan.Method.IsUnknown() {
		c.String("method", plan.Method, current.Method)
	}
	c.Bool("autostart", plan.Autostart, current.Autostart)
	c.String("cidr", plan.CIDR, current.CIDR)
	c.String("gateway", plan.Gateway, current.Gateway)
	if !plan.Method6.IsUnknown() {
		c.String("method6", plan.Method6, current.Method6)
	}
	c.String("cidr6", plan.CIDR6, current.CIDR6)
	c.String("gateway6", plan.Gateway6, current.Gateway6)
	c.Int64("mtu", plan.MTU, current.MTU)
	c.String("comments", plan.Comments, current.Comments)
	c.String("comments6", plan.Comments6, current.Comments6)
	switch plan.Type.ValueString() {
	case networkTypeBridge:
		c.CommaSeparated("bridge_ports", plan.BridgePorts, current.BridgePorts)
		// false is PBS's default, which deleting the property gives.
		c.BoolDefault("bridge_vlan_aware", plan.BridgeVLANAware, current.BridgeVLANAware, false)
	case networkTypeBond:
		c.CommaSeparated("slaves", plan.Slaves, current.Slaves)
		c.String("bond_mode", plan.BondMode, current.BondMode)
		c.String("bond-primary", plan.BondPrimary, current.BondPrimary)
		c.String("bond_xmit_hash_policy", plan.BondXmitHashPolicy, current.BondXmitHashPolicy)
	case networkTypeVLAN:
		c.Int64("vlan-id", plan.VLANID, current.VLANID)
		c.String("vlan-raw-device", plan.VLANRawDevice, current.VLANRawDevice)
	}
	params := c.Values()
	// PBS sets a bond's primary and transmit hash policy only when the
	// same call carries the mode.
	if plan.Type.ValueString() == networkTypeBond && (params.Has("bond-primary") || params.Has("bond_xmit_hash_policy")) {
		params.Set("bond_mode", plan.BondMode.ValueString())
	}
	return params
}

// networkWriteError reports a failed write with advice for what PBS
// answers to network changes.
func (r *networkInterfaceResource) networkWriteError(diags *diag.Diagnostics, summary string, create bool, err error) {
	client := r.data.client
	detail := apiErrorDetail(client, networkInterfaceModifyPrivilege, err)
	switch {
	case create && pbsclient.IsForbidden(err):
		detail = fmt.Sprintf("PBS lets only root@pam, signed in with a password, create a network interface: it "+
			"checks %s with the name from the request's path, which a create does not have, and so refuses everyone "+
			"else — an API token, even root@pam's, and any other user —, whatever the ACL. The provider signs in as "+
			"%s. Set the provider's username to \"root@pam\" and its password (PBS_USERNAME and PBS_PASSWORD); "+
			"changing, deleting and applying interfaces works with an API token as well.%s %s",
			networkInterfaceModifyPrivilege, client.AuthID(), noRootAdvice, err)
	case create && pbsclient.IsAlreadyExists(err):
		detail = "The node already has an interface of that name — perhaps only in the pending configuration. " +
			"Import it (`terraform import`, with the id <node>/<name>) to manage it. " + detail
	case pbsclient.IsDuplicateGateway(err):
		detail = "PBS allows one default gateway per address family in the whole configuration, and checks the " +
			"pending configuration. To move the gateway, remove it from the other interface in the same apply and " +
			"give this interface a depends_on on that one, so that the removal is written first; one reload then " +
			"moves the default route. Do not move it in two applies with the network applied in between: the node " +
			"has no default route then. " + detail
	case isNetworkMTUConflict(err):
		detail = "PBS refuses a port or slave whose MTU is larger than its bridge's — a bridge without an MTU counts " +
			"as 1500 — and Terraform writes ports and slaves before the bridges and bonds that use them. To raise " +
			"both, raise the bridge's MTU in one apply and its ports' in the next, keeping the network apply out of " +
			"the first one; lowering works in one apply. " + detail
	case isNetworkPortInUse(err):
		detail = "PBS lets a port or slave belong to one bridge or bond only, and checks the whole pending " +
			"configuration at every write. To move it, free it in one apply — without applying the network, so " +
			"that the node never runs the state in between, for instance with -target on the interfaces — and use " +
			"it in the next. " + detail
	}
	diags.AddError(summary, detail)
}

// isNetworkMTUConflict and isNetworkPortInUse recognise PBS's refusals of
// an MTU larger than the parent's and of a port or slave used twice.
func isNetworkMTUConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "is lower than")
}

func isNetworkPortInUse(err error) bool {
	return err != nil && strings.Contains(err.Error(), "is already used on interface")
}

// readCurrent reads the interface for a write, under the configuration's
// lock.
func (r *networkInterfaceResource) readCurrent(ctx context.Context, node, name string, diags *diag.Diagnostics) (networkInterfaceModel, string, error) {
	iface, err := r.data.client.NetworkInterface(ctx, node, name)
	if err != nil {
		return networkInterfaceModel{}, "", err
	}
	var current networkInterfaceModel
	current.fromInterface(node, iface, diags)
	return current, iface.Digest, nil
}

func (r *networkInterfaceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config networkInterfaceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	node, name := plan.Node.ValueString(), plan.Name.ValueString()

	if plan.Type.ValueString() != networkTypeEth {
		params := createParams(plan, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		err := client.WithConfigLock(pbsclient.ConfigNetwork, func() error {
			return client.CreateNetworkInterface(ctx, node, params)
		})
		if err != nil {
			r.networkWriteError(&resp.Diagnostics, "Unable to create the PBS network interface", true, err)
			return
		}
		r.readBack(ctx, plan, &resp.State, resp.Identity, &resp.Diagnostics)
		return
	}

	// A physical interface: take it over. Every attempt settles the
	// takeover anew from the interface it has just read.
	planned := plan
	var changes []string
	err := client.WithConfigLock(pbsclient.ConfigNetwork, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			current, digest, err := r.readCurrent(ctx, node, name, &resp.Diagnostics)
			if err != nil {
				return err
			}
			attempt := planned
			changes, err = settleTakeover(&attempt, config, current, r.data.version)
			if err != nil {
				return err
			}
			plan = attempt
			params := updateParams(attempt, current, &resp.Diagnostics)
			if resp.Diagnostics.HasError() || len(params) == 0 {
				return nil
			}
			params.Set(pbsclient.DigestParam, digest)
			return client.UpdateNetworkInterface(ctx, node, name, params)
		})
	})
	if resp.Diagnostics.HasError() {
		return
	}
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddError("Unable to take over the PBS network interface",
				noSuchPhysicalInterface(node, name)+" "+err.Error())
			return
		}
		r.networkWriteError(&resp.Diagnostics, "Unable to take over the PBS network interface", false, err)
		return
	}
	if len(changes) > 0 {
		resp.Diagnostics.AddWarning("Took over a physical network interface",
			fmt.Sprintf("Taking over %s on node %s changed what the configuration leaves out: %s. The change is "+
				"pending until the network is applied.", name, node, strings.Join(changes, ", ")))
	}
	r.readBack(ctx, plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

// readBack reads the interface after a write and records it, or the plan
// when reading fails: the write took effect.
func (r *networkInterfaceResource) readBack(ctx context.Context, plan networkInterfaceModel, state *tfsdk.State, identity *tfsdk.ResourceIdentity, diags *diag.Diagnostics) {
	node, name := plan.Node.ValueString(), plan.Name.ValueString()
	iface, err := r.data.client.NetworkInterface(ctx, node, name)
	if err != nil {
		if plan.Options.IsUnknown() {
			plan.Options = stringListOf([]string{}, diags)
		}
		if plan.Options6.IsUnknown() {
			plan.Options6 = stringListOf([]string{}, diags)
		}
		diags.Append(state.Set(ctx, &plan)...)
		setIdentity(ctx, identity, "node", node, diags)
		setIdentity(ctx, identity, "name", name, diags)
		diags.AddWarning("Unable to read the PBS network interface back",
			fmt.Sprintf("PBS changed the pending configuration of %s on node %s, and the change was recorded in "+
				"state, but reading it back failed; the next refresh reads it again. %s",
				name, node, apiErrorDetail(r.data.client, networkInterfaceReadPrivilege, err)))
		return
	}
	var m networkInterfaceModel
	m.fromInterface(node, iface, diags)
	diags.Append(state.Set(ctx, &m)...)
	setIdentity(ctx, identity, "node", node, diags)
	setIdentity(ctx, identity, "name", name, diags)
}

func (r *networkInterfaceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkInterfaceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node, name := state.Node.ValueString(), state.Name.ValueString()
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
	iface, err := r.data.client.NetworkInterface(ctx, node, name)
	if pbsclient.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS network interface",
			networkErrorDetail(r.data.client, err))
		return
	}
	state.fromInterface(node, iface, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *networkInterfaceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan networkInterfaceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	node, name := plan.Node.ValueString(), plan.Name.ValueString()
	err := client.WithConfigLock(pbsclient.ConfigNetwork, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			current, digest, err := r.readCurrent(ctx, node, name, &resp.Diagnostics)
			if err != nil {
				return err
			}
			params := updateParams(plan, current, &resp.Diagnostics)
			if resp.Diagnostics.HasError() || len(params) == 0 {
				return nil
			}
			params.Set(pbsclient.DigestParam, digest)
			return client.UpdateNetworkInterface(ctx, node, name, params)
		})
	})
	if resp.Diagnostics.HasError() {
		return
	}
	if err != nil {
		r.networkWriteError(&resp.Diagnostics, "Unable to change the PBS network interface", false, err)
		return
	}
	r.readBack(ctx, plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

// Delete removes a bridge, bond or VLAN interface from the pending
// configuration, and resets a physical one to what PBS lists for a NIC the
// file does not configure. Removing a physical interface's stanza would do
// that too, but PBS refuses it while the interface is a bridge port or bond
// slave; the reset keeps the stanza, with method manual and nothing else
// the resource manages but an IPv6 method dhcp or auto, which PBS 4.1.7 and
// later keep.
func (r *networkInterfaceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state networkInterfaceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	node, name := state.Node.ValueString(), state.Name.ValueString()
	err := client.WithConfigLock(pbsclient.ConfigNetwork, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			iface, err := client.NetworkInterface(ctx, node, name)
			if err != nil {
				return err
			}
			if state.Type.ValueString() != networkTypeEth {
				return client.DeleteNetworkInterface(ctx, node, name, iface.Digest)
			}
			params := url.Values{}
			deletes := []string{"autostart", "cidr", "cidr6", "comments", "comments6", "gateway", "gateway6", "mtu"}
			// A static IPv6 method goes with the addresses; dhcp and auto,
			// which PBS 4.1.7 and later keep, stay, as a takeover that keeps
			// them plans — the same NIC taken over again after a replacement
			// must plan the same.
			if m := iface.Method6; m == "" || m == networkMethodManual || m == networkMethodStatic {
				deletes = append(deletes, "method6")
			}
			pbsclient.AddDelete(params, deletes...)
			params.Set(pbsclient.DigestParam, iface.Digest)
			return client.UpdateNetworkInterface(ctx, node, name, params)
		})
	})
	if err != nil && !pbsclient.IsNotFound(err) {
		detail := apiErrorDetail(client, networkInterfaceModifyPrivilege, err)
		if state.Type.ValueString() != networkTypeEth {
			detail += " PBS refuses to remove an interface that a bridge uses as a port or a bond as a slave: " +
				"remove it from there first."
		}
		resp.Diagnostics.AddError("Unable to delete the PBS network interface", detail)
	}
}

// ImportState imports an interface by <node>/<name>, given either as the
// import id or, from Terraform 1.12, as the identity of an import block.
func (r *networkInterfaceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, values, byIdentity := importedID(ctx, req, &resp.Diagnostics, "node", "name")
	if resp.Diagnostics.HasError() {
		return
	}
	var node, name string
	if byIdentity {
		node, name = values[0], values[1]
	} else {
		node, name, _ = strings.Cut(id, "/")
	}
	if !nodeNamePattern.MatchString(node) || len(node) > 63 || !safeIDPattern.MatchString(name) || len(name) > maxNetworkInterfaceNameLength {
		got := id
		if byIdentity {
			got = node + "/" + name
		}
		resp.Diagnostics.AddError("Unexpected import identifier",
			"Import a PBS network interface by <node>/<name>, such as localhost/vmbr1, got "+strconv.Quote(got)+".")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), networkInterfaceID(node, name))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node"), node)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}
