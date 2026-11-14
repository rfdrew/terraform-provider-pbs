package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// networkListTypes are the interface types pbs_network_interface manages,
// and so lists. PBS also lists aliases and interfaces of types it does not
// know, which the resource cannot hold; it leaves out the loopback
// interface itself.
var networkListTypes = []string{networkTypeBridge, networkTypeBond, networkTypeVLAN, networkTypeEth}

// NewNetworkInterfaceListResource returns the pbs_network_interface list
// resource.
func NewNetworkInterfaceListResource() list.ListResource {
	return &importedList{
		newResource:   NewNetworkInterfaceResource,
		identityOrder: []string{"node", "name"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the network interfaces of a Proxmox Backup Server node, for `terraform query`, " +
				"to import them as `pbs_network_interface` resources: the bridges, bonds, VLAN interfaces and " +
				"physical interfaces (`eth`) of `/etc/network/interfaces`, and the physical NICs the file does not " +
				"name, which PBS lists as `eth`, method `manual`, without autostart — in a Docker container, " +
				"typically the container's `eth0`. Interfaces of other types, such as aliases, are left out, as is " +
				"the loopback interface.\n\n" +
				"Listing needs `" + networkReadPrivilege + "`, and reading each interface `" +
				networkInterfaceReadPrivilege + "`.\n\n" +
				"~> **Pending changes.** While `/etc/network/interfaces.new` holds changes made through the API or " +
				"the web interface and not applied yet, PBS lists that pending configuration, not the one the node " +
				"runs, and the list warns. Importing interfaces then records the pending configuration, which takes " +
				"effect only once the changes are applied; apply them, or revert them, first to import what the node " +
				"runs.\n\n" +
				"The generated configuration sets the interface's methods as PBS reports them. A physical interface " +
				"with the IPv4 method `dhcp` gets `method = \"dhcp\"`, which the resource refuses for type `eth` " +
				"(`DHCP on a physical interface`): remove that line, and the plan changes nothing. PBS's API cannot " +
				"keep DHCP through a change, though, so the resource refuses to change the interface until it gets " +
				"an address or `method = \"manual\"`. Destroying an imported physical interface resets it — method `manual`, no addresses — " +
				"and destroying a bridge, bond or VLAN interface deletes it from the pending configuration; to stop " +
				"managing an interface, remove it from the state instead.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{
				"node": listschema.StringAttribute{
					Optional: true,
					MarkdownDescription: "Node whose interfaces to list: `localhost`, which every PBS answers to, or " +
						"the node's host name. Defaults to the provider's `node`; the results' `node` is this name.",
					Validators: []validator.String{
						stringvalidator.LengthBetween(1, 63),
						stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
					},
				},
				"type": listschema.StringAttribute{
					Optional:            true,
					MarkdownDescription: "List only interfaces of this type: `bridge`, `bond`, `vlan` or `eth`.",
					Validators:          []validator.String{stringvalidator.OneOf(networkListTypes...)},
				},
			},
		},
		enumerate: listNetworkInterfaces,
	}
}

type networkInterfaceListModel struct {
	Node types.String `tfsdk:"node"`
	Type types.String `tfsdk:"type"`
}

func listNetworkInterfaces(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	var filter networkInterfaceListModel
	diags.Append(config.Get(ctx, &filter)...)
	if diags.HasError() {
		return nil
	}
	node := filter.Node.ValueString()
	if node == "" {
		node = data.client.Node()
	}
	interfaces, changes, err := data.client.NetworkInterfaces(ctx, node)
	if err != nil {
		diags.AddError("Unable to list the PBS network interfaces", networkErrorDetail(data.client, err))
		return nil
	}
	if changes != "" {
		diags.AddWarning("Network changes are pending",
			fmt.Sprintf("Node %s has network changes that are not applied yet, and PBS lists that pending "+
				"configuration, not the one the node runs; importing the interfaces records it. The changes, which "+
				"the pending_changes attribute of the pbs_network_interfaces data source shows too:\n\n%s",
				node, quoteChanges(changes)))
	}
	var objects []listedObject
	for _, iface := range interfaces {
		if !slices.Contains(networkListTypes, iface.Type) || (!filter.Type.IsNull() && iface.Type != filter.Type.ValueString()) {
			continue
		}
		// A comment of several lines shows its first.
		comment, _, _ := strings.Cut(iface.Comments, "\n")
		objects = append(objects, listedObject{
			identity:    map[string]any{"node": node, "name": iface.Name},
			displayName: displayNameWithComment(iface.Name+" ("+iface.Type+")", comment),
		})
	}
	return objects
}
