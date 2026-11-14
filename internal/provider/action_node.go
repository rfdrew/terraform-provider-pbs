package provider

import (
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// What the actions that work on a node — pbs_apt_update,
// pbs_network_reload — share: the node attribute, which defaults to the
// provider's node, as the node resources' does (node.go). An action has no
// plan to fill a default into, so Invoke takes the provider's node when the
// configuration leaves the attribute out.

// nodeAttributeOfAction is the node attribute of an action; what says what
// the action does on the node, such as "whose package lists to refresh".
func nodeAttributeOfAction(what string) schema.StringAttribute {
	return schema.StringAttribute{
		Optional: true,
		MarkdownDescription: "Node " + what + ": `localhost`, which every PBS answers to, or the node's host name. " +
			"Defaults to the provider's `node`.",
		Validators: []validator.String{
			stringvalidator.LengthBetween(1, 63),
			stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
		},
	}
}

// invokedNode is the node an action's configuration names, or the
// provider's node when it names none.
func invokedNode(client *pbsclient.Client, node types.String) string {
	if node.IsNull() || node.IsUnknown() {
		return client.Node()
	}
	return node.ValueString()
}
