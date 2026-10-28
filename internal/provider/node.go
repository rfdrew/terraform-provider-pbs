package provider

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Resources of a node — its ACME settings, its certificate — are singletons:
// PBS is a single node, and /nodes/{node} paths accept its host name and
// localhost alike. Such a resource has a node attribute, which defaults to the
// provider's node, and is identified and imported by it.

// nodeNamePattern is PBS's node name: a host name label.
var nodeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// nodeAttribute is the node attribute of a node resource, what describes it.
func nodeAttribute(what string) schema.StringAttribute {
	return schema.StringAttribute{
		Optional: true,
		Computed: true,
		MarkdownDescription: "Node whose " + what + " to manage: `localhost`, which every PBS answers to, or the " +
			"node's host name. Defaults to the provider's `node`. PBS is a single node, so both name the same " +
			"settings: manage them with one resource only. Changing it replaces the resource.",
		Validators: []validator.String{
			stringvalidator.LengthBetween(1, 63),
			stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
		},
		PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown(), stringplanmodifier.RequiresReplace()},
	}
}

// planNode fills in the provider's node when a create leaves node out, and
// the id, which is the node, once the node is known. A node the
// configuration sets but does not know yet stays unknown, and so does the
// node while the provider is not configured yet: d is nil then.
func planNode(ctx context.Context, d *providerData, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var node, configured, id types.String
	resp.Diagnostics.Append(resp.Plan.GetAttribute(ctx, path.Root("node"), &node)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("node"), &configured)...)
	resp.Diagnostics.Append(resp.Plan.GetAttribute(ctx, path.Root("id"), &id)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if node.IsUnknown() && configured.IsNull() && d != nil {
		node = types.StringValue(d.client.Node())
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("node"), node)...)
	}
	if id.IsUnknown() && !node.IsUnknown() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), node)...)
	}
}

// importedNode returns the node an import names, by import id or identity.
func importedNode(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse, what string) (string, bool) {
	id, values, byIdentity := importedID(ctx, req, &resp.Diagnostics, "node")
	if resp.Diagnostics.HasError() {
		return "", false
	}
	if byIdentity {
		id = values[0]
	}
	if !nodeNamePattern.MatchString(id) || len(id) > 63 {
		resp.Diagnostics.AddError("Unexpected import identifier",
			"Import the "+what+" of a PBS node by the node's name, such as localhost, got \""+id+"\".")
		return "", false
	}
	return id, true
}
