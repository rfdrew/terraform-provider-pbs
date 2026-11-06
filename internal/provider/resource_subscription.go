package provider

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &subscriptionResource{}
	_ resource.ResourceWithConfigure   = &subscriptionResource{}
	_ resource.ResourceWithIdentity    = &subscriptionResource{}
	_ resource.ResourceWithImportState = &subscriptionResource{}
	_ resource.ResourceWithModifyPlan  = &subscriptionResource{}
)

// NewSubscriptionResource returns the pbs_subscription resource.
func NewSubscriptionResource() resource.Resource { return &subscriptionResource{} }

type subscriptionResource struct {
	data *providerData
}

type subscriptionModel struct {
	ID               types.String `tfsdk:"id"`
	Node             types.String `tfsdk:"node"`
	Key              types.String `tfsdk:"key"`
	Status           types.String `tfsdk:"status"`
	Message          types.String `tfsdk:"message"`
	ServerID         types.String `tfsdk:"server_id"`
	ProductName      types.String `tfsdk:"product_name"`
	RegistrationDate types.String `tfsdk:"registration_date"`
	NextDueDate      types.String `tfsdk:"next_due_date"`
	CheckTime        types.String `tfsdk:"check_time"`
}

// The subscription is set and removed with Sys.Modify on /system; its key and
// details are read with Sys.Audit on /, without which PBS reports only the
// status.
const (
	subscriptionModifyPrivilege = "Sys.Modify on /system"
	subscriptionReadPrivilege   = "Sys.Audit on /"
)

// subscriptionKeyPattern is a PBS subscription key: pbs, the level, and ten
// hexadecimal digits, with arm- before them for an arm64 host (PBS 4.2.5).
var subscriptionKeyPattern = regexp.MustCompile(`^pbs[cbsp]-(arm-)?[0-9a-f]{10}$`)

func (r *subscriptionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_subscription"
}

// subscriptionAttributes are the computed attributes the resource and the
// data source share.
func subscriptionAttributeDescriptions() map[string]string {
	return map[string]string{
		"status": "Status of the subscription as PBS last checked it: `active`, `new`, `notfound`, `invalid`, " +
			"`expired` or `suspended`. PBS's daily update checks an active key with Proxmox again once its last " +
			"check is more than five days old, and a key that is not active every day; PBS reports an active " +
			"subscription `invalid` when its last check is more than 20 days old.",
		"message":           "PBS's or Proxmox's message about the status, such as why a key is invalid.",
		"server_id":         "ID of the server the key is bound to, which Proxmox's shop shows.",
		"product_name":      "Name of the subscription, such as `Proxmox Backup Server Basic Subscription 1 CPU/year`.",
		"registration_date": "When the subscription was registered, as Proxmox reports it.",
		"next_due_date":     "When the subscription is due for renewal, as Proxmox reports it.",
		"check_time": "When PBS last checked the key with Proxmox, in RFC 3339 format (UTC): up to about six " +
			"days ago for an active key.",
	}
}

func (r *subscriptionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	descriptions := subscriptionAttributeDescriptions()
	computed := func(name string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: descriptions[name]}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the subscription of a Proxmox Backup Server node: its key, which gives access " +
			"to the enterprise repository and Proxmox's support.\n\n" +
			"Setting the key has PBS check it with Proxmox's shop, `shop.proxmox.com`, so the node needs to reach " +
			"the internet, directly or through the HTTP proxy of `pbs_node_config`. PBS stores whatever the shop " +
			"answers: a key it reports invalid or expired is no error, and the apply warns with the shop's " +
			"message; `status` says how it stands. PBS checks the key again in its daily update: an active key " +
			"every five days, another one every day.\n\n" +
			"The node is a singleton: creating the resource replaces a key the node has. **Destroying the resource " +
			"removes the subscription from the node only**, with APT's credentials for the enterprise repository; " +
			"Proxmox is not told, and the key stays bound to this server's ID. To use the key on another server, " +
			"reissue it in the Proxmox shop.\n\n" +
			"PBS returns the key, so it is `Sensitive` and stored in state, and a key changed outside Terraform " +
			"shows in the plan. Setting and removing the key needs `" + subscriptionModifyPrivilege + "`; reading it " +
			"back needs `" + subscriptionReadPrivilege + "`, without which PBS reports only the status.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `node`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"node": nodeAttribute("subscription"),
			"key": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				MarkdownDescription: "Subscription key, such as `pbsc-0123456789`: `pbs`, the level, and ten " +
					"hexadecimal digits — with `arm-` before them for an arm64 server, which needs PBS 4.2.5 or " +
					"later. Changing it has PBS check the new key.",
				Validators: []validator.String{
					stringCheck{
						description: "must be a PBS subscription key such as pbsc-0123456789, without white space " +
							"(trimspace() takes the line break off a key read with file())",
						check: subscriptionKeyPattern.MatchString,
					}.secret(),
				},
			},
			"status":            computed("status"),
			"message":           computed("message"),
			"server_id":         computed("server_id"),
			"product_name":      computed("product_name"),
			"registration_date": computed("registration_date"),
			"next_due_date":     computed("next_due_date"),
			"check_time":        computed("check_time"),
		},
	}
}

func (r *subscriptionResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"node", "Node name, such as `localhost`."})
}

func (r *subscriptionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *subscriptionResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planNode(ctx, r.data, req, resp)
}

// fromSubscription records the subscription PBS reports. A key PBS leaves
// out — for want of Sys.Audit on / — keeps the one in m.
func (m *subscriptionModel) fromSubscription(node string, s pbsclient.Subscription) {
	m.ID = types.StringValue(node)
	m.Node = types.StringValue(node)
	if s.Key != "" {
		m.Key = types.StringValue(s.Key)
	}
	m.Status = stringOrNull(s.Status)
	m.Message = stringOrNull(s.Message)
	m.ServerID = stringOrNull(s.ServerID)
	m.ProductName = stringOrNull(s.ProductName)
	m.RegistrationDate = stringOrNull(s.RegDate)
	m.NextDueDate = stringOrNull(s.NextDueDate)
	m.CheckTime = types.StringNull()
	if s.CheckTime != 0 {
		m.CheckTime = types.StringValue(time.Unix(s.CheckTime, 0).UTC().Format(time.RFC3339))
	}
}

// set has the node check and store the planned key, unless it holds it
// already, and records what PBS then reports.
func (r *subscriptionResource) set(ctx context.Context, plan *subscriptionModel, diags *diag.Diagnostics) {
	client := r.data.client
	node := plan.Node.ValueString()
	key := plan.Key.ValueString()
	current, err := client.GetSubscription(ctx, node)
	if err != nil {
		diags.AddError("Unable to read the subscription of the PBS node", apiErrorDetail(client, subscriptionReadPrivilege, err))
		return
	}
	if current.Key != key || current.Status != "active" {
		if err := client.SetSubscription(ctx, node, key); err != nil {
			detail := apiErrorDetail(client, subscriptionModifyPrivilege, err)
			if pbsclient.IsSubscriptionShopUnreachable(err) {
				detail = "PBS checks a subscription key with Proxmox's shop, shop.proxmox.com, and node " + node +
					" could not reach it: give the node access to the internet, or set the HTTP proxy it uses " +
					"(http_proxy of pbs_node_config). " + detail
			}
			diags.AddError("Unable to set the subscription of the PBS node", detail)
			return
		}
		if current, err = client.GetSubscription(ctx, node); err != nil {
			plan.fromSubscription(node, pbsclient.Subscription{Key: key})
			diags.AddWarning("Unable to read the subscription of the PBS node back",
				fmt.Sprintf("PBS stored the subscription key of node %s, and it was recorded in state, but reading "+
					"its status back failed; the next refresh reads it again. %s", node, apiErrorDetail(client, subscriptionReadPrivilege, err)))
			return
		}
	}
	plan.fromSubscription(node, current)
	if current.Key != "" && current.Key != key {
		diags.AddError("PBS holds another subscription key",
			fmt.Sprintf("PBS stored the subscription key of node %s, but now reports another one. Someone else changed it meanwhile.", node))
		return
	}
	if current.Status != "active" {
		message := ""
		if current.Message != "" {
			message = ": " + current.Message
		}
		diags.AddWarning("The PBS subscription is not active",
			fmt.Sprintf("PBS stored the subscription key of node %s, and reports its status as %q%s. The node has no "+
				"access to the enterprise repository while it is not active.", node, current.Status, message))
	}
}

func (r *subscriptionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan subscriptionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.set(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "node", plan.Node.ValueString(), &resp.Diagnostics)
}

func (r *subscriptionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state subscriptionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := state.Node.ValueString()
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
	current, err := r.data.client.GetSubscription(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the subscription of the PBS node",
			apiErrorDetail(r.data.client, subscriptionReadPrivilege, err))
		return
	}
	if current.Status == pbsclient.SubscriptionNotFound && current.Key == "" {
		if !state.Key.IsNull() {
			resp.Diagnostics.AddWarning("The PBS node has no subscription",
				"Node "+node+" has no subscription key any more — it was removed outside Terraform —, and "+
					"pbs_subscription is removed from state. A plan sets the key again.")
		}
		resp.State.RemoveResource(ctx)
		return
	}
	if current.Key == "" && !state.Key.IsNull() {
		resp.Diagnostics.AddWarning("Unable to read the PBS subscription key",
			fmt.Sprintf("PBS reports only the status of the subscription of node %s to %s, which lacks %s; the key "+
				"in state stays as it was, and a key changed outside Terraform goes unnoticed.",
				node, r.data.client.AuthID(), subscriptionReadPrivilege))
	}
	state.fromSubscription(node, current)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *subscriptionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan subscriptionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.set(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "node", plan.Node.ValueString(), &resp.Diagnostics)
}

// Delete removes the subscription from the node, which tells Proxmox
// nothing.
func (r *subscriptionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state subscriptionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.client.DeleteSubscription(ctx, state.Node.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to remove the subscription of the PBS node",
			apiErrorDetail(r.data.client, subscriptionModifyPrivilege, err))
	}
}

// ImportState imports the subscription of a node by the node's name, given
// either as the import id or, from Terraform 1.12, as the identity of an
// import block.
func (r *subscriptionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	node, ok := importedNode(ctx, req, resp, "subscription")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node"), node)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), node)...)
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
}
