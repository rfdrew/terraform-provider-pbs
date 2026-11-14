package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource               = &networkApplyResource{}
	_ resource.ResourceWithConfigure  = &networkApplyResource{}
	_ resource.ResourceWithModifyPlan = &networkApplyResource{}
)

// NewNetworkApplyResource returns the pbs_network_apply resource.
func NewNetworkApplyResource() resource.Resource { return &networkApplyResource{} }

type networkApplyResource struct {
	data *providerData
}

type networkApplyModel struct {
	ID             types.String `tfsdk:"id"`
	Node           types.String `tfsdk:"node"`
	Triggers       types.Map    `tfsdk:"triggers"`
	PendingChanges types.String `tfsdk:"pending_changes"`
}

// pathPendingChanges is the attribute that shows the pending changes.
var pathPendingChanges = path.Root("pending_changes")

// maxPendingChangesInWarning bounds the diff a plan's warning quotes.
const maxPendingChangesInWarning = 4096

// reloadOutageGrace is how long the wait for a reload keeps trying to reach
// PBS before it reports lost contact: longer than a request timeout plus
// the half minute a bond or a bridge with STP may take to forward again.
const reloadOutageGrace = 2 * time.Minute

func (r *networkApplyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_apply"
}

func (r *networkApplyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Applies the pending network changes of a Proxmox Backup Server node, as Apply " +
			"Configuration in its web interface does: PBS moves `/etc/network/interfaces.new` over " +
			"`/etc/network/interfaces` and runs `ifreload -a` (ifupdown2), in a task the resource waits for.\n\n" +
			"The resource applies when it is created and whenever `triggers` change, after the " +
			"`pbs_network_interface` resources its triggers refer to are written — reference each of them, for " +
			"instance with `jsonencode()`, so that any change of an interface changes the triggers. It also " +
			"notices changes that are pending when Terraform refreshes it, or when it is created — made in the web " +
			"interface, by another tool, or left by an earlier run —, shows them in `pending_changes` and in a " +
			"warning, and plans to apply them: PBS applies the whole pending configuration or nothing, whoever made " +
			"it. To drop changes you do not want applied, revert them first: Revert in the Network Interfaces panel " +
			"of the web interface, or `proxmox-backup-manager network revert` on the node. To apply what is " +
			"pending once, outside a configuration, Terraform 1.14.1 and later have the `pbs_network_reload` " +
			"action.\n\n" +
			"Every apply runs `ifreload -a`, also when nothing is pending, which brings every interface with an " +
			"`auto` line in line with the whole of `/etc/network/interfaces`: it applies edits made to that file " +
			"directly, and removes addresses added outside it, such as by hand or by keepalived. `pending_changes` " +
			"shows neither.\n\n" +
			"!> **PBS does not roll back.** Once the task has moved the file, the previous configuration is gone, " +
			"and when `ifreload` fails, the node may run part of the new one. A change that cuts the node off — a " +
			"new address, gateway or MTU on the interface Terraform reaches PBS through — leaves it cut off: have " +
			"the node's console at hand, and read the guide _Managing the network of a PBS node_. While the reload " +
			"runs, the resource waits up to two minutes for an unreachable node to answer again, as a bond or bridge " +
			"may take half a minute to forward.\n\n" +
			"Removing an interface from the configuration together with its trigger deletes it from the pending " +
			"configuration and then applies: Terraform deletes a resource before it updates those that referred " +
			"to it — unless `create_before_destroy` is set on either, which reverses the order and leaves the " +
			"removal pending for the next plan to apply. Destroying this resource changes nothing on the node; " +
			"changes made by the interfaces destroyed with it stay pending — and PBS 4.0.8 and later apply pending " +
			"changes when the node boots.\n\n" +
			"Needs `" + networkApplyPrivilege + "`, which an API token may have, and ifupdown2 on the node, which " +
			"an installation from the PBS ISO has.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `node`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"node": nodeAttributeDescribed("Node whose pending network changes to apply: `localhost`, which every " +
				"PBS answers to, or the node's host name. Defaults to the provider's `node`. Changing it replaces " +
				"the resource, which applies the changes."),
			"triggers": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				MarkdownDescription: "Values whose change applies the pending changes again, such as " +
					"`{ vmbr1 = jsonencode(pbs_network_interface.vmbr1) }`. Referring to an interface also makes " +
					"Terraform write it before applying.",
			},
			"pending_changes": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Changes pending on the node, as the unified diff from " +
					"`/etc/network/interfaces` that PBS shows, as of the last refresh or apply; null when none are " +
					"pending. When a refresh finds some, the plan applies them.",
			},
		},
	}
}

func (r *networkApplyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan plans an apply for changes a refresh found pending, and warns
// about them: whoever made them, the apply makes them take effect.
func (r *networkApplyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	var state *networkApplyModel
	if !req.State.Raw.IsNull() {
		state = &networkApplyModel{}
		resp.Diagnostics.Append(req.State.Get(ctx, state)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	pending := state != nil && known(state.PendingChanges) && state.PendingChanges.ValueString() != ""

	if req.Plan.Raw.IsNull() {
		if pending {
			resp.Diagnostics.AddWarning("Network changes stay pending",
				fmt.Sprintf("Destroying pbs_network_apply changes nothing on node %s, which has network changes that "+
					"are not applied yet; they stay pending:\n\n%s", state.Node.ValueString(), quoteChanges(state.PendingChanges.ValueString())))
		}
		return
	}
	planNode(ctx, r.data, req, resp)
	if state == nil {
		r.warnPendingOnCreate(ctx, resp)
		return
	}
	if !pending {
		return
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, pathPendingChanges, types.StringUnknown())...)
	resp.Diagnostics.AddWarning("Pending network changes will be applied",
		fmt.Sprintf("Node %s has network changes that are not applied yet, which this plan applies, together with "+
			"any changes it makes to network interfaces. PBS applies the whole pending configuration, whoever "+
			"wrote it; revert what you do not want first — Revert in the Network Interfaces panel of the web "+
			"interface, or `proxmox-backup-manager network revert`. Pending now:\n\n%s",
			state.Node.ValueString(), quoteChanges(state.PendingChanges.ValueString())))
}

// warnPendingOnCreate warns, when the resource is created, about the
// changes already pending, which creating it applies. Nothing of this run
// has been written when Terraform plans, so they were made elsewhere; when
// it plans again during the apply, they include this run's. A failed read
// is left to Create to report.
func (r *networkApplyResource) warnPendingOnCreate(ctx context.Context, resp *resource.ModifyPlanResponse) {
	var node types.String
	resp.Diagnostics.Append(resp.Plan.GetAttribute(ctx, path.Root("node"), &node)...)
	if r.data == nil || !known(node) {
		return
	}
	changes, err := r.data.client.NetworkChanges(ctx, node.ValueString())
	switch {
	case pbsclient.IsNetworkDiffFailed(err):
		resp.Diagnostics.AddWarning("PBS cannot show the pending network changes",
			fmt.Sprintf("Node %s has network changes pending, which creating pbs_network_apply applies, but PBS could "+
				"not compare them with the running configuration — typically because /etc/network/interfaces does not "+
				"exist. Check them on the node (/etc/network/interfaces.new) before applying. %s", node.ValueString(), err))
	case err == nil && changes != "":
		resp.Diagnostics.AddWarning("Pending network changes will be applied",
			fmt.Sprintf("Node %s has network changes that are not applied yet, which creating pbs_network_apply "+
				"applies, together with any changes this plan makes to network interfaces. PBS applies the whole "+
				"pending configuration, whoever wrote it; revert what you do not want first — Revert in the Network "+
				"Interfaces panel of the web interface, or `proxmox-backup-manager network revert`. Pending now:\n\n%s",
				node.ValueString(), quoteChanges(changes)))
	}
}

// quoteChanges indents a diff for a diagnostic, shortened to a few
// kilobytes.
func quoteChanges(diff string) string {
	if len(diff) > maxPendingChangesInWarning {
		diff = strings.ToValidUTF8(diff[:maxPendingChangesInWarning], "") + "\n… (shortened; pending_changes has all of it)"
	}
	return diff
}

// apply reloads the node's network and returns what is pending afterwards.
func (r *networkApplyResource) apply(ctx context.Context, node string, diags *diag.Diagnostics) types.String {
	client := r.data.client
	var upid pbsclient.UPID
	started := false
	// Holding the configuration's lock keeps this provider's interface
	// writes out while PBS moves the file and reloads.
	err := client.WithConfigLock(pbsclient.ConfigNetwork, func() error {
		var err error
		upid, err = client.ReloadNetwork(ctx, node)
		if err != nil {
			return err
		}
		started = true
		_, err = client.WaitTaskThroughOutages(ctx, upid, reloadOutageGrace)
		return err
	})
	if err != nil {
		diags.AddError("Unable to apply the network changes of the PBS node", networkApplyErrorDetail(client, node, upid, started, err))
		return types.StringUnknown()
	}
	changes, err := client.NetworkChanges(ctx, node)
	if err != nil {
		diags.AddWarning("Unable to read the PBS network configuration back",
			fmt.Sprintf("PBS applied the network changes of node %s, but listing the interfaces afterwards failed; "+
				"the next refresh reads the pending changes again. %s", node, networkErrorDetail(client, err)))
		return types.StringNull()
	}
	return stringOrNull(changes)
}

// networkApplyErrorDetail explains a failed reload.
func networkApplyErrorDetail(client *pbsclient.Client, node string, upid pbsclient.UPID, started bool, err error) string {
	var taskErr *pbsclient.TaskError
	switch {
	case pbsclient.IsIfupdown2Missing(err):
		return fmt.Sprintf("PBS applies network changes with ifupdown2's ifreload, which node %s does not have: PBS "+
			"installs it as a recommended package, and a minimal or container installation may leave it out. "+
			"Install ifupdown2 on the node, or apply the changes another way; they stay pending in "+
			"/etc/network/interfaces.new. %s", node, err)
	case errors.As(err, &taskErr):
		return fmt.Sprintf("PBS moved the pending configuration over /etc/network/interfaces, and ifreload then "+
			"failed: node %s may run part of the new configuration. PBS keeps no copy of the previous one and "+
			"does not roll back. Fix the configuration — the error names the interface — and apply again, which "+
			"runs ifreload anew; the task log (%s) has the details. %s", node, upid.Raw, err)
	case errors.Is(err, pbsclient.ErrTaskTimeout):
		return fmt.Sprintf("The reload of node %s's network is still running; apply again once it has ended, or "+
			"raise the provider's task_timeout. %s", node, err)
	case started && pbsclient.IsUnreachable(err):
		return fmt.Sprintf("PBS started applying the network changes of node %s (task %s), and then the provider "+
			"lost contact with it while waiting for the task: the new configuration may have cut the node off from "+
			"this address — or the reload ended and the node answers again later. Once it answers, run terraform "+
			"plan: pending_changes shows whether anything is still pending, and `proxmox-backup-manager task log "+
			"'%s'` on the node what the reload did. If it does not answer at all, check it from its console: PBS does "+
			"not roll back. %s", node, upid.Raw, upid.Raw, err)
	}
	return apiErrorDetail(client, networkApplyPrivilege, err)
}

func (r *networkApplyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan networkApplyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.PendingChanges = r.apply(ctx, plan.Node.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = plan.Node
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *networkApplyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkApplyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := state.Node.ValueString()
	changes, err := r.data.client.NetworkChanges(ctx, node)
	switch {
	case pbsclient.IsNetworkDiffFailed(err):
		// PBS lists the interfaces only after comparing the pending file
		// with the running one, which it does only when changes are
		// pending; on a node without /etc/network/interfaces the
		// comparison itself fails.
		state.PendingChanges = types.StringValue("PBS has changes pending in /etc/network/interfaces.new, but " +
			"could not compare them with /etc/network/interfaces: " + err.Error())
		resp.Diagnostics.AddWarning("PBS cannot show the pending network changes",
			fmt.Sprintf("Node %s has network changes pending, but PBS could not compare them with the running "+
				"configuration — typically because /etc/network/interfaces does not exist. Applying them creates it. %s",
				node, err))
	case err != nil:
		resp.Diagnostics.AddError("Unable to read the pending network changes of the PBS node", networkErrorDetail(r.data.client, err))
		return
	default:
		state.PendingChanges = stringOrNull(changes)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *networkApplyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan networkApplyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.PendingChanges = r.apply(ctx, plan.Node.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete changes nothing on the node: see the resource's description.
func (r *networkApplyResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}
