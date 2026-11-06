package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &timezoneResource{}
	_ resource.ResourceWithConfigure   = &timezoneResource{}
	_ resource.ResourceWithIdentity    = &timezoneResource{}
	_ resource.ResourceWithImportState = &timezoneResource{}
	_ resource.ResourceWithModifyPlan  = &timezoneResource{}
)

// NewTimezoneResource returns the pbs_timezone resource.
func NewTimezoneResource() resource.Resource { return &timezoneResource{} }

type timezoneResource struct {
	data *providerData
}

type timezoneModel struct {
	ID       types.String `tfsdk:"id"`
	Node     types.String `tfsdk:"node"`
	Timezone types.String `tfsdk:"timezone"`
}

// Anyone signed in may read the time zone; changing it needs Sys.Modify on
// /system/time.
const timezoneModifyPrivilege = "Sys.Modify on /system/time"

// timezonePattern is a time zone name in the characters systemd's
// timedated allows: names joined by slashes, without dots, so that no name
// leaves /usr/share/zoneinfo. PBS checks only that the file exists.
var timezonePattern = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`)

// notTimezones are the names under /usr/share/zoneinfo that are no zones:
// directories of zones — legacy ones of tzdata-legacy too — and other
// files. PBS links /etc/localtime to them all the same, and the node then
// runs in UTC without a word; localtime would even be a loop.
var notTimezones = map[string]bool{
	"Africa": true, "America": true, "Antarctica": true, "Arctic": true, "Asia": true, "Atlantic": true,
	"Australia": true, "Etc": true, "Europe": true, "Indian": true, "Pacific": true,
	"Brazil": true, "Canada": true, "Chile": true, "Mexico": true, "US": true, "posix": true, "right": true,
	"America/Argentina": true, "America/Indiana": true, "America/Kentucky": true, "America/North_Dakota": true,
	"localtime": true, "leapseconds": true, "posixrules": true,
}

func (r *timezoneResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_timezone"
}

func (r *timezoneResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the time zone of a Proxmox Backup Server node, which its job schedules, task " +
			"logs and web interface go by. The `pbs_time` data source reads the node's current time.\n\n" +
			"The node is a singleton: creating the resource sets the zone the node has. A node always has a zone, " +
			"so **destroying the resource leaves it as it is**.\n\n" +
			"PBS sets the zone with `timedatectl` from PBS 4.2.3 and by linking `/etc/localtime` to the zone's " +
			"file otherwise. Changing it needs `" + timezoneModifyPrivilege + "`; anyone signed in may read it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `node`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"node": nodeAttribute("time zone"),
			"timezone": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Time zone, as named in the tz database: `UTC`, `Etc/UTC`, `Europe/Vienna`, " +
					"`America/New_York`. The node must have its file under `/usr/share/zoneinfo`; PBS 4's Debian " +
					"installs no legacy names, such as `US/Eastern` or `Europe/Kiev`, unless `tzdata-legacy` is " +
					"installed. PBS keeps the name as given, so `UTC` and `Etc/UTC` are different values.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(2, 64),
					stringvalidator.RegexMatches(timezonePattern, "must be a time zone name such as Europe/Vienna"),
					stringCheck{
						description: "must name a time zone, not a directory of them or another file of the tz database",
						check:       func(s string) bool { return !notTimezones[s] },
					},
				},
			},
		},
	}
}

func (r *timezoneResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"node", "Node name, such as `localhost`."})
}

func (r *timezoneResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *timezoneResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planNode(ctx, r.data, req, resp)
}

// set sets the planned zone, unless the node has it, and records it.
func (r *timezoneResource) set(ctx context.Context, plan *timezoneModel, diags *diag.Diagnostics) {
	client := r.data.client
	node := plan.Node.ValueString()
	timezone := plan.Timezone.ValueString()
	current, err := client.GetTime(ctx, node)
	if err != nil {
		diags.AddError("Unable to read the time zone of the PBS node", apiErrorDetail(client, "", err))
		return
	}
	if current.Timezone != timezone {
		if err := client.SetTimezone(ctx, node, timezone); err != nil {
			detail := apiErrorDetail(client, timezoneModifyPrivilege, err)
			if strings.Contains(err.Error(), "No such timezone") {
				detail = fmt.Sprintf("Node %s has no time zone %q: there is no such file under /usr/share/zoneinfo. "+
					"Check the name; legacy names need the tzdata-legacy package. %s", node, timezone, detail)
			}
			diags.AddError("Unable to set the time zone of the PBS node", detail)
			return
		}
	}
	plan.ID = types.StringValue(node)
}

func (r *timezoneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan timezoneModel
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

func (r *timezoneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state timezoneModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := state.Node.ValueString()
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
	current, err := r.data.client.GetTime(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the time zone of the PBS node", apiErrorDetail(r.data.client, "", err))
		return
	}
	state.ID = types.StringValue(node)
	state.Timezone = stringOrNull(current.Timezone)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *timezoneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan timezoneModel
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

// Delete leaves the node's time zone as it is: a node always has one.
func (r *timezoneResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}

// ImportState imports the time zone of a node by the node's name, given
// either as the import id or, from Terraform 1.12, as the identity of an
// import block.
func (r *timezoneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	node, ok := importedNode(ctx, req, resp, "time zone")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node"), node)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), node)...)
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
}
