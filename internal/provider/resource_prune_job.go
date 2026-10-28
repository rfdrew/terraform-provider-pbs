package provider

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &pruneJobResource{}
	_ resource.ResourceWithConfigure   = &pruneJobResource{}
	_ resource.ResourceWithIdentity    = &pruneJobResource{}
	_ resource.ResourceWithImportState = &pruneJobResource{}
)

// NewPruneJobResource returns the pbs_prune_job resource.
func NewPruneJobResource() resource.Resource { return &pruneJobResource{} }

type pruneJobResource struct {
	data *providerData
}

type pruneJobModel struct {
	ID       types.String `tfsdk:"id"`
	Store    types.String `tfsdk:"store"`
	Schedule types.String `tfsdk:"schedule"`
	NS       types.String `tfsdk:"ns"`
	MaxDepth types.Int64  `tfsdk:"max_depth"`
	Keep     types.Object `tfsdk:"keep"`
	Disable  types.Bool   `tfsdk:"disable"`
	Comment  types.String `tfsdk:"comment"`
}

// pruneJobDeletable are the properties PBS lets a prune job update delete.
// store and schedule are not among them; both are required.
var pruneJobDeletable = []string{
	"comment", "disable", "ns", "max-depth",
	"keep-last", "keep-hourly", "keep-daily", "keep-weekly", "keep-monthly", "keep-yearly",
}

// keepKinds are the attributes of keep and the properties they stand for, in
// the order PBS applies them.
var keepKinds = []struct{ attribute, property, description string }{
	{"last", "keep-last", "the most recent backups"},
	{"hourly", "keep-hourly", "the last backup of each of the most recent hours"},
	{"daily", "keep-daily", "the last backup of each of the most recent days"},
	{"weekly", "keep-weekly", "the last backup of each of the most recent weeks, which start on Monday"},
	{"monthly", "keep-monthly", "the last backup of each of the most recent months"},
	{"yearly", "keep-yearly", "the last backup of each of the most recent years"},
}

// keepAttributeTypes is the type of keep.
func keepAttributeTypes() map[string]attr.Type {
	attributeTypes := make(map[string]attr.Type, len(keepKinds))
	for _, k := range keepKinds {
		attributeTypes[k.attribute] = types.Int64Type
	}
	return attributeTypes
}

// maxNamespaceDepth is how deep namespaces nest. A job's max_depth counts the
// levels below its namespace; PBS stops at the deepest level that can exist,
// whatever max_depth says.
const maxNamespaceDepth = 7

func (r *pruneJobResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_prune_job"
}

func (r *pruneJobResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	keepAttributes := make(map[string]schema.Attribute, len(keepKinds))
	for _, k := range keepKinds {
		keepAttributes[k.attribute] = schema.Int64Attribute{
			Optional:            true,
			MarkdownDescription: "How many backups to keep that are " + k.description + ".",
			Validators:          []validator.Int64{int64validator.AtLeast(1)},
		}
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server prune job: on a schedule, it removes the backups of a " +
			"datastore, or of a namespace in it, that its retention options do not keep. Each backup group — the " +
			"backups of one VM, container or host — is pruned on its own. The space the removed backups held is " +
			"freed by the datastore's garbage collection, `gc_schedule` of `pbs_datastore`.\n\n" +
			"PBS goes through the options in order — `last`, `hourly`, `daily`, `weekly`, `monthly`, `yearly` — " +
			"and a backup that one of them keeps is not counted again by the next. A backup that none keeps is " +
			"removed, unless it is protected.\n\n" +
			"Deleting a datastore without `keep_job_configs` deletes its prune jobs too; a `pbs_prune_job` then " +
			"plans to create its job again. Managing prune jobs needs `Datastore.Modify` on the datastore, reading " +
			"them `Datastore.Audit`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Job ID, 3 to 32 characters: letters, digits, `_`, `.` and `-`, not starting " +
					"with `.` or `-`. Changing it replaces the job.",
				Validators:    safeIDValidators(minSafeIDLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore to prune, such as the `name` of a `pbs_datastore`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"schedule": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "When the job runs, as a PBS calendar event such as `daily`, `hourly`, " +
					"`sat 03:00` or `mon..fri *:00/30`. PBS checks it.",
				Validators: textValidators(1, 256),
			},
			"ns": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Namespace to prune, such as `dept1` or `dept1/hosts`; the datastore's root " +
					"namespace when left out.",
				Validators: namespaceValidators(),
			},
			"max_depth": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many levels of namespaces below `ns` to prune too, from `0`, `ns` alone, to " +
					"`7`; all of them when left out. Namespaces nest at most 7 levels deep, and PBS goes no deeper " +
					"than that below `ns`.",
				Validators: []validator.Int64{int64validator.Between(0, maxNamespaceDepth)},
			},
			"keep": schema.SingleNestedAttribute{
				Required: true,
				MarkdownDescription: "Retention: how many backups of each kind to keep, at least one kind. A kind left " +
					"out keeps no backups for its own sake.",
				Attributes: keepAttributes,
				Validators: []validator.Object{nonEmptyObject{}},
			},
			"disable": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the job is disabled: it keeps its settings but does not run. Defaults to `false`.",
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
		},
	}
}

func (r *pruneJobResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"id", "Job ID, such as `daily-store1`."})
}

func (r *pruneJobResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// pruneJobDefaults is the model of a prune job as PBS creates it when a
// property is left out, the prior state of a create.
var pruneJobDefaults = pruneJobModel{
	NS:       types.StringNull(),
	MaxDepth: types.Int64Null(),
	Keep:     types.ObjectNull(keepAttributeTypes()),
	Disable:  types.BoolValue(false),
	Comment:  types.StringNull(),
}

// keepValue returns one kind of keep; null when keep itself is.
func keepValue(keep types.Object, attribute string) types.Int64 {
	if v, ok := keep.Attributes()[attribute].(types.Int64); ok {
		return v
	}
	return types.Int64Null()
}

// createParams are the parameters of the call that creates the job m
// describes: what differs from PBS's defaults, and the ID.
func (m *pruneJobModel) createParams(diags *diag.Diagnostics) url.Values {
	changes := newPropertyChanges(diags)
	m.changes(pruneJobDefaults, changes)
	params := changes.Values()
	params.Set("id", m.ID.ValueString())
	return params
}

// changes records the properties that differ between prior and m.
func (m *pruneJobModel) changes(prior pruneJobModel, c *propertyChanges) {
	c.String("store", m.Store, prior.Store)
	c.String("schedule", m.Schedule, prior.Schedule)
	c.String("ns", m.NS, prior.NS)
	c.Int64("max-depth", m.MaxDepth, prior.MaxDepth)
	for _, k := range keepKinds {
		c.Int64(k.property, keepValue(m.Keep, k.attribute), keepValue(prior.Keep, k.attribute))
	}
	c.BoolDefault("disable", m.Disable, prior.Disable, false)
	c.String("comment", m.Comment, prior.Comment)
}

// fromPruneJob records a prune job as PBS reports it. The ID is the one it
// was looked up by.
func (m *pruneJobModel) fromPruneJob(id string, job pbsclient.PruneJob) {
	m.ID = types.StringValue(id)
	m.Store = types.StringValue(job.Store)
	m.Schedule = types.StringValue(job.Schedule)
	m.NS = stringOrNull(job.NS)
	m.MaxDepth = int64OrNull(job.MaxDepth)
	m.Keep = keepObject(job.KeepOptions)
	m.Disable = boolOr(job.Disable, false)
	m.Comment = stringOrNull(job.Comment)
}

// keepObject is keep for the retention options PBS reports; null when there
// are none.
func keepObject(o pbsclient.KeepOptions) types.Object {
	counts := map[string]*int64{
		"last": o.KeepLast, "hourly": o.KeepHourly, "daily": o.KeepDaily,
		"weekly": o.KeepWeekly, "monthly": o.KeepMonthly, "yearly": o.KeepYearly,
	}
	values := make(map[string]attr.Value, len(counts))
	found := false
	for attribute, n := range counts {
		values[attribute] = int64OrNull(n)
		found = found || n != nil
	}
	if !found {
		return types.ObjectNull(keepAttributeTypes())
	}
	return types.ObjectValueMust(keepAttributeTypes(), values)
}

// pruneJobPrivilege names a privilege on the job's datastore, for errors.
func pruneJobPrivilege(privilege string, m pruneJobModel) string {
	return privilege + " on /datastore/" + m.Store.ValueString()
}

func (r *pruneJobResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pruneJobModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	params := plan.createParams(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigPruneJobs, func() error { return client.CreatePruneJob(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS prune job already exists",
				fmt.Sprintf("PBS already has a prune job %q. To manage it with Terraform, import it, with an import "+
					"block whose id is %q or with `terraform import`. %s", id, id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS prune job",
			apiErrorDetail(client, pruneJobPrivilege("Datastore.Modify", plan), err))
		return
	}

	// From here on the job exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	job, err := client.GetPruneJob(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS prune job back after creation",
			fmt.Sprintf("PBS created prune job %q, and it was recorded in state, but reading it back failed, so it is "+
				"marked tainted: the next apply replaces it. %s", id, apiErrorDetail(client, pruneJobPrivilege("Datastore.Audit", plan), err)))
		return
	}
	plan.fromPruneJob(id, job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// Read drops a job that is gone, as it is after its datastore was deleted
// without keep_job_configs, so that the next plan creates it again.
func (r *pruneJobResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state pruneJobModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	// Before the lookup, so that a refresh finding the job gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)

	job, err := r.data.client.GetPruneJob(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS prune job",
			apiErrorDetail(r.data.client, pruneJobPrivilege("Datastore.Audit", state), err))
		return
	}
	state.fromPruneJob(id, job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *pruneJobResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state pruneJobModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, pruneJobDeletable...)
	plan.changes(state, changes)
	if resp.Diagnostics.HasError() {
		return
	}
	if !changes.Empty() {
		err := client.WithConfigLock(pbsclient.ConfigPruneJobs, func() error {
			err := client.UpdatePruneJob(ctx, id, changes.Values())
			// PBS deletes a datastore's jobs with it, as when a new name
			// replaces the datastore, with this job's store following it:
			// the job is created again, as the plan describes it.
			if pbsclient.IsNotFound(err) {
				tflog.Info(ctx, "the PBS prune job is gone; creating it again", map[string]any{"id": id})
				params := plan.createParams(&resp.Diagnostics)
				if resp.Diagnostics.HasError() {
					return nil
				}
				err = client.CreatePruneJob(ctx, params)
			}
			return err
		})
		if resp.Diagnostics.HasError() {
			return
		}
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS prune job",
				apiErrorDetail(client, pruneJobPrivilege("Datastore.Modify", plan), err))
			return
		}
	}

	job, err := client.GetPruneJob(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS prune job back after update",
			fmt.Sprintf("PBS updated prune job %q, and the change was recorded in state, but reading it back failed. %s",
				id, apiErrorDetail(client, pruneJobPrivilege("Datastore.Audit", plan), err)))
		return
	}
	plan.fromPruneJob(id, job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// Delete deletes the job; one already gone, with its datastore say, is not an
// error.
func (r *pruneJobResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state pruneJobModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigPruneJobs, func() error {
		return client.DeletePruneJob(ctx, state.ID.ValueString())
	})
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS prune job",
			apiErrorDetail(client, pruneJobPrivilege("Datastore.Modify", state), err))
	}
}

// ImportState imports a prune job by its ID, given either as the import id
// or, from Terraform 1.12, as the identity of an import block. Read fills in
// the rest, or drops a job that does not exist, which Terraform reports.
func (r *pruneJobResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := importedSafeID(ctx, req, resp, "id", "prune job", "daily-store1")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// importedSafeID returns the ID an import names an object by, from the import
// id or the identity attribute of the given name, after checking that it is
// a safe ID; it reports what it expected otherwise. what and example describe
// the object, for that error.
func importedSafeID(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse, attribute, what, example string) (string, bool) {
	id, values, byIdentity := importedID(ctx, req, &resp.Diagnostics, attribute)
	if resp.Diagnostics.HasError() {
		return "", false
	}
	if byIdentity {
		id = values[0]
	}
	if !safeIDPattern.MatchString(id) || len(id) > maxSafeIDLength {
		resp.Diagnostics.AddError("Unexpected import identifier",
			"Import a PBS "+what+" by its "+attribute+", such as "+example+", got "+strconv.Quote(id)+".")
		return "", false
	}
	return id, true
}
