package provider

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &verifyJobResource{}
	_ resource.ResourceWithConfigure   = &verifyJobResource{}
	_ resource.ResourceWithIdentity    = &verifyJobResource{}
	_ resource.ResourceWithImportState = &verifyJobResource{}
	_ resource.ResourceWithModifyPlan  = &verifyJobResource{}
)

// NewVerifyJobResource returns the pbs_verify_job resource.
func NewVerifyJobResource() resource.Resource { return &verifyJobResource{} }

type verifyJobResource struct {
	data *providerData
}

type verifyJobModel struct {
	ID             types.String `tfsdk:"id"`
	Store          types.String `tfsdk:"store"`
	NS             types.String `tfsdk:"ns"`
	MaxDepth       types.Int64  `tfsdk:"max_depth"`
	Schedule       types.String `tfsdk:"schedule"`
	IgnoreVerified types.Bool   `tfsdk:"ignore_verified"`
	OutdatedAfter  types.Int64  `tfsdk:"outdated_after"`
	ReadThreads    types.Int64  `tfsdk:"read_threads"`
	VerifyThreads  types.Int64  `tfsdk:"verify_threads"`
	Comment        types.String `tfsdk:"comment"`
}

// verifyJobDeletable are the properties PBS lets a verify job update delete.
var verifyJobDeletable = []string{
	"ignore-verified", "comment", "schedule", "outdated-after", "ns", "max-depth", "read-threads", "verify-threads",
}

// PBS's defaults for a verify job.
const (
	verifyJobDefaultMaxDepth       = maxNamespaceDepth
	verifyJobDefaultIgnoreVerified = true
)

// maxVerifyThreads bounds read_threads and verify_threads.
const maxVerifyThreads = 32

func (r *verifyJobResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_verify_job"
}

func (r *verifyJobResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server verify job: on a schedule, it reads the backups of a " +
			"datastore, or of a namespace in it, and checks every chunk against its checksum, so that a damaged " +
			"backup is found before it is needed. A backup that fails is marked, and the next backup of the same " +
			"guest uploads its chunks again instead of reusing the damaged ones.\n\n" +
			"Deleting a datastore without `keep_job_configs` deletes its verify jobs too; a `pbs_verify_job` then " +
			"plans to create its job again. Managing verify jobs needs `Datastore.Verify` on the datastore, " +
			"reading them `Datastore.Audit` or `Datastore.Verify`.",
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
				MarkdownDescription: "Name of the datastore to verify, such as the `name` of a `pbs_datastore`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"ns": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Namespace to verify, such as `dept1` or `dept1/hosts`; the datastore's root " +
					"namespace when left out.",
				Validators: namespaceValidators(),
			},
			"max_depth": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(verifyJobDefaultMaxDepth),
				MarkdownDescription: "How many levels of namespaces below `ns` to verify too, from `0`, `ns` alone, " +
					"to `7`, the default: all of them. Namespaces nest at most 7 levels deep, and PBS goes no deeper " +
					"than that below `ns`.",
				Validators: []validator.Int64{int64validator.Between(0, maxNamespaceDepth)},
			},
			"schedule": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "When the job runs, as a PBS calendar event such as `daily`, `sat 03:00` or " +
					"`mon..fri 22:00`. PBS checks it. Without a schedule, the job runs only when started by hand.",
				Validators: textValidators(1, 256),
			},
			"ignore_verified": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(verifyJobDefaultIgnoreVerified),
				MarkdownDescription: "Whether to skip backups that were verified before, unless that verification " +
					"is older than `outdated_after`. Defaults to `true`; `false` verifies every backup on every run.",
			},
			"outdated_after": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "With `ignore_verified`, how many days after its last verification a backup " +
					"is verified again; when left out, a verified backup is never verified again.",
				Validators: []validator.Int64{int64validator.AtLeast(1)},
			},
			"read_threads": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many threads read chunks, 1 to 32. When left out, the datastore's " +
					"`tuning.default_verification_readers` applies, and 1 without it. Needs PBS 4.1 or newer.",
				Validators: []validator.Int64{int64validator.Between(1, maxVerifyThreads)},
			},
			"verify_threads": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many threads verify chunks, 1 to 32. When left out, the datastore's " +
					"`tuning.default_verification_workers` applies, and 4 without it. Needs PBS 4.1 or newer.",
				Validators: []validator.Int64{int64validator.Between(1, maxVerifyThreads)},
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
		},
	}
}

func (r *verifyJobResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"id", "Job ID, such as `verify-store1`."})
}

func (r *verifyJobResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan refuses the thread counts on a server older than PBS 4.1.
func (r *verifyJobResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan verifyJobModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.data.requireRelease(&resp.Diagnostics, path.Root("read_threads"), plan.ReadThreads, pbs41)
	r.data.requireRelease(&resp.Diagnostics, path.Root("verify_threads"), plan.VerifyThreads, pbs41)
}

// verifyJobDefaults is the model of a verify job as PBS creates it when a
// property is left out, the prior state of a create.
var verifyJobDefaults = verifyJobModel{
	NS:             types.StringNull(),
	MaxDepth:       types.Int64Value(verifyJobDefaultMaxDepth),
	Schedule:       types.StringNull(),
	IgnoreVerified: types.BoolValue(verifyJobDefaultIgnoreVerified),
	OutdatedAfter:  types.Int64Null(),
	ReadThreads:    types.Int64Null(),
	VerifyThreads:  types.Int64Null(),
	Comment:        types.StringNull(),
}

// createParams are the parameters of the call that creates the job m
// describes: what differs from PBS's defaults, and the ID.
func (m *verifyJobModel) createParams(diags *diag.Diagnostics) url.Values {
	changes := newPropertyChanges(diags)
	m.changes(verifyJobDefaults, changes)
	params := changes.Values()
	params.Set("id", m.ID.ValueString())
	return params
}

// changes records the properties that differ between prior and m.
func (m *verifyJobModel) changes(prior verifyJobModel, c *propertyChanges) {
	c.String("store", m.Store, prior.Store)
	c.String("ns", m.NS, prior.NS)
	c.Int64Default("max-depth", m.MaxDepth, prior.MaxDepth, verifyJobDefaultMaxDepth)
	c.String("schedule", m.Schedule, prior.Schedule)
	c.BoolDefault("ignore-verified", m.IgnoreVerified, prior.IgnoreVerified, verifyJobDefaultIgnoreVerified)
	c.Int64("outdated-after", m.OutdatedAfter, prior.OutdatedAfter)
	c.Int64("read-threads", m.ReadThreads, prior.ReadThreads)
	c.Int64("verify-threads", m.VerifyThreads, prior.VerifyThreads)
	c.String("comment", m.Comment, prior.Comment)
}

// fromVerifyJob records a verify job as PBS reports it. The ID is the one it
// was looked up by.
func (m *verifyJobModel) fromVerifyJob(id string, job pbsclient.VerifyJob) {
	m.ID = types.StringValue(id)
	m.Store = types.StringValue(job.Store)
	m.NS = stringOrNull(job.NS)
	m.MaxDepth = int64Or(job.MaxDepth, verifyJobDefaultMaxDepth)
	m.Schedule = stringOrNull(job.Schedule)
	m.IgnoreVerified = boolOr(job.IgnoreVerified, verifyJobDefaultIgnoreVerified)
	m.OutdatedAfter = int64OrNull(job.OutdatedAfter)
	m.ReadThreads = int64OrNull(job.ReadThreads)
	m.VerifyThreads = int64OrNull(job.VerifyThreads)
	m.Comment = stringOrNull(job.Comment)
}

// verifyJobPrivilege names a privilege on the job's datastore, for errors.
func verifyJobPrivilege(privilege string, m verifyJobModel) string {
	return privilege + " on /datastore/" + m.Store.ValueString()
}

func (r *verifyJobResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan verifyJobModel
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

	err := client.WithConfigLock(pbsclient.ConfigVerifyJobs, func() error { return client.CreateVerifyJob(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS verify job already exists",
				fmt.Sprintf("PBS already has a verify job %q. To manage it with Terraform, import it, with an import "+
					"block whose id is %q or with `terraform import`. %s", id, id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS verify job",
			apiErrorDetail(client, verifyJobPrivilege("Datastore.Verify", plan), err))
		return
	}

	// From here on the job exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	job, err := client.GetVerifyJob(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS verify job back after creation",
			fmt.Sprintf("PBS created verify job %q, and it was recorded in state, but reading it back failed, so it is "+
				"marked tainted: the next apply replaces it. %s", id, apiErrorDetail(client, verifyJobPrivilege("Datastore.Audit", plan), err)))
		return
	}
	plan.fromVerifyJob(id, job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// Read drops a job that is gone, as it is after its datastore was deleted
// without keep_job_configs, so that the next plan creates it again.
func (r *verifyJobResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state verifyJobModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	// Before the lookup, so that a refresh finding the job gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)

	job, err := r.data.client.GetVerifyJob(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS verify job",
			apiErrorDetail(r.data.client, verifyJobPrivilege("Datastore.Audit", state), err))
		return
	}
	state.fromVerifyJob(id, job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *verifyJobResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state verifyJobModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, verifyJobDeletable...)
	plan.changes(state, changes)
	if resp.Diagnostics.HasError() {
		return
	}
	if !changes.Empty() {
		err := client.WithConfigLock(pbsclient.ConfigVerifyJobs, func() error {
			err := client.UpdateVerifyJob(ctx, id, changes.Values())
			// PBS deletes a datastore's jobs with it, as when a new name
			// replaces the datastore, with this job's store following it:
			// the job is created again, as the plan describes it.
			if pbsclient.IsNotFound(err) {
				tflog.Info(ctx, "the PBS verify job is gone; creating it again", map[string]any{"id": id})
				params := plan.createParams(&resp.Diagnostics)
				if resp.Diagnostics.HasError() {
					return nil
				}
				err = client.CreateVerifyJob(ctx, params)
			}
			return err
		})
		if resp.Diagnostics.HasError() {
			return
		}
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS verify job",
				apiErrorDetail(client, verifyJobPrivilege("Datastore.Verify", plan), err))
			return
		}
	}

	job, err := client.GetVerifyJob(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS verify job back after update",
			fmt.Sprintf("PBS updated verify job %q, and the change was recorded in state, but reading it back failed. %s",
				id, apiErrorDetail(client, verifyJobPrivilege("Datastore.Audit", plan), err)))
		return
	}
	plan.fromVerifyJob(id, job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// Delete deletes the job; one already gone, with its datastore say, is not an
// error.
func (r *verifyJobResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state verifyJobModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigVerifyJobs, func() error {
		return client.DeleteVerifyJob(ctx, state.ID.ValueString())
	})
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS verify job",
			apiErrorDetail(client, verifyJobPrivilege("Datastore.Verify", state), err))
	}
}

// ImportState imports a verify job by its ID, given either as the import id
// or, from Terraform 1.12, as the identity of an import block. Read fills in
// the rest, or drops a job that does not exist, which Terraform reports.
func (r *verifyJobResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := importedSafeID(ctx, req, resp, "id", "verify job", "verify-store1")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}
