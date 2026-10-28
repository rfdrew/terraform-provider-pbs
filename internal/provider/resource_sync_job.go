package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                   = &syncJobResource{}
	_ resource.ResourceWithConfigure      = &syncJobResource{}
	_ resource.ResourceWithIdentity       = &syncJobResource{}
	_ resource.ResourceWithImportState    = &syncJobResource{}
	_ resource.ResourceWithModifyPlan     = &syncJobResource{}
	_ resource.ResourceWithValidateConfig = &syncJobResource{}
)

// NewSyncJobResource returns the pbs_sync_job resource.
func NewSyncJobResource() resource.Resource { return &syncJobResource{} }

type syncJobResource struct {
	data *providerData
}

type syncJobModel struct {
	ID             types.String  `tfsdk:"id"`
	SyncDirection  types.String  `tfsdk:"sync_direction"`
	Store          types.String  `tfsdk:"store"`
	NS             types.String  `tfsdk:"ns"`
	Remote         types.String  `tfsdk:"remote"`
	RemoteStore    types.String  `tfsdk:"remote_store"`
	RemoteNS       types.String  `tfsdk:"remote_ns"`
	MaxDepth       types.Int64   `tfsdk:"max_depth"`
	Schedule       types.String  `tfsdk:"schedule"`
	Owner          types.String  `tfsdk:"owner"`
	RemoveVanished types.Bool    `tfsdk:"remove_vanished"`
	GroupFilter    types.Set     `tfsdk:"group_filter"`
	TransferLast   types.Int64   `tfsdk:"transfer_last"`
	EncryptedOnly  types.Bool    `tfsdk:"encrypted_only"`
	VerifiedOnly   types.Bool    `tfsdk:"verified_only"`
	ResyncCorrupt  types.Bool    `tfsdk:"resync_corrupt"`
	RunOnMount     types.Bool    `tfsdk:"run_on_mount"`
	UnmountOnDone  types.Bool    `tfsdk:"unmount_on_done"`
	WorkerThreads  types.Int64   `tfsdk:"worker_threads"`
	RateIn         byteSizeValue `tfsdk:"rate_in"`
	BurstIn        byteSizeValue `tfsdk:"burst_in"`
	RateOut        byteSizeValue `tfsdk:"rate_out"`
	BurstOut       byteSizeValue `tfsdk:"burst_out"`
	Comment        types.String  `tfsdk:"comment"`
}

// syncJobDeletable are the properties PBS lets a sync job update delete.
// store and remote-store are required, and resync-corrupt cannot be deleted,
// only set to false. The encryption keys are left alone: see the resource's
// description.
var syncJobDeletable = []string{
	"remote", "owner", "comment", "schedule", "remove-vanished", "group-filter",
	"rate-in", "burst-in", "rate-out", "burst-out", "ns", "remote-ns", "max-depth", "transfer-last",
	"encrypted-only", "verified-only", "run-on-mount", "unmount-on-done", "sync-direction", "worker-threads",
}

// maxSyncWorkerThreads bounds worker_threads.
const maxSyncWorkerThreads = 32

// maxByteSizeLength bounds a byte size, as PBS does.
const maxByteSizeLength = 64

// groupFilterPattern is a group filter in the form PBS writes it back: an
// optional "exclude:", then a backup type, a backup group or a regular
// expression. PBS drops an "include:" prefix, which includes anyway, so the
// filter would read back changed; it is refused instead.
var groupFilterPattern = regexp.MustCompile(`^(exclude:)?(type:(vm|ct|host)|group:(vm|ct|host)/[A-Za-z0-9_][A-Za-z0-9._-]*|regex:.+)$`)

// byteSizeDecimals is a byte size with more than three decimals, which PBS
// rounds to three when it stores the size.
var byteSizeDecimals = regexp.MustCompile(`\.[0-9]{4,}`)

// byteSizeValidators check a rate or burst limit: a size PBS parses, which it
// stores without rounding it.
func byteSizeValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(1, maxByteSizeLength),
		stringCheck{
			description: "must be a byte size such as 500, 64KiB, 10MiB or 1.5GB, with at most three decimals",
			check: func(s string) bool {
				_, err := pbsclient.ParseByteSize(s)
				return err == nil && !byteSizeDecimals.MatchString(s)
			},
		},
	}
}

func (r *syncJobResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sync_job"
}

// rateAttribute is one of the rate and burst limits.
func rateAttribute(description string) schema.StringAttribute {
	return schema.StringAttribute{
		CustomType: byteSizeType{},
		Optional:   true,
		MarkdownDescription: description + " A byte size such as `500`, `64KiB`, `10MiB` or `1.5GB`: `K`, `M`, " +
			"`G`, `T` and `P` are powers of 1000, `Ki` to `Pi` powers of 1024, and `B` is optional. PBS writes " +
			"it back in its own spelling, such as `10 MiB`, which counts as the same: state keeps the " +
			"configuration's. Only after an import, state has PBS's spelling, and the next plan shows an update " +
			"that sends nothing. No limit when left out.",
		Validators: byteSizeValidators(),
	}
}

func (r *syncJobResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server sync job: on a schedule, it copies the backups of " +
			"one datastore, or of a namespace in it, to another, skipping those the target has already. One " +
			"resource covers three kinds of job:\n\n" +
			"* **pull from a remote** — `remote` set, `sync_direction = \"pull\"`, the default: from `remote_store` " +
			"on the remote to `store` here;\n" +
			"* **local pull** — `remote` left out: from `remote_store`, another datastore of this server, to " +
			"`store`;\n" +
			"* **push** — `sync_direction = \"push\"`, which needs `remote`: from `store` here to `remote_store` " +
			"on the remote.\n\n" +
			"An offsite copy is either a push job on the PBS that holds the backups, or a pull job on the offsite " +
			"one: a pull keeps the offsite server's credentials off the primary server, a push the primary's off " +
			"the offsite one.\n\n" +
			"PBS checks neither the datastores nor the remote when it saves the job; a wrong name shows when the " +
			"job runs.\n\n" +
			"Deleting a datastore without `keep_job_configs` deletes the sync jobs whose `store` it is — pulls " +
			"always, pushes from PBS 4.1.1, while older releases keep a push job whose source is gone — and a " +
			"`pbs_sync_job` then plans to create its job again. A local pull from the datastore is kept.\n\n" +
			"**Privileges.** The user or token the provider signs in as needs, besides `Datastore.Audit` on " +
			"`/datastore/<store>[/<ns>]` to read the job:\n\n" +
			"* to pull from a remote, `Datastore.Backup` there — plus `Datastore.Prune` for `remove_vanished`, and " +
			"`Datastore.Modify` unless `owner` is exactly the user or token the provider signs in as, or a token of " +
			"that user — and `Remote.Read` on " +
			"`/remote/<remote>/<remote_store>`; reading the job also needs `Remote.Audit` on `/remote/<remote>`;\n" +
			"* for a local pull, the same on `store`, and on `/datastore/<remote_store>[/<remote_ns>]` " +
			"`Datastore.Audit` with `Datastore.Read`, or `Datastore.Backup` for the owner's own backups;\n" +
			"* to push, `RemoteDatastore.Backup` on `/remote/<remote>/<remote_store>[/<remote_ns>]` — plus " +
			"`RemoteDatastore.Prune` for `remove_vanished` — and `Datastore.Read` on `/datastore/<store>[/<ns>]`, " +
			"or `Datastore.Backup`, with `Datastore.Modify` unless `owner` is the provider's own, for the owner's " +
			"own backups; reading the job also needs `Remote.Audit` on the remote path.\n\n" +
			"With an `owner` other than root@pam, the owner itself needs the same privileges on this server when " +
			"the job runs. On the remote, `auth_id` of the `pbs_remote` acts: to pull, it needs " +
			"`Datastore.Audit` with `Datastore.Read` on the remote datastore — the role `DatastoreReader` — or " +
			"`Datastore.Backup` for its own backups; to push, `Datastore.Backup` there, plus `Datastore.Prune` for " +
			"`remove_vanished` and `Datastore.Modify` to create the namespaces it pushes into.\n\n" +
			"The resource leaves the sync encryption keys of PBS 4.2, `active-encryption-key` and " +
			"`associated-key`, alone: a job keeps the ones set in the web interface.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Job ID, 3 to 32 characters: letters, digits, `_`, `.` and `-`, not starting " +
					"with `.` or `-`. Changing it replaces the job.",
				Validators:    safeIDValidators(minSafeIDLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"sync_direction": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(pbsclient.SyncDirectionPull),
				MarkdownDescription: "`pull`, the default, to copy backups from `remote_store` to `store`, or " +
					"`push`, to copy them from `store` to `remote_store` on `remote`. Changing it replaces the job: " +
					"the two directions swap source and target.",
				Validators: []validator.String{
					stringvalidator.OneOf(pbsclient.SyncDirectionPull, pbsclient.SyncDirectionPush),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"store": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Local datastore, such as the `name` of a `pbs_datastore`: the target of a pull, " +
					"the source of a push.",
				Validators: safeIDValidators(minSafeIDLength),
			},
			"ns": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Namespace in `store`, such as `dept1` or `dept1/hosts`; the datastore's root " +
					"namespace when left out. A pull creates the namespaces it copies below it; a push copies from " +
					"it, and it must exist.",
				Validators: namespaceValidators(),
			},
			"remote": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Name of the other PBS, such as the `name` of a `pbs_remote`. Required to push; " +
					"when left out, the job pulls from a datastore of this server.",
				Validators: safeIDValidators(minSafeIDLength),
			},
			"remote_store": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Datastore on the remote — the source of a pull, the target of a push — or, " +
					"without `remote`, the local datastore to pull from, which must be another than `store`.",
				Validators: safeIDValidators(minSafeIDLength),
			},
			"remote_ns": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Namespace in `remote_store`, such as `site-a`; its root namespace when left " +
					"out. A push creates the namespaces it copies below it on the remote.",
				Validators: namespaceValidators(),
			},
			"max_depth": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many levels of namespaces below the source namespace to sync too, from " +
					"`0`, the namespace alone, to `7`; all of them when left out. Added to the depth of `ns` and of " +
					"`remote_ns`, it must not exceed 7, the deepest that namespaces nest.",
				Validators: []validator.Int64{int64validator.Between(0, maxNamespaceDepth)},
			},
			"schedule": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "When the job runs, as a PBS calendar event such as `hourly`, `daily` or " +
					"`mon..fri 21:00`. PBS checks it. Without a schedule, the job runs only when started by hand, " +
					"or with `run_on_mount`.",
				Validators: textValidators(1, 256),
			},
			"owner": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "User or API token of this server that the job acts as, such as `sync@pbs`; " +
					"`root@pam` when left out. A pull makes it the owner of the backup groups it creates, and fails " +
					"to sync a group the target has with another owner, so that the run ends with errors; a push " +
					"copies the backups it may read. Leaving it out, or naming another user or token than the one the " +
					"provider signs in as, needs `Datastore.Modify` on the target of a pull, and on the source of a " +
					"push unless the provider has `Datastore.Read` there; `root@pam` needs neither. When the job runs, " +
					"the owner needs the job's privileges on this server: a pull creates the namespaces it copies as " +
					"the owner, which needs `Datastore.Modify` on their parent.",
				Validators: authIDValidators(),
			},
			"remove_vanished": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether to delete, from the target, the backups, backup groups and namespaces " +
					"the source no longer has, protected backups excepted. Defaults to `false`. A vanished backup " +
					"group is deleted only when `group_filter` selects it and the job owns it — for a pull, `owner`; " +
					"for a push, the remote's `auth_id` — but a vanished namespace below `ns` (pull) or `remote_ns` " +
					"(push) is deleted with every backup group in it, whatever the filter and owners. With " +
					"`encrypted_only` or `verified_only`, backups the source has but the filter skips count as gone.",
			},
			"group_filter": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Which backup groups to sync, all of them when left out. Each filter is " +
					"`type:<vm|ct|host>`, `group:<type>/<id>` such as `group:vm/100`, or `regex:<expression>`, " +
					"which is matched against `<type>/<id>` anywhere in it; `exclude:` in front of a filter " +
					"excludes what it matches. A group is synced when it matches at least one filter that is not " +
					"an exclude — or there is none — and no exclude.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(
						stringvalidator.LengthAtLeast(1),
						stringvalidator.RegexMatches(groupFilterPattern, "must be type:<vm|ct|host>, group:<type>/<id> "+
							"or regex:<expression>, optionally after exclude:; leave include: out"),
						stringCheck{
							description: "must not contain control characters",
							check:       func(s string) bool { return !strings.ContainsFunc(s, unicode.IsControl) },
						},
					),
				},
			},
			"transfer_last": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many of the most recent backups of each group to copy, at least 1; all " +
					"the target lacks when left out.",
				Validators: []validator.Int64{int64validator.AtLeast(1)},
			},
			"encrypted_only": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to copy only encrypted backups. Defaults to `false`.",
			},
			"verified_only": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to copy only backups that a verification found intact. Defaults to `false`.",
			},
			"resync_corrupt": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether a pull copies again the backups whose local copy failed verification. " +
					"Defaults to `false`. Pull jobs only.",
			},
			"run_on_mount": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether the job also runs whenever a removable datastore it syncs with is " +
					"mounted. Defaults to `false`.",
			},
			"unmount_on_done": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether PBS unmounts the removable datastore after a run that its mount " +
					"started. Defaults to `false`. `true` needs `run_on_mount`, and PBS 4.1 or newer.",
			},
			"worker_threads": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many backup groups of a namespace to sync at the same time, 1 to 32; one " +
					"after another, 1, when left out. Needs PBS 4.2 or newer.",
				Validators: []validator.Int64{int64validator.Between(1, maxSyncWorkerThreads)},
			},
			"rate_in": rateAttribute("Rate limit on the data the job receives from the remote, the copies of a " +
				"pull, in bytes per second."),
			"burst_in": rateAttribute("How many bytes over `rate_in` the job may receive at once."),
			"rate_out": rateAttribute("Rate limit on the data the job sends to the remote, the copies of a push, in " +
				"bytes per second."),
			"burst_out": rateAttribute("How many bytes over `rate_out` the job may send at once."),
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
		},
	}
}

func (r *syncJobResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"id", "Job ID, such as `pull-offsite`."})
}

func (r *syncJobResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// namespaceLevels is how many levels below the root a namespace is.
func namespaceLevels(ns string) int64 {
	if ns == "" {
		return 0
	}
	return int64(strings.Count(ns, "/") + 1)
}

// ValidateConfig refuses the combinations PBS refuses: a push without a
// remote, a local pull into its own source, resync_corrupt on a push,
// unmount_on_done without run_on_mount, and a max_depth that reaches below
// the deepest namespace.
func (r *syncJobResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config syncJobModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	push := config.SyncDirection.ValueString() == pbsclient.SyncDirectionPush
	if push && config.Remote.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("remote"), "Push needs a remote",
			"A push job copies backups to another PBS: set remote to the pbs_remote to push to. To copy between "+
				"two datastores of this server, use a pull job without remote instead.")
	}
	if push && config.ResyncCorrupt.ValueBool() {
		resp.Diagnostics.AddAttributeError(path.Root("resync_corrupt"), "Pull jobs only",
			"PBS copies corrupt backups again only for pull jobs; a push job refuses resync_corrupt.")
	}
	if config.Remote.IsNull() && !config.SyncDirection.IsUnknown() && !push && !config.Store.IsUnknown() &&
		!config.RemoteStore.IsUnknown() && config.Store.Equal(config.RemoteStore) {
		resp.Diagnostics.AddAttributeError(path.Root("remote_store"), "Source and target datastore are the same",
			"Without remote, the job pulls from remote_store, a datastore of this server, into store, and PBS "+
				"refuses a job whose two datastores are the same, even for different namespaces.")
	}
	if config.UnmountOnDone.ValueBool() && !config.RunOnMount.IsUnknown() && !config.RunOnMount.ValueBool() {
		resp.Diagnostics.AddAttributeError(path.Root("unmount_on_done"), "unmount_on_done needs run_on_mount",
			"PBS unmounts the datastore only after a run that mounting it started: set run_on_mount = true too.")
	}
	if !config.MaxDepth.IsNull() && !config.MaxDepth.IsUnknown() {
		for _, ns := range []struct {
			attribute string
			value     types.String
		}{{"ns", config.NS}, {"remote_ns", config.RemoteNS}} {
			if ns.value.IsUnknown() {
				continue
			}
			if depth := namespaceLevels(ns.value.ValueString()); depth+config.MaxDepth.ValueInt64() > maxNamespaceDepth {
				resp.Diagnostics.AddAttributeError(path.Root("max_depth"), "Namespaces nest at most 7 levels deep",
					fmt.Sprintf("%s is %d levels deep, and max_depth = %d reaches %d levels below it; namespaces nest "+
						"at most %d levels deep, and PBS refuses the job. Lower max_depth to %d at most.",
						ns.attribute, depth, config.MaxDepth.ValueInt64(), config.MaxDepth.ValueInt64(), maxNamespaceDepth,
						maxNamespaceDepth-depth))
			}
		}
	}
}

// ModifyPlan refuses the attributes a server too old for them would.
func (r *syncJobResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan syncJobModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if mayBeTrue(plan.UnmountOnDone) {
		r.data.requireRelease(&resp.Diagnostics, path.Root("unmount_on_done"), plan.UnmountOnDone, pbs41)
	}
	r.data.requireRelease(&resp.Diagnostics, path.Root("worker_threads"), plan.WorkerThreads, pbs42)
}

// syncJobDefaults is the model of a sync job as PBS creates it when a
// property is left out, the prior state of a create.
var syncJobDefaults = syncJobModel{
	SyncDirection:  types.StringValue(pbsclient.SyncDirectionPull),
	NS:             types.StringNull(),
	Remote:         types.StringNull(),
	RemoteNS:       types.StringNull(),
	MaxDepth:       types.Int64Null(),
	Schedule:       types.StringNull(),
	Owner:          types.StringNull(),
	RemoveVanished: types.BoolValue(false),
	GroupFilter:    types.SetNull(types.StringType),
	TransferLast:   types.Int64Null(),
	EncryptedOnly:  types.BoolValue(false),
	VerifiedOnly:   types.BoolValue(false),
	ResyncCorrupt:  types.BoolValue(false),
	RunOnMount:     types.BoolValue(false),
	UnmountOnDone:  types.BoolValue(false),
	WorkerThreads:  types.Int64Null(),
	RateIn:         byteSizeOrNull(""),
	BurstIn:        byteSizeOrNull(""),
	RateOut:        byteSizeOrNull(""),
	BurstOut:       byteSizeOrNull(""),
	Comment:        types.StringNull(),
}

// createParams are the parameters of the call that creates the job m
// describes: what differs from PBS's defaults, and the ID.
func (m *syncJobModel) createParams(diags *diag.Diagnostics) url.Values {
	changes := newPropertyChanges(diags)
	m.changes(syncJobDefaults, changes)
	params := changes.Values()
	params.Set("id", m.ID.ValueString())
	return params
}

// sameSize is plan, or prior when both stand for the same size, so that a
// new spelling of the same size sends nothing.
func sameSize(plan, prior byteSizeValue) types.String {
	if !plan.IsNull() && !plan.IsUnknown() && !prior.IsNull() && pbsclient.SameByteSize(plan.ValueString(), prior.ValueString()) {
		return prior.StringValue
	}
	return plan.StringValue
}

// changes records the properties that differ between prior and m.
// resync-corrupt cannot be deleted, so resetting it writes false.
func (m *syncJobModel) changes(prior syncJobModel, c *propertyChanges) {
	c.StringDefault("sync-direction", m.SyncDirection, prior.SyncDirection, pbsclient.SyncDirectionPull)
	c.String("store", m.Store, prior.Store)
	c.String("ns", m.NS, prior.NS)
	c.String("remote", m.Remote, prior.Remote)
	c.String("remote-store", m.RemoteStore, prior.RemoteStore)
	c.String("remote-ns", m.RemoteNS, prior.RemoteNS)
	c.Int64("max-depth", m.MaxDepth, prior.MaxDepth)
	c.String("schedule", m.Schedule, prior.Schedule)
	c.String("owner", m.Owner, prior.Owner)
	c.BoolDefault("remove-vanished", m.RemoveVanished, prior.RemoveVanished, false)
	c.StringSet("group-filter", m.GroupFilter, prior.GroupFilter)
	c.Int64("transfer-last", m.TransferLast, prior.TransferLast)
	c.BoolDefault("encrypted-only", m.EncryptedOnly, prior.EncryptedOnly, false)
	c.BoolDefault("verified-only", m.VerifiedOnly, prior.VerifiedOnly, false)
	c.Bool("resync-corrupt", m.ResyncCorrupt, prior.ResyncCorrupt)
	c.BoolDefault("run-on-mount", m.RunOnMount, prior.RunOnMount, false)
	c.BoolDefault("unmount-on-done", m.UnmountOnDone, prior.UnmountOnDone, false)
	c.Int64("worker-threads", m.WorkerThreads, prior.WorkerThreads)
	c.String("rate-in", sameSize(m.RateIn, prior.RateIn), prior.RateIn.StringValue)
	c.String("burst-in", sameSize(m.BurstIn, prior.BurstIn), prior.BurstIn.StringValue)
	c.String("rate-out", sameSize(m.RateOut, prior.RateOut), prior.RateOut.StringValue)
	c.String("burst-out", sameSize(m.BurstOut, prior.BurstOut), prior.BurstOut.StringValue)
	c.String("comment", m.Comment, prior.Comment)
}

// fromSyncJob records a sync job as PBS reports it. The ID is the one it was
// looked up by.
func (m *syncJobModel) fromSyncJob(id string, job pbsclient.SyncJob, diags *diag.Diagnostics) {
	m.ID = types.StringValue(id)
	m.SyncDirection = types.StringValue(job.Direction())
	m.Store = types.StringValue(job.Store)
	m.NS = stringOrNull(job.NS)
	m.Remote = stringOrNull(job.Remote)
	m.RemoteStore = types.StringValue(job.RemoteStore)
	m.RemoteNS = stringOrNull(job.RemoteNS)
	m.MaxDepth = int64OrNull(job.MaxDepth)
	m.Schedule = stringOrNull(job.Schedule)
	m.Owner = stringOrNull(job.Owner)
	m.RemoveVanished = boolOr(job.RemoveVanished, false)
	m.GroupFilter = stringSetOrNull(job.GroupFilter, diags)
	m.TransferLast = int64OrNull(job.TransferLast)
	m.EncryptedOnly = boolOr(job.EncryptedOnly, false)
	m.VerifiedOnly = boolOr(job.VerifiedOnly, false)
	m.ResyncCorrupt = boolOr(job.ResyncCorrupt, false)
	m.RunOnMount = boolOr(job.RunOnMount, false)
	m.UnmountOnDone = boolOr(job.UnmountOnDone, false)
	m.WorkerThreads = int64OrNull(job.WorkerThreads)
	m.RateIn = byteSizeOrNull(job.RateIn)
	m.BurstIn = byteSizeOrNull(job.BurstIn)
	m.RateOut = byteSizeOrNull(job.RateOut)
	m.BurstOut = byteSizeOrNull(job.BurstOut)
	m.Comment = stringOrNull(job.Comment)
}

// aclPath is a datastore or remote ACL path, with the namespace below it.
func aclPath(base, ns string) string {
	if ns == "" {
		return base
	}
	return base + "/" + ns
}

// syncJobPrivileges names the privileges a change of the job needs, for
// errors.
func syncJobPrivileges(m syncJobModel) string {
	target := aclPath("/datastore/"+m.Store.ValueString(), m.NS.ValueString())
	switch {
	case m.SyncDirection.ValueString() == pbsclient.SyncDirectionPush:
		return fmt.Sprintf("RemoteDatastore.Backup on %s, plus RemoteDatastore.Prune for remove_vanished, and "+
			"Datastore.Audit with Datastore.Read on %s, or Datastore.Backup for the owner's own backups, with "+
			"Datastore.Modify unless owner is the user or token the provider signs in as",
			aclPath("/remote/"+m.Remote.ValueString()+"/"+m.RemoteStore.ValueString(), m.RemoteNS.ValueString()), target)
	case m.Remote.IsNull():
		return fmt.Sprintf("Datastore.Audit and Datastore.Backup on %s, plus Datastore.Prune for remove_vanished and "+
			"Datastore.Modify unless owner is the user or token the provider signs in as, and Datastore.Audit with "+
			"Datastore.Read on %s", target, aclPath("/datastore/"+m.RemoteStore.ValueString(), m.RemoteNS.ValueString()))
	default:
		return fmt.Sprintf("Datastore.Audit and Datastore.Backup on %s, plus Datastore.Prune for remove_vanished and "+
			"Datastore.Modify unless owner is the user or token the provider signs in as, and Remote.Read on "+
			"/remote/%s/%s", target, m.Remote.ValueString(), m.RemoteStore.ValueString())
	}
}

// syncJobReadPrivileges names the privileges reading the job needs, for
// errors.
func syncJobReadPrivileges(m syncJobModel) string {
	target := "Datastore.Audit on " + aclPath("/datastore/"+m.Store.ValueString(), m.NS.ValueString())
	switch {
	case m.SyncDirection.ValueString() == pbsclient.SyncDirectionPush:
		return target + " and Remote.Audit on " +
			aclPath("/remote/"+m.Remote.ValueString()+"/"+m.RemoteStore.ValueString(), m.RemoteNS.ValueString())
	case m.Remote.IsNull():
		return target + " and on /datastore/" + m.RemoteStore.ValueString()
	default:
		return target + " and Remote.Audit on /remote/" + m.Remote.ValueString()
	}
}

// syncJobErrorDetail explains a failed call. PBS answers a missing privilege
// of a sync job with 400 "permission check failed", which names none.
func syncJobErrorDetail(client *pbsclient.Client, privileges string, err error) string {
	var apiErr *pbsclient.Error
	if errors.As(err, &apiErr) && apiErr.StatusCode == 400 && strings.HasPrefix(apiErr.Message, "permission check failed") {
		detail := fmt.Sprintf("%q lacks a privilege the job needs: %s.", client.AuthID(), privileges)
		if client.UsesAPIToken() {
			detail += " An API token has no privileges of its own: besides its user's ACL entries, it needs " +
				"entries for the token ID itself."
		}
		return detail + " " + err.Error()
	}
	return apiErrorDetail(client, privileges, err)
}

func (r *syncJobResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan syncJobModel
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

	err := client.WithConfigLock(pbsclient.ConfigSyncJobs, func() error { return client.CreateSyncJob(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS sync job already exists",
				fmt.Sprintf("PBS already has a sync job %q. To manage it with Terraform, import it, with an import "+
					"block whose id is %q or with `terraform import`. %s", id, id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS sync job", syncJobErrorDetail(client, syncJobPrivileges(plan), err))
		return
	}

	// From here on the job exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	job, err := client.GetSyncJob(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS sync job back after creation",
			fmt.Sprintf("PBS created sync job %q, and it was recorded in state, but reading it back failed, so it is "+
				"marked tainted: the next apply replaces it. %s", id, syncJobErrorDetail(client, syncJobReadPrivileges(plan), err)))
		return
	}
	plan.fromSyncJob(id, job, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// Read drops a job that is gone, as it is after its datastore was deleted
// without keep_job_configs, so that the next plan creates it again. A push
// job reads like a pull job: by its ID.
func (r *syncJobResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state syncJobModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	// Before the lookup, so that a refresh finding the job gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)

	job, err := r.data.client.GetSyncJob(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS sync job",
			syncJobErrorDetail(r.data.client, syncJobReadPrivileges(state), err))
		return
	}
	state.fromSyncJob(id, job, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *syncJobResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state syncJobModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, syncJobDeletable...)
	plan.changes(state, changes)
	if resp.Diagnostics.HasError() {
		return
	}
	if !changes.Empty() {
		err := client.WithConfigLock(pbsclient.ConfigSyncJobs, func() error {
			err := client.UpdateSyncJob(ctx, id, changes.Values())
			// PBS deletes a datastore's sync jobs with it, as when a new
			// name replaces the datastore, with this job's store following
			// it: the job is created again, as the plan describes it. An
			// update also fails with "no such key or cannot access key" when
			// a new owner may not use the job's encryption keys, so a read
			// confirms that the job itself is gone.
			if pbsclient.IsNotFound(err) && syncJobGone(ctx, client, id) {
				tflog.Info(ctx, "the PBS sync job is gone; creating it again", map[string]any{"id": id})
				params := plan.createParams(&resp.Diagnostics)
				if resp.Diagnostics.HasError() {
					return nil
				}
				err = client.CreateSyncJob(ctx, params)
			}
			return err
		})
		if resp.Diagnostics.HasError() {
			return
		}
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS sync job", syncJobErrorDetail(client, syncJobPrivileges(plan), err))
			return
		}
	}

	job, err := client.GetSyncJob(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS sync job back after update",
			fmt.Sprintf("PBS updated sync job %q, and the change was recorded in state, but reading it back failed. %s",
				id, syncJobErrorDetail(client, syncJobReadPrivileges(plan), err)))
		return
	}
	plan.fromSyncJob(id, job, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// syncJobGone reports whether PBS has no sync job id.
func syncJobGone(ctx context.Context, client *pbsclient.Client, id string) bool {
	_, err := client.GetSyncJob(ctx, id)
	return pbsclient.IsNotFound(err)
}

// Delete deletes the job; one already gone, with its datastore say, is not an
// error.
func (r *syncJobResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state syncJobModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigSyncJobs, func() error {
		return client.DeleteSyncJob(ctx, state.ID.ValueString())
	})
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS sync job", syncJobErrorDetail(client, syncJobPrivileges(state), err))
	}
}

// ImportState imports a sync job of either direction by its ID, given either
// as the import id or, from Terraform 1.12, as the identity of an import
// block. Read fills in the rest, or drops a job that does not exist, which
// Terraform reports.
func (r *syncJobResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := importedSafeID(ctx, req, resp, "id", "sync job", "pull-offsite")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}
