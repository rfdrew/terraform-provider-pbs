package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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
	_ resource.Resource                   = &datastoreResource{}
	_ resource.ResourceWithConfigure      = &datastoreResource{}
	_ resource.ResourceWithIdentity       = &datastoreResource{}
	_ resource.ResourceWithImportState    = &datastoreResource{}
	_ resource.ResourceWithModifyPlan     = &datastoreResource{}
	_ resource.ResourceWithValidateConfig = &datastoreResource{}
)

// NewDatastoreResource returns the pbs_datastore resource.
func NewDatastoreResource() resource.Resource { return &datastoreResource{} }

type datastoreResource struct {
	data *providerData
}

type datastoreModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Path             types.String `tfsdk:"path"`
	Comment          types.String `tfsdk:"comment"`
	GCSchedule       types.String `tfsdk:"gc_schedule"`
	VerifyNew        types.Bool   `tfsdk:"verify_new"`
	NotificationMode types.String `tfsdk:"notification_mode"`
	NotifyUser       types.String `tfsdk:"notify_user"`
	Notify           types.Object `tfsdk:"notify"`
	Tuning           types.Object `tfsdk:"tuning"`
	MaintenanceMode  types.Object `tfsdk:"maintenance_mode"`
	BackingDevice    types.String `tfsdk:"backing_device"`
	GCOnUnmount      types.Bool   `tfsdk:"gc_on_unmount"`
	MountStatus      types.String `tfsdk:"mount_status"`
	ReuseDatastore   types.Bool   `tfsdk:"reuse_datastore"`
	DestroyData      types.Bool   `tfsdk:"destroy_data"`
	KeepJobConfigs   types.Bool   `tfsdk:"keep_job_configs"`
}

// datastoreDeletable are the properties of a datastore that this resource
// manages and PBS lets an update delete.
var datastoreDeletable = []string{
	"comment", "gc-schedule", "gc-on-unmount", "verify-new", "notify-user", "notify", "notification-mode", "tuning",
	"maintenance-mode",
}

// Notification modes. PBS 4.0 made notification-system the default; a
// datastore upgraded from PBS 3 carries legacy-sendmail explicitly.
const (
	notificationModeLegacy = "legacy-sendmail"
	notificationModeSystem = "notification-system"
)

// The property strings of a datastore.
var (
	datastoreNotifyFormat = propertyStringFormat{keys: []propertyStringKey{
		{"gc", "gc", types.StringType},
		{"prune", "prune", types.StringType},
		{"sync", "sync", types.StringType},
		{"verify", "verify", types.StringType},
	}}
	datastoreTuningFormat = propertyStringFormat{keys: []propertyStringKey{
		{"chunk_order", "chunk-order", types.StringType},
		{"sync_level", "sync-level", types.StringType},
		{"gc_atime_cutoff", "gc-atime-cutoff", types.Int64Type},
		{"gc_atime_safety_check", "gc-atime-safety-check", types.BoolType},
		{"gc_cache_capacity", "gc-cache-capacity", types.Int64Type},
		{"default_verification_readers", "default-verification-readers", types.Int64Type},
		{"default_verification_workers", "default-verification-workers", types.Int64Type},
	}}
	datastoreMaintenanceFormat = propertyStringFormat{defaultKey: "type", keys: []propertyStringKey{
		{"type", "type", types.StringType},
		{"message", "message", types.StringType},
	}}
)

// Privileges the datastore resource needs, for error messages.
const (
	datastoreAllocatePrivilege = "Datastore.Allocate on /datastore"
	// A removable datastore needs Sys.Modify on /system/disks too, to be
	// created, mounted or destroyed.
	removableDatastorePrivilege = datastoreAllocatePrivilege + " and Sys.Modify on /system/disks"
)

// allocatePrivilege names what creating or destroying the datastore of m
// needs, for errors.
func (m datastoreModel) allocatePrivilege() string {
	if m.BackingDevice.ValueString() != "" {
		return removableDatastorePrivilege
	}
	return datastoreAllocatePrivilege
}

// filesystemUUIDPattern is the UUID of a file system, as PBS accepts it for
// a removable datastore's backing device: lower-case hexadecimal digits in
// groups of 8, 4, 4, 4 and 12.
var filesystemUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

// datastorePrivilege names a privilege on one datastore, for errors.
func datastorePrivilege(privilege, name string) string {
	return privilege + " on /datastore/" + name
}

// maxMaintenanceMessageLength bounds the message of a maintenance mode.
const maxMaintenanceMessageLength = 64

func (r *datastoreResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore"
}

func (r *datastoreResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	notifyAttribute := func(job, def string) schema.StringAttribute {
		return schema.StringAttribute{
			Optional: true,
			MarkdownDescription: "When to send a mail about " + job + ": `always`, `error` or `never`. PBS defaults " +
				"to `" + def + "`.",
			Validators: []validator.String{stringvalidator.OneOf("always", "error", "never")},
		}
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server datastore in a directory, or on a removable disk: " +
			"where backups are stored, as a chunk store that deduplicates them, and how PBS looks after it. Mount " +
			"the disk of a datastore in a directory outside Terraform; PBS creates the directory if it is missing.\n\n" +
			"Creating a datastore is a PBS task that creates 65536 chunk directories, which takes a few seconds; " +
			"the provider waits for it, up to the provider's `task_timeout`, and reports the task's error should it " +
			"fail. PBS creates the datastore in an empty directory, or one with dotfiles and `lost+found` only; " +
			"a directory that already holds a chunk store — one a datastore destroyed without `destroy_data` left " +
			"behind — needs `reuse_datastore`, which keeps its backups.\n\n" +
			"Retention is not set here: a `pbs_prune_job` prunes the datastore, and a `pbs_verify_job` verifies it. " +
			"`gc_schedule` frees the space pruned backups held.\n\n" +
			"~> **Destroying a datastore deletes its jobs and access rights.** Unless `keep_job_configs` is set, PBS " +
			"deletes the datastore's prune, verify, sync and tape backup jobs and every ACL entry on " +
			"`/datastore/<name>` with it — also when a change of `name`, `path` or `backing_device` replaces the " +
			"datastore. Terraform creates the ones it manages again: in the same apply those that refer to a new " +
			"`name`, on the next apply the others. The backups stay on disk unless `destroy_data` is set, and a " +
			"datastore created again in the same directory then needs `reuse_datastore`.\n\n" +
			"A **removable datastore** lives on a disk that is connected only at times, such as a USB disk for " +
			"backups kept offsite: `backing_device` names the file system on it by UUID, and `path` is a directory " +
			"on that file system, which PBS mounts at `/mnt/datastore/<name>`. PBS mounts it when it creates the " +
			"datastore, which needs the disk connected, when the disk is plugged in, and when told to — in the " +
			"web interface, or with `proxmox-backup-manager datastore mount <name>` —; it unmounts it when told " +
			"to, or after a sync job set to unmount when done. `mount_status` shows which. The provider changes " +
			"the datastore's settings whether it is mounted or not, but `destroy_data` needs it mounted, and so " +
			"does creating or destroying its namespaces.\n\n" +
			"Namespaces live in the datastore's directory: a datastore renamed with `reuse_datastore` keeps them, " +
			"and one moved to another `path` or `backing_device` starts without them. `pbs_namespace` says what " +
			"that means for the namespaces Terraform manages.\n\n" +
			"Datastores on S3 object storage are not supported yet, and cannot be imported. Managing datastores " +
			"needs `" + datastoreAllocatePrivilege + "` to create and destroy them — and, for a removable " +
			"datastore, `Sys.Modify` on `/system/disks` —, `Datastore.Modify` on the datastore to change it and " +
			"`Datastore.Audit` to read it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `name`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Datastore name, 3 to 32 characters: letters, digits, `_`, `.` and `-`, not " +
					"starting with `.` or `-`. Changing it replaces the datastore.",
				Validators:    safeIDValidators(minSafeIDLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"path": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Absolute path of the directory, such as `/mnt/datastore/store1`. It must not " +
					"lie inside another datastore's directory, nor contain one. For a removable datastore, the " +
					"directory's path on the device's file system instead, relative to its root, such as `store1` " +
					"or `pbs/store1`; PBS creates it if it is missing. Changing it replaces the datastore.",
				Validators:    []validator.String{datastorePathValidator()},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"backing_device": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Makes the datastore removable: the UUID of the file system on the removable " +
					"disk that holds it, as `blkid` or `lsblk -f` shows it, such as " +
					"`0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d`. The disk must be connected to the PBS host when the " +
					"datastore is created. Changing it replaces the datastore.",
				Validators: []validator.String{stringvalidator.RegexMatches(filesystemUUIDPattern,
					"must be the UUID of a file system in lower case, such as 0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"gc_on_unmount": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether PBS runs garbage collection on a removable datastore before it " +
					"unmounts it, so that the space pruned backups held is freed while the disk is connected. " +
					"Defaults to `false`. Needs `backing_device` and PBS 4.2 or newer.",
			},
			"mount_status": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Whether the file system of a removable datastore is mounted: `mounted` or " +
					"`notmounted`. `nonremovable` for a datastore without `backing_device`.",
				PlanModifiers: []planmodifier.String{nonRemovableMountStatus{}},
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
			"gc_schedule": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "When garbage collection runs, as a PBS calendar event such as `daily` or " +
					"`sat 05:00`. Garbage collection frees the chunks no backup uses any more, after a prune: without " +
					"a schedule, it runs only when started by hand, and pruned backups keep their space.",
				Validators: textValidators(1, 256),
			},
			"verify_new": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether PBS verifies every new backup right after it is written. Defaults to " +
					"`false`.",
			},
			"notification_mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(notificationModeSystem),
				MarkdownDescription: "How PBS reports the outcome of garbage collection and of the datastore's " +
					"jobs: `notification-system`, the default, sends notifications through PBS's notification " +
					"system — matchers such as `pbs_notification_matcher` route them to endpoints such as " +
					"`pbs_notification_endpoint_smtp` — while `legacy-sendmail` mails `notify_user` as `notify` " +
					"says, with the host's sendmail. Datastores created by PBS 3 use `legacy-sendmail`.",
				Validators: []validator.String{stringvalidator.OneOf(notificationModeSystem, notificationModeLegacy)},
			},
			"notify_user": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "With `notification_mode = \"legacy-sendmail\"`, the user whose email " +
					"address gets the mails, such as `admin@pbs`; `root@pam` when left out.",
				Validators: userIDValidators(),
			},
			"notify": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "With `notification_mode = \"legacy-sendmail\"`, which mails to send. The " +
					"notification system ignores it: matchers decide there.",
				Attributes: map[string]schema.Attribute{
					"gc":     notifyAttribute("garbage collection", "always"),
					"prune":  notifyAttribute("prune jobs", "error"),
					"sync":   notifyAttribute("sync jobs", "always"),
					"verify": notifyAttribute("verify jobs", "always"),
				},
				Validators: []validator.Object{nonEmptyObject{}},
			},
			"tuning": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "Tuning options, for special cases; each one left out has PBS's default. The " +
					"provider writes them as a whole: options set outside Terraform that are not described here " +
					"are dropped when `tuning` changes.",
				Attributes: map[string]schema.Attribute{
					"chunk_order": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: "Order in which verification and tape backups read chunks: `inode`, the " +
							"default, which is faster on spinning disks, or `none`.",
						Validators: []validator.String{stringvalidator.OneOf("inode", "none")},
					},
					"sync_level": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: "How PBS makes sure written chunks are on disk: `filesystem`, the " +
							"default, syncs the file system at the end of a backup; `file` syncs each chunk; `none` " +
							"leaves it to the operating system, which risks losing data on a crash.",
						Validators: []validator.String{stringvalidator.OneOf("filesystem", "file", "none")},
					},
					"gc_atime_cutoff": schema.Int64Attribute{
						Optional: true,
						MarkdownDescription: "Minutes, 1 to 2880, after which garbage collection treats a chunk it " +
							"did not mark as unused; PBS defaults to 1445, 24 hours and 5 minutes.",
						Validators: []validator.Int64{int64validator.Between(1, 2880)},
					},
					"gc_atime_safety_check": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: "Whether PBS checks, when it creates the datastore and before garbage " +
							"collection, that the file system updates access times, which garbage collection " +
							"relies on. PBS defaults to `true`.",
					},
					"gc_cache_capacity": schema.Int64Attribute{
						Optional: true,
						MarkdownDescription: "How many chunk digests garbage collection caches, 0 to 8388608; PBS " +
							"defaults to 1048576. `0` disables the cache.",
						Validators: []validator.Int64{int64validator.Between(0, 8388608)},
					},
					"default_verification_readers": schema.Int64Attribute{
						Optional: true,
						MarkdownDescription: "Threads that read chunks in a verification that does not set its " +
							"own, 1 to 32; PBS defaults to 1. Needs PBS 4.1 or newer.",
						Validators: []validator.Int64{int64validator.Between(1, maxVerifyThreads)},
					},
					"default_verification_workers": schema.Int64Attribute{
						Optional: true,
						MarkdownDescription: "Threads that verify chunks in a verification that does not set its " +
							"own, 1 to 32; PBS defaults to 4. Needs PBS 4.1 or newer.",
						Validators: []validator.Int64{int64validator.Between(1, maxVerifyThreads)},
					},
				},
				Validators: []validator.Object{nonEmptyObject{}},
			},
			"maintenance_mode": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "Puts the datastore into maintenance. PBS also sets maintenance modes of its " +
					"own while it unmounts, refreshes or deletes a datastore; the provider does not report those as " +
					"a change.",
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Required: true,
						MarkdownDescription: "`read-only`, which allows restores but no backups, prunes or " +
							"garbage collection, or `offline`, which allows nothing.",
						Validators: []validator.String{stringvalidator.OneOf(pbsclient.MaintenanceReadOnly, pbsclient.MaintenanceOffline)},
					},
					"message": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Why, up to 64 characters on one line, without commas; PBS shows it to clients.",
						Validators: append(textValidators(1, maxMaintenanceMessageLength), stringCheck{
							description: "must not contain commas",
							check:       func(s string) bool { return !strings.Contains(s, ",") },
						}),
					},
				},
			},
			"reuse_datastore": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether to create the datastore on a directory that already holds a chunk " +
					"store, as one left behind by a datastore destroyed without `destroy_data`, keeping its " +
					"backups. Only used when the datastore is created; defaults to `false`.",
			},
			"destroy_data": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether destroying the datastore also deletes its directory and every backup " +
					"in it. Defaults to `false`, which leaves them on disk, ready for `reuse_datastore`. Destroying " +
					"uses the value in state: set it in an apply before the one that destroys or replaces the " +
					"datastore.",
			},
			"keep_job_configs": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether destroying the datastore keeps its prune, verify, sync and tape backup " +
					"jobs and its ACL entries, which PBS deletes otherwise. Defaults to `false`. Like `destroy_data`, " +
					"it is read from state.",
			},
		},
	}
}

// datastorePathValidator accepts the path of a datastore's directory, of
// either kind: at most 4096 characters, on one line. Whether it must be
// absolute or relative depends on backing_device, which ValidateConfig
// checks.
func datastorePathValidator() validator.String {
	return stringCheck{
		description: "must be a path of at most 4096 characters without control characters",
		check: func(s string) bool {
			return s != "" && len(s) <= 4096 && !strings.ContainsFunc(s, unicode.IsControl)
		},
	}
}

// isAbsoluteDatastorePath reports whether s is an absolute path below /, as
// the directory of a datastore that is not removable.
func isAbsoluteDatastorePath(s string) bool {
	return strings.HasPrefix(s, "/") && strings.Trim(s, "/") != ""
}

// isOnDevicePath reports whether s is a path relative to the root of a file
// system that stays inside it, as the directory of a removable datastore.
func isOnDevicePath(s string) bool {
	if strings.HasPrefix(s, "/") {
		return false
	}
	for part := range strings.SplitSeq(s, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// nonRemovableMountStatus plans mount_status as nonremovable for a datastore
// without backing_device, which is never mounted or unmounted. A removable
// datastore's is left as Terraform plans it: unknown when the datastore
// changes, since PBS mounts and unmounts it on its own.
type nonRemovableMountStatus struct{}

func (nonRemovableMountStatus) Description(_ context.Context) string {
	return "nonremovable for a datastore without backing_device"
}

func (m nonRemovableMountStatus) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (nonRemovableMountStatus) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	var backingDevice types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("backing_device"), &backingDevice)...)
	if backingDevice.IsNull() {
		resp.PlanValue = types.StringValue(pbsclient.MountStatusNonRemovable)
	}
}

func (r *datastoreResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Datastore name, such as `store1`."})
}

func (r *datastoreResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ValidateConfig checks path against the kind of datastore backing_device
// makes it, refuses gc_on_unmount for a datastore that is not removable, and
// warns about the settings of mails that the notification system ignores.
func (r *datastoreResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config datastoreModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !config.BackingDevice.IsUnknown() && !config.Path.IsNull() && !config.Path.IsUnknown() {
		dir := config.Path.ValueString()
		switch removable := !config.BackingDevice.IsNull(); {
		case !removable && !isAbsoluteDatastorePath(dir):
			resp.Diagnostics.AddAttributeError(path.Root("path"), "Invalid Attribute Value",
				fmt.Sprintf("Attribute path must be an absolute path below /, such as /mnt/datastore/store1, got: %q. "+
					"Only a removable datastore, with backing_device, has a relative path, on its device.", dir))
		case removable && !isOnDevicePath(dir):
			resp.Diagnostics.AddAttributeError(path.Root("path"), "Invalid Attribute Value",
				fmt.Sprintf("Attribute path of a removable datastore must be a path relative to the root of its "+
					"device's file system, such as store1 or pbs/store1, without \"..\", got: %q.", dir))
		}
	}
	if config.BackingDevice.IsNull() && config.GCOnUnmount.ValueBool() {
		resp.Diagnostics.AddAttributeError(path.Root("gc_on_unmount"), "Invalid Attribute Combination",
			"gc_on_unmount = true needs backing_device: only a removable datastore is unmounted.")
	}

	if config.NotificationMode.IsUnknown() || config.NotificationMode.ValueString() == notificationModeLegacy {
		return
	}
	for _, setting := range []struct {
		attribute string
		set       bool
	}{
		{"notify_user", !config.NotifyUser.IsNull()},
		{"notify", !config.Notify.IsNull()},
	} {
		if setting.set {
			resp.Diagnostics.AddAttributeWarning(path.Root(setting.attribute), "Setting without effect",
				setting.attribute+" applies only with notification_mode = \"legacy-sendmail\". With the notification "+
					"system, the default, notification matchers decide where notifications go.")
		}
	}
}

// ModifyPlan refuses tuning options a server older than PBS 4.1 does not
// know, and warns that replacing the datastore deletes its jobs.
func (r *datastoreResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan datastoreModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Tuning.IsNull() && !plan.Tuning.IsUnknown() {
		attributes := plan.Tuning.Attributes()
		for _, name := range []string{"default_verification_readers", "default_verification_workers"} {
			r.data.requireRelease(&resp.Diagnostics, path.Root("tuning").AtName(name), attributes[name], pbs41)
		}
	}
	// gc_on_unmount = false, its default, is never sent.
	if plan.GCOnUnmount.IsUnknown() || plan.GCOnUnmount.ValueBool() {
		r.data.requireRelease(&resp.Diagnostics, path.Root("gc_on_unmount"), plan.GCOnUnmount, pbs42)
	}

	if req.State.Raw.IsNull() {
		return
	}
	var state datastoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() ||
		(plan.Name.Equal(state.Name) && plan.Path.Equal(state.Path) && plan.BackingDevice.Equal(state.BackingDevice)) {
		return
	}

	// PBS cannot rename a datastore, so a new name replaces it. In the same
	// directory, the new one meets the chunk store the old one leaves
	// behind without destroy_data, and PBS refuses to create it there unless
	// it reuses that — after the old datastore, its jobs and its ACL entries
	// are already gone.
	if !plan.Name.IsUnknown() && plan.Path.Equal(state.Path) && plan.BackingDevice.Equal(state.BackingDevice) &&
		!state.DestroyData.ValueBool() && !plan.ReuseDatastore.IsUnknown() && !plan.ReuseDatastore.ValueBool() {
		resp.Diagnostics.AddAttributeError(path.Root("reuse_datastore"), "Renaming the datastore needs reuse_datastore",
			fmt.Sprintf("PBS cannot rename a datastore, so this plan destroys datastore %q and creates %q in the same "+
				"directory, %s. Destroying it with destroy_data = false, as in state, leaves its chunk store there, "+
				"and PBS creates no datastore on a chunk store unless asked to reuse it. Set reuse_datastore = true "+
				"to create the new datastore on it, keeping the backups.",
				state.Name.ValueString(), plan.Name.ValueString(), state.Path.ValueString()))
		return
	}
	if state.KeepJobConfigs.ValueBool() {
		return
	}
	resp.Diagnostics.AddWarning("Replacing the datastore deletes its jobs and ACL entries",
		fmt.Sprintf("This plan replaces datastore %q. Destroying it, with keep_job_configs = false as in state, "+
			"makes PBS delete its prune, verify, sync and tape backup jobs and every ACL entry on %s, also those "+
			"Terraform does not manage. Terraform creates the jobs and entries it manages again: in this apply "+
			"those whose datastore or path refers to the new name, on the next apply the others. To keep them, set "+
			"keep_job_configs = true and apply that first. Namespaces stay with the old chunk store: a datastore "+
			"renamed with reuse_datastore keeps them, but destroying its pbs_namespace resources that hold backups "+
			"fails — take those out of state first —, and one in a new place starts without them, which Terraform "+
			"creates again on the next apply.",
			state.Name.ValueString(), "/datastore/"+state.Name.ValueString()))
}

// datastoreDefaults is the model of a datastore as PBS creates it when a
// property is left out, the prior state of a create.
var datastoreDefaults = datastoreModel{
	Comment:          types.StringNull(),
	GCSchedule:       types.StringNull(),
	GCOnUnmount:      types.BoolValue(false),
	VerifyNew:        types.BoolValue(false),
	NotificationMode: types.StringValue(notificationModeSystem),
	NotifyUser:       types.StringNull(),
	Notify:           types.ObjectNull(datastoreNotifyFormat.attributeTypes()),
	Tuning:           types.ObjectNull(datastoreTuningFormat.attributeTypes()),
	MaintenanceMode:  types.ObjectNull(datastoreMaintenanceFormat.attributeTypes()),
}

// changes records the properties that differ between prior and m.
func (m *datastoreModel) changes(prior datastoreModel, c *propertyChanges) {
	c.String("comment", m.Comment, prior.Comment)
	c.String("gc-schedule", m.GCSchedule, prior.GCSchedule)
	c.BoolDefault("gc-on-unmount", m.GCOnUnmount, prior.GCOnUnmount, false)
	c.BoolDefault("verify-new", m.VerifyNew, prior.VerifyNew, false)
	c.StringDefault("notification-mode", m.NotificationMode, prior.NotificationMode, notificationModeSystem)
	c.String("notify-user", m.NotifyUser, prior.NotifyUser)
	c.PropertyString("notify", m.Notify, prior.Notify, datastoreNotifyFormat)
	c.PropertyString("tuning", m.Tuning, prior.Tuning, datastoreTuningFormat)
	c.PropertyString("maintenance-mode", m.MaintenanceMode, prior.MaintenanceMode, datastoreMaintenanceFormat)
}

// fromDatastore records a datastore as PBS reports it, with its mount status.
// The name is the one it was looked up by. A maintenance mode PBS set itself,
// for an operation in progress, leaves the recorded one as it was, and so do
// the attributes that exist only in Terraform, which get their defaults after
// an import.
func (m *datastoreModel) fromDatastore(name string, ds pbsclient.Datastore, mountStatus string, diags *diag.Diagnostics) {
	if backend := ds.BackendType(); backend != pbsclient.BackendFilesystem {
		diags.AddError("Unsupported PBS datastore",
			fmt.Sprintf("Datastore %q is on S3 object storage. pbs_datastore manages datastores in a directory and "+
				"removable ones only, so far, and cannot import it.", name))
		return
	}

	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	m.Path = types.StringValue(ds.Path)
	m.BackingDevice = stringOrNull(ds.BackingDevice)
	m.GCOnUnmount = boolOr(ds.GCOnUnmount, false)
	m.MountStatus = stringOrNull(mountStatus)
	m.Comment = stringOrNull(ds.Comment)
	m.GCSchedule = stringOrNull(ds.GCSchedule)
	m.VerifyNew = boolOr(ds.VerifyNew, false)
	m.NotificationMode = stringOr(ds.NotificationMode, notificationModeSystem)
	m.NotifyUser = stringOrNull(ds.NotifyUser)
	m.Notify = datastoreNotifyFormat.object("notify", ds.Notify, diags)
	m.Tuning = datastoreTuningFormat.object("tuning", ds.Tuning, diags)

	if maintenance := maintenanceType(ds.MaintenanceMode); pbsclient.IsInternalMaintenance(maintenance) {
		if m.MaintenanceMode.IsNull() || m.MaintenanceMode.IsUnknown() {
			m.MaintenanceMode = types.ObjectNull(datastoreMaintenanceFormat.attributeTypes())
		}
	} else {
		m.MaintenanceMode = datastoreMaintenanceFormat.object("maintenance-mode", ds.MaintenanceMode, diags)
	}

	for _, flag := range []*types.Bool{&m.ReuseDatastore, &m.DestroyData, &m.KeepJobConfigs} {
		if flag.IsNull() || flag.IsUnknown() {
			*flag = types.BoolValue(false)
		}
	}
}

// maintenanceType is the type of a maintenance mode as PBS sends it; "" for
// none.
func maintenanceType(mode string) string {
	parsed, err := pbsclient.ParsePropertyString(mode, "type")
	if err != nil {
		return ""
	}
	return parsed["type"]
}

func (r *datastoreResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan datastoreModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(datastoreDefaults, changes)
	params := changes.Values()
	params.Set("name", name)
	params.Set("path", plan.Path.ValueString())
	if device := plan.BackingDevice.ValueString(); device != "" {
		params.Set("backing-device", device)
	}
	if plan.ReuseDatastore.ValueBool() {
		params.Set("reuse-datastore", "true")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigDatastores, func() error { return client.CreateDatastore(ctx, params) })
	if err != nil {
		resp.Diagnostics.AddError("Unable to create PBS datastore", datastoreCreateErrorDetail(client, plan, err))
		return
	}

	// From here on the datastore exists, so it is recorded in state even
	// when reading it back fails. Unlike other resources, it is not tainted
	// then, with an error: replacing it would delete its jobs and ACL entries
	// and meet its own chunk store. The next refresh reads it again.
	ds, err := client.WaitForDatastore(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		plan.unknownMountStatusToNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddWarning("Unable to read PBS datastore back after creation",
			fmt.Sprintf("PBS created datastore %q, and it was recorded in state as planned, but reading it back "+
				"failed; the next plan reads it again. %s", name, apiErrorDetail(client, datastorePrivilege("Datastore.Audit", name), err)))
		return
	}
	plan.fromDatastore(name, ds, r.mountStatus(ctx, ds, &resp.Diagnostics), &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// mountStatus returns the mount status of a datastore, or "" — null in state —
// with a warning when PBS does not say.
func (r *datastoreResource) mountStatus(ctx context.Context, ds pbsclient.Datastore, diags *diag.Diagnostics) string {
	status, err := r.data.client.DatastoreMountStatus(ctx, ds)
	if err != nil {
		diags.AddWarning("Unable to read whether the PBS datastore is mounted",
			fmt.Sprintf("Reading the mount status of removable datastore %q failed, so mount_status is left "+
				"empty. %s", ds.Name, apiErrorDetail(r.data.client, datastorePrivilege("Datastore.Audit", ds.Name), err)))
	}
	return status
}

// unknownMountStatusToNull leaves mount_status null rather than unknown, for
// state written without reading the datastore back.
func (m *datastoreModel) unknownMountStatusToNull() {
	if m.MountStatus.IsUnknown() {
		m.MountStatus = types.StringNull()
	}
}

// datastoreCreateErrorDetail explains why creating a datastore failed, with
// advice for the failures of the create-datastore task.
func datastoreCreateErrorDetail(client *pbsclient.Client, plan datastoreModel, err error) string {
	name, dir := plan.Name.ValueString(), plan.Path.ValueString()
	var taskErr *pbsclient.TaskError
	switch {
	case pbsclient.IsAlreadyExists(err):
		return fmt.Sprintf("PBS already has a datastore %q. To manage it with Terraform, import it, with an import "+
			"block whose id is %q or with `terraform import`. %s", name, name, err)
	case errors.As(err, &taskErr) && isUsedDirectory(taskErr.ExitStatus):
		return fmt.Sprintf("PBS did not create datastore %q: %s already holds a chunk store or other files. PBS "+
			"creates a datastore in an empty directory, or — with reuse_datastore = true — on the chunk store a "+
			"datastore destroyed without destroy_data left behind, keeping its backups. %s", name, dir, err)
	case errors.As(err, &taskErr) && strings.Contains(taskErr.ExitStatus, "existing chunk store"):
		return fmt.Sprintf("PBS did not create datastore %q: reuse_datastore is set, but %s does not hold a chunk "+
			"store PBS can open, or its owner or permissions are wrong. Leave reuse_datastore out for a new, "+
			"empty directory. %s", name, dir, err)
	case errors.As(err, &taskErr) && strings.Contains(taskErr.ExitStatus, "mounting to tmp path failed"):
		return fmt.Sprintf("PBS did not create removable datastore %q: it could not mount the file system with UUID "+
			"%s. The disk must be connected to the PBS host and hold a file system with that UUID, which blkid "+
			"shows. %s", name, plan.BackingDevice.ValueString(), err)
	case errors.As(err, &taskErr):
		return fmt.Sprintf("PBS did not create datastore %q in %s; its task failed. PBS may have left the chunk "+
			"store it had begun in the directory, which a new attempt then needs reuse_datastore for. The task log "+
			"in PBS has the details. %s", name, dir, err)
	}
	return apiErrorDetail(client, plan.allocatePrivilege(), err)
}

// isUsedDirectory reports whether a create-datastore task failed because the
// directory is in use: "datastore path not empty" when it holds anything but
// dotfiles — backups, say — and, when it holds a chunk store and no backups,
// "unable to create chunk store '<name>' subdir \"<path>/.chunks\" - EEXIST:
// File exists".
func isUsedDirectory(exitStatus string) bool {
	return strings.Contains(exitStatus, "datastore path not empty") ||
		(strings.Contains(exitStatus, "unable to create chunk store") && strings.Contains(exitStatus, "EEXIST"))
}

func (r *datastoreResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state datastoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the datastore gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	ds, err := r.data.client.GetDatastore(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS datastore",
			apiErrorDetail(r.data.client, datastorePrivilege("Datastore.Audit", name), err))
		return
	}
	if maintenance := maintenanceType(ds.MaintenanceMode); pbsclient.IsInternalMaintenance(maintenance) {
		tflog.Info(ctx, "PBS has the datastore in a maintenance mode of its own", map[string]any{"name": name, "type": maintenance})
	}
	state.fromDatastore(name, ds, r.mountStatus(ctx, ds, &resp.Diagnostics), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *datastoreResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state datastoreModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, datastoreDeletable...)
	plan.changes(state, changes)
	if resp.Diagnostics.HasError() {
		return
	}
	// reuse_datastore, destroy_data and keep_job_configs live in Terraform
	// alone; a change of only those has nothing to send.
	if !changes.Empty() {
		err := client.WithConfigLock(pbsclient.ConfigDatastores, func() error {
			return client.UpdateDatastore(ctx, name, changes.Values())
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS datastore",
				apiErrorDetail(client, datastorePrivilege("Datastore.Modify", name), err))
			return
		}
	}

	ds, err := client.GetDatastore(ctx, name)
	if err != nil {
		plan.unknownMountStatusToNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS datastore back after update",
			fmt.Sprintf("PBS updated datastore %q, and the change was recorded in state, but reading it back failed. %s",
				name, apiErrorDetail(client, datastorePrivilege("Datastore.Audit", name), err)))
		return
	}
	plan.fromDatastore(name, ds, r.mountStatus(ctx, ds, &resp.Diagnostics), &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// Delete deletes the datastore as destroy_data and keep_job_configs in state
// say, and waits for PBS's delete-datastore task.
func (r *datastoreResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state datastoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	client := r.data.client
	deletion := pbsclient.DatastoreDeletion{
		DestroyData:    state.DestroyData.ValueBool(),
		KeepJobConfigs: state.KeepJobConfigs.ValueBool(),
	}
	err := client.WithConfigLock(pbsclient.ConfigDatastores, func() error { return client.DeleteDatastore(ctx, name, deletion) })
	var taskErr *pbsclient.TaskError
	switch {
	case pbsclient.IsNotFound(err):
	case err == nil:
		// A task that could not remove all the data ends with warnings and
		// keeps the datastore, in its "delete" maintenance mode.
		if _, err := client.GetDatastore(ctx, name); err == nil {
			resp.Diagnostics.AddError("Unable to delete PBS datastore",
				fmt.Sprintf("PBS's task to delete datastore %q ended with warnings and kept the datastore, in its "+
					"\"delete\" maintenance mode: it could not remove all its data. The task log in PBS names what "+
					"failed; destroying it again retries.", name))
		} else if !pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddError("Unable to check that the PBS datastore is deleted",
				fmt.Sprintf("PBS's task to delete datastore %q ended, but reading the datastore afterwards failed. %s",
					name, apiErrorDetail(client, datastorePrivilege("Datastore.Audit", name), err)))
		}
	case errors.As(err, &taskErr):
		resp.Diagnostics.AddError("Unable to delete PBS datastore",
			fmt.Sprintf("PBS's task to delete datastore %q failed, and PBS keeps the datastore in its \"delete\" "+
				"maintenance mode until a deletion succeeds; destroying it again retries. A datastore in use — by "+
				"a running backup, say — cannot be deleted. %s", name, err))
	case strings.Contains(err.Error(), "unless the datastore is mounted"):
		resp.Diagnostics.AddError("Unable to delete PBS datastore",
			fmt.Sprintf("Removable datastore %q is not mounted, and PBS deletes its data, as destroy_data = true in "+
				"state asks, only while it is. Connect the disk and mount the datastore — in the web interface, or "+
				"with `proxmox-backup-manager datastore mount %s` —, or set destroy_data = false and apply that "+
				"first to keep the data on the disk. %s", name, name, err))
	default:
		resp.Diagnostics.AddError("Unable to delete PBS datastore", apiErrorDetail(client, state.allocatePrivilege(), err))
	}
}

// ImportState imports a datastore by name, given either as the import id or,
// from Terraform 1.12, as the identity of an import block. Read fills in the
// rest, or drops a datastore that does not exist, which Terraform reports.
func (r *datastoreResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "datastore", "store1")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}
