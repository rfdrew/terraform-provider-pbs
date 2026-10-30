package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	stdpath "path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
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
	// Backend, NotificationThresholds and CounterResetSchedule are for a
	// datastore on S3.
	Backend                types.Object `tfsdk:"backend"`
	NotificationThresholds types.Object `tfsdk:"notification_thresholds"`
	CounterResetSchedule   types.String `tfsdk:"counter_reset_schedule"`
	ReuseDatastore         types.Bool   `tfsdk:"reuse_datastore"`
	OverwriteInUse         types.Bool   `tfsdk:"overwrite_in_use"`
	DestroyData            types.Bool   `tfsdk:"destroy_data"`
	KeepJobConfigs         types.Bool   `tfsdk:"keep_job_configs"`
}

// datastoreDeletable are the properties of a datastore that this resource
// manages and PBS lets an update delete.
var datastoreDeletable = []string{
	"comment", "gc-schedule", "gc-on-unmount", "verify-new", "notify-user", "notify", "notification-mode", "tuning",
	"maintenance-mode", "notification-thresholds", "counter-reset-schedule",
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
	// PBS stores backend as it was sent; the provider writes every key with
	// its name, sorted, as PBS's web interface does:
	// "bucket=b,client=c,type=s3".
	datastoreBackendFormat = propertyStringFormat{defaultKey: "type", keys: []propertyStringKey{
		{"type", "type", types.StringType},
		{"client", "client", types.StringType},
		{"bucket", "bucket", types.StringType},
		{"max_cache_size", "max-cache-size", byteSizeType{}},
	}}
	datastoreBackendWriteFormat = propertyStringFormat{keys: datastoreBackendFormat.keys}
	datastoreThresholdsFormat   = propertyStringFormat{keys: []propertyStringKey{
		{"s3_get", "s3-get", types.Int64Type},
		{"s3_put", "s3-put", types.Int64Type},
		{"s3_post", "s3-post", types.Int64Type},
		{"s3_head", "s3-head", types.Int64Type},
		{"s3_delete", "s3-delete", types.Int64Type},
		{"s3_upload", "s3-upload", types.StringType},
		{"s3_download", "s3-download", types.StringType},
	}}
)

// s3BucketPattern is a bucket name as PBS takes it: lower-case letters,
// digits and inner hyphens, without dots.
var s3BucketPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// s3BucketValidators check a bucket name, as PBS does after AWS's rules: 3
// to 63 characters, and none of the prefixes and suffixes AWS reserves.
func s3BucketValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(3, 63),
		stringvalidator.RegexMatches(s3BucketPattern, "must be lower-case letters, digits and hyphens, starting and ending with a letter or digit"),
		stringCheck{
			description: "must not start with xn--, sthree- or amzn-s3-demo-, nor end with --ol-s3, .mrap or --x-s3",
			check: func(s string) bool {
				for _, prefix := range []string{"xn--", "sthree-", "amzn-s3-demo-"} {
					if strings.HasPrefix(s, prefix) {
						return false
					}
				}
				for _, suffix := range []string{"--ol-s3", ".mrap", "--x-s3"} {
					if strings.HasSuffix(s, suffix) {
						return false
					}
				}
				return true
			},
		},
	}
}

// isS3 reports whether a planned or recorded backend is on S3.
func isS3(backend types.Object) bool {
	return !backend.IsNull() && !backend.IsUnknown()
}

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
		MarkdownDescription: "Manages a Proxmox Backup Server datastore in a directory, on a removable disk or on S3 " +
			"object storage: where backups are stored, as a chunk store that deduplicates them, and how PBS looks " +
			"after it. Mount the disk of a datastore in a directory outside Terraform; PBS creates the directory if " +
			"it is missing.\n\n" +
			"Creating a datastore is a PBS task that creates 65536 chunk directories, which takes a few seconds; " +
			"the provider waits for it, up to the provider's `task_timeout`, and reports the task's error should it " +
			"fail. PBS creates the datastore in an empty directory, or one with dotfiles and `lost+found` only; " +
			"a directory that already holds a chunk store — one a datastore destroyed without `destroy_data` left " +
			"behind — needs `reuse_datastore`, which keeps its backups.\n\n" +
			"Retention is not set here: a `pbs_prune_job` prunes the datastore, and a `pbs_verify_job` verifies it. " +
			"`gc_schedule` frees the space pruned backups held.\n\n" +
			"~> **Destroying a datastore deletes its jobs and access rights.** Unless `keep_job_configs` is set, PBS " +
			"deletes the datastore's prune, verify, sync and tape backup jobs and every ACL entry on " +
			"`/datastore/<name>` with it — also when a change of `name`, `path`, `backing_device` or `backend` replaces the " +
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
			"and one moved to another `path` or `backing_device` starts without them. On S3 they live in the " +
			"bucket, under the datastore's name: a datastore created again with the same name and bucket and " +
			"`reuse_datastore` has them, whatever its `path` — all of them from PBS 4.1.5, before only those with " +
			"backups in or below them —, and a new name or bucket starts without them. " +
			"`pbs_namespace` says what that means for the namespaces Terraform manages.\n\n" +
			"A datastore **on S3** keeps its backups in a bucket of an S3-compatible object store, through a " +
			"`pbs_s3_endpoint` named in `backend`, under a prefix that is the datastore's name; `path` is then a " +
			"local cache. Several datastores can share a bucket. PBS checks, when it creates the datastore, that it " +
			"can reach the bucket, and marks it in use by this host; PBS creates neither the bucket nor the access " +
			"key. The guide **Back up to S3 object storage** goes through it.\n\n" +
			"~> **A datastore on S3 must be created with `reuse_datastore = true` when its bucket already holds its " +
			"backups**, as after a destroy without `destroy_data`, or on another PBS: created without it, it starts " +
			"empty, and its next garbage collection deletes the chunks it finds in the bucket. The name decides " +
			"which backups it finds, so a new `name` starts empty; the old backups stay in the bucket.\n\n" +
			"Managing datastores needs `" + datastoreAllocatePrivilege + "` to create and destroy them — and, for a " +
			"removable datastore, `Sys.Modify` on `/system/disks` —, `Datastore.Modify` on the datastore to change " +
			"it and `Datastore.Audit` to read it. A datastore on S3 needs nothing on its S3 endpoint.",
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
					"or `pbs/store1`; PBS creates it if it is missing. For a datastore on S3, the local cache, such " +
					"as `/mnt/datastore/s3-cache`: PBS recommends 64 to 128 GiB on a disk, partition or dataset of " +
					"its own, and an existing datastore's directory cannot serve. Changing it replaces the datastore.",
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
			"backend": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "Puts the datastore on S3 object storage. Left out for a datastore in a " +
					"directory or on a removable disk. Changing it replaces the datastore: PBS cannot move a " +
					"datastore to another backend.",
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "`s3`.",
						Validators:          []validator.String{stringvalidator.OneOf(pbsclient.BackendS3)},
					},
					"client": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "ID of the S3 endpoint, such as the `id` of a `pbs_s3_endpoint`.",
						Validators:          safeIDValidators(minSafeIDLength),
					},
					"bucket": schema.StringAttribute{
						Required: true,
						MarkdownDescription: "Bucket that holds the backups, 3 to 63 lower-case letters, digits and " +
							"hyphens. It must exist, and the endpoint's access key must be allowed to list, read, " +
							"write and delete objects in it.",
						Validators: s3BucketValidators(),
					},
					"max_cache_size": schema.StringAttribute{
						CustomType: byteSizeType{},
						Optional:   true,
						MarkdownDescription: "Most space the local cache of chunks may take, such as `100GiB`, in " +
							"slots of 16 MiB; the free space of `path` when left out. `K` to `P` are powers of 1000, " +
							"`Ki` to `Pi` powers of 1024.",
						Validators: byteSizeValidators(),
					},
				},
				PlanModifiers: []planmodifier.Object{objectplanmodifier.RequiresReplaceIf(
					func(_ context.Context, req planmodifier.ObjectRequest, resp *objectplanmodifier.RequiresReplaceIfFuncResponse) {
						resp.RequiresReplace = !sameBackend(req.PlanValue, req.StateValue)
					},
					"A change of the backend replaces the datastore; a new spelling of the same max_cache_size does not.",
					"A change of the backend replaces the datastore; a new spelling of the same `max_cache_size` does not.",
				)},
			},
			"notification_thresholds": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "For a datastore on S3, how many requests and bytes to its bucket make PBS " +
					"send a notification, of severity `warning` and type `thresholds`: once, when a counter goes " +
					"over its threshold, until `counter_reset_schedule` resets the counters. Object stores bill " +
					"requests and traffic, which these keep an eye on. A threshold left out, or `0`, is none. Needs " +
					"PBS 4.2 or newer.",
				Attributes: map[string]schema.Attribute{
					"s3_get":    s3ThresholdAttribute("`GET` requests, which restores, verification, garbage collection and S3 refreshes make"),
					"s3_put":    s3ThresholdAttribute("`PUT` requests, which backups and syncs make"),
					"s3_post":   s3ThresholdAttribute("`POST` requests, which garbage collection makes to delete chunks in bulk"),
					"s3_head":   s3ThresholdAttribute("`HEAD` requests, which checks of objects make"),
					"s3_delete": s3ThresholdAttribute("`DELETE` requests"),
					"s3_upload": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Bytes uploaded to the bucket, such as `500GiB`.",
						Validators:          byteSizeValidators(),
					},
					"s3_download": schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Bytes downloaded from the bucket, such as `100GiB`.",
						Validators:          byteSizeValidators(),
					},
				},
				Validators: []validator.Object{nonEmptyObject{}},
			},
			"counter_reset_schedule": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "For a datastore on S3, when PBS resets the request and traffic counters of " +
					"`notification_thresholds`, as a PBS calendar event such as `monthly`; never when left out. " +
					"Needs PBS 4.2 or newer.",
				Validators: textValidators(1, 256),
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
					"backups. For a datastore on S3, whether to take over the backups its bucket holds under its " +
					"name: PBS then empties the local cache — deleting whatever chunk store `path` holds, also one a " +
					"datastore in a directory left there, with its backups — and reads the backups' indexes from the " +
					"bucket, which takes a while, in maintenance mode `s3-refresh`, and holds up the other datastores " +
					"of the server meanwhile. Only used when the datastore is created; defaults to `false`.",
			},
			"overwrite_in_use": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "For a datastore on S3, whether to take it over although its bucket marks it in " +
					"use by a PBS, as after the loss of the PBS that had it: two PBS must never use one datastore. " +
					"Requires `reuse_datastore`. Only used when the datastore is created; defaults to `false`.",
			},
			"destroy_data": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether destroying the datastore also deletes its directory and every backup " +
					"in it — for a datastore on S3, every object under its name in the bucket, and the local cache. " +
					"Defaults to `false`, which leaves them, ready for `reuse_datastore`; PBS then removes only the " +
					"bucket's mark that the datastore is in use. Destroying a datastore on S3 needs its bucket " +
					"reachable. Destroying uses the value in state: set it in an apply before the one that destroys " +
					"or replaces the datastore.",
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

// s3ThresholdAttribute is a request count threshold of a datastore on S3.
func s3ThresholdAttribute(what string) schema.Int64Attribute {
	return schema.Int64Attribute{
		Optional:            true,
		MarkdownDescription: "Number of " + what + ".",
		Validators:          []validator.Int64{int64validator.AtLeast(0)},
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
	if !config.Backend.IsNull() && !config.BackingDevice.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("backend"), "Invalid Attribute Combination",
			"A datastore is either removable, with backing_device, or on S3, with backend, not both.")
	}
	if config.Backend.IsNull() {
		for _, setting := range []struct {
			attribute string
			set       bool
		}{
			{"notification_thresholds", !config.NotificationThresholds.IsNull()},
			{"counter_reset_schedule", !config.CounterResetSchedule.IsNull()},
		} {
			if setting.set {
				resp.Diagnostics.AddAttributeError(path.Root(setting.attribute), "Invalid Attribute Combination",
					setting.attribute+" counts the requests to a datastore's bucket, so it needs backend: only a "+
						"datastore on S3 has one.")
			}
		}
	}
	if config.OverwriteInUse.ValueBool() && (config.Backend.IsNull() ||
		(!config.ReuseDatastore.IsUnknown() && !config.ReuseDatastore.ValueBool())) {
		resp.Diagnostics.AddAttributeError(path.Root("overwrite_in_use"), "Invalid Attribute Combination",
			"overwrite_in_use = true takes over a datastore on S3 that its bucket marks in use, with its backups, "+
				"so it needs backend and reuse_datastore = true: without reuse_datastore, the new datastore would "+
				"start empty, and its garbage collection would delete the backups' chunks in the bucket.")
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
// know, and the S3 counters a server older than PBS 4.2 does not, and warns
// that replacing the datastore deletes its jobs — and, on S3, what becomes of
// its backups.
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
	r.data.requireRelease(&resp.Diagnostics, path.Root("notification_thresholds"), plan.NotificationThresholds, pbs42)
	r.data.requireRelease(&resp.Diagnostics, path.Root("counter_reset_schedule"), plan.CounterResetSchedule, pbs42)

	if req.State.Raw.IsNull() {
		return
	}
	var state datastoreModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || (plan.Name.Equal(state.Name) && plan.Path.Equal(state.Path) &&
		plan.BackingDevice.Equal(state.BackingDevice) && sameBackend(plan.Backend, state.Backend)) {
		return
	}
	samePlace := sameDirectory(plan.Path, state.Path) && plan.BackingDevice.Equal(state.BackingDevice)
	keepsData := !state.DestroyData.ValueBool()
	reuses := plan.ReuseDatastore.IsUnknown() || plan.ReuseDatastore.ValueBool()
	// The guards that keep the backups take a value known only during apply
	// for the worst it may turn out to be: the same directory, the same name,
	// the same bucket, another backend, no reuse_datastore. During apply,
	// Terraform plans the new datastore without the old one's state, so
	// nothing checks them again.
	maybeSamePlace := (plan.Path.IsUnknown() || sameDirectory(plan.Path, state.Path)) &&
		(plan.BackingDevice.IsUnknown() || plan.BackingDevice.Equal(state.BackingDevice))
	where := "in the same directory, " + state.Path.ValueString()
	if !samePlace {
		where = "in a place known only during apply, which may be the same directory, " + state.Path.ValueString()
	}
	newName := strconv.Quote(plan.Name.ValueString())
	if plan.Name.IsUnknown() {
		newName = "a datastore whose name is known only during apply"
	}

	// A datastore in a directory and one on S3 must not take over each other's
	// chunk store: PBS empties the chunk store of a datastore on S3 that it
	// creates with reuse_datastore, and a datastore in a directory would take
	// over a cache whose evicted chunks are empty files.
	if keepsData && maybeSamePlace && plan.Backend.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("backend"), "The datastore's new backend is not known yet",
			fmt.Sprintf("This plan destroys datastore %q and creates %s %s, with a backend known only during "+
				"apply. Destroying it with destroy_data = false, as in state, leaves its chunk store there, which a "+
				"datastore with the other backend cannot take over: PBS empties the chunk store of a datastore on S3 "+
				"it creates with reuse_datastore, deleting the backups in it, and a datastore in a directory would "+
				"take over the cache of one on S3, in which the chunks the cache evicted are empty files. Make backend "+
				"known when planning, for example by applying what it "+
				"depends on first with -target, use another path, or set destroy_data = true and apply that first.",
				state.Name.ValueString(), newName, where))
		return
	}
	if keepsData && maybeSamePlace && isS3(plan.Backend) != isS3(state.Backend) {
		resp.Diagnostics.AddAttributeError(path.Root("backend"), "Moving the datastore to or from S3 needs another path",
			fmt.Sprintf("This plan destroys datastore %q and creates %s with another backend %s. Destroying it "+
				"with destroy_data = false, as in state, leaves its chunk store there, which the new datastore "+
				"cannot take over: PBS empties the chunk store of a datastore on S3 it creates with "+
				"reuse_datastore, deleting the backups in it, and a datastore in a directory would take over the "+
				"cache of one on S3, in which the chunks the cache evicted are empty files. Use another path, or set "+
				"destroy_data = true and apply that first.",
				state.Name.ValueString(), newName, where))
		return
	}
	if isS3(state.Backend) {
		r.warnS3Replacement(plan, state, &resp.Diagnostics)
	}

	// PBS cannot rename a datastore, so a new name replaces it. In the same
	// directory, the new one meets the chunk store the old one leaves
	// behind without destroy_data, and PBS refuses to create it there unless
	// it reuses that — after the old datastore, its jobs and its ACL entries
	// are already gone.
	if samePlace && keepsData && !reuses {
		keeps := "Set reuse_datastore = true to create the new datastore on it, keeping the backups."
		switch {
		case isS3(state.Backend) && plan.Name.Equal(state.Name) && sameBucket(plan.Backend, state.Backend):
			keeps = "Set reuse_datastore = true to create the new datastore in that directory, which then reads " +
				"its backups from the bucket again."
		case isS3(state.Backend) && plan.Name.Equal(state.Name) && backendKey(plan.Backend, "bucket").IsUnknown():
			keeps = "Set reuse_datastore = true to create the new datastore in that directory, which then reads " +
				"its backups from the bucket again if the bucket, known only during apply, is the same, and finds " +
				"none in another."
		case isS3(state.Backend) && plan.Name.IsUnknown():
			keeps = fmt.Sprintf("Set reuse_datastore = true to create the new datastore in that directory: it "+
				"reads the backups its bucket holds under its name, those of %q only if the name and bucket stay the "+
				"same. Or use another path.", state.Name.ValueString())
		case isS3(state.Backend):
			keeps = fmt.Sprintf("Set reuse_datastore = true to create the new datastore in that directory: it "+
				"reads the backups its bucket holds under %s/, not those of %q, which stay in the old bucket under "+
				"%s/. Or use another path.", plan.Name.ValueString(), state.Name.ValueString(), state.Name.ValueString())
		}
		summary := "Replacing the datastore in place needs reuse_datastore"
		if !plan.Name.IsUnknown() && !plan.Name.Equal(state.Name) {
			summary = "Renaming the datastore needs reuse_datastore"
		}
		resp.Diagnostics.AddAttributeError(path.Root("reuse_datastore"), summary,
			fmt.Sprintf("PBS cannot rename a datastore or change its backend, so this plan destroys datastore %q and "+
				"creates %s in the same directory, %s. Destroying it with destroy_data = false, as in state, leaves "+
				"its chunk store there, and PBS creates no datastore on a chunk store unless asked to reuse it. %s",
				state.Name.ValueString(), newName, state.Path.ValueString(), keeps))
		return
	}
	// On S3, a new datastore of the same name in the same bucket finds the
	// backups the old one leaves there without destroy_data, whatever its
	// directory, endpoint and cache size: another endpoint may reach the same
	// object store. PBS creates it without reusing them all the same, empty,
	// and its first garbage collection deletes their chunks.
	maybeSameName := plan.Name.IsUnknown() || plan.Name.Equal(state.Name)
	bucketUnknown := isS3(plan.Backend) && backendKey(plan.Backend, "bucket").IsUnknown()
	maybeSameBucket := plan.Backend.IsUnknown() || bucketUnknown || sameBucket(plan.Backend, state.Backend)
	if isS3(state.Backend) && keepsData && maybeSameName && maybeSameBucket && !plan.ReuseDatastore.ValueBool() {
		name := state.Name.ValueString()
		var unknown []string
		for _, u := range []struct {
			name    string
			unknown bool
		}{
			{"name", plan.Name.IsUnknown()},
			{"backend", plan.Backend.IsUnknown()},
			{"backend.bucket", bucketUnknown},
			{"reuse_datastore", plan.ReuseDatastore.IsUnknown()},
		} {
			if u.unknown {
				unknown = append(unknown, u.name)
			}
		}
		if len(unknown) == 0 {
			in := plan.Path.ValueString()
			if plan.Path.IsUnknown() {
				in = "a directory known only during apply"
			}
			resp.Diagnostics.AddAttributeError(path.Root("reuse_datastore"), "Replacing the datastore on S3 needs reuse_datastore",
				fmt.Sprintf("This plan destroys datastore %q on S3 and creates it again with the same name and bucket, in "+
					"%s. Destroying it with destroy_data = false, as in state, leaves its backups in the bucket under %s/; "+
					"created without reuse_datastore, the new datastore starts without them, and its first garbage "+
					"collection deletes their chunks — also through another endpoint, which may reach the same object "+
					"store. Set reuse_datastore = true to keep the backups, or set destroy_data = true and apply that "+
					"first to start without them.", name, in, name))
			return
		}
		// On S3, reuse_datastore keeps the backups in the same bucket and
		// finds none in another; but a backend that may turn out to be a
		// directory cannot be reused unless it holds a chunk store.
		reuse := ""
		if isS3(plan.Backend) && !plan.ReuseDatastore.IsUnknown() {
			same := "the bucket is"
			if plan.Name.IsUnknown() {
				same = "the name and bucket are"
			}
			reuse = fmt.Sprintf("set reuse_datastore = true, which keeps the backups if %s the same and finds none "+
				"otherwise, ", same)
		}
		resp.Diagnostics.AddAttributeError(path.Root("reuse_datastore"), "Replacing the datastore on S3 needs known values",
			fmt.Sprintf("This plan destroys datastore %q on S3 and creates a datastore whose %s Terraform knows only "+
				"during apply. Destroying it with destroy_data = false, as in state, leaves its backups in the bucket "+
				"under %s/; should the new datastore have the same name and bucket without reuse_datastore, it starts "+
				"without them, and its first garbage collection deletes their chunks. Make %s known when planning, "+
				"for example by applying what it depends on first with -target, %sor set destroy_data = true and apply "+
				"that first to start without them.", name, strings.Join(unknown, ", "), name, strings.Join(unknown, ", "), reuse))
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
			"keep_job_configs = true and apply that first. %s",
			state.Name.ValueString(), "/datastore/"+state.Name.ValueString(), namespacesAfterReplacement(plan, state)))
}

// warnS3Replacement warns what replacing a datastore on S3 does to its
// backups in the bucket: destroy_data deletes them, and a new name or bucket
// does not find them.
func (r *datastoreResource) warnS3Replacement(plan, state datastoreModel, diags *diag.Diagnostics) {
	name := state.Name.ValueString()
	if state.DestroyData.ValueBool() {
		diags.AddAttributeWarning(path.Root("destroy_data"), "Replacing the datastore deletes its backups in the bucket",
			fmt.Sprintf("This plan replaces datastore %q on S3, and destroy_data = true in state: destroying it "+
				"deletes every object under %s/ in its bucket, all of its backups, and its local cache. Set "+
				"destroy_data = false and apply that first to keep them.", name, name))
		return
	}
	startsEmpty := (!plan.Name.IsUnknown() && !plan.Name.Equal(state.Name)) ||
		(!plan.Backend.IsUnknown() && !backendKey(plan.Backend, "bucket").IsUnknown() && !sameBucket(plan.Backend, state.Backend))
	if startsEmpty {
		diags.AddAttributeWarning(path.Root("backend"), "The new datastore starts without the backups",
			fmt.Sprintf("This plan replaces datastore %q on S3. Its backups stay in its bucket under %s/, but a "+
				"datastore finds the backups under its own name, in its own bucket, so the new datastore starts "+
				"without them. Keep the name and backend, with reuse_datastore = true, to keep them.", name, name))
		return
	}
	// Without reuse_datastore, ModifyPlan fails the plan when the name or
	// bucket is not known yet.
	if (plan.Name.IsUnknown() || plan.Backend.IsUnknown() || backendKey(plan.Backend, "bucket").IsUnknown()) &&
		plan.ReuseDatastore.ValueBool() {
		diags.AddAttributeWarning(path.Root("backend"), "The new datastore may start without the backups",
			fmt.Sprintf("This plan replaces datastore %q on S3 with a datastore whose name or bucket Terraform "+
				"knows only during apply. Its backups stay in its bucket under %s/, and a datastore finds the "+
				"backups under its own name, in its own bucket: the new datastore has them only if it keeps both.",
				name, name))
	}
}

// namespacesAfterReplacement says what becomes of a replaced datastore's
// namespaces, for the replacement's warning.
func namespacesAfterReplacement(plan, state datastoreModel) string {
	if isS3(state.Backend) || isS3(plan.Backend) {
		return "On S3, the new datastore has the namespaces its bucket holds under its name: the old ones with the " +
			"same name and bucket and reuse_datastore — from PBS 4.1.5 all of them, before only those with backups " +
			"in or below them —, none otherwise; Terraform creates the missing ones it manages again on the next " +
			"apply."
	}
	return "Namespaces stay with the old chunk store: a datastore renamed with reuse_datastore keeps them, but " +
		"destroying its pbs_namespace resources that hold backups fails — take those out of state first —, and one " +
		"in a new place starts without them, which Terraform creates again on the next apply."
}

// sameDirectory reports whether two paths name the same directory: PBS keeps
// a path as written, so /mnt/datastore/x/ is /mnt/datastore/x.
func sameDirectory(a, b types.String) bool {
	if a.IsNull() || a.IsUnknown() || b.IsNull() || b.IsUnknown() {
		return a.Equal(b)
	}
	return stdpath.Clean(a.ValueString()) == stdpath.Clean(b.ValueString())
}

// sameBucket reports whether two backends name the same bucket, the place
// a datastore of the same name finds its backups in; false when either is
// not on S3 or not known yet.
func sameBucket(a, b types.Object) bool {
	if !isS3(a) || !isS3(b) {
		return false
	}
	bucket := backendKey(a, "bucket")
	return !bucket.IsUnknown() && bucket.Equal(backendKey(b, "bucket"))
}

// sameBackend reports whether two backends are the same, comparing
// max_cache_size by the size it stands for: PBS stores it as written, and a
// change of spelling alone is no change.
func sameBackend(a, b types.Object) bool {
	if a.IsNull() || b.IsNull() || a.IsUnknown() || b.IsUnknown() {
		return a.Equal(b)
	}
	for _, key := range []string{"type", "client", "bucket"} {
		if !backendKey(a, key).Equal(backendKey(b, key)) {
			return false
		}
	}
	x, xOK := backendKey(a, "max_cache_size").(byteSizeValue)
	y, yOK := backendKey(b, "max_cache_size").(byteSizeValue)
	switch {
	case !xOK || !yOK || x.IsUnknown() || y.IsUnknown():
		return false
	case x.IsNull() || y.IsNull():
		return x.IsNull() && y.IsNull()
	}
	return pbsclient.SameByteSize(x.ValueString(), y.ValueString())
}

// backendKey is one key of a planned or recorded backend; null for none.
func backendKey(backend types.Object, key string) attr.Value {
	if backend.IsNull() || backend.IsUnknown() {
		return types.StringNull()
	}
	return backend.Attributes()[key]
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
	// backend is sent at creation only.
	NotificationThresholds: types.ObjectNull(datastoreThresholdsFormat.attributeTypes()),
	CounterResetSchedule:   types.StringNull(),
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
	c.PropertyString("notification-thresholds", m.NotificationThresholds, prior.NotificationThresholds, datastoreThresholdsFormat)
	c.String("counter-reset-schedule", m.CounterResetSchedule, prior.CounterResetSchedule)
}

// fromDatastore records a datastore as PBS reports it, with its mount status.
// The name is the one it was looked up by. A maintenance mode PBS set itself,
// for an operation in progress, leaves the recorded one as it was, and so do
// the attributes that exist only in Terraform, which get their defaults after
// an import.
func (m *datastoreModel) fromDatastore(name string, ds pbsclient.Datastore, mountStatus string, diags *diag.Diagnostics) {
	switch backend := ds.BackendType(); backend {
	case pbsclient.BackendFilesystem:
		m.Backend = types.ObjectNull(datastoreBackendFormat.attributeTypes())
	case pbsclient.BackendS3:
		m.Backend = datastoreBackendFormat.object("backend", ds.Backend, diags)
	default:
		diags.AddError("Unsupported PBS datastore",
			fmt.Sprintf("Datastore %q keeps its chunks in a backend of type %q, which the provider does not know.",
				name, backend))
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
	m.NotificationThresholds = datastoreThresholdsFormat.object("notification-thresholds", ds.NotificationThresholds, diags)
	m.CounterResetSchedule = stringOrNull(ds.CounterResetSchedule)

	if maintenance := maintenanceType(ds.MaintenanceMode); pbsclient.IsInternalMaintenance(maintenance) {
		if m.MaintenanceMode.IsNull() || m.MaintenanceMode.IsUnknown() {
			m.MaintenanceMode = types.ObjectNull(datastoreMaintenanceFormat.attributeTypes())
		}
	} else {
		m.MaintenanceMode = datastoreMaintenanceFormat.object("maintenance-mode", ds.MaintenanceMode, diags)
	}

	for _, flag := range []*types.Bool{&m.ReuseDatastore, &m.OverwriteInUse, &m.DestroyData, &m.KeepJobConfigs} {
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
	if isS3(plan.Backend) {
		backend, err := datastoreBackendWriteFormat.format(plan.Backend)
		if err != nil {
			resp.Diagnostics.AddError("Unknown planned value",
				fmt.Sprintf("Part of backend was still unknown when the datastore was created: %s. This is a bug in "+
					"the provider.", err))
		}
		params.Set("backend", backend)
		if plan.OverwriteInUse.ValueBool() {
			params.Set("overwrite-in-use", "true")
		}
	}
	if plan.ReuseDatastore.ValueBool() {
		params.Set("reuse-datastore", "true")
	}
	// Taking over a datastore on S3, PBS replaces any maintenance mode with
	// s3-refresh while it reads the backups from the bucket, and clears it
	// after: the configured one is set when that is done.
	var maintenance url.Values
	if mode, ok := params["maintenance-mode"]; ok && isS3(plan.Backend) && plan.ReuseDatastore.ValueBool() {
		maintenance = url.Values{"maintenance-mode": mode}
		params.Del("maintenance-mode")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	var maintenanceErr error
	err := client.WithConfigLock(pbsclient.ConfigDatastores, func() error {
		if err := client.CreateDatastore(ctx, params); err != nil || maintenance == nil {
			return err
		}
		maintenanceErr = client.UpdateDatastore(ctx, name, maintenance)
		return nil
	})
	var taskErr *pbsclient.TaskError
	if errors.As(err, &taskErr) || errors.Is(err, pbsclient.ErrTaskTimeout) {
		// A task can fail after PBS saved the datastore, as when it took over
		// one on S3 and could not read all of its backups from the bucket:
		// the datastore stays, in maintenance mode s3-refresh. It is recorded
		// without tainting it, with a warning rather than an error: replacing
		// it would delete its jobs and ACL entries, and with destroy_data its
		// backups. Like any maintenance mode PBS sets itself, s3-refresh
		// leaves the planned maintenance mode in state — Terraform requires
		// the planned value — although PBS did not get it; once a refresh
		// succeeds, PBS clears the mode, and the next apply sets it. A task
		// that outlasts task_timeout, such as a long refresh, is the same.
		if ds, readErr := client.GetDatastore(ctx, name); readErr == nil {
			plan.fromDatastore(name, ds, r.mountStatus(ctx, ds, &resp.Diagnostics), &resp.Diagnostics)
			resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
			setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
			summary, outcome := "PBS datastore created, but its task failed", "failed"
			if errors.Is(err, pbsclient.ErrTaskTimeout) {
				summary, outcome = "PBS datastore created, but its task is still running", "has not finished yet"
			}
			resp.Diagnostics.AddWarning(summary,
				fmt.Sprintf("PBS's task to create datastore %q %s, but the datastore is configured, so it was "+
					"recorded in state. %s Once the datastore works, the next apply sets the rest of its "+
					"configuration. %s", name, outcome, datastoreTaskLeftover(ds, errors.Is(err, pbsclient.ErrTaskTimeout)), err))
			return
		}
	}
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
	planned := plan.MaintenanceMode
	plan.fromDatastore(name, ds, r.mountStatus(ctx, ds, &resp.Diagnostics), &resp.Diagnostics)
	if maintenanceErr != nil {
		// Terraform requires the planned maintenance mode in state; the next
		// refresh shows that PBS does not have it, and the next apply sets it.
		plan.MaintenanceMode = planned
		resp.Diagnostics.AddWarning("Unable to set the maintenance mode of the PBS datastore",
			fmt.Sprintf("PBS created datastore %q and read its backups from the bucket, but setting its maintenance "+
				"mode afterwards failed; the next apply sets it again. %s", name,
				apiErrorDetail(client, datastorePrivilege("Datastore.Modify", name), maintenanceErr)))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// datastoreTaskLeftover says what a failed create task left behind.
func datastoreTaskLeftover(ds pbsclient.Datastore, running bool) string {
	switch {
	case maintenanceType(ds.MaintenanceMode) != pbsclient.MaintenanceS3Refresh:
		return "The task log in PBS has the details."
	case running:
		return "It is in maintenance mode s3-refresh, which no backup or restore passes, while PBS reads its " +
			"backups from the bucket; PBS clears it when the task ends. The task log in PBS shows the progress."
	}
	return fmt.Sprintf("It is in maintenance mode s3-refresh, which no backup or restore passes, until reading "+
		"its backups from the bucket succeeds: fix the cause, then run `proxmox-backup-manager datastore "+
		"s3-refresh %s`, or S3 Refresh in the web interface.", ds.Name)
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
	var apiErr *pbsclient.Error
	isAPIErr := errors.As(err, &apiErr)
	s3 := isS3(plan.Backend)
	var endpoint, bucket string
	if s3 {
		attributes := plan.Backend.Attributes()
		endpoint = attributes["client"].(types.String).ValueString()
		bucket = attributes["bucket"].(types.String).ValueString()
	}
	switch {
	case pbsclient.IsAlreadyExists(err):
		return fmt.Sprintf("PBS already has a datastore %q. To manage it with Terraform, import it, with an import "+
			"block whose id is %q or with `terraform import`. %s", name, name, err)
	case s3 && isAPIErr && strings.HasPrefix(apiErr.Message, "no '") && strings.HasSuffix(apiErr.Message, "' in config"):
		return fmt.Sprintf("PBS has no S3 endpoint %q, which backend.client names. %s", endpoint, err)
	case s3 && isAPIErr && strings.HasPrefix(apiErr.Message, "failed to access bucket"):
		return fmt.Sprintf("PBS could not reach bucket %q through S3 endpoint %q. The bucket must exist — PBS does not "+
			"create it —, and the endpoint's access key must be allowed to use it; a wrong endpoint, region, "+
			"path_style or fingerprint of the pbs_s3_endpoint shows here too. %s", bucket, endpoint, err)
	case s3 && errors.As(err, &taskErr) && strings.Contains(taskErr.ExitStatus, "Bucket already contains datastore in use"):
		return fmt.Sprintf("Bucket %q already holds datastore %q, and marks it in use by a PBS, which the message "+
			"names: two PBS must never use one datastore. Only when that PBS no longer uses it, take the datastore "+
			"over, with its backups, with reuse_datastore = true and overwrite_in_use = true. %s", bucket, name, err)
	case s3 && errors.As(err, &taskErr) && isUsedDirectory(taskErr.ExitStatus):
		return fmt.Sprintf("PBS did not create datastore %q: its local cache, %s, already holds a chunk store. If it is "+
			"the cache of this datastore on S3, as a destroy without destroy_data leaves it, reuse_datastore = true "+
			"makes PBS empty it and read the backups the bucket holds under %s/ again. If it belongs to a datastore in "+
			"a directory, reuse_datastore would delete that datastore's backups: use another path. %s", name, dir, name, err)
	case s3 && errors.As(err, &taskErr):
		return fmt.Sprintf("PBS did not create datastore %q on S3; its task failed. PBS may have left its local cache "+
			"in %s, which a new attempt then needs reuse_datastore for, and its mark that the datastore is in use by "+
			"this host in the bucket, which a new attempt needs overwrite_in_use for. The task log in PBS has the "+
			"details. %s", name, dir, err)
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
		if maintenance == pbsclient.MaintenanceS3Refresh {
			resp.Diagnostics.AddWarning("PBS datastore in maintenance mode s3-refresh",
				fmt.Sprintf("PBS is reading the backups of datastore %q from its bucket, and lets no backup or restore "+
					"pass until it is done; it then clears the maintenance mode, also one set in Terraform, which the "+
					"next apply sets again. Should the mode stay, the refresh failed: the task log in PBS says why.", name))
		}
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
	var internalMode string
	if !changes.Empty() {
		err := client.WithConfigLock(pbsclient.ConfigDatastores, func() error {
			values := changes.Values()
			// PBS lets any maintenance mode replace one it set itself, such as
			// s3-refresh while it reads the backups from the bucket, or the
			// unmount of a removable datastore; leaving that early would let
			// garbage collection run on half-read indexes. The configured mode
			// waits for the next apply.
			if changesMaintenance(values) {
				if ds, err := client.GetDatastore(ctx, name); err == nil {
					if mode := maintenanceType(ds.MaintenanceMode); pbsclient.IsInternalMaintenance(mode) {
						internalMode = mode
						withoutMaintenance(values)
					}
				}
			}
			if len(values) == 0 {
				return nil
			}
			return client.UpdateDatastore(ctx, name, values)
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
	planned := plan.MaintenanceMode
	plan.fromDatastore(name, ds, r.mountStatus(ctx, ds, &resp.Diagnostics), &resp.Diagnostics)
	if internalMode != "" {
		// PBS may have cleared its mode since; Terraform requires the planned
		// value, which the next apply then sends.
		plan.MaintenanceMode = planned
		resp.Diagnostics.AddWarning("Maintenance mode of the PBS datastore not changed",
			fmt.Sprintf("PBS has datastore %q in maintenance mode %s, which it set itself and clears when it is done, so "+
				"the configured maintenance mode was not sent; the next apply after that sends it. The datastore's other "+
				"settings were changed.", name, internalMode))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// changesMaintenance reports whether an update sets or deletes the
// maintenance mode.
func changesMaintenance(values url.Values) bool {
	return values.Has("maintenance-mode") || slices.Contains(values[pbsclient.DeleteParam], "maintenance-mode")
}

// withoutMaintenance takes the maintenance mode out of an update.
func withoutMaintenance(values url.Values) {
	values.Del("maintenance-mode")
	deletes := slices.DeleteFunc(values[pbsclient.DeleteParam], func(name string) bool { return name == "maintenance-mode" })
	if len(deletes) == 0 {
		values.Del(pbsclient.DeleteParam)
	} else {
		values[pbsclient.DeleteParam] = deletes
	}
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
		onS3 := ""
		if isS3(state.Backend) {
			onS3 = " A datastore on S3 is deleted only while its bucket is reachable: PBS deletes its objects, or, " +
				"without destroy_data, its mark that the datastore is in use."
		}
		resp.Diagnostics.AddError("Unable to delete PBS datastore",
			fmt.Sprintf("PBS's task to delete datastore %q failed, and PBS keeps the datastore in its \"delete\" "+
				"maintenance mode until a deletion succeeds; destroying it again retries. A datastore in use — by "+
				"a running backup, say — cannot be deleted.%s %s", name, onS3, err))
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
