package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &datastoreDataSource{}
	_ datasource.DataSourceWithConfigure = &datastoreDataSource{}
	_ datasource.DataSource              = &datastoresDataSource{}
	_ datasource.DataSourceWithConfigure = &datastoresDataSource{}
)

// NewDatastoreDataSource returns the pbs_datastore data source.
func NewDatastoreDataSource() datasource.DataSource { return &datastoreDataSource{} }

// NewDatastoresDataSource returns the pbs_datastores data source.
func NewDatastoresDataSource() datasource.DataSource { return &datastoresDataSource{} }

type datastoreDataSource struct {
	data *providerData
}

type datastoresDataSource struct {
	data *providerData
}

// datastoreDataModel is a datastore as the pbs_datastore and pbs_datastores
// data sources report it.
type datastoreDataModel struct {
	Name             types.String `tfsdk:"name"`
	Path             types.String `tfsdk:"path"`
	Comment          types.String `tfsdk:"comment"`
	GCSchedule       types.String `tfsdk:"gc_schedule"`
	GCOnUnmount      types.Bool   `tfsdk:"gc_on_unmount"`
	VerifyNew        types.Bool   `tfsdk:"verify_new"`
	NotificationMode types.String `tfsdk:"notification_mode"`
	NotifyUser       types.String `tfsdk:"notify_user"`
	Notify           types.Object `tfsdk:"notify"`
	Tuning           types.Object `tfsdk:"tuning"`
	MaintenanceMode  types.Object `tfsdk:"maintenance_mode"`
	BackingDevice    types.String `tfsdk:"backing_device"`
	MountStatus      types.String `tfsdk:"mount_status"`
	BackendType      types.String `tfsdk:"backend_type"`
	// Backend, NotificationThresholds and CounterResetSchedule are for a
	// datastore on S3.
	Backend                types.Object `tfsdk:"backend"`
	NotificationThresholds types.Object `tfsdk:"notification_thresholds"`
	CounterResetSchedule   types.String `tfsdk:"counter_reset_schedule"`
}

// datastoreData records a datastore as PBS reports it, with its mount
// status, "" for unknown. Unlike the resource, it shows the maintenance modes
// PBS sets itself.
func datastoreData(ds pbsclient.Datastore, mountStatus string, diags *diag.Diagnostics) datastoreDataModel {
	return datastoreDataModel{
		Name:             types.StringValue(ds.Name),
		Path:             types.StringValue(ds.Path),
		Comment:          stringOrNull(ds.Comment),
		GCSchedule:       stringOrNull(ds.GCSchedule),
		GCOnUnmount:      boolOr(ds.GCOnUnmount, false),
		VerifyNew:        boolOr(ds.VerifyNew, false),
		NotificationMode: stringOr(ds.NotificationMode, notificationModeSystem),
		NotifyUser:       stringOrNull(ds.NotifyUser),
		Notify:           datastoreNotifyFormat.object("notify", ds.Notify, diags),
		Tuning:           datastoreTuningFormat.object("tuning", ds.Tuning, diags),
		MaintenanceMode:  datastoreMaintenanceFormat.object("maintenance-mode", ds.MaintenanceMode, diags),
		BackingDevice:    stringOrNull(ds.BackingDevice),
		MountStatus:      stringOrNull(mountStatus),
		BackendType:      types.StringValue(ds.BackendType()),
		Backend:          datastoreBackendData(ds, diags),
		NotificationThresholds: datastoreThresholdsFormat.object("notification-thresholds",
			ds.NotificationThresholds, diags),
		CounterResetSchedule: stringOrNull(ds.CounterResetSchedule),
	}
}

// datastoreBackendData is the backend of a datastore on S3, as PBS reports
// it; null for one in a directory or on a removable disk.
func datastoreBackendData(ds pbsclient.Datastore, diags *diag.Diagnostics) types.Object {
	if ds.BackendType() == pbsclient.BackendFilesystem {
		return types.ObjectNull(datastoreBackendFormat.attributeTypes())
	}
	return datastoreBackendFormat.object("backend", ds.Backend, diags)
}

// computedNested is a computed single nested attribute whose attributes are
// computed strings, numbers and booleans, described in turn.
func computedNested(description string, format propertyStringFormat, descriptions map[string]string) schema.SingleNestedAttribute {
	attributes := make(map[string]schema.Attribute, len(format.keys))
	for _, k := range format.keys {
		switch k.typ {
		case types.Int64Type:
			attributes[k.attribute] = schema.Int64Attribute{Computed: true, MarkdownDescription: descriptions[k.attribute]}
		case types.BoolType:
			attributes[k.attribute] = schema.BoolAttribute{Computed: true, MarkdownDescription: descriptions[k.attribute]}
		case byteSizeType{}:
			attributes[k.attribute] = schema.StringAttribute{
				CustomType: byteSizeType{}, Computed: true, MarkdownDescription: descriptions[k.attribute],
			}
		default:
			attributes[k.attribute] = schema.StringAttribute{Computed: true, MarkdownDescription: descriptions[k.attribute]}
		}
	}
	return schema.SingleNestedAttribute{Computed: true, MarkdownDescription: description, Attributes: attributes}
}

// datastoreDataAttributes are the attributes of a datastore in a data
// source, all computed but the name when it is the lookup key.
func datastoreDataAttributes(nameRequired bool) map[string]schema.Attribute {
	name := schema.StringAttribute{Computed: true, MarkdownDescription: "Datastore name."}
	if nameRequired {
		name = schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Name of the datastore to read, such as `store1`.",
			Validators:          safeIDValidators(minSafeIDLength),
		}
	}
	notify := func(job string) string { return "When PBS mails about " + job + ": `always`, `error` or `never`." }
	return map[string]schema.Attribute{
		"name": name,
		"path": schema.StringAttribute{
			Computed: true,
			MarkdownDescription: "Absolute path of the datastore's directory, or for a removable datastore the " +
				"directory's path on its device; for a datastore on S3 object storage, the local cache.",
		},
		"comment":     schema.StringAttribute{Computed: true, MarkdownDescription: "Comment; null when there is none."},
		"gc_schedule": schema.StringAttribute{Computed: true, MarkdownDescription: "When garbage collection runs, as a calendar event; null when it runs only when started."},
		"gc_on_unmount": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether PBS runs garbage collection on a removable datastore before it unmounts it.",
		},
		"verify_new": schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether PBS verifies every new backup."},
		"notification_mode": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "`notification-system` or `legacy-sendmail`.",
		},
		"notify_user": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "With `legacy-sendmail`, the user who gets the mails; null for `root@pam`.",
		},
		"notify": computedNested("With `legacy-sendmail`, which mails PBS sends; null when it sends its defaults.",
			datastoreNotifyFormat, map[string]string{
				"gc": notify("garbage collection"), "prune": notify("prune jobs"),
				"sync": notify("sync jobs"), "verify": notify("verify jobs"),
			}),
		"tuning": computedNested("Tuning options; null when all are at PBS's defaults, and each one left out is.",
			datastoreTuningFormat, map[string]string{
				"chunk_order":                  "`inode` or `none`.",
				"sync_level":                   "`filesystem`, `file` or `none`.",
				"gc_atime_cutoff":              "Minutes after which garbage collection treats a chunk it did not mark as unused.",
				"gc_atime_safety_check":        "Whether PBS checks that the file system updates access times.",
				"gc_cache_capacity":            "How many chunk digests garbage collection caches.",
				"default_verification_readers": "Threads that read chunks in a verification that does not set its own.",
				"default_verification_workers": "Threads that verify chunks in a verification that does not set its own.",
			}),
		"maintenance_mode": computedNested("The datastore's maintenance mode; null when there is none. Besides "+
			"`read-only` and `offline`, which are set by hand, PBS sets `unmount`, `delete` and `s3-refresh` "+
			"itself while it unmounts, deletes or refreshes the datastore.",
			datastoreMaintenanceFormat, map[string]string{
				"type":    "`read-only`, `offline`, `unmount`, `delete` or `s3-refresh`.",
				"message": "Why, as PBS shows it to clients; null when there is no message.",
			}),
		"backing_device": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "For a removable datastore, the UUID of the file system on its disk; null otherwise.",
		},
		"mount_status": schema.StringAttribute{
			Computed: true,
			MarkdownDescription: "Whether a removable datastore is mounted: `mounted` or `notmounted`; " +
				"`nonremovable` for any other datastore.",
		},
		"backend_type": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Where the datastore keeps its chunks: `filesystem` or `s3`.",
		},
		"backend": computedNested("For a datastore on S3, where its backups are; null for one in a directory or "+
			"on a removable disk.", datastoreBackendFormat, map[string]string{
			"type":           "`s3`.",
			"client":         "ID of the S3 endpoint.",
			"bucket":         "Bucket that holds the backups, under the datastore's name.",
			"max_cache_size": "Most space the local cache of chunks may take, as PBS stores it; null for the free space of `path`.",
		}),
		"notification_thresholds": computedNested("For a datastore on S3, how many requests and bytes to its "+
			"bucket make PBS send a notification; null when none do.", datastoreThresholdsFormat, map[string]string{
			"s3_get":      "Number of `GET` requests.",
			"s3_put":      "Number of `PUT` requests.",
			"s3_post":     "Number of `POST` requests.",
			"s3_head":     "Number of `HEAD` requests.",
			"s3_delete":   "Number of `DELETE` requests.",
			"s3_upload":   "Bytes uploaded, as PBS stores them.",
			"s3_download": "Bytes downloaded, as PBS stores them.",
		}),
		"counter_reset_schedule": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "For a datastore on S3, when PBS resets its request and traffic counters, as a calendar event; null for never.",
		},
	}
}

func (d *datastoreDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore"
}

func (d *datastoreDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the configuration of a Proxmox Backup Server datastore, of any kind: in a " +
			"directory, removable or on S3 object storage. Needs `Datastore.Audit` on the datastore.",
		Attributes: datastoreDataAttributes(true),
	}
}

func (d *datastoreDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *datastoreDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config datastoreDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := config.Name.ValueString()
	client := d.data.client
	ds, err := client.GetDatastore(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS datastore not found",
				fmt.Sprintf("PBS has no datastore %q. %s", name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS datastore",
			apiErrorDetail(client, datastorePrivilege("Datastore.Audit", name), err))
		return
	}
	mountStatus, err := client.DatastoreMountStatus(ctx, ds)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read whether the PBS datastore is mounted",
			apiErrorDetail(client, datastorePrivilege("Datastore.Audit", name), err))
		return
	}
	model := datastoreData(ds, mountStatus, &resp.Diagnostics)
	model.Name = types.StringValue(name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

type datastoresDataSourceModel struct {
	Datastores []datastoreDataModel `tfsdk:"datastores"`
}

func (d *datastoresDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastores"
}

func (d *datastoresDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the datastores of a Proxmox Backup Server, of every kind, with their " +
			"configuration. The list has the datastores the provider has `Datastore.Audit` on.",
		Attributes: map[string]schema.Attribute{
			"datastores": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The datastores, sorted by name.",
				NestedObject:        schema.NestedAttributeObject{Attributes: datastoreDataAttributes(false)},
			},
		},
	}
}

func (d *datastoresDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *datastoresDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	client := d.data.client
	datastores, err := client.ListDatastores(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS datastores", apiErrorDetail(client, "Datastore.Audit on /datastore/<name>", err))
		return
	}
	sort.Slice(datastores, func(i, j int) bool { return datastores[i].Name < datastores[j].Name })

	// One list has the mount status of every removable datastore.
	mountStatus := map[string]string{}
	for _, ds := range datastores {
		if ds.BackingDevice == "" {
			continue
		}
		states, err := client.ListDatastoreStates(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read whether the PBS datastores are mounted", apiErrorDetail(client, "", err))
			return
		}
		for _, state := range states {
			mountStatus[state.Store] = state.MountStatus
		}
		break
	}

	model := datastoresDataSourceModel{Datastores: []datastoreDataModel{}}
	for _, ds := range datastores {
		status := pbsclient.MountStatusNonRemovable
		if ds.BackingDevice != "" {
			status = mountStatus[ds.Name]
		}
		model.Datastores = append(model.Datastores, datastoreData(ds, status, &resp.Diagnostics))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
