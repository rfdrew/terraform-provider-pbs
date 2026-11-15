package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &datastoreStatusDataSource{}
	_ datasource.DataSourceWithConfigure = &datastoreStatusDataSource{}
)

// NewDatastoreStatusDataSource returns the pbs_datastore_status data source.
func NewDatastoreStatusDataSource() datasource.DataSource { return &datastoreStatusDataSource{} }

type datastoreStatusDataSource struct {
	data *providerData
}

type datastoreStatusModel struct {
	Store             types.String `tfsdk:"store"`
	MountStatus       types.String `tfsdk:"mount_status"`
	BackendType       types.String `tfsdk:"backend_type"`
	Total             types.Int64  `tfsdk:"total"`
	Used              types.Int64  `tfsdk:"used"`
	Avail             types.Int64  `tfsdk:"avail"`
	EstimatedFullDate types.Int64  `tfsdk:"estimated_full_date"`
	Error             types.String `tfsdk:"error"`
	CountBackups      types.Bool   `tfsdk:"count_backups"`
	Counts            types.Object `tfsdk:"counts"`
	S3Statistics      types.Object `tfsdk:"s3_statistics"`
}

// backupTypeCountsTypes is the type of each backup type of counts, and
// backupCountsTypes that of counts.
var (
	backupTypeCountsTypes = map[string]attr.Type{"groups": types.Int64Type, "snapshots": types.Int64Type}
	backupCountsTypes     = map[string]attr.Type{
		"vm":   types.ObjectType{AttrTypes: backupTypeCountsTypes},
		"ct":   types.ObjectType{AttrTypes: backupTypeCountsTypes},
		"host": types.ObjectType{AttrTypes: backupTypeCountsTypes},
	}
)

// s3StatisticsTypes is the type of s3_statistics.
var s3StatisticsTypes = map[string]attr.Type{
	"get": types.Int64Type, "put": types.Int64Type, "post": types.Int64Type, "head": types.Int64Type,
	"delete": types.Int64Type, "uploaded": types.Int64Type, "downloaded": types.Int64Type,
}

func (d *datastoreStatusDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore_status"
}

func (d *datastoreStatusDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	count := func(description string) schema.Int64Attribute {
		return schema.Int64Attribute{Computed: true, MarkdownDescription: description}
	}
	backupType := func(description string) schema.SingleNestedAttribute {
		return schema.SingleNestedAttribute{
			Computed:            true,
			MarkdownDescription: description,
			Attributes: map[string]schema.Attribute{
				"groups": count("Backup groups — one per backup ID in each namespace — with at least one snapshot; " +
					"`0` when there are none."),
				"snapshots": count("Snapshots in those groups; `0` when there are none."),
			},
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads how full a Proxmox Backup Server datastore is: the size, use and free space " +
			"of the file system it is on, as the dashboard of the web interface shows them, and when PBS expects it " +
			"to be full. The figures need `Datastore.Audit` or `Datastore.Backup` on the datastore; with a " +
			"privilege on one of its namespaces only, they are null.\n\n" +
			"A removable datastore that is not mounted has no figures either, and a datastore PBS cannot open — " +
			"in maintenance mode `offline`, say — has `error` instead; reading such a datastore is not an error.\n\n" +
			"For a datastore on S3, `s3_statistics` has the requests PBS made to its bucket and the bytes it moved; " +
			"with `count_backups`, `counts` has how many backup groups and snapshots the datastore holds. PBS " +
			"answers them in one more call, which, like the figures, needs `Datastore.Audit` or `Datastore.Backup` " +
			"on the datastore.",
		Attributes: map[string]schema.Attribute{
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore, such as `store1`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"count_backups": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Whether to count the backup groups and snapshots of the datastore, for `counts`. " +
					"PBS then goes through every namespace, backup group and snapshot of the datastore on disk — in " +
					"its local cache for a datastore on S3, without requests to the bucket — before it answers, which " +
					"takes the longer the more backups the datastore holds. The provider's `request_timeout` bounds " +
					"that wait: a datastore with very many snapshots may need a longer one. The datastore's summary in " +
					"the web interface, while open, counts them every five seconds. Defaults to `false`, which leaves " +
					"`counts` null.",
			},
			"mount_status": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Whether a removable datastore is mounted: `mounted` or `notmounted`; " +
					"`nonremovable` for any other datastore.",
			},
			"backend_type": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Where the datastore keeps its chunks: `filesystem` or `s3`. PBS reports it with " +
					"the figures from 4.1.6; on older releases, the provider reads it from the datastore's " +
					"configuration, which needs `Datastore.Audit` on the datastore, and it is null without that.",
			},
			"total": schema.Int64Attribute{
				Computed: true,
				MarkdownDescription: "Size of the file system the datastore is on, in bytes; for a datastore on S3, " +
					"that of its local cache.",
			},
			"used": schema.Int64Attribute{
				Computed: true,
				MarkdownDescription: "Bytes in use on that file system, by the datastore and anything else on it. " +
					"Pruned backups keep their space until garbage collection frees it.",
			},
			"avail": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Bytes free for the datastore on that file system.",
			},
			"estimated_full_date": schema.Int64Attribute{
				Computed: true,
				MarkdownDescription: "When PBS expects the datastore to be full, in seconds since the Unix epoch, from " +
					"the trend of its use over the last month: `0` when its use does not change, and a time in the " +
					"past when it shrinks. Null until PBS has seven half-hour samples of its use, a few hours after " +
					"it starts tracking the datastore; early estimates are rough.",
			},
			"error": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Why PBS could not open the datastore; null when it could.",
			},
			"counts": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "How many backup groups, and snapshots in them, the datastore holds in all its " +
					"namespaces, by backup type, as the datastore's summary in the web interface shows them. Groups " +
					"without snapshots are not counted, and a snapshot still being written is. With " +
					"`Datastore.Backup` but not `Datastore.Audit` on the datastore, PBS counts, outside namespaces " +
					"where the provider has `Datastore.Audit` or `Datastore.Read`, only the groups it owns: a user's " +
					"own and its API tokens', an API token's own. A group or snapshot removed while PBS counts — by a " +
					"prune, a sync or the deletion of a namespace — fails the read, which a `check` block turns into " +
					"a warning. Null without `count_backups`, and when the figures are null.",
				Attributes: map[string]schema.Attribute{
					"vm":   backupType("Backups of virtual machines."),
					"ct":   backupType("Backups of containers."),
					"host": backupType("Backups of hosts, made with `proxmox-backup-client`."),
				},
			},
			"s3_statistics": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "For a datastore on S3, the requests PBS has made to its bucket and the bytes it " +
					"has moved since the counters were last reset — by `counter_reset_schedule` of `pbs_datastore`, " +
					"or with `proxmox-backup-manager s3 endpoint reset-counters` — as the datastore's summary in the " +
					"web interface shows them: the counters `notification_thresholds` compares with its thresholds. " +
					"They include the requests of creating the datastore, and those of `pbs_s3_endpoint_check` with " +
					"the datastore's name as `store_prefix`. PBS counts a request once however often it retries it, " +
					"whatever the object store answers, and keeps the counters on disk across restarts, also for a " +
					"datastore deleted and created again with the same name, endpoint and bucket. Null for a " +
					"datastore on a file system, on PBS before 4.1.7, and when the figures are null.",
				Attributes: map[string]schema.Attribute{
					"get":        count("`GET` requests, which restores, verification, garbage collection and S3 refreshes make."),
					"put":        count("`PUT` requests, which backups and syncs make."),
					"post":       count("`POST` requests, which garbage collection makes to delete chunks in bulk."),
					"head":       count("`HEAD` requests, which checks of objects make."),
					"delete":     count("`DELETE` requests."),
					"uploaded":   count("Bytes uploaded to the bucket, in the bodies of the requests."),
					"downloaded": count("Bytes downloaded from the bucket, in the bodies of the answers."),
				},
			},
		},
	}
}

func (d *datastoreStatusDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *datastoreStatusDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config datastoreStatusModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	store := config.Store.ValueString()
	client := d.data.client
	usage, err := client.ListDatastoreUsage(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read PBS datastore usage", apiErrorDetail(client, "", err))
		return
	}
	for _, u := range usage {
		if u.Store != store {
			continue
		}
		model := datastoreStatusModel{
			Store:             types.StringValue(store),
			MountStatus:       stringOrNull(u.MountStatus),
			BackendType:       stringOrNull(u.BackendType),
			Total:             int64OrNull(u.Total),
			Used:              int64OrNull(u.Used),
			Avail:             int64OrNull(u.Avail),
			EstimatedFullDate: int64OrNull(u.EstimatedFullDate),
			Error:             stringOrNull(u.Error),
		}
		d.readStatus(ctx, u, config.CountBackups, &model, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
		return
	}
	resp.Diagnostics.AddAttributeError(path.Root("store"), "PBS datastore not found",
		fmt.Sprintf("PBS lists no datastore %q: it does not exist, or the provider has no privilege on it or on "+
			"any of its namespaces — Datastore.Audit or Datastore.Backup on %s shows its figures.",
			store, "/datastore/"+store))
}

// readStatus adds to model, the datastore as the usage list has it, what the
// list leaves out: the backend type on PBS before 4.1.6, from the datastore's
// configuration; and, from the status of the datastore alone, the request
// statistics of a datastore on S3 and, with countBackups, the counts of its
// backups. The status is asked for only when the list has figures, which
// needs Datastore.Audit or Datastore.Backup on the datastore, and only when
// it adds something: s3-statistics come with PBS 4.1.7, which lists the
// backend type, and counts only with verbose, which walks the whole
// datastore (src/api2/admin/datastore.rs, status, proxmox-backup 7c86c5ad5,
// after 4.2.11).
func (d *datastoreStatusDataSource) readStatus(ctx context.Context, u pbsclient.DatastoreUsage, countBackups types.Bool, model *datastoreStatusModel, diags *diag.Diagnostics) {
	client := d.data.client
	store := u.Store
	model.CountBackups = countBackups
	model.Counts = types.ObjectNull(backupCountsTypes)
	model.S3Statistics = types.ObjectNull(s3StatisticsTypes)

	if u.BackendType == "" {
		ds, err := client.GetDatastore(ctx, store)
		switch {
		case err == nil:
			model.BackendType = types.StringValue(ds.BackendType())
		case pbsclient.IsForbidden(err), pbsclient.IsNotFound(err):
			// Without Datastore.Audit, or deleted since the list: unknown.
		default:
			diags.AddError("Unable to read PBS datastore",
				fmt.Sprintf("PBS before 4.1.6 lists datastore %q without its backend type, which the provider then "+
					"reads from its configuration, and that failed. %s", store,
					apiErrorDetail(client, datastorePrivilege("Datastore.Audit", store), err)))
			return
		}
	}

	if u.Total == nil || (u.BackendType != pbsclient.BackendS3 && !countBackups.ValueBool()) {
		return
	}
	status, err := client.DatastoreStatus(ctx, store, countBackups.ValueBool())
	switch {
	case pbsclient.IsDatastoreUnavailable(err), pbsclient.IsNotFound(err):
		// Unmounted, put into maintenance or deleted since the list: no
		// figures to add, as the list would have none either.
		return
	case err != nil:
		detail := apiErrorDetail(client, datastorePrivilege("Datastore.Audit or Datastore.Backup", store), err)
		var urlErr *url.Error
		if countBackups.ValueBool() && errors.As(err, &urlErr) && urlErr.Timeout() {
			detail = fmt.Sprintf("PBS did not answer within the provider's request_timeout: with count_backups, it "+
				"counts the backups of datastore %q before it answers, which takes the longer the more snapshots "+
				"the datastore holds. Raise request_timeout, or leave count_backups out. %s", store, detail)
		}
		diags.AddError("Unable to read PBS datastore status", detail)
		return
	}
	if stats := status.S3Statistics; stats != nil {
		model.S3Statistics = objectValue(s3StatisticsTypes, map[string]attr.Value{
			"get": types.Int64Value(stats.Get), "put": types.Int64Value(stats.Put),
			"post": types.Int64Value(stats.Post), "head": types.Int64Value(stats.Head),
			"delete": types.Int64Value(stats.Delete), "uploaded": types.Int64Value(stats.Uploaded),
			"downloaded": types.Int64Value(stats.Downloaded),
		}, diags)
	}
	if counts := status.Counts; counts != nil && countBackups.ValueBool() {
		model.Counts = objectValue(backupCountsTypes, map[string]attr.Value{
			"vm":   backupTypeCountsValue(counts.VM, diags),
			"ct":   backupTypeCountsValue(counts.CT, diags),
			"host": backupTypeCountsValue(counts.Host, diags),
		}, diags)
	}
}

// backupTypeCountsValue is the counts of one backup type: zeros for a type
// PBS answers null for, as it does when there are no backups of it.
func backupTypeCountsValue(counts *pbsclient.BackupTypeCounts, diags *diag.Diagnostics) types.Object {
	if counts == nil {
		counts = &pbsclient.BackupTypeCounts{}
	}
	return objectValue(backupTypeCountsTypes, map[string]attr.Value{
		"groups": types.Int64Value(counts.Groups), "snapshots": types.Int64Value(counts.Snapshots),
	}, diags)
}

// objectValue builds an object of the given attribute types, adding any
// error to diags.
func objectValue(attrTypes map[string]attr.Type, values map[string]attr.Value, diags *diag.Diagnostics) types.Object {
	object, d := types.ObjectValue(attrTypes, values)
	diags.Append(d...)
	return object
}
