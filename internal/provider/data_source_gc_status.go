package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &gcStatusDataSource{}
	_ datasource.DataSourceWithConfigure = &gcStatusDataSource{}
)

// NewGCStatusDataSource returns the pbs_gc_status data source.
func NewGCStatusDataSource() datasource.DataSource { return &gcStatusDataSource{} }

type gcStatusDataSource struct {
	data *providerData
}

type gcStatusModel struct {
	Store          types.String `tfsdk:"store"`
	Schedule       types.String `tfsdk:"schedule"`
	NextRun        types.Int64  `tfsdk:"next_run"`
	LastRunEndtime types.Int64  `tfsdk:"last_run_endtime"`
	LastRunState   types.String `tfsdk:"last_run_state"`
	Duration       types.Int64  `tfsdk:"duration"`
	UPID           types.String `tfsdk:"upid"`
	IndexFileCount types.Int64  `tfsdk:"index_file_count"`
	IndexDataBytes types.Int64  `tfsdk:"index_data_bytes"`
	DiskBytes      types.Int64  `tfsdk:"disk_bytes"`
	DiskChunks     types.Int64  `tfsdk:"disk_chunks"`
	RemovedBytes   types.Int64  `tfsdk:"removed_bytes"`
	RemovedChunks  types.Int64  `tfsdk:"removed_chunks"`
	PendingBytes   types.Int64  `tfsdk:"pending_bytes"`
	PendingChunks  types.Int64  `tfsdk:"pending_chunks"`
	RemovedBad     types.Int64  `tfsdk:"removed_bad"`
	StillBad       types.Int64  `tfsdk:"still_bad"`
	CacheStats     types.Object `tfsdk:"cache_stats"`
}

// gcCacheStatsTypes is the type of cache_stats.
var gcCacheStatsTypes = map[string]attr.Type{"hits": types.Int64Type, "misses": types.Int64Type}

func (d *gcStatusDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gc_status"
}

func (d *gcStatusDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	figure := func(description string) schema.Int64Attribute {
		return schema.Int64Attribute{Computed: true, MarkdownDescription: description + " `0` before the first run."}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the garbage collection status of a Proxmox Backup Server datastore: its " +
			"schedule, when it runs next, how its last run ended, and that run's figures, as the web interface " +
			"shows them under Datastore → Prune & GC. Garbage collection frees the chunks no backup uses any more; " +
			"`gc_schedule` of `pbs_datastore` sets when it runs.\n\n" +
			"Needs `Datastore.Audit` or `Datastore.Backup` on the datastore. PBS reads the status from the " +
			"datastore itself, so a removable datastore must be mounted and one in maintenance mode `offline` " +
			"cannot be read: that is an error, which a `check` block turns into a warning.",
		Attributes: map[string]schema.Attribute{
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore, such as `store1`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"schedule": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "When garbage collection runs, as a calendar event; null when it runs only when started.",
			},
			"next_run": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "When it runs next, in seconds since the Unix epoch; null without a schedule.",
			},
			"last_run_endtime": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "When the last run ended, in seconds since the Unix epoch; null before the first run.",
			},
			"last_run_state": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "How the last run ended: `OK`, `WARNINGS: <count>`, or the error; null before the " +
					"first run.",
			},
			"duration": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "How long the last run took, in seconds; null before the first run.",
			},
			"upid": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Task ID of the last run, whose log PBS keeps; null before the first run.",
			},
			"index_file_count": figure("Index files — one per backed-up archive — the last run went through."),
			"index_data_bytes": figure("Bytes those index files refer to: the size of all backups before deduplication."),
			"disk_bytes":       figure("Bytes of the chunks on disk after the last run."),
			"disk_chunks":      figure("Chunks on disk after the last run."),
			"removed_bytes":    figure("Bytes of the chunks the last run removed."),
			"removed_chunks":   figure("Chunks the last run removed."),
			"pending_bytes":    figure("Bytes of unused chunks the last run kept, because they are too recent to remove safely."),
			"pending_chunks":   figure("Unused chunks the last run kept, because they are too recent to remove safely."),
			"removed_bad":      figure("Chunks that verification marked as bad and the last run removed."),
			"still_bad":        figure("Chunks still marked as bad after the last run."),
			"cache_stats": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "How the last run's cache of chunk digests did, which `tuning.gc_cache_capacity` " +
					"of `pbs_datastore` sizes; null when PBS does not say.",
				Attributes: map[string]schema.Attribute{
					"hits":   schema.Int64Attribute{Computed: true, MarkdownDescription: "Chunks found in the cache."},
					"misses": schema.Int64Attribute{Computed: true, MarkdownDescription: "Chunks not found in the cache."},
				},
			},
		},
	}
}

func (d *gcStatusDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *gcStatusDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config gcStatusModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	store := config.Store.ValueString()
	client := d.data.client
	privilege := "Datastore.Audit or Datastore.Backup on /datastore/" + store
	status, ok, err := client.GCJobStatus(ctx, store)
	switch {
	case pbsclient.IsNotFound(err):
		resp.Diagnostics.AddAttributeError(path.Root("store"), "PBS datastore not found",
			fmt.Sprintf("PBS has no datastore %q. %s", store, err))
		return
	case pbsclient.IsDatastoreUnavailable(err):
		resp.Diagnostics.AddError("Unable to read PBS garbage collection status",
			fmt.Sprintf("PBS reads the garbage collection status from datastore %q itself, and cannot open it: a "+
				"removable datastore must be mounted, and one in maintenance mode \"offline\" cannot be read. %s", store, err))
		return
	case err != nil:
		resp.Diagnostics.AddError("Unable to read PBS garbage collection status", apiErrorDetail(client, privilege, err))
		return
	case !ok:
		resp.Diagnostics.AddError("Unable to read PBS garbage collection status",
			fmt.Sprintf("PBS answered no garbage collection status for datastore %q: %q lacks %s.", store, client.AuthID(), privilege))
		return
	}

	model := gcStatusModel{
		Store:          types.StringValue(store),
		Schedule:       stringOrNull(status.Schedule),
		NextRun:        int64OrNull(status.NextRun),
		LastRunEndtime: int64OrNull(status.LastRunEndtime),
		LastRunState:   stringOrNull(status.LastRunState),
		Duration:       int64OrNull(status.Duration),
		UPID:           stringOrNull(status.UPID),
		IndexFileCount: types.Int64Value(status.IndexFileCount),
		IndexDataBytes: types.Int64Value(status.IndexDataBytes),
		DiskBytes:      types.Int64Value(status.DiskBytes),
		DiskChunks:     types.Int64Value(status.DiskChunks),
		RemovedBytes:   types.Int64Value(status.RemovedBytes),
		RemovedChunks:  types.Int64Value(status.RemovedChunks),
		PendingBytes:   types.Int64Value(status.PendingBytes),
		PendingChunks:  types.Int64Value(status.PendingChunks),
		RemovedBad:     types.Int64Value(status.RemovedBad),
		StillBad:       types.Int64Value(status.StillBad),
		CacheStats:     types.ObjectNull(gcCacheStatsTypes),
	}
	if stats := status.CacheStats; stats != nil {
		object, diags := types.ObjectValue(gcCacheStatsTypes, map[string]attr.Value{
			"hits": types.Int64Value(stats.Hits), "misses": types.Int64Value(stats.Misses),
		})
		resp.Diagnostics.Append(diags...)
		model.CacheStats = object
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
