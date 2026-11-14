package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
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
}

func (d *datastoreStatusDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore_status"
}

func (d *datastoreStatusDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads how full a Proxmox Backup Server datastore is: the size, use and free space " +
			"of the file system it is on, as the dashboard of the web interface shows them, and when PBS expects it " +
			"to be full. The figures need `Datastore.Audit` or `Datastore.Backup` on the datastore; with a " +
			"privilege on one of its namespaces only, they are null.\n\n" +
			"A removable datastore that is not mounted has no figures either, and a datastore PBS cannot open — " +
			"in maintenance mode `offline`, say — has `error` instead; reading such a datastore is not an error.\n\n" +
			"PBS answers with the figures of every datastore of the server at once, and opens each for them, but " +
			"removable ones that are not mounted. Opening a datastore takes the lock of PBS's datastore " +
			"configuration, which a task such as an S3 refresh can hold for minutes. PBS then waits 10 seconds " +
			"for the lock for each datastore, so the read can outlast the provider's `request_timeout`, and has " +
			"its refusal for the lock as the `error` of each datastore, with a warning — or, with privileges on " +
			"its namespaces only, leaves the datastore out.",
		Attributes: map[string]schema.Attribute{
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore, such as `store1`.",
				Validators:          safeIDValidators(minSafeIDLength),
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
			"total": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Size of the file system the datastore is on, in bytes.",
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
				Computed: true,
				MarkdownDescription: "Why PBS could not open the datastore, such as its refusal for the lock of " +
					"its datastore configuration while a task holds it; null when it could.",
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
		resp.Diagnostics.AddError("Unable to read PBS datastore usage", datastoreUsageFailedDetail(client, err))
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
		// PBS takes the lock in DataStore::lookup_datastore, and answers its
		// error as the entry's (src/api2/status/mod.rs:90-102,
		// pbs-datastore/src/datastore.rs:578-581; proxmox-backup 7c86c5ad5).
		if strings.Contains(u.Error, pbsclient.DatastoreConfigLockFile) {
			resp.Diagnostics.AddWarning("PBS could not open the datastore",
				fmt.Sprintf("PBS could not open datastore %q for its figures, which are null: a PBS task held the "+
					"lock of PBS's datastore configuration (%s) for longer than PBS waits for it, 10 seconds; "+
					"`error` has PBS's answer. %s", store, pbsclient.DatastoreConfigLockFile, datastoreConfigLockHolders))
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
		return
	}
	// PBS lists a datastore the caller has privileges on the namespaces of
	// only when it can open it (src/api2/status/mod.rs:75-88).
	resp.Diagnostics.AddAttributeError(path.Root("store"), "PBS datastore not found",
		fmt.Sprintf("PBS lists no datastore %q: it does not exist, or the provider has no privilege on it or on "+
			"any of its namespaces — Datastore.Audit or Datastore.Backup on %s shows its figures. With privileges "+
			"on its namespaces only, PBS also leaves out a datastore it cannot open, such as while a task holds "+
			"the lock of its datastore configuration (%s) or while it deletes the datastore.",
			store, "/datastore/"+store, pbsclient.DatastoreConfigLockFile))
}

// datastoreUsageFailedDetail explains why PBS's list of datastore usage
// failed: when the request timed out, a task that holds the lock of PBS's
// datastore configuration can be why.
func datastoreUsageFailedDetail(client *pbsclient.Client, err error) string {
	detail := apiErrorDetail(client, "", err)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		detail += " " + datastoreUsageTimeoutAdvice
	}
	return detail
}

// datastoreUsageTimeoutAdvice explains a list of datastore usage that took
// longer than the request timeout: PBS opens every datastore for it, but
// removable ones that are not mounted, each after waiting up to 10 s for the
// lock of its datastore configuration, and answers the list as a whole, with
// no refusal the client could try again (src/api2/status/mod.rs:52-102,
// pbs-datastore/src/datastore.rs:578-581; proxmox-backup 7c86c5ad5).
const datastoreUsageTimeoutAdvice = "PBS opens every datastore of the server for this call, but removable ones " +
	"that are not mounted, and waits up to 10 seconds for the lock of its datastore configuration (" +
	pbsclient.DatastoreConfigLockFile + ") to open each: while a task holds that lock, the call takes 10 seconds " +
	"per datastore, which can outlast the provider's `request_timeout`. " + datastoreConfigLockHolders
