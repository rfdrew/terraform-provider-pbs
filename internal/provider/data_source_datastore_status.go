package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
			"in maintenance mode `offline`, say — has `error` instead; reading such a datastore is not an error.",
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
				Computed:            true,
				MarkdownDescription: "Why PBS could not open the datastore; null when it could.",
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
		resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
		return
	}
	resp.Diagnostics.AddAttributeError(path.Root("store"), "PBS datastore not found",
		fmt.Sprintf("PBS lists no datastore %q: it does not exist, or the provider has no privilege on it or on "+
			"any of its namespaces — Datastore.Audit or Datastore.Backup on %s shows its figures.",
			store, "/datastore/"+store))
}
