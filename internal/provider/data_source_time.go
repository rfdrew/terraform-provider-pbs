package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &timeDataSource{}
	_ datasource.DataSourceWithConfigure = &timeDataSource{}
)

// NewTimeDataSource returns the pbs_time data source.
func NewTimeDataSource() datasource.DataSource { return &timeDataSource{} }

type timeDataSource struct {
	data *providerData
}

type timeDataSourceModel struct {
	Node      types.String `tfsdk:"node"`
	Timezone  types.String `tfsdk:"timezone"`
	Time      types.String `tfsdk:"time"`
	LocalTime types.String `tfsdk:"local_time"`
	UTCOffset types.Int64  `tfsdk:"utc_offset"`
}

func (d *timeDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_time"
}

func (d *timeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the current time of a Proxmox Backup Server node and its time zone, which " +
			"`pbs_timezone` sets. Comparing `time` with `plantimestamp()` shows whether the node's clock is off. " +
			"Anyone signed in may read it.",
		Attributes: map[string]schema.Attribute{
			"node": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Node to read: `localhost` or the node's host name. Defaults to the provider's `node`.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 63),
					stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
				},
			},
			"timezone": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Time zone of the node, such as `Europe/Vienna` or `Etc/UTC`.",
			},
			"time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current time of the node, in RFC 3339 format (UTC), to the second.",
			},
			"local_time": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The same time in the node's time zone, in RFC 3339 format with the zone's " +
					"current offset from UTC, such as `2026-11-02T11:00:00+01:00`.",
			},
			"utc_offset": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Current offset of the node's time zone from UTC, in seconds: `3600` for one hour east.",
			},
		},
	}
}

func (d *timeDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *timeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config timeDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	t, err := d.data.client.GetTime(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the time of the PBS node", apiErrorDetail(d.data.client, "", err))
		return
	}
	// PBS reports the local time as the epoch time shifted by the zone's
	// offset.
	offset := t.LocalTime - t.Time
	now := time.Unix(t.Time, 0)
	resp.Diagnostics.Append(resp.State.Set(ctx, &timeDataSourceModel{
		Node:      types.StringValue(node),
		Timezone:  stringOrNull(t.Timezone),
		Time:      types.StringValue(now.UTC().Format(time.RFC3339)),
		LocalTime: types.StringValue(now.In(time.FixedZone(t.Timezone, int(offset))).Format(time.RFC3339)),
		UTCOffset: types.Int64Value(offset),
	})...)
}
