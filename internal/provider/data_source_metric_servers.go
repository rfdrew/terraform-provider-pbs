package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &metricServersDataSource{}
	_ datasource.DataSourceWithConfigure = &metricServersDataSource{}
)

// NewMetricServersDataSource returns the pbs_metric_servers data source.
func NewMetricServersDataSource() datasource.DataSource { return &metricServersDataSource{} }

type metricServersDataSource struct {
	data *providerData
}

// metricServerDataModel is a metric server of either type; the attributes
// of the other type are null.
type metricServerDataModel struct {
	Name         types.String `tfsdk:"name"`
	Type         types.String `tfsdk:"type"`
	Enable       types.Bool   `tfsdk:"enable"`
	Comment      types.String `tfsdk:"comment"`
	URL          types.String `tfsdk:"url"`
	Organization types.String `tfsdk:"organization"`
	Bucket       types.String `tfsdk:"bucket"`
	MaxBodySize  types.Int64  `tfsdk:"max_body_size"`
	VerifyTLS    types.Bool   `tfsdk:"verify_tls"`
	Host         types.String `tfsdk:"host"`
	MTU          types.Int64  `tfsdk:"mtu"`
}

type metricServersDataSourceModel struct {
	Servers []metricServerDataModel `tfsdk:"servers"`
}

func (d *metricServersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_metric_servers"
}

func (d *metricServersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	httpOnly := func(description string) string { return description + " Null for a UDP server." }
	udpOnly := func(description string) string { return description + " Null for an HTTP server." }
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the metric servers of a Proxmox Backup Server — the InfluxDB servers it sends " +
			"its metrics to, over HTTP or UDP — with their settings, but without tokens, which PBS never returns. " +
			"Needs `" + metricServerReadPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"servers": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The metric servers of both types, sorted by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Metric server name.",
					},
					"type": schema.StringAttribute{
						Computed: true,
						MarkdownDescription: "Type of the server: `" + pbsclient.MetricServerTypeInfluxDBHTTP + "` " +
							"(`pbs_metric_server_influxdb_http`) or `" + pbsclient.MetricServerTypeInfluxDBUDP + "` " +
							"(`pbs_metric_server_influxdb_udp`).",
					},
					"enable": schema.BoolAttribute{
						Computed:            true,
						MarkdownDescription: "Whether PBS sends its metrics to the server.",
					},
					"comment": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Comment; null when there is none.",
					},
					"url": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: httpOnly("Base URL of the InfluxDB server."),
					},
					"organization": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: httpOnly("InfluxDB organization; `" + pbsclient.DefaultInfluxDBOrganization + "` when the server sets none."),
					},
					"bucket": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: httpOnly("InfluxDB bucket; `" + pbsclient.DefaultInfluxDBBucket + "` when the server sets none."),
					},
					"max_body_size": schema.Int64Attribute{
						Computed:            true,
						MarkdownDescription: httpOnly("Most bytes of metrics PBS sends in one request."),
					},
					"verify_tls": schema.BoolAttribute{
						Computed:            true,
						MarkdownDescription: httpOnly("Whether PBS verifies the TLS certificate of an `https://` URL."),
					},
					"host": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: udpOnly("Address of the UDP listener, `<host>:<port>`."),
					},
					"mtu": schema.Int64Attribute{
						Computed:            true,
						MarkdownDescription: udpOnly("Largest datagram PBS sends, in bytes."),
					},
				}},
			},
		},
	}
}

func (d *metricServersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *metricServersDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	client := d.data.client
	httpServers, err := client.ListInfluxDBHTTPServers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS InfluxDB HTTP metric servers", apiErrorDetail(client, metricServerReadPrivilege, err))
		return
	}
	udpServers, err := client.ListInfluxDBUDPServers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS InfluxDB UDP metric servers", apiErrorDetail(client, metricServerReadPrivilege, err))
		return
	}

	model := metricServersDataSourceModel{Servers: []metricServerDataModel{}}
	for _, s := range httpServers {
		model.Servers = append(model.Servers, metricServerDataModel{
			Name:         types.StringValue(s.Name),
			Type:         types.StringValue(pbsclient.MetricServerTypeInfluxDBHTTP),
			Enable:       boolOr(s.Enable, true),
			Comment:      stringOrNull(s.Comment),
			URL:          types.StringValue(s.URL),
			Organization: stringOr(s.Organization, pbsclient.DefaultInfluxDBOrganization),
			Bucket:       stringOr(s.Bucket, pbsclient.DefaultInfluxDBBucket),
			MaxBodySize:  int64Or(s.MaxBodySize, pbsclient.DefaultInfluxDBMaxBodySize),
			VerifyTLS:    boolOr(s.VerifyTLS, true),
			Host:         types.StringNull(),
			MTU:          types.Int64Null(),
		})
	}
	for _, s := range udpServers {
		model.Servers = append(model.Servers, metricServerDataModel{
			Name:         types.StringValue(s.Name),
			Type:         types.StringValue(pbsclient.MetricServerTypeInfluxDBUDP),
			Enable:       boolOr(s.Enable, true),
			Comment:      stringOrNull(s.Comment),
			URL:          types.StringNull(),
			Organization: types.StringNull(),
			Bucket:       types.StringNull(),
			MaxBodySize:  types.Int64Null(),
			VerifyTLS:    types.BoolNull(),
			Host:         types.StringValue(s.Host),
			MTU:          int64Or(s.MTU, pbsclient.DefaultInfluxDBMTU),
		})
	}
	// PBS lists each type in the order of its hash map.
	sort.Slice(model.Servers, func(i, j int) bool {
		return model.Servers[i].Name.ValueString() < model.Servers[j].Name.ValueString()
	})
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
