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
	_ datasource.DataSource              = &notificationTargetsDataSource{}
	_ datasource.DataSourceWithConfigure = &notificationTargetsDataSource{}
)

// NewNotificationTargetsDataSource returns the pbs_notification_targets data
// source.
func NewNotificationTargetsDataSource() datasource.DataSource {
	return &notificationTargetsDataSource{}
}

type notificationTargetsDataSource struct {
	data *providerData
}

type notificationTargetsDataSourceModel struct {
	Targets []notificationTargetDataModel `tfsdk:"targets"`
}

type notificationTargetDataModel struct {
	Name    types.String `tfsdk:"name"`
	Type    types.String `tfsdk:"type"`
	Origin  types.String `tfsdk:"origin"`
	Disable types.Bool   `tfsdk:"disable"`
	Comment types.String `tfsdk:"comment"`
}

func (d *notificationTargetsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_targets"
}

func (d *notificationTargetsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the notification endpoints of a Proxmox Backup Server, of every type, the " +
			"built-in `" + mailToRoot + "` included: what a `pbs_notification_matcher` may name in `target`. " +
			"Reading them needs `" + notificationsReadPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"targets": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The endpoints, sorted by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Endpoint name.",
					},
					"type": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Endpoint type: `sendmail`, `smtp`, `gotify` or `webhook`.",
					},
					"origin": schema.StringAttribute{
						Computed: true,
						MarkdownDescription: "Where the endpoint comes from: `user-created`, `builtin` or " +
							"`modified-builtin`.",
					},
					"disable": schema.BoolAttribute{
						Computed:            true,
						MarkdownDescription: "Whether the endpoint is disabled.",
					},
					"comment": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "The endpoint's comment; null when there is none.",
					},
				}},
			},
		},
	}
}

func (d *notificationTargetsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *notificationTargetsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	targets, err := d.data.client.ListNotificationTargets(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS notification targets",
			apiErrorDetail(d.data.client, notificationsReadPrivilege, err))
		return
	}
	sort.SliceStable(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })
	model := notificationTargetsDataSourceModel{Targets: make([]notificationTargetDataModel, 0, len(targets))}
	for _, t := range targets {
		model.Targets = append(model.Targets, notificationTargetDataModel{
			Name:    types.StringValue(t.Name),
			Type:    types.StringValue(t.Type),
			Origin:  stringOr(t.Origin, pbsclient.OriginUserCreated),
			Disable: boolOr(t.Disable, false),
			Comment: stringOrNull(t.Comment),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
