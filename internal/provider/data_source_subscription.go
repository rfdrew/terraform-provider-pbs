package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &subscriptionDataSource{}
	_ datasource.DataSourceWithConfigure = &subscriptionDataSource{}
)

// NewSubscriptionDataSource returns the pbs_subscription data source.
func NewSubscriptionDataSource() datasource.DataSource { return &subscriptionDataSource{} }

type subscriptionDataSource struct {
	data *providerData
}

type subscriptionDataSourceModel struct {
	Node             types.String `tfsdk:"node"`
	Key              types.String `tfsdk:"key"`
	Status           types.String `tfsdk:"status"`
	Message          types.String `tfsdk:"message"`
	ServerID         types.String `tfsdk:"server_id"`
	ProductName      types.String `tfsdk:"product_name"`
	RegistrationDate types.String `tfsdk:"registration_date"`
	NextDueDate      types.String `tfsdk:"next_due_date"`
	CheckTime        types.String `tfsdk:"check_time"`
	URL              types.String `tfsdk:"url"`
}

func (d *subscriptionDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_subscription"
}

func (d *subscriptionDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	descriptions := subscriptionAttributeDescriptions()
	computed := func(name string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: descriptions[name]}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the subscription of a Proxmox Backup Server node as PBS last checked it, without " +
			"asking Proxmox: `status` is `notfound` on a node without one. `pbs_subscription` sets the key.\n\n" +
			"Anyone signed in may read the status; the key and the other details need `" +
			subscriptionReadPrivilege + "`, without which they are null.",
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
			"key": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Subscription key; null on a node without one.",
			},
			"status":            computed("status"),
			"message":           computed("message"),
			"server_id":         computed("server_id"),
			"product_name":      computed("product_name"),
			"registration_date": computed("registration_date"),
			"next_due_date":     computed("next_due_date"),
			"check_time":        computed("check_time"),
			"url": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Where to buy a subscription, or manage one, as PBS reports it.",
			},
		},
	}
}

func (d *subscriptionDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *subscriptionDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config subscriptionDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	current, err := d.data.client.GetSubscription(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the subscription of the PBS node",
			apiErrorDetail(d.data.client, subscriptionReadPrivilege, err))
		return
	}
	var m subscriptionModel
	m.fromSubscription(node, current)
	resp.Diagnostics.Append(resp.State.Set(ctx, &subscriptionDataSourceModel{
		Node:             m.Node,
		Key:              m.Key,
		Status:           m.Status,
		Message:          m.Message,
		ServerID:         m.ServerID,
		ProductName:      m.ProductName,
		RegistrationDate: m.RegistrationDate,
		NextDueDate:      m.NextDueDate,
		CheckTime:        m.CheckTime,
		URL:              stringOrNull(current.URL),
	})...)
}
