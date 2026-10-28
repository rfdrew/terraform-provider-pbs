package provider

import (
	"context"
	"maps"
	"slices"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &notificationMatcherFieldsDataSource{}
	_ datasource.DataSourceWithConfigure = &notificationMatcherFieldsDataSource{}
)

// NewNotificationMatcherFieldsDataSource returns the
// pbs_notification_matcher_fields data source.
func NewNotificationMatcherFieldsDataSource() datasource.DataSource {
	return &notificationMatcherFieldsDataSource{}
}

type notificationMatcherFieldsDataSource struct {
	data *providerData
}

type notificationMatcherFieldsDataSourceModel struct {
	Fields []notificationMatcherFieldDataModel `tfsdk:"fields"`
}

type notificationMatcherFieldDataModel struct {
	Name   types.String                        `tfsdk:"name"`
	Values []notificationMatcherValueDataModel `tfsdk:"values"`
}

type notificationMatcherValueDataModel struct {
	Value   types.String `tfsdk:"value"`
	Comment types.String `tfsdk:"comment"`
}

func (d *notificationMatcherFieldsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_matcher_fields"
}

func (d *notificationMatcherFieldsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the metadata fields of Proxmox Backup Server notifications that a " +
			"`pbs_notification_matcher` can match in `match_field`, such as `type` or `datastore`, with the values " +
			"PBS knows for each: its notification types, datastores, media pools, job IDs and host name. A " +
			"notification may carry other values, such as those of jobs created later. Reading them needs `" +
			notificationsReadPrivilege + "`; datastores, jobs and media pools the provider's user may not see — " +
			"without `Datastore.Audit` or `Tape.Audit` on them — are left out.",
		Attributes: map[string]schema.Attribute{
			"fields": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The fields, sorted by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Computed: true,
						MarkdownDescription: "Field name, such as `type`, as `match_field` names it: " +
							"`exact:<name>=<value>`.",
					},
					"values": schema.ListNestedAttribute{
						Computed:            true,
						MarkdownDescription: "Values PBS knows for the field, sorted; an empty list when it knows none.",
						NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
							"value": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "The value, such as `gc` for `type`.",
							},
							"comment": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "What the value stands for, such as a datastore's comment; null when there is none.",
							},
						}},
					},
				}},
			},
		},
	}
}

func (d *notificationMatcherFieldsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *notificationMatcherFieldsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	client := d.data.client
	names, err := client.ListMatcherFields(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS notification matcher fields",
			apiErrorDetail(client, notificationsReadPrivilege, err))
		return
	}
	values, err := client.ListMatcherFieldValues(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS notification matcher field values",
			apiErrorDetail(client, notificationsReadPrivilege, err))
		return
	}

	// Every field PBS names, and any other a value belongs to.
	byField := map[string][]notificationMatcherValueDataModel{}
	for _, name := range names {
		byField[name] = []notificationMatcherValueDataModel{}
	}
	for _, v := range values {
		byField[v.Field] = append(byField[v.Field], notificationMatcherValueDataModel{
			Value:   types.StringValue(v.Value),
			Comment: stringOrNull(v.Comment),
		})
	}
	model := notificationMatcherFieldsDataSourceModel{Fields: make([]notificationMatcherFieldDataModel, 0, len(byField))}
	for _, name := range slices.Sorted(maps.Keys(byField)) {
		fieldValues := byField[name]
		sort.SliceStable(fieldValues, func(i, j int) bool {
			return fieldValues[i].Value.ValueString() < fieldValues[j].Value.ValueString()
		})
		model.Fields = append(model.Fields, notificationMatcherFieldDataModel{Name: types.StringValue(name), Values: fieldValues})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
