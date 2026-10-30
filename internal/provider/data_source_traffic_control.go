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
	_ datasource.DataSource              = &trafficControlRuleDataSource{}
	_ datasource.DataSourceWithConfigure = &trafficControlRuleDataSource{}
	_ datasource.DataSource              = &trafficControlRulesDataSource{}
	_ datasource.DataSourceWithConfigure = &trafficControlRulesDataSource{}
)

// NewTrafficControlRuleDataSource returns the pbs_traffic_control_rule data
// source.
func NewTrafficControlRuleDataSource() datasource.DataSource { return &trafficControlRuleDataSource{} }

// NewTrafficControlRulesDataSource returns the pbs_traffic_control_rules data
// source.
func NewTrafficControlRulesDataSource() datasource.DataSource {
	return &trafficControlRulesDataSource{}
}

type trafficControlRuleDataSource struct {
	data *providerData
}

type trafficControlRulesDataSource struct {
	data *providerData
}

// trafficControlRuleDataModel is a rule as the pbs_traffic_control_rule data
// source reports it.
type trafficControlRuleDataModel struct {
	Name      types.String  `tfsdk:"name"`
	Network   types.Set     `tfsdk:"network"`
	Users     types.Set     `tfsdk:"users"`
	Timeframe types.Set     `tfsdk:"timeframe"`
	RateIn    byteSizeValue `tfsdk:"rate_in"`
	BurstIn   byteSizeValue `tfsdk:"burst_in"`
	RateOut   byteSizeValue `tfsdk:"rate_out"`
	BurstOut  byteSizeValue `tfsdk:"burst_out"`
	Comment   types.String  `tfsdk:"comment"`
}

// trafficControlRuleRatesModel is a rule as the pbs_traffic_control_rules
// data source lists it, with its current rates.
type trafficControlRuleRatesModel struct {
	trafficControlRuleDataModel
	CurrentRateIn  types.Int64 `tfsdk:"current_rate_in"`
	CurrentRateOut types.Int64 `tfsdk:"current_rate_out"`
}

type trafficControlRulesDataSourceModel struct {
	Rules []trafficControlRuleRatesModel `tfsdk:"rules"`
}

func trafficControlRuleData(rule pbsclient.TrafficControlRule, diags *diag.Diagnostics) trafficControlRuleDataModel {
	return trafficControlRuleDataModel{
		Name:      types.StringValue(rule.Name),
		Network:   stringSetOrNull(rule.Network, diags),
		Users:     stringSetOrNull(rule.Users, diags),
		Timeframe: stringSetOrNull(rule.Timeframe, diags),
		RateIn:    byteSizeOrNull(rule.RateIn),
		BurstIn:   byteSizeOrNull(rule.BurstIn),
		RateOut:   byteSizeOrNull(rule.RateOut),
		BurstOut:  byteSizeOrNull(rule.BurstOut),
		Comment:   stringOrNull(rule.Comment),
	}
}

// trafficControlRuleDataAttributes are the attributes of a rule in a data
// source, all computed but the name when it is the lookup key.
func trafficControlRuleDataAttributes(nameRequired bool) map[string]schema.Attribute {
	name := schema.StringAttribute{Computed: true, MarkdownDescription: "Rule name, such as `office`."}
	if nameRequired {
		name = schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Name of the rule to read, such as `office`.",
			Validators:          safeIDValidators(minSafeIDLength),
		}
	}
	stringSet := func(description string) schema.SetAttribute {
		return schema.SetAttribute{ElementType: types.StringType, Computed: true, MarkdownDescription: description}
	}
	byteSize := func(description string) schema.StringAttribute {
		return schema.StringAttribute{
			CustomType:          byteSizeType{},
			Computed:            true,
			MarkdownDescription: description + ", as PBS writes it, such as `10 MiB`; null when not set.",
		}
	}
	return map[string]schema.Attribute{
		"name":      name,
		"network":   stringSet("Client networks the rule applies to, in CIDR notation."),
		"users":     stringSet("Users the rule applies to; null for every client."),
		"timeframe": stringSet("Times the rule applies at; null for always."),
		"rate_in":   byteSize("Rate limit on the data PBS receives from the matching clients, in bytes per second"),
		"burst_in":  byteSize("How many bytes over `rate_in` PBS may receive at once"),
		"rate_out":  byteSize("Rate limit on the data PBS sends to the matching clients, in bytes per second"),
		"burst_out": byteSize("How many bytes over `rate_out` PBS may send at once"),
		"comment":   schema.StringAttribute{Computed: true, MarkdownDescription: "Comment; null when there is none."},
	}
}

func (d *trafficControlRuleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_traffic_control_rule"
}

func (d *trafficControlRuleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a Proxmox Backup Server traffic control rule. Needs `" +
			trafficControlReadPrivilege + "`.",
		Attributes: trafficControlRuleDataAttributes(true),
	}
}

func (d *trafficControlRuleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *trafficControlRuleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config trafficControlRuleDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := config.Name.ValueString()
	rule, err := d.data.client.GetTrafficControlRule(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS traffic control rule not found",
				fmt.Sprintf("PBS has no traffic control rule %q. %s", name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS traffic control rule",
			apiErrorDetail(d.data.client, trafficControlReadPrivilege, err))
		return
	}
	model := trafficControlRuleData(rule, &resp.Diagnostics)
	model.Name = types.StringValue(name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (d *trafficControlRulesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_traffic_control_rules"
}

func (d *trafficControlRulesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attributes := trafficControlRuleDataAttributes(false)
	attributes["current_rate_in"] = schema.Int64Attribute{
		Computed: true,
		MarkdownDescription: "Rate at which PBS receives from the rule's connections now, in bytes per second; " +
			"always `0` without `rate_in`, and for a rule PBS has not applied yet.",
	}
	attributes["current_rate_out"] = schema.Int64Attribute{
		Computed: true,
		MarkdownDescription: "Rate at which PBS sends to the rule's connections now, in bytes per second; always " +
			"`0` without `rate_out`, and for a rule PBS has not applied yet.",
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the traffic control rules of a Proxmox Backup Server, with the rates their " +
			"connections reach now, which change from one read to the next. Needs `" +
			trafficControlReadPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"rules": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The rules, sorted by name.",
				NestedObject:        schema.NestedAttributeObject{Attributes: attributes},
			},
		},
	}
}

func (d *trafficControlRulesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *trafficControlRulesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	rules, err := d.data.client.ListTrafficControlRates(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS traffic control rules",
			apiErrorDetail(d.data.client, trafficControlReadPrivilege, err))
		return
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	model := trafficControlRulesDataSourceModel{Rules: []trafficControlRuleRatesModel{}}
	for _, rule := range rules {
		model.Rules = append(model.Rules, trafficControlRuleRatesModel{
			trafficControlRuleDataModel: trafficControlRuleData(rule.TrafficControlRule, &resp.Diagnostics),
			CurrentRateIn:               types.Int64Value(rule.CurrentRateIn),
			CurrentRateOut:              types.Int64Value(rule.CurrentRateOut),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
