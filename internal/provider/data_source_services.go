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
	_ datasource.DataSource              = &servicesDataSource{}
	_ datasource.DataSourceWithConfigure = &servicesDataSource{}
)

// servicesPrivilege is what reading a node's services needs.
const servicesPrivilege = "Sys.Audit on /system/services"

// servicesUnknownState is what PBS reports for a state systemd does not
// show.
const servicesUnknownState = "unknown"

// NewServicesDataSource returns the pbs_services data source.
func NewServicesDataSource() datasource.DataSource { return &servicesDataSource{} }

type servicesDataSource struct {
	data *providerData
}

type servicesDataSourceModel struct {
	Node     types.String       `tfsdk:"node"`
	Services []serviceDataModel `tfsdk:"services"`
}

type serviceDataModel struct {
	Service     types.String `tfsdk:"service"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	State       types.String `tfsdk:"state"`
	UnitState   types.String `tfsdk:"unit_state"`
}

func (d *servicesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_services"
}

func (d *servicesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the system services of a Proxmox Backup Server node and their state, as the " +
			"Services panel of its interface shows them. PBS reports a fixed set of services, always in this " +
			"order: `proxmox-backup` (the API server), `proxmox-backup-proxy` (the proxy that serves the web " +
			"interface and the API on port 8007), `sshd`, `systemd-journald`, `cron`, `postfix` and `chrony`. " +
			"A service that is not installed is still listed, with `unit_state` `not-found`.\n\n" +
			"PBS asks systemd, with `systemctl show`, and leaves out a service systemd cannot show. A node " +
			"without systemd, such as PBS in a Docker container, therefore reports no services: `services` is an " +
			"empty list then, not an error.\n\n" +
			"Needs `" + servicesPrivilege + "`.",
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
			"services": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The services, in PBS's fixed order; empty on a node without systemd.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"service": computedString("ID of the service in PBS, one of those above, such as " +
						"`proxmox-backup-proxy`."),
					"name": computedString("Name of the service as PBS reports it. PBS takes it from a `Name` " +
						"property that `systemctl show` does not print, so it is the same as `service` — `sshd`, " +
						"say, not the `ssh.service` unit it is an alias of."),
					"description": computedString("Description of the unit, as systemd reports it, such as " +
						"`Proxmox Backup API Proxy Server`."),
					"state": computedString("State of the unit: systemd's sub-state, such as `running`, " +
						"`exited`, `dead` or `failed`; for a oneshot unit that is not running, the result of its " +
						"last run instead, such as `success` or `exit-code`. `unknown` when systemd reports none."),
					"unit_state": computedString("State of the unit's file, which says whether the unit starts " +
						"at boot: `enabled`, `disabled`, `static`, `masked` and so on, or `not-found` when the " +
						"unit is not installed. `unknown` when systemd reports none."),
				}},
			},
		},
	}
}

func (d *servicesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *servicesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config servicesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	services, err := d.data.client.Services(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS services", apiErrorDetail(d.data.client, servicesPrivilege, err))
		return
	}
	// PBS's order is meaningful — the services that make up PBS first — so
	// it is kept. PBS fills every property, falling back to the service's ID
	// for the name and to "unknown" for the states; the provider does the
	// same should a release leave one out.
	model := servicesDataSourceModel{
		Node:     types.StringValue(node),
		Services: []serviceDataModel{},
	}
	for _, s := range services {
		model.Services = append(model.Services, serviceDataModel{
			Service:     types.StringValue(s.Service),
			Name:        stringOr(s.Name, s.Service),
			Description: types.StringValue(s.Description),
			State:       stringOr(s.State, servicesUnknownState),
			UnitState:   stringOr(s.UnitState, servicesUnknownState),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
