package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &aptUpdatesDataSource{}
	_ datasource.DataSourceWithConfigure = &aptUpdatesDataSource{}
)

// NewAPTUpdatesDataSource returns the pbs_apt_updates data source.
func NewAPTUpdatesDataSource() datasource.DataSource { return &aptUpdatesDataSource{} }

// aptUpdatesDataSource reads what APT's cache on the node offers, without
// refreshing it; see internal/pbsclient/apt_updates.go. PBS refreshes it with
// POST /nodes/{node}/apt/update, which the provider does not send yet.
type aptUpdatesDataSource struct {
	data *providerData
}

type aptUpdatesDataSourceModel struct {
	Node    types.String         `tfsdk:"node"`
	Updates []aptUpdateDataModel `tfsdk:"updates"`
}

type aptUpdateDataModel struct {
	Package     types.String `tfsdk:"package"`
	Title       types.String `tfsdk:"title"`
	Description types.String `tfsdk:"description"`
	Arch        types.String `tfsdk:"arch"`
	Version     types.String `tfsdk:"version"`
	OldVersion  types.String `tfsdk:"old_version"`
	Origin      types.String `tfsdk:"origin"`
	Priority    types.String `tfsdk:"priority"`
	Section     types.String `tfsdk:"section"`
}

func (d *aptUpdatesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_apt_updates"
}

func (d *aptUpdatesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the package updates of a Proxmox Backup Server node, as the Updates panel of " +
			"its interface shows them: every installed package whose candidate version in APT's package cache, " +
			"the one an upgrade installs, differs from the installed one, and the packages those versions depend " +
			"on that are not installed, which an upgrade would install anew, such as the package of a new " +
			"kernel.\n\n" +
			"PBS reads APT's package cache on the node and does not refresh it: reading the data source makes no " +
			"network access, and the list is as current as the node's last `apt update`. PBS's daily update runs " +
			"one, and so does the **Refresh** button of the Updates panel; the provider cannot refresh it yet. A " +
			"container whose image removed APT's package lists, as images often do to save space, lists no " +
			"updates until `apt update` runs in it.\n\n" +
			"Needs `" + aptReadPrivilege + "`.",
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
			"updates": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The packages an upgrade would change or install, sorted by `package`, then " +
					"`arch`; empty when the node is up to date as far as its package cache knows.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"package": computedString("Name of the package, such as `proxmox-backup-server`."),
					"title":   computedString("Short description of the package; its name when it has none."),
					"description": computedString("Long description of the package, which may span several " +
						"lines; empty when it has none."),
					"arch": computedString("Architecture of the package, such as `amd64`, or `all` for one " +
						"that runs on every architecture."),
					"version": computedString("Version an upgrade installs: the candidate version in APT's " +
						"package cache."),
					"old_version": computedString("Version installed now; null for a package an upgrade would " +
						"install anew."),
					"origin": computedString("Origin of the repository that offers `version`, such as `Proxmox` or " +
						"`Debian`; `unknown` when APT does not know it."),
					"priority": computedString("Debian priority of the package, such as `optional` or " +
						"`important`; `unknown` when APT does not know it."),
					"section": computedString("Debian section of the package, such as `admin` or `libs`; " +
						"`unknown` when APT does not know it."),
				}},
			},
		},
	}
}

func (d *aptUpdatesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *aptUpdatesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config aptUpdatesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	updates, err := d.data.client.APTUpdates(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS APT updates", apiErrorDetail(d.data.client, aptReadPrivilege, err))
		return
	}
	// PBS lists the packages in the order of APT's cache. A node with
	// several architectures may list a package once for each.
	sort.SliceStable(updates, func(i, j int) bool {
		a, b := updates[i], updates[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Arch < b.Arch
	})

	model := aptUpdatesDataSourceModel{Node: types.StringValue(node), Updates: []aptUpdateDataModel{}}
	for _, u := range updates {
		model.Updates = append(model.Updates, aptUpdateDataModel{
			Package:     types.StringValue(u.Package),
			Title:       types.StringValue(u.Title),
			Description: types.StringValue(u.Description),
			Arch:        types.StringValue(u.Arch),
			Version:     types.StringValue(u.Version),
			// PBS before 4.0.20 sent "" for a package an upgrade would
			// install anew; later releases leave it out.
			OldVersion: stringOrNull(u.OldVersion),
			Origin:     types.StringValue(u.Origin),
			Priority:   types.StringValue(u.Priority),
			Section:    types.StringValue(u.Section),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
