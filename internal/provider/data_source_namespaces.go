package provider

import (
	"context"
	"fmt"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &namespacesDataSource{}
	_ datasource.DataSourceWithConfigure = &namespacesDataSource{}
)

// NewNamespacesDataSource returns the pbs_namespaces data source.
func NewNamespacesDataSource() datasource.DataSource { return &namespacesDataSource{} }

type namespacesDataSource struct {
	data *providerData
}

type namespacesDataSourceModel struct {
	Store      types.String `tfsdk:"store"`
	Parent     types.String `tfsdk:"parent"`
	MaxDepth   types.Int64  `tfsdk:"max_depth"`
	Namespaces types.List   `tfsdk:"namespaces"`
}

func (d *namespacesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_namespaces"
}

func (d *namespacesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the namespaces of a Proxmox Backup Server datastore, or those below one of " +
			"them. PBS lists only the namespaces the provider has `Datastore.Audit`, `Datastore.Modify` or " +
			"`Datastore.Backup` on. A removable datastore must be mounted, and a datastore in maintenance mode " +
			"`offline` cannot be read.",
		Attributes: map[string]schema.Attribute{
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore, such as `store1`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"parent": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "List only the namespaces below this one, such as `dept1`; it must exist. " +
					"Those below the datastore's root when left out.",
				Validators: namespaceValidators(),
			},
			"max_depth": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many levels below `parent` to list, from `1`, its children only, to " +
					"`7`; all of them when left out. Namespaces nest at most 7 levels deep.",
				Validators: []validator.Int64{int64validator.Between(1, maxNamespaceDepth)},
			},
			"namespaces": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				MarkdownDescription: "The namespaces below `parent`, or below the root, each with its parents, such " +
					"as `dept1/hosts`, sorted. Neither `parent` nor the root is in the list.",
			},
		},
	}
}

func (d *namespacesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *namespacesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config namespacesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	store, parent := config.Store.ValueString(), config.Parent.ValueString()
	client := d.data.client
	privilege := namespaceAuditPrivilege(store, parent)

	// PBS lists a parent that does not exist as if it did, with nothing
	// below it; a typo in parent would read as an empty list.
	if parent != "" {
		exists, err := client.NamespaceExists(ctx, store, parent)
		if err != nil {
			addNamespacesError(&resp.Diagnostics, client, store, privilege, err)
			return
		}
		if !exists {
			resp.Diagnostics.AddAttributeError(path.Root("parent"), "PBS namespace not found",
				fmt.Sprintf("Datastore %q has no namespace %q, or the provider may not see it: that needs %s.",
					store, parent, privilege))
			return
		}
	}

	maxDepth := -1
	if !config.MaxDepth.IsNull() {
		maxDepth = int(config.MaxDepth.ValueInt64())
	}
	listed, err := client.ListNamespaces(ctx, store, parent, maxDepth)
	if err != nil {
		addNamespacesError(&resp.Diagnostics, client, store, privilege, err)
		return
	}
	namespaces := make([]string, 0, len(listed))
	for _, ns := range listed {
		// PBS lists the parent, or the root, first.
		if ns != parent && ns != "" {
			namespaces = append(namespaces, ns)
		}
	}
	slices.Sort(namespaces)
	list, diags := types.ListValueFrom(ctx, types.StringType, namespaces)
	resp.Diagnostics.Append(diags...)
	config.Namespaces = list
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// addNamespacesError reports a failed list of namespaces.
func addNamespacesError(diags *diag.Diagnostics, client *pbsclient.Client, store, privilege string, err error) {
	switch {
	case pbsclient.IsNotFound(err):
		diags.AddAttributeError(path.Root("store"), "PBS datastore not found", fmt.Sprintf("PBS has no datastore %q. %s", store, err))
	case pbsclient.IsDatastoreUnavailable(err):
		diags.AddError("Unable to list PBS namespaces",
			fmt.Sprintf("PBS cannot open datastore %q: a removable datastore must be mounted, and one in "+
				"maintenance mode \"offline\" cannot be read. %s", store, err))
	default:
		diags.AddError("Unable to list PBS namespaces", apiErrorDetail(client, privilege, err))
	}
}
