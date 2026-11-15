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
	_ datasource.DataSource              = &dnsDataSource{}
	_ datasource.DataSourceWithConfigure = &dnsDataSource{}
)

// NewDNSDataSource returns the pbs_dns data source.
func NewDNSDataSource() datasource.DataSource { return &dnsDataSource{} }

type dnsDataSource struct {
	data *providerData
}

// dnsDataSourceModel is the node's DNS settings as the pbs_dns data source
// reports them: the resource's dnsModel without its id. The other lines of
// /etc/resolv.conf, which PBS returns as options, and the file's digest are
// left out, as the resource leaves them out.
type dnsDataSourceModel struct {
	Node   types.String `tfsdk:"node"`
	Search types.String `tfsdk:"search"`
	DNS1   types.String `tfsdk:"dns1"`
	DNS2   types.String `tfsdk:"dns2"`
	DNS3   types.String `tfsdk:"dns3"`
}

func (d *dnsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dns"
}

func (d *dnsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	nameserver := func(which, lines string) schema.StringAttribute {
		return schema.StringAttribute{
			Computed: true,
			MarkdownDescription: "IP address of the node's " + which + " nameserver, from the " + which +
				" `nameserver` line; null when there " + lines + ".",
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the DNS settings of a Proxmox Backup Server node — its search domain and up to " +
			"three nameservers —, as PBS reads them from `/etc/resolv.conf`; `pbs_dns` manages them. The file is " +
			"read as it is: where systemd-resolved or a container runtime provides it, the nameservers are theirs, " +
			"such as systemd-resolved's `127.0.0.53`. PBS reads only the first domain of the last `search` or " +
			"`domain` line and the first three nameservers, without the zone of a link-local one, such as " +
			"`%eth0`. Reading works where Docker or Kubernetes mounts `/etc/resolv.conf`, where `pbs_dns` cannot " +
			"change it.\n\n" +
			"Needs `" + dnsReadPrivilege + "`.",
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
			"search": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Search domain of the node, such as `example.org`: the first domain of the last " +
					"`search` or `domain` line of `/etc/resolv.conf`; null when there is none.",
			},
			"dns1": nameserver("first", "is none"),
			"dns2": nameserver("second", "are fewer"),
			"dns3": nameserver("third", "are fewer"),
		},
	}
}

func (d *dnsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *dnsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config dnsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	// PBS reads the file without writing it, so this works where it is a
	// mount point; a missing file is a plain 400, "unable to read
	// "/etc/resolv.conf" - No such file or directory (os error 2)", which
	// goes through as it is.
	dns, err := d.data.client.GetDNS(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the DNS settings of the PBS node",
			apiErrorDetail(d.data.client, dnsReadPrivilege, err))
		return
	}
	var m dnsModel
	m.fromDNS(node, dns)
	resp.Diagnostics.Append(resp.State.Set(ctx, &dnsDataSourceModel{
		Node:   m.Node,
		Search: m.Search,
		DNS1:   m.DNS1,
		DNS2:   m.DNS2,
		DNS3:   m.DNS3,
	})...)
}
