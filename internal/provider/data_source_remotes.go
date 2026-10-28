package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &remoteDataSource{}
	_ datasource.DataSourceWithConfigure = &remoteDataSource{}
	_ datasource.DataSource              = &remotesDataSource{}
	_ datasource.DataSourceWithConfigure = &remotesDataSource{}
)

// NewRemoteDataSource returns the pbs_remote data source.
func NewRemoteDataSource() datasource.DataSource { return &remoteDataSource{} }

// NewRemotesDataSource returns the pbs_remotes data source.
func NewRemotesDataSource() datasource.DataSource { return &remotesDataSource{} }

type remoteDataSource struct {
	data *providerData
}

type remotesDataSource struct {
	data *providerData
}

// remoteDataModel is a remote as the pbs_remote and pbs_remotes data sources
// report it. PBS never returns the password, so neither do they.
type remoteDataModel struct {
	Name         types.String `tfsdk:"name"`
	Host         types.String `tfsdk:"host"`
	Port         types.Int64  `tfsdk:"port"`
	AuthID       types.String `tfsdk:"auth_id"`
	Fingerprint  types.String `tfsdk:"fingerprint"`
	UseNodeProxy types.Bool   `tfsdk:"use_node_proxy"`
	Comment      types.String `tfsdk:"comment"`
}

type remotesDataSourceModel struct {
	Remotes []remoteDataModel `tfsdk:"remotes"`
}

func remoteData(r pbsclient.Remote) remoteDataModel {
	return remoteDataModel{
		Name:         types.StringValue(r.Name),
		Host:         types.StringValue(r.Host),
		Port:         int64OrNull(r.Port),
		AuthID:       types.StringValue(r.AuthID),
		Fingerprint:  pbsFingerprint(fingerprintOrNull(r.Fingerprint)),
		UseNodeProxy: boolOr(r.UseNodeProxy, false),
		Comment:      stringOrNull(r.Comment),
	}
}

// remoteDataAttributes are the attributes of a remote in a data source, all
// computed but the name when it is the lookup key.
func remoteDataAttributes(nameRequired bool) map[string]schema.Attribute {
	name := schema.StringAttribute{Computed: true, MarkdownDescription: "Remote name, such as `offsite`."}
	if nameRequired {
		name = schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Name of the remote to read, such as `offsite`.",
			Validators:          safeIDValidators(minSafeIDLength),
		}
	}
	return map[string]schema.Attribute{
		"name": name,
		"host": schema.StringAttribute{Computed: true, MarkdownDescription: "DNS name or IP address of the remote."},
		"port": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "Port of the remote's API; null for the default, 8007.",
		},
		"auth_id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "User or API token PBS signs in to the remote as.",
		},
		"fingerprint": schema.StringAttribute{
			Computed: true,
			MarkdownDescription: "SHA-256 fingerprint of the remote's certificate that PBS accepts, as " +
				"colon-separated lower-case hex pairs like `pbs_fingerprint`'s, whatever spelling PBS stores; null " +
				"when PBS accepts only certificates its system's CAs validate.",
		},
		"use_node_proxy": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether PBS connects to the remote through the HTTP proxy of its node configuration.",
		},
		"comment": schema.StringAttribute{Computed: true, MarkdownDescription: "Comment; null when there is none."},
	}
}

func (d *remoteDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_remote"
}

func (d *remoteDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a Proxmox Backup Server remote, without its password, which PBS never " +
			"returns. It does not contact the remote: `pbs_remote_datastores` does. Needs `Remote.Audit` on " +
			"`/remote/<name>`.",
		Attributes: remoteDataAttributes(true),
	}
}

func (d *remoteDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *remoteDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config remoteDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := config.Name.ValueString()
	remote, err := d.data.client.GetRemote(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS remote not found",
				fmt.Sprintf("PBS has no remote %q. %s", name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS remote",
			apiErrorDetail(d.data.client, remotePrivilege(remoteReadPrivilege, name), err))
		return
	}
	model := remoteData(remote)
	model.Name = types.StringValue(name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (d *remotesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_remotes"
}

func (d *remotesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the remotes of a Proxmox Backup Server, without their passwords: those on " +
			"which the provider's user or token has `Remote.Audit`, `/remote/<name>` or above; PBS leaves the others " +
			"out.",
		Attributes: map[string]schema.Attribute{
			"remotes": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The remotes, sorted by name.",
				NestedObject:        schema.NestedAttributeObject{Attributes: remoteDataAttributes(false)},
			},
		},
	}
}

func (d *remotesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *remotesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	remotes, err := d.data.client.ListRemotes(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS remotes",
			apiErrorDetail(d.data.client, strings.Replace(remoteReadPrivilege, "/<name>", "", 1), err))
		return
	}
	sort.Slice(remotes, func(i, j int) bool { return remotes[i].Name < remotes[j].Name })
	model := remotesDataSourceModel{Remotes: []remoteDataModel{}}
	for _, r := range remotes {
		model.Remotes = append(model.Remotes, remoteData(r))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
