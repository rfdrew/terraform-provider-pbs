package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &permissionsDataSource{}
	_ datasource.DataSourceWithConfigure = &permissionsDataSource{}
)

// NewPermissionsDataSource returns the pbs_permissions data source.
func NewPermissionsDataSource() datasource.DataSource { return &permissionsDataSource{} }

type permissionsDataSource struct {
	data *providerData
}

type permissionsDataSourceModel struct {
	AuthID      types.String `tfsdk:"auth_id"`
	Path        types.String `tfsdk:"path"`
	Permissions types.Map    `tfsdk:"permissions"`
}

// privilegeMapType is a map from privilege to whether it propagates.
var privilegeMapType = types.MapType{ElemType: types.BoolType}

func (d *permissionsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_permissions"
}

func (d *permissionsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the privileges a Proxmox Backup Server user or API token has, as PBS works them " +
			"out from its roles: whether a token can back up to a datastore, say. For an API token, these are " +
			"what it can actually do — the privileges of its own ACL entries that its user has too. Every user " +
			"and token may read its own; reading another's needs Sys.Audit on /access, except that a user signed " +
			"in with its password may read those of its own API tokens.\n\n" +
			"-> Before PBS 4.2.6, PBS caches privileges for up to 5 seconds and does not drop them when an ACL " +
			"entry changes. Read in the same apply that changes `pbs_acl` resources, this data source may then " +
			"still show the privileges from before.",
		Attributes: map[string]schema.Attribute{
			"auth_id": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "User ID or API token ID to read the privileges of, such as `alice@pbs!ci`. " +
					"Leave it out for the user or token the provider signs in as.",
				Validators: authIDValidators(),
			},
			"path": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Read the privileges on this path only, such as `/datastore/store1`. Leave it " +
					"out for every path with an ACL entry that applies.",
				Validators: aclPathValidators(),
			},
			"permissions": schema.MapAttribute{
				Computed:    true,
				ElementType: privilegeMapType,
				MarkdownDescription: "Privileges by path: for each path, a map from privilege, such as " +
					"`Datastore.Backup`, to whether it also applies below the path. PBS leaves out a path where the " +
					"user or token has no privilege, so test with `lookup()` or `try()`.",
			},
		},
	}
}

func (d *permissionsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *permissionsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config permissionsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := d.data.client
	permissions, err := client.Permissions(ctx, config.AuthID.ValueString(), config.Path.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read PBS permissions", permissionsErrorDetail(client, err))
		return
	}
	value, diags := types.MapValueFrom(ctx, privilegeMapType, permissions)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	config.Permissions = value
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// permissionsErrorDetail explains a failed read of privileges. Every caller
// may call GET /access/permissions, so PBS refuses to tell a caller without
// Sys.Audit on /access the privileges of another user or token itself, with
// a 400 "not allowed to list permissions of ...", not a 403; it lets a user
// signed in with its password read its own API tokens' (src/api2/access/mod.rs,
// list_permissions, proxmox-backup 7c86c5ad5, after 4.2.11).
func permissionsErrorDetail(client *pbsclient.Client, err error) string {
	if pbsclient.IsListPermissionsRefused(err) {
		return fmt.Sprintf("%q lacks Sys.Audit on /access, which reading the privileges of another user or token "+
			"needs: without it, PBS lets a user signed in with its password read only its own and those of its own "+
			"API tokens, and an API token only its own. %s", client.AuthID(), err)
	}
	return err.Error()
}
