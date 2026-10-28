package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The scan data sources have PBS sign in to a remote and list what its auth
// ID may see there: they are the way to check, before a sync job runs, that
// a remote's host, port, fingerprint and credentials work.

var (
	_ datasource.DataSource              = &remoteDatastoresDataSource{}
	_ datasource.DataSourceWithConfigure = &remoteDatastoresDataSource{}
	_ datasource.DataSource              = &remoteNamespacesDataSource{}
	_ datasource.DataSourceWithConfigure = &remoteNamespacesDataSource{}
)

// NewRemoteDatastoresDataSource returns the pbs_remote_datastores data
// source.
func NewRemoteDatastoresDataSource() datasource.DataSource { return &remoteDatastoresDataSource{} }

// NewRemoteNamespacesDataSource returns the pbs_remote_namespaces data
// source.
func NewRemoteNamespacesDataSource() datasource.DataSource { return &remoteNamespacesDataSource{} }

type remoteDatastoresDataSource struct {
	data *providerData
}

type remoteNamespacesDataSource struct {
	data *providerData
}

type remoteDatastoresDataSourceModel struct {
	Remote     types.String               `tfsdk:"remote"`
	Datastores []remoteDatastoreDataModel `tfsdk:"datastores"`
}

type remoteDatastoreDataModel struct {
	Store           types.String `tfsdk:"store"`
	Comment         types.String `tfsdk:"comment"`
	MaintenanceMode types.Object `tfsdk:"maintenance_mode"`
	MountStatus     types.String `tfsdk:"mount_status"`
	BackendType     types.String `tfsdk:"backend_type"`
}

type remoteNamespacesDataSourceModel struct {
	Remote     types.String               `tfsdk:"remote"`
	Store      types.String               `tfsdk:"store"`
	Namespaces []remoteNamespaceDataModel `tfsdk:"namespaces"`
}

type remoteNamespaceDataModel struct {
	NS      types.String `tfsdk:"ns"`
	Comment types.String `tfsdk:"comment"`
}

// remoteMaintenanceTypes is the type of maintenance_mode.
var remoteMaintenanceTypes = map[string]attr.Type{"type": types.StringType, "message": types.StringType}

// remoteMaintenanceMode is maintenance_mode for the property string a scan
// reports; null when there is none.
func remoteMaintenanceMode(mode string, diags *diag.Diagnostics) types.Object {
	if mode == "" {
		return types.ObjectNull(remoteMaintenanceTypes)
	}
	parsed, err := pbsclient.ParsePropertyString(mode, "type")
	if err != nil {
		diags.AddWarning("Unexpected maintenance mode",
			fmt.Sprintf("The remote reported a maintenance mode the provider cannot read, %q: %s", mode, err))
		return types.ObjectNull(remoteMaintenanceTypes)
	}
	message := types.StringNull()
	if m, ok := parsed["message"]; ok {
		message = types.StringValue(m)
	}
	object, d := types.ObjectValue(remoteMaintenanceTypes, map[string]attr.Value{
		"type":    stringOrNull(parsed["type"]),
		"message": message,
	})
	diags.Append(d...)
	return object
}

// remoteAttribute is the remote a scan data source names.
func remoteAttribute() schema.StringAttribute {
	return schema.StringAttribute{
		Required:            true,
		MarkdownDescription: "Name of the remote to scan, such as the `name` of a `pbs_remote`.",
		Validators:          safeIDValidators(minSafeIDLength),
	}
}

// remoteScanErrorDetail explains a failed scan: PBS answers 500 when it
// cannot reach the remote or sign in there.
func remoteScanErrorDetail(client *pbsclient.Client, name string, err error) string {
	var apiErr *pbsclient.Error
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusInternalServerError {
		return fmt.Sprintf("PBS could not reach remote %q or sign in to it. Check its host and port, its "+
			"fingerprint, which must match the remote's certificate when it is set, and that its auth_id and "+
			"password are valid on the remote, and that the auth ID may see the datastore there. %s", name, err)
	}
	return apiErrorDetail(client, remotePrivilege(remoteReadPrivilege, name), err)
}

func (d *remoteDatastoresDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_remote_datastores"
}

func (d *remoteDatastoresDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the datastores of a remote: PBS signs in to the remote with its credentials " +
			"and lists the datastores its `auth_id` may see there. Reading it fails when the remote cannot be " +
			"reached or refuses the credentials, so it doubles as a check of a `pbs_remote` — for one in the same " +
			"configuration, refer to its `name`, so that the scan waits for it. Needs `Remote.Audit` on " +
			"`/remote/<remote>`.",
		Attributes: map[string]schema.Attribute{
			"remote": remoteAttribute(),
			"datastores": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The remote's datastores, sorted by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"store":   schema.StringAttribute{Computed: true, MarkdownDescription: "Datastore name, as `remote_store` of a `pbs_sync_job` takes it."},
					"comment": schema.StringAttribute{Computed: true, MarkdownDescription: "Comment; null when there is none."},
					"maintenance_mode": schema.SingleNestedAttribute{
						Computed:            true,
						MarkdownDescription: "The datastore's maintenance mode; null when there is none.",
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "`read-only`, `offline`, or a mode PBS sets itself: `delete`, `unmount` or `s3-refresh`.",
							},
							"message": schema.StringAttribute{Computed: true, MarkdownDescription: "Message; null when there is none."},
						},
					},
					"mount_status": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "`mounted` or `notmounted` for a removable datastore, `nonremovable` for any other.",
					},
					"backend_type": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "`filesystem`, or `s3` for a datastore on S3.",
					},
				}},
			},
		},
	}
}

func (d *remoteDatastoresDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *remoteDatastoresDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config remoteDatastoresDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := config.Remote.ValueString()
	datastores, err := d.data.client.ScanRemoteDatastores(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("remote"), "PBS remote not found",
				fmt.Sprintf("PBS has no remote %q. %s", name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to scan PBS remote", remoteScanErrorDetail(d.data.client, name, err))
		return
	}
	sort.Slice(datastores, func(i, j int) bool { return datastores[i].Store < datastores[j].Store })

	config.Datastores = []remoteDatastoreDataModel{}
	for _, ds := range datastores {
		config.Datastores = append(config.Datastores, remoteDatastoreDataModel{
			Store:           types.StringValue(ds.Store),
			Comment:         stringOrNull(ds.Comment),
			MaintenanceMode: remoteMaintenanceMode(ds.Maintenance, &resp.Diagnostics),
			MountStatus:     stringOr(ds.MountStatus, "nonremovable"),
			BackendType:     stringOr(ds.BackendType, "filesystem"),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

func (d *remoteNamespacesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_remote_namespaces"
}

func (d *remoteNamespacesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the namespaces of a datastore on a remote: PBS signs in to the remote with its " +
			"credentials and lists the namespaces of the datastore its `auth_id` may see there, the root " +
			"namespace among them. Like `pbs_remote_datastores`, reading it fails when the remote cannot be " +
			"reached, refuses the credentials, or has no such datastore. Needs `Remote.Audit` on `/remote/<remote>`.",
		Attributes: map[string]schema.Attribute{
			"remote": remoteAttribute(),
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore on the remote.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"namespaces": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The namespaces, sorted by path, so that each comes after its parent: the root " +
					"namespace first, when the auth ID may see it.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"ns": schema.StringAttribute{
						Computed: true,
						MarkdownDescription: "The namespace, such as `dept1/hosts`; an empty string for the root " +
							"namespace, which `remote_ns` of a `pbs_sync_job` takes as left out.",
					},
					"comment": schema.StringAttribute{Computed: true, MarkdownDescription: "Comment; null when there is none."},
				}},
			},
		},
	}
}

func (d *remoteNamespacesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *remoteNamespacesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config remoteNamespacesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := config.Remote.ValueString()
	namespaces, err := d.data.client.ScanRemoteNamespaces(ctx, name, config.Store.ValueString())
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("remote"), "PBS remote not found",
				fmt.Sprintf("PBS has no remote %q. %s", name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to scan PBS remote", remoteScanErrorDetail(d.data.client, name, err))
		return
	}
	sort.Slice(namespaces, func(i, j int) bool { return namespaces[i].NS < namespaces[j].NS })

	config.Namespaces = []remoteNamespaceDataModel{}
	for _, ns := range namespaces {
		config.Namespaces = append(config.Namespaces, remoteNamespaceDataModel{
			NS:      types.StringValue(ns.NS),
			Comment: stringOrNull(ns.Comment),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
