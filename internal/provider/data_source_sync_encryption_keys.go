package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &syncEncryptionKeysDataSource{}
	_ datasource.DataSourceWithConfigure = &syncEncryptionKeysDataSource{}
)

// NewSyncEncryptionKeysDataSource returns the pbs_sync_encryption_keys data
// source.
func NewSyncEncryptionKeysDataSource() datasource.DataSource { return &syncEncryptionKeysDataSource{} }

type syncEncryptionKeysDataSource struct {
	data *providerData
}

// syncEncryptionKeyDataModel is a key as the pbs_sync_encryption_keys data
// source lists it, without the key itself, which PBS never returns.
type syncEncryptionKeyDataModel struct {
	ID          types.String `tfsdk:"id"`
	Fingerprint types.String `tfsdk:"fingerprint"`
	Created     types.Int64  `tfsdk:"created"`
	Archived    types.Bool   `tfsdk:"archived"`
	ArchivedAt  types.Int64  `tfsdk:"archived_at"`
}

type syncEncryptionKeysDataSourceModel struct {
	Keys []syncEncryptionKeyDataModel `tfsdk:"keys"`
}

func (d *syncEncryptionKeysDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sync_encryption_keys"
}

func (d *syncEncryptionKeysDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the sync encryption keys of a Proxmox Backup Server, PBS 4.2 or newer, archived " +
			"ones included, without the keys themselves, which PBS never returns: those on which the provider's " +
			"user or token has `Sys.Audit`, `/system/encryption-keys/<id>` or above; PBS leaves the others out.",
		Attributes: map[string]schema.Attribute{
			"keys": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The keys, sorted by ID.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"id": schema.StringAttribute{Computed: true, MarkdownDescription: "Key ID."},
					"fingerprint": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Fingerprint of the key, which the backups it encrypted carry; null when its key file has none.",
					},
					"created": schema.Int64Attribute{
						Computed:            true,
						MarkdownDescription: "When the key was created, as a Unix time.",
					},
					"archived": schema.BoolAttribute{
						Computed:            true,
						MarkdownDescription: "Whether the key is archived: kept for decrypting, no longer used to encrypt.",
					},
					"archived_at": schema.Int64Attribute{
						Computed:            true,
						MarkdownDescription: "When the key was archived, as a Unix time; null while it is not.",
					},
				}},
			},
		},
	}
}

func (d *syncEncryptionKeysDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *syncEncryptionKeysDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	keys, _, err := d.data.client.ListEncryptionKeys(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS sync encryption keys",
			apiErrorDetail(d.data.client, "Sys.Audit on /system/encryption-keys", err))
		return
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	model := syncEncryptionKeysDataSourceModel{Keys: []syncEncryptionKeyDataModel{}}
	for _, key := range keys {
		model.Keys = append(model.Keys, syncEncryptionKeyDataModel{
			ID:          types.StringValue(key.ID),
			Fingerprint: stringOrNull(key.Fingerprint),
			Created:     types.Int64Value(key.Created),
			Archived:    types.BoolValue(key.Archived()),
			ArchivedAt:  int64OrNull(key.ArchivedAt),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
