package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &syncEncryptionKeyResource{}
	_ resource.ResourceWithConfigure   = &syncEncryptionKeyResource{}
	_ resource.ResourceWithIdentity    = &syncEncryptionKeyResource{}
	_ resource.ResourceWithImportState = &syncEncryptionKeyResource{}
	_ resource.ResourceWithModifyPlan  = &syncEncryptionKeyResource{}
)

// NewSyncEncryptionKeyResource returns the pbs_sync_encryption_key resource.
func NewSyncEncryptionKeyResource() resource.Resource { return &syncEncryptionKeyResource{} }

type syncEncryptionKeyResource struct {
	data *providerData
}

type syncEncryptionKeyModel struct {
	ID           types.String `tfsdk:"id"`
	KeyWO        types.String `tfsdk:"key_wo"`
	KeyWOVersion types.Int64  `tfsdk:"key_wo_version"`
	Archived     types.Bool   `tfsdk:"archived"`
	Fingerprint  types.String `tfsdk:"fingerprint"`
	Created      types.Int64  `tfsdk:"created"`
	ArchivedAt   types.Int64  `tfsdk:"archived_at"`
}

// Privileges the sync encryption key resources need, for error messages.
const (
	encryptionKeyReadPrivilege   = "Sys.Audit on /system/encryption-keys/<id>"
	encryptionKeyModifyPrivilege = "Sys.Modify on /system/encryption-keys/<id>"
	encryptionKeyCreatePrivilege = "Sys.Modify on /system/encryption-keys"
)

// encryptionKeyPrivilege names a privilege on the key, for errors.
func encryptionKeyPrivilege(privilege, id string) string {
	return strings.Replace(privilege, "<id>", id, 1)
}

// encryptionKeyDirectory is where PBS keeps the key files, <id>.enc each.
const encryptionKeyDirectory = "/etc/proxmox-backup/encryption-keys"

// keyFileCheck accepts a key file PBS can store: JSON with a 32-byte key in
// base64, its creation and modification times, and no password — "kdf" null
// —, as `proxmox-backup-client key create --kdf none` writes it. PBS checks
// the fingerprint, should the file have one, but a key of another length
// makes it fail without an answer.
var keyFileCheck = stringCheck{
	description: "must be a key file without a password, as `proxmox-backup-client key create --kdf none` writes it: " +
		"JSON with \"kdf\" null, \"created\", \"modified\" and \"data\", a 32-byte key in base64; convert a key " +
		"with a password with `proxmox-backup-client key change-passphrase --kdf none`",
	check: func(s string) bool {
		var file struct {
			KDF      json.RawMessage `json:"kdf"`
			Created  *string         `json:"created"`
			Modified *string         `json:"modified"`
			Data     *string         `json:"data"`
		}
		if json.Unmarshal([]byte(s), &file) != nil || file.Created == nil || file.Modified == nil || file.Data == nil {
			return false
		}
		if len(file.KDF) > 0 && string(file.KDF) != "null" {
			return false
		}
		key, err := base64.StdEncoding.DecodeString(*file.Data)
		if err != nil {
			key, err = base64.RawStdEncoding.DecodeString(*file.Data)
		}
		return err == nil && len(key) == 32
	},
}.secret()

func (r *syncEncryptionKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sync_encryption_key"
}

func (r *syncEncryptionKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server sync encryption key, from PBS 4.2: a key PBS keeps to " +
			"encrypt the backups a push sync job copies to a remote, so that the remote never sees them " +
			"unencrypted. A `pbs_sync_job` names it in `active_encryption_key`; a key a job used before, which " +
			"its backups on the remote still need, stays in its `associated_key`.\n\n" +
			"The key is either one of yours, in `key_wo` — a key file without a password, as " +
			"`proxmox-backup-client key create --kdf none` writes it — or, when `key_wo` is left out, one PBS " +
			"generates. A generated key never reaches Terraform: PBS keeps it in `" + encryptionKeyDirectory +
			"/<id>.enc`. **Keep a copy of the key outside PBS**: without it, the backups it encrypted cannot be " +
			"restored, should the server be lost.\n\n" +
			"A key cannot change: a new `key_wo_version` replaces the key, and so does a new `id`, which PBS " +
			"refuses while a sync job holds the key. To rotate the key of a sync job, create a new key, set it as " +
			"the job's `active_encryption_key`, and keep the old one, which the job's `associated_key` then holds, " +
			"for as long as backups on the remote need it: destroying it in the same apply fails, unless " +
			"`associated_key` is set without it.\n\n" +
			"`archived` retires a key: PBS encrypts nothing more with it, but keeps it for decrypting. PBS deletes " +
			"only archived keys, so destroying the resource archives the key first, should it not be. PBS refuses " +
			"to archive the active key of a sync job, and to delete a key a sync job holds as its active or an " +
			"associated key.\n\n" +
			"Managing keys needs `Sys.Modify` on `/system/encryption-keys`, or on `/system/encryption-keys/<id>` " +
			"for an existing one; reading them `Sys.Audit`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Key ID, 3 to 32 characters: letters, digits, `_`, `.` and `-`, not starting " +
					"with `.` or `-`. Sync jobs name it in `active_encryption_key` and `associated_key`. Changing it " +
					"replaces the key.",
				Validators:    safeIDValidators(minSafeIDLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"key_wo": schema.StringAttribute{
				Optional:  true,
				WriteOnly: true,
				Sensitive: true,
				MarkdownDescription: "The key, as the content of a key file without a password, such as " +
					"`file(\"sync-key.json\")` for one `proxmox-backup-client key create --kdf none sync-key.json` " +
					"wrote; PBS generates a key when left out. Write-only: Terraform passes it to PBS without " +
					"storing it in the plan or state, and PBS never returns it. PBS receives it when the key is " +
					"created. Requires `key_wo_version`, and Terraform or OpenTofu 1.11 or later.",
				Validators: []validator.String{
					stringvalidator.AlsoRequires(path.MatchRoot("key_wo_version")),
					keyFileCheck,
				},
			},
			"key_wo_version": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Version of `key_wo`, which Terraform stores in its place. Changing it replaces " +
					"the key with the one in `key_wo`; removing it, with `key_wo`, leaves the key as it is. Set on a " +
					"key that has none in state — an imported key, or one PBS generated —, it replaces the key only " +
					"when `key_wo` holds another key, as the fingerprints tell. PBS refuses to delete a key a sync job " +
					"holds, so such a key is not replaced. Requires `key_wo`.",
				Validators:    []validator.Int64{int64validator.AlsoRequires(path.MatchRoot("key_wo"))},
				PlanModifiers: []planmodifier.Int64{keyVersionPlan{}},
			},
			"archived": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether the key is archived: kept for decrypting, but no longer used to " +
					"encrypt. Defaults to `false`. PBS refuses to archive the active key of a sync job.",
			},
			"fingerprint": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Fingerprint of the key, which the backups it encrypted carry, as " +
					"`proxmox-backup-client key show` shows it for the key file.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "When the key was created, as a Unix time.",
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"archived_at": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "When the key was archived, as a Unix time; null while it is not.",
				PlanModifiers:       []planmodifier.Int64{archivedAtPlan{}},
			},
		},
	}
}

// keyVersionPlan replaces the key when key_wo_version changes from one
// version to another. Removing the pair keeps the key, as it keeps the
// secret of the other write-only pairs: replacing it would delete a key that
// backups may need, for one PBS generates. A version set where state has
// none — after an import, or on a key PBS generated — replaces the key only
// when the fingerprint of the key in key_wo differs from the key's in PBS.
type keyVersionPlan struct{}

func (keyVersionPlan) Description(_ context.Context) string {
	return "a new key_wo_version replaces the key, unless key_wo holds the key PBS has"
}

func (m keyVersionPlan) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (keyVersionPlan) PlanModifyInt64(ctx context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	if req.State.Raw.IsNull() || req.PlanValue.IsNull() || req.PlanValue.Equal(req.StateValue) {
		return
	}
	var id, key, fingerprint types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &id)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("fingerprint"), &fingerprint)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("key_wo"), &key)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !req.StateValue.IsNull() {
		resp.RequiresReplace = true
		warnKeyReplacement(&resp.Diagnostics, req.Path, id, fingerprint, false)
		return
	}
	switch {
	case key.IsNull():
		return
	case key.IsUnknown():
		// Deciding at apply, once it is known, would change the planned
		// action, which Terraform refuses.
		resp.Diagnostics.AddAttributeError(req.Path, "Key not known yet",
			"key_wo_version is set on a key whose version Terraform does not know — an imported key, or one PBS "+
				"generated —, and the provider tells by the fingerprint whether key_wo holds that key or another, "+
				"which replaces it. key_wo is not known until apply, so it cannot: give key_wo a value known at plan "+
				"time, or set key_wo_version in a later apply.")
		return
	case fingerprint.IsNull():
		resp.Diagnostics.AddAttributeWarning(req.Path, "Key not compared",
			"key_wo_version is set on a key whose version Terraform does not know, and PBS lists no fingerprint for "+
				"the key, so the provider cannot tell whether key_wo holds it. The key is left as it is; change "+
				"key_wo_version again, or the id, to replace it.")
		return
	}
	configured, err := pbsclient.KeyFileFingerprint(key.ValueString())
	if err != nil || strings.EqualFold(configured, fingerprint.ValueString()) {
		return
	}
	resp.RequiresReplace = true
	warnKeyReplacement(&resp.Diagnostics, req.Path, id, fingerprint, true)
}

// warnKeyReplacement warns that a plan replaces a key, which deletes its
// file on PBS for good. unseen tells that Terraform never held the key.
func warnKeyReplacement(diags *diag.Diagnostics, p path.Path, id, fingerprint types.String, unseen bool) {
	detail := fmt.Sprintf("This plan replaces sync encryption key %q", id.ValueString())
	if !fingerprint.IsNull() {
		detail += fmt.Sprintf(", fingerprint %s", fingerprint.ValueString())
	}
	detail += fmt.Sprintf(": destroying it deletes %s/%s.enc on PBS, and backups encrypted with it cannot be "+
		"restored without a copy of it. PBS refuses while a sync job holds the key.", encryptionKeyDirectory, id.ValueString())
	if unseen {
		detail += " Terraform never held this key — PBS generated it, or it was imported —, so that file may be the " +
			"only copy."
	}
	diags.AddAttributeWarning(p, "Replacing the key deletes it", detail)
}

// archivedAtPlan keeps archived_at from state while archived stays as it is,
// plans null for a key that is not to be archived, and leaves it unknown when
// the key is archived now.
type archivedAtPlan struct{}

func (archivedAtPlan) Description(_ context.Context) string {
	return "kept while archived does not change"
}

func (m archivedAtPlan) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (archivedAtPlan) PlanModifyInt64(ctx context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	var planned, prior types.Bool
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("archived"), &planned)...)
	if planned.IsUnknown() {
		return
	}
	if !planned.ValueBool() {
		resp.PlanValue = types.Int64Null()
		return
	}
	if req.State.Raw.IsNull() {
		return
	}
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("archived"), &prior)...)
	if prior.ValueBool() {
		resp.PlanValue = req.StateValue
	}
}

func (r *syncEncryptionKeyResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"id", "Key ID, such as `offsite-2026`."})
}

func (r *syncEncryptionKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan refuses the resource on a server older than PBS 4.2, which has
// no sync encryption keys, and warns that a new id replaces the key, which
// deletes it.
func (r *syncEncryptionKeyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	if r.data != nil && !r.data.version.AtLeast(pbs42.major, pbs42.minor, pbs42.release) {
		resp.Diagnostics.AddError("Resource needs a newer PBS",
			fmt.Sprintf("pbs_sync_encryption_key needs PBS %s or newer, but the server at %s runs PBS %s. Remove it, or "+
				"upgrade the server first.", pbs42, r.data.client.BaseURL(), r.data.version))
		return
	}
	if req.State.Raw.IsNull() {
		return
	}
	var plan, state syncEncryptionKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if !resp.Diagnostics.HasError() && !plan.ID.IsUnknown() && !plan.ID.Equal(state.ID) {
		warnKeyReplacement(&resp.Diagnostics, path.Root("id"), state.ID, state.Fingerprint, state.KeyWOVersion.IsNull())
	}
}

// fromKey records a key as PBS lists it. The ID is the one it was looked up
// by; the key and its version exist only in Terraform.
func (m *syncEncryptionKeyModel) fromKey(id string, key pbsclient.EncryptionKey) {
	m.ID = types.StringValue(id)
	m.KeyWO = types.StringNull()
	m.Archived = types.BoolValue(key.Archived())
	m.Fingerprint = stringOrNull(key.Fingerprint)
	m.Created = types.Int64Value(key.Created)
	m.ArchivedAt = int64OrNull(key.ArchivedAt)
}

// encryptionKeyErrorDetail explains a refused archiving or deletion.
func encryptionKeyErrorDetail(client *pbsclient.Client, id string, err error) string {
	if pbsclient.IsEncryptionKeyInUse(err) {
		return fmt.Sprintf("A sync job uses encryption key %q, and PBS archives no active key of a sync job and "+
			"deletes no key a sync job holds as its active or an associated key. Set another active_encryption_key "+
			"on the job, or remove the key from its associated_key, first. %s", id, err)
	}
	return apiErrorDetail(client, encryptionKeyPrivilege(encryptionKeyModifyPrivilege, id), err)
}

// setArchived archives the key or brings it back into use, as archived says,
// unless it already is. It reads the key first, since PBS only toggles, and
// toggles with the digest of that read, under the lock of the keys'
// configuration. changed reports whether it toggled.
func setArchived(ctx context.Context, client *pbsclient.Client, id string, archived bool) (changed bool, err error) {
	err = client.WithConfigLock(pbsclient.ConfigEncryptionKeys, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			key, digest, err := client.GetEncryptionKey(ctx, id)
			if err != nil {
				return err
			}
			if key.Archived() == archived {
				return nil
			}
			if err := client.ToggleEncryptionKeyArchived(ctx, id, digest); err != nil {
				return err
			}
			changed = true
			return nil
		})
	})
	return changed, err
}

func (r *syncEncryptionKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan syncEncryptionKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	key := ""
	if !plan.KeyWOVersion.IsNull() {
		var ok bool
		key, ok = writeOnlySecret(ctx, req.Config, "key", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("key_wo"), "Missing sync encryption key",
				"key_wo_version is set, but key_wo is not known.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigEncryptionKeys, func() error { return client.CreateEncryptionKey(ctx, id, key) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS sync encryption key already exists",
				fmt.Sprintf("PBS already has a sync encryption key %q. To manage it with Terraform, import it, with an "+
					"import block whose id is %q or with `terraform import`. %s", id, id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS sync encryption key", apiErrorDetail(client, encryptionKeyCreatePrivilege, err))
		return
	}

	// From here on the key exists, so it is recorded in state even when what
	// follows fails: Terraform then marks it tainted instead of losing track
	// of it.
	recordAnyway := func(summary, detail string) {
		plan.Fingerprint = types.StringNull()
		plan.Created = types.Int64Null()
		plan.ArchivedAt = types.Int64Null()
		plan.Archived = types.BoolValue(false)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError(summary, detail)
	}
	if plan.Archived.ValueBool() {
		if _, err := setArchived(ctx, client, id, true); err != nil {
			recordAnyway("Unable to archive PBS sync encryption key",
				fmt.Sprintf("PBS created sync encryption key %q, and it was recorded in state, but archiving it "+
					"failed, so it is marked tainted. %s", id, encryptionKeyErrorDetail(client, id, err)))
			return
		}
	}
	created, _, err := client.GetEncryptionKey(ctx, id)
	if err != nil {
		detail := apiErrorDetail(client, encryptionKeyPrivilege(encryptionKeyReadPrivilege, id), err)
		if pbsclient.IsNotFound(err) {
			detail = fmt.Sprintf("PBS lists only the keys the caller has Sys.Audit on: %q needs %s. %s",
				client.AuthID(), encryptionKeyPrivilege(encryptionKeyReadPrivilege, id), err)
		}
		recordAnyway("Unable to read PBS sync encryption key back after creation",
			fmt.Sprintf("PBS created sync encryption key %q, and it was recorded in state, but reading it back "+
				"failed, so it is marked tainted: the next apply replaces it. %s", id, detail))
		return
	}
	plan.fromKey(id, created)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

func (r *syncEncryptionKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state syncEncryptionKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	// Before the lookup, so that a refresh finding the key gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)

	key, _, err := r.data.client.GetEncryptionKey(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS sync encryption key",
			apiErrorDetail(r.data.client, encryptionKeyPrivilege(encryptionKeyReadPrivilege, id), err))
		return
	}
	state.fromKey(id, key)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update archives the key or brings it back into use: nothing else of a key
// changes without replacing it.
func (r *syncEncryptionKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan syncEncryptionKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	if _, err := setArchived(ctx, client, id, plan.Archived.ValueBool()); err != nil {
		resp.Diagnostics.AddError("Unable to update PBS sync encryption key", encryptionKeyErrorDetail(client, id, err))
		return
	}
	key, _, err := client.GetEncryptionKey(ctx, id)
	if err != nil {
		if plan.ArchivedAt.IsUnknown() {
			plan.ArchivedAt = types.Int64Null()
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS sync encryption key back after update",
			fmt.Sprintf("PBS updated sync encryption key %q, and the change was recorded in state, but reading it "+
				"back failed. %s", id, apiErrorDetail(client, encryptionKeyPrivilege(encryptionKeyReadPrivilege, id), err)))
		return
	}
	plan.fromKey(id, key)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// Delete archives the key, should it not be, as PBS deletes only archived
// keys, and deletes it. A key a sync job still holds stays as it was.
func (r *syncEncryptionKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state syncEncryptionKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	client := r.data.client

	archivedNow, err := setArchived(ctx, client, id, true)
	if pbsclient.IsNotFound(err) {
		// The list leaves out keys the caller may not audit. Deleting a key
		// that is gone succeeds, so a DELETE tells the two apart.
		err = client.WithConfigLock(pbsclient.ConfigEncryptionKeys, func() error { return client.DeleteEncryptionKey(ctx, id) })
		if err != nil {
			resp.Diagnostics.AddError("Unable to delete PBS sync encryption key",
				fmt.Sprintf("PBS does not list sync encryption key %q, and refuses to delete it. PBS lists only the keys "+
					"the caller may audit, so the key may exist all the same: seeing it needs %s for %q. %s", id,
					encryptionKeyPrivilege(encryptionKeyReadPrivilege, id), client.AuthID(),
					encryptionKeyErrorDetail(client, id, err)))
		}
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to delete PBS sync encryption key", encryptionKeyErrorDetail(client, id, err))
		return
	}
	err = client.WithConfigLock(pbsclient.ConfigEncryptionKeys, func() error { return client.DeleteEncryptionKey(ctx, id) })
	if err == nil {
		return
	}
	detail := encryptionKeyErrorDetail(client, id, err)
	if archivedNow {
		if _, undo := setArchived(ctx, client, id, false); undo != nil {
			detail += fmt.Sprintf(" The provider archived the key to delete it, and bringing it back into use failed "+
				"too, so it stays archived: %s", undo)
		}
	}
	resp.Diagnostics.AddError("Unable to delete PBS sync encryption key", detail)
}

// ImportState imports a key by ID, given either as the import id or, from
// Terraform 1.12, as the identity of an import block. Read fills in the
// rest, or drops a key that does not exist, which Terraform reports. The key
// itself cannot be imported: PBS never returns it.
func (r *syncEncryptionKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := importedSafeID(ctx, req, resp, "id", "sync encryption key", "offsite-2026")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}
