package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &aptRepositoryResource{}
	_ resource.ResourceWithConfigure   = &aptRepositoryResource{}
	_ resource.ResourceWithIdentity    = &aptRepositoryResource{}
	_ resource.ResourceWithImportState = &aptRepositoryResource{}
	_ resource.ResourceWithModifyPlan  = &aptRepositoryResource{}
)

// NewAPTRepositoryResource returns the pbs_apt_repository resource.
func NewAPTRepositoryResource() resource.Resource { return &aptRepositoryResource{} }

type aptRepositoryResource struct {
	data *providerData
}

type aptRepositoryModel struct {
	ID           types.String `tfsdk:"id"`
	Node         types.String `tfsdk:"node"`
	FilePath     types.String `tfsdk:"file_path"`
	Index        types.Int64  `tfsdk:"index"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	FileType     types.String `tfsdk:"file_type"`
	PackageTypes types.List   `tfsdk:"package_types"`
	URIs         types.List   `tfsdk:"uris"`
	Suites       types.List   `tfsdk:"suites"`
	Components   types.List   `tfsdk:"components"`
	Comment      types.String `tfsdk:"comment"`
}

// aptRepositoryIdentity is the identity of pbs_apt_repository.
type aptRepositoryIdentity struct {
	Node     types.String `tfsdk:"node"`
	FilePath types.String `tfsdk:"file_path"`
	Index    types.Int64  `tfsdk:"index"`
}

func (m aptRepositoryModel) details() aptEntryDetails {
	return aptEntryDetails{FileType: m.FileType, PackageTypes: m.PackageTypes, URIs: m.URIs, Suites: m.Suites,
		Components: m.Components, Comment: m.Comment}
}

func (m *aptRepositoryModel) setDetails(d aptEntryDetails) {
	m.FileType, m.PackageTypes, m.URIs, m.Suites, m.Components, m.Comment =
		d.FileType, d.PackageTypes, d.URIs, d.Suites, d.Components, d.Comment
}

func (r *aptRepositoryResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_apt_repository"
}

// aptEntryDetailAttributes are the computed attributes that describe an
// entry. A refresh reads them; an update checks that the index still points
// to the entry they describe.
func aptEntryDetailAttributes() map[string]schema.Attribute {
	keep := []planmodifier.List{listplanmodifier.UseStateForUnknown()}
	return map[string]schema.Attribute{
		"file_type": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Format of the file: `list` for one-line entries, `sources` for deb822 stanzas.",
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"package_types": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Package types of the entry: `deb`, `deb-src`.",
			PlanModifiers:       keep,
		},
		"uris": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "URIs of the entry, such as `http://download.proxmox.com/debian/pbs`.",
			PlanModifiers:       keep,
		},
		"suites": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Suites of the entry, such as `trixie`.",
			PlanModifiers:       keep,
		},
		"components": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Components of the entry, such as `pbs-no-subscription`; empty for an absolute suite.",
			PlanModifiers:       keep,
		},
		"comment": schema.StringAttribute{
			Computed: true,
			MarkdownDescription: "Comment lines above the entry, without their `#`, one per line; null when there " +
				"are none.",
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
	}
}

// aptFilePathAttributeValidators check a source file path the way PBS
// accepts it.
func aptFilePathAttributeValidators() []validator.String {
	return []validator.String{
		stringvalidator.RegexMatches(aptFilePathPattern, "must be /etc/apt/sources.list or a .list or .sources "+
			"file in /etc/apt/sources.list.d, such as /etc/apt/sources.list.d/pbs-enterprise.sources"),
	}
}

func (r *aptRepositoryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attributes := map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "`<node>,<file_path>,<index>`, such as `localhost,/etc/apt/sources.list.d/pbs-enterprise.sources,0`.",
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"node": aptNodeAttribute(),
		"file_path": schema.StringAttribute{
			Required: true,
			MarkdownDescription: "Path of the APT source file that holds the entry: `/etc/apt/sources.list`, or a " +
				"`.list` or `.sources` file in `/etc/apt/sources.list.d`, such as " +
				"`/etc/apt/sources.list.d/pbs-enterprise.sources`. Changing it replaces the resource.",
			Validators:    aptFilePathAttributeValidators(),
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"index": schema.Int64Attribute{
			Required: true,
			MarkdownDescription: "Position of the entry in the file, from 0. Disabled entries count — in a `.list` " +
				"file, a commented-out line —, and a stanza of a `.sources` file is one entry, however many URIs or " +
				"suites it lists. Changing it replaces the resource.",
			Validators:    []validator.Int64{int64validator.AtLeast(0)},
			PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
		},
		"enabled": schema.BoolAttribute{
			Required: true,
			MarkdownDescription: "Whether APT uses the entry. PBS disables an entry of a `.list` file by commenting " +
				"it out and one of a `.sources` file with `Enabled: false`.",
		},
	}
	for name, attribute := range aptEntryDetailAttributes() {
		attributes[name] = attribute
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Enables or disables an existing entry of the APT source files of a Proxmox Backup " +
			"Server node, such as the enterprise repository on a host without a subscription. The counterpart of " +
			"`proxmox_apt_repository` in bpg/proxmox.\n\n" +
			"The entry is addressed by its file and its index in the file, as PBS lists them; " +
			"`pbs_apt_repositories` lists them all, and `pbs_apt_standard_repository` and " +
			"`pbs_apt_repositories` tell where the entry of a standard repository is. PBS adds entries only for " +
			"standard repositories, with `pbs_apt_standard_repository`, and removes none, so this resource neither " +
			"adds nor removes one: creating it takes over an entry that is there, and destroying it leaves the " +
			"entry as it is, enabled or not.\n\n" +
			"An index counts the entries before it in the same file. Should someone add or remove one of them " +
			"outside Terraform, the index points to another entry. The provider tells them apart by their package " +
			"types, URIs, suites and components: a refresh then warns and keeps the entry the state records, an " +
			"update fails rather than change the other entry, and the warning says where the recorded entry is " +
			"now, if it is still in the file. Editing an entry's URIs, suites or components outside Terraform " +
			"looks the same; replace the resource to take over the entry as it is.\n\n" +
			"PBS rewrites the whole file when it enables or disables an entry: it normalises the formatting, and " +
			"comment lines move to the top of their entry.\n\n" +
			"Reading the source files needs `" + aptReadPrivilege + "`, changing them `" + aptModifyPrivilege + "`.",
		Attributes: attributes,
	}
}

func (r *aptRepositoryResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{Attributes: map[string]identityschema.Attribute{
		"node":      identityschema.StringAttribute{RequiredForImport: true, Description: "Node name, such as `localhost`."},
		"file_path": identityschema.StringAttribute{RequiredForImport: true, Description: "Path of the APT source file."},
		"index":     identityschema.Int64Attribute{RequiredForImport: true, Description: "Index of the entry in the file, from 0."},
	}}
}

func (r *aptRepositoryResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan fills in the node and, once the node, the file and the index
// are known, the id.
func (r *aptRepositoryResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan aptRepositoryModel
	resp.Diagnostics.Append(resp.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var configured types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("node"), &configured)...)
	if plan.Node.IsUnknown() && configured.IsNull() && r.data != nil {
		plan.Node = types.StringValue(r.data.client.Node())
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("node"), plan.Node)...)
	}
	if plan.ID.IsUnknown() && !plan.Node.IsUnknown() && !plan.FilePath.IsUnknown() && !plan.Index.IsUnknown() {
		id := aptRepositoryID(plan.Node.ValueString(), plan.FilePath.ValueString(), plan.Index.ValueInt64())
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), id)...)
	}
}

// recordAPTRepositoryIdentity records the identity of an entry.
func recordAPTRepositoryIdentity(ctx context.Context, identity *tfsdk.ResourceIdentity, m aptRepositoryModel, diags *diag.Diagnostics) {
	if identity == nil || m.Node.ValueString() == "" || m.FilePath.ValueString() == "" {
		return
	}
	diags.Append(identity.Set(ctx, aptRepositoryIdentity{Node: m.Node, FilePath: m.FilePath, Index: m.Index})...)
}

// apply enables or disables the entry the plan addresses, under the lock of
// the source files and with their digest, and returns the entry as PBS has
// it afterwards, with its file. expected are the details the entry has in
// state, which it must still have, or nil on create. When reading the
// entry back after a write fails, apply warns and returns the entry as it
// was before, with enabled as planned: the write took effect.
func (r *aptRepositoryResource) apply(ctx context.Context, plan aptRepositoryModel, expected *aptEntryDetails, diags *diag.Diagnostics) (pbsclient.APTRepositoryFile, pbsclient.APTRepository, bool) {
	client := r.data.client
	node, filePath, index := plan.Node.ValueString(), plan.FilePath.ValueString(), plan.Index.ValueInt64()
	enabled := plan.Enabled.ValueBool()
	var repos pbsclient.APTRepositories
	var file pbsclient.APTRepositoryFile
	var entry pbsclient.APTRepository
	var missing, moved string
	wrote := false
	err := client.WithConfigLock(pbsclient.ConfigAPTSources, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			missing, moved, wrote = "", "", false
			var err error
			if repos, err = client.APTRepositories(ctx, node); err != nil {
				return err
			}
			var ok bool
			file, _ = repos.File(filePath)
			if entry, ok = repos.Repository(filePath, index); !ok {
				missing = aptMissingEntryDetail(repos, node, filePath, index)
				return nil
			}
			if expected != nil {
				if current := newAPTEntryDetails(file, entry, diags); !current.sameEntry(*expected) {
					moved = aptMovedEntryDetail(ctx, repos, node, filePath, index, *expected, current, diags) +
						" The update changes nothing rather than change that entry."
					return nil
				}
			}
			if entry.Enabled == enabled {
				return nil
			}
			if err := client.SetAPTRepositoryEnabled(ctx, node, filePath, index, enabled, repos.Digest); err != nil {
				return err
			}
			wrote = true
			return nil
		})
	})
	switch {
	case err != nil:
		diags.AddError("Unable to change the PBS APT repository", aptWriteErrorDetail(client, repos, err))
		return file, entry, false
	case missing != "":
		diags.AddError("PBS APT repository not found", missing)
		return file, entry, false
	case moved != "":
		diags.AddError("PBS APT repository moved", moved)
		return file, entry, false
	case !wrote:
		return file, entry, true
	}

	after, err := client.APTRepositories(ctx, node)
	if err != nil {
		diags.AddWarning("Unable to read the PBS APT repository back",
			fmt.Sprintf("PBS %s the entry at index %d of %s on node %s, and it was recorded in state, but reading it "+
				"back failed; the next refresh reads it again. %s", enabledWord(enabled), index, filePath, node,
				apiErrorDetail(client, aptReadPrivilege, err)))
		entry.Enabled = enabled
		return file, entry, true
	}
	file, _ = after.File(filePath)
	entry, ok := after.Repository(filePath, index)
	if !ok || entry.Enabled != enabled {
		diags.AddError("PBS did not change the APT repository",
			fmt.Sprintf("PBS accepted the change of the entry at index %d of %s on node %s, but does not report it %s "+
				"afterwards.", index, filePath, node, enabledWord(enabled)))
		return file, entry, false
	}
	return file, entry, true
}

// fromEntry records the entry the model addresses as PBS has it.
func (m *aptRepositoryModel) fromEntry(file pbsclient.APTRepositoryFile, entry pbsclient.APTRepository, diags *diag.Diagnostics) {
	m.ID = types.StringValue(aptRepositoryID(m.Node.ValueString(), m.FilePath.ValueString(), m.Index.ValueInt64()))
	m.Enabled = types.BoolValue(entry.Enabled)
	m.setDetails(newAPTEntryDetails(file, entry, diags))
}

// fillUnknown records what the plan leaves unknown — on create, the id and
// every detail of the entry — as PBS has it after a write. What the plan
// knows stays: rewriting a file, PBS may reformat an entry's comment, which
// the next refresh reads.
func (m *aptRepositoryModel) fillUnknown(file pbsclient.APTRepositoryFile, entry pbsclient.APTRepository, diags *diag.Diagnostics) {
	if m.ID.IsUnknown() {
		m.ID = types.StringValue(aptRepositoryID(m.Node.ValueString(), m.FilePath.ValueString(), m.Index.ValueInt64()))
	}
	read := newAPTEntryDetails(file, entry, diags)
	if m.FileType.IsUnknown() {
		m.FileType = read.FileType
	}
	for _, l := range []struct {
		planned *types.List
		read    types.List
	}{
		{&m.PackageTypes, read.PackageTypes}, {&m.URIs, read.URIs}, {&m.Suites, read.Suites}, {&m.Components, read.Components},
	} {
		if l.planned.IsUnknown() {
			*l.planned = l.read
		}
	}
	if m.Comment.IsUnknown() {
		m.Comment = read.Comment
	}
}

func (r *aptRepositoryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan aptRepositoryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	file, entry, ok := r.apply(ctx, plan, nil, &resp.Diagnostics)
	if !ok {
		return
	}
	plan.fillUnknown(file, entry, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	recordAPTRepositoryIdentity(ctx, resp.Identity, plan, &resp.Diagnostics)
}

func (r *aptRepositoryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state aptRepositoryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	recordAPTRepositoryIdentity(ctx, resp.Identity, state, &resp.Diagnostics)

	node, filePath := state.Node.ValueString(), state.FilePath.ValueString()
	repos, err := r.data.client.APTRepositories(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS APT repositories", apiErrorDetail(r.data.client, aptReadPrivilege, err))
		return
	}
	if msg, failed := repos.FileError(filePath); failed {
		resp.Diagnostics.AddError("Unable to read the PBS APT repository",
			fmt.Sprintf("PBS cannot parse %s on node %s: %s", filePath, node, msg))
		return
	}
	index := state.Index.ValueInt64()
	file, _ := repos.File(filePath)
	entry, ok := repos.Repository(filePath, index)
	if !ok {
		resp.Diagnostics.AddWarning("PBS APT repository gone",
			aptMissingEntryDetail(repos, node, filePath, index)+" It is removed from the state.")
		resp.State.RemoveResource(ctx)
		return
	}
	// After an import the state has no details yet, and the entry at the
	// index is the one to manage. Otherwise it must still be the entry the
	// state records: one that moved is not followed to the entry that took
	// its place.
	if prior := state.details(); !state.FileType.IsNull() {
		if current := newAPTEntryDetails(file, entry, &resp.Diagnostics); !current.sameEntry(prior) {
			resp.Diagnostics.AddWarning("PBS APT repository moved",
				aptMovedEntryDetail(ctx, repos, node, filePath, index, prior, current, &resp.Diagnostics)+
					" The state keeps the entry it records, and an update fails rather than change the other one.")
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	state.fromEntry(file, entry, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *aptRepositoryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior aptRepositoryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	expected := prior.details()
	file, entry, ok := r.apply(ctx, plan, &expected, &resp.Diagnostics)
	if !ok {
		return
	}
	plan.fillUnknown(file, entry, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	recordAPTRepositoryIdentity(ctx, resp.Identity, plan, &resp.Diagnostics)
}

// Delete leaves the entry as it is: PBS cannot remove it, and there is no
// state of its own to return it to.
func (r *aptRepositoryResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState imports an entry by <node>,<file path>,<index>, given either
// as the import id or, from Terraform 1.12, as the identity of an import
// block.
func (r *aptRepositoryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var node, filePath, indexText string
	if req.ID != "" || req.Identity == nil || req.Identity.Raw.IsNull() {
		parts := strings.Split(req.ID, aptIDSeparator)
		if len(parts) == 3 {
			node, filePath, indexText = parts[0], parts[1], parts[2]
		}
	} else {
		var identity aptRepositoryIdentity
		resp.Diagnostics.Append(req.Identity.Get(ctx, &identity)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if identity.Node.ValueString() == "" || identity.FilePath.ValueString() == "" || identity.Index.IsNull() {
			resp.Diagnostics.AddError("Missing import identity",
				"The import block's identity must set `node`, `file_path` and `index` to name the APT repository to import.")
			return
		}
		node, filePath = identity.Node.ValueString(), identity.FilePath.ValueString()
		indexText = strconv.FormatInt(identity.Index.ValueInt64(), 10)
	}
	index, err := strconv.ParseInt(indexText, 10, 64)
	if err != nil || index < 0 || !nodeNamePattern.MatchString(node) || len(node) > 63 || !aptFilePathPattern.MatchString(filePath) {
		got := req.ID
		if got == "" {
			got = strings.Join([]string{node, filePath, indexText}, aptIDSeparator)
		}
		resp.Diagnostics.AddError("Unexpected import identifier",
			"Import a PBS APT repository by <node>,<file path>,<index>, such as "+
				"localhost,/etc/apt/sources.list.d/pbs-enterprise.sources,0, got "+strconv.Quote(got)+".")
		return
	}
	m := aptRepositoryModel{
		ID: types.StringValue(aptRepositoryID(node, filePath, index)), Node: types.StringValue(node),
		FilePath: types.StringValue(filePath), Index: types.Int64Value(index), Enabled: types.BoolNull(),
		FileType: types.StringNull(), Comment: types.StringNull(),
		PackageTypes: types.ListNull(types.StringType), URIs: types.ListNull(types.StringType),
		Suites: types.ListNull(types.StringType), Components: types.ListNull(types.StringType),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	recordAPTRepositoryIdentity(ctx, resp.Identity, m, &resp.Diagnostics)
}

// enabledWord is "enabled" or "disabled".
func enabledWord(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}
