package provider

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &aptStandardRepositoryResource{}
	_ resource.ResourceWithConfigure   = &aptStandardRepositoryResource{}
	_ resource.ResourceWithIdentity    = &aptStandardRepositoryResource{}
	_ resource.ResourceWithImportState = &aptStandardRepositoryResource{}
	_ resource.ResourceWithModifyPlan  = &aptStandardRepositoryResource{}
)

// NewAPTStandardRepositoryResource returns the pbs_apt_standard_repository
// resource.
func NewAPTStandardRepositoryResource() resource.Resource { return &aptStandardRepositoryResource{} }

type aptStandardRepositoryResource struct {
	data *providerData
}

type aptStandardRepositoryModel struct {
	ID          types.String `tfsdk:"id"`
	Node        types.String `tfsdk:"node"`
	Handle      types.String `tfsdk:"handle"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	FilePath    types.String `tfsdk:"file_path"`
	Index       types.Int64  `tfsdk:"index"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

func (r *aptStandardRepositoryResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_apt_standard_repository"
}

func (r *aptStandardRepositoryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Adds one of the standard APT repositories of Proxmox Backup Server to a node: " +
			"`enterprise`, `no-subscription` or `test`. The counterpart of `proxmox_apt_standard_repository` in " +
			"bpg/proxmox.\n\n" +
			"Creating the resource has PBS add the repository's entry, enabled — on PBS 4, to " +
			"`/etc/apt/sources.list.d/pbs-enterprise.sources` for `enterprise` and to " +
			"`/etc/apt/sources.list.d/proxmox.sources` for the others. When the node has an entry of the " +
			"repository already, PBS enables it instead, and leaves it as it is when it is enabled — but for the " +
			"test repository's component as PBS 3 wrote it, `pbstest`, which PBS 4.2.1 and later rewrite to " +
			"`pbs-test`. `file_path` and `index` tell where the entry is, for a `pbs_apt_repository` that enables " +
			"or disables it later; this resource does not change it again while it is there. A refresh that " +
			"finds no entry of the repository removes it from the state, and the next apply adds the entry " +
			"again.\n\n" +
			"PBS cannot remove an entry, so **destroying the resource disables the repository**: every enabled " +
			"entry of it, which is what PBS's own interface offers. bpg/proxmox leaves the repository enabled " +
			"instead; here destroy undoes what create did as far as PBS allows, so that, for instance, changing " +
			"`handle` from `test` to `no-subscription` replaces the one by the other rather than leaving both " +
			"enabled. To stop managing a repository and keep it enabled, remove the resource from the state " +
			"(`terraform state rm`, or a `removed` block with `destroy = false`) instead of destroying it.\n\n" +
			"~> **One resource per repository.** Destroying a resource disables its repository even when another " +
			"resource has it too, and that one then reads it disabled without planning a change. So manage a " +
			"repository with one resource only, on one spelling of the node; move a resource to another address " +
			"— renaming it, changing its `count` or `for_each` key — with a `moved` block rather than by destroying " +
			"and creating it; and do not combine `create_before_destroy` with a replacement. An entry that lists " +
			"the components of two standard repositories is disabled as an entry of either.\n\n" +
			"Reading the source files needs `" + aptReadPrivilege + "`, changing them `" + aptModifyPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "`<node>,<handle>`, such as `localhost,no-subscription`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"node": aptNodeAttribute(),
			"handle": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Standard repository to add: `enterprise`, the stable repository for hosts with " +
					"a subscription, `no-subscription`, for hosts without one, or `test`, for testing new releases. " +
					"Changing it replaces the resource, which disables the old repository.",
				Validators:    []validator.String{stringvalidator.OneOf(aptStandardHandles...)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"enabled": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "Whether an enabled entry of the repository is there; false when its entries " +
					"are disabled, such as by a `pbs_apt_repository`.",
			},
			"file_path": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Path of the file that holds the repository's entry — the first one, should " +
					"there be several. Null when the provider cannot tell which entry PBS counts: PBS 4.2.1 and later " +
					"also count an entry with another URI, such as a local mirror or the download server over " +
					"`https://`, by the key that signs it.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"index": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Index of that entry in the file, from 0; null when `file_path` is.",
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Name of the repository as PBS shows it, such as `No-Subscription`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Description of the repository as PBS shows it.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *aptStandardRepositoryResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(
		identityAttribute{"node", "Node name, such as `localhost`."},
		identityAttribute{"handle", "Handle of the standard repository, such as `no-subscription`."},
	)
}

func (r *aptStandardRepositoryResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan fills in the node and, once the node and the handle are known,
// the id.
func (r *aptStandardRepositoryResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan aptStandardRepositoryModel
	resp.Diagnostics.Append(resp.Plan.Get(ctx, &plan)...)
	var configured types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("node"), &configured)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Node.IsUnknown() && configured.IsNull() && r.data != nil {
		plan.Node = types.StringValue(r.data.client.Node())
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("node"), plan.Node)...)
	}
	if plan.ID.IsUnknown() && !plan.Node.IsUnknown() && !plan.Handle.IsUnknown() {
		id := aptStandardRepositoryID(plan.Node.ValueString(), plan.Handle.ValueString())
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), id)...)
	}
}

// recordAPTStandardRepositoryIdentity records the identity of a standard
// repository.
func recordAPTStandardRepositoryIdentity(ctx context.Context, identity *tfsdk.ResourceIdentity, m aptStandardRepositoryModel, diags *diag.Diagnostics) {
	setIdentity(ctx, identity, "node", m.Node.ValueString(), diags)
	setIdentity(ctx, identity, "handle", m.Handle.ValueString(), diags)
}

// fromRepositories records the standard repository as repos has it. ok is
// false when the node has no entry of it.
func (m *aptStandardRepositoryModel) fromRepositories(repos pbsclient.APTRepositories, matcher pbsclient.APTMatcher) bool {
	node, handle := m.Node.ValueString(), m.Handle.ValueString()
	standard, offered := repos.StandardRepository(handle)
	if !offered || standard.Status == nil {
		return false
	}
	m.ID = types.StringValue(aptStandardRepositoryID(node, handle))
	m.Enabled = types.BoolValue(*standard.Status)
	m.Name = types.StringValue(standard.Name)
	m.Description = types.StringValue(standard.Description)
	m.FilePath, m.Index = types.StringNull(), types.Int64Null()
	if filePath, index, found := repos.FindStandardRepository(matcher, handle, false); found {
		m.FilePath, m.Index = types.StringValue(filePath), types.Int64Value(index)
	}
	return true
}

// offeredHandles lists the standard repositories the node offers.
func offeredHandles(repos pbsclient.APTRepositories) string {
	var handles []string
	for _, s := range repos.StandardRepos {
		handles = append(handles, s.Handle)
	}
	return strings.Join(handles, ", ")
}

func (r *aptStandardRepositoryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan aptStandardRepositoryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	node, handle := plan.Node.ValueString(), plan.Handle.ValueString()
	matcher := r.data.aptMatcher()
	var before pbsclient.APTRepositories
	offered := true
	err := client.WithConfigLock(pbsclient.ConfigAPTSources, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			var err error
			if before, err = client.APTRepositories(ctx, node); err != nil {
				return err
			}
			if _, offered = before.StandardRepository(handle); !offered {
				return nil
			}
			return client.AddAPTStandardRepository(ctx, node, handle, before.Digest)
		})
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to add the PBS APT standard repository", aptWriteErrorDetail(client, before, err))
		return
	}
	if !offered {
		resp.Diagnostics.AddAttributeError(path.Root("handle"), "PBS does not offer the APT standard repository",
			fmt.Sprintf("Node %s offers the standard repositories %s, not %s.", node, offeredHandles(before), handle))
		return
	}

	after, err := client.APTRepositories(ctx, node)
	if err != nil {
		// PBS enabled the first entry of the repository it had, or appended
		// one, at an index the provider does not know.
		resp.Diagnostics.AddWarning("Unable to read the PBS APT standard repository back",
			fmt.Sprintf("PBS added the standard repository %s to node %s, and it was recorded in state, but reading it "+
				"back failed; the next refresh reads it again. %s", handle, node, apiErrorDetail(client, aptReadPrivilege, err)))
		standard, _ := before.StandardRepository(handle)
		plan.ID = types.StringValue(aptStandardRepositoryID(node, handle))
		plan.Enabled = types.BoolValue(true)
		plan.Name, plan.Description = types.StringValue(standard.Name), types.StringValue(standard.Description)
		plan.FilePath, plan.Index = types.StringNull(), types.Int64Null()
		if filePath, index, found := before.FindStandardRepository(matcher, handle, false); found {
			plan.FilePath, plan.Index = types.StringValue(filePath), types.Int64Value(index)
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		recordAPTStandardRepositoryIdentity(ctx, resp.Identity, plan, &resp.Diagnostics)
		return
	}
	if !plan.fromRepositories(after, matcher) {
		resp.Diagnostics.AddError("PBS did not add the APT standard repository",
			fmt.Sprintf("PBS accepted adding the standard repository %s to node %s, but does not list an entry of it "+
				"afterwards.", handle, node))
		return
	}
	if plan.FilePath.IsNull() {
		resp.Diagnostics.AddWarning("Entry of the PBS APT standard repository not found",
			fmt.Sprintf("PBS counts an entry of node %s as the standard repository %s, but the provider cannot tell "+
				"which one: PBS 4.2.1 and later also count an entry with another URI, such as a local mirror or the "+
				"download server over https://, by the key that signs it. file_path and index stay null.", node, handle))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	recordAPTStandardRepositoryIdentity(ctx, resp.Identity, plan, &resp.Diagnostics)
}

func (r *aptStandardRepositoryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state aptStandardRepositoryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	recordAPTStandardRepositoryIdentity(ctx, resp.Identity, state, &resp.Diagnostics)

	node, handle := state.Node.ValueString(), state.Handle.ValueString()
	repos, err := r.data.client.APTRepositories(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS APT repositories", apiErrorDetail(r.data.client, aptReadPrivilege, err))
		return
	}
	if !state.fromRepositories(repos, r.data.aptMatcher()) {
		resp.Diagnostics.AddWarning("PBS APT standard repository gone",
			fmt.Sprintf("Node %s has no entry of the standard repository %s; it is removed from the state, and the "+
				"next apply adds it again.", node, handle))
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update has nothing to change: every attribute but node and handle, which
// replace the resource, is computed. It records the plan, which keeps what
// the last refresh read.
func (r *aptStandardRepositoryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan aptStandardRepositoryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	recordAPTStandardRepositoryIdentity(ctx, resp.Identity, plan, &resp.Diagnostics)
}

// aptDisableLimit bounds the entries Delete disables, one write each: a
// node has a handful of entries of one repository at most, while a loop
// that never ends points at an entry PBS does not disable.
const aptDisableLimit = 16

// Delete disables the repository: every enabled entry of it, one at a time,
// each write with the digest of the files it read.
func (r *aptStandardRepositoryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state aptStandardRepositoryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	node, handle := state.Node.ValueString(), state.Handle.ValueString()
	matcher := r.data.aptMatcher()
	var left pbsclient.APTRepositories
	err := client.WithConfigLock(pbsclient.ConfigAPTSources, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			for range aptDisableLimit {
				repos, err := client.APTRepositories(ctx, node)
				if err != nil {
					return err
				}
				left = repos
				filePath, index, found := repos.FindStandardRepository(matcher, handle, true)
				if !found {
					return nil
				}
				if err := client.SetAPTRepositoryEnabled(ctx, node, filePath, index, false, repos.Digest); err != nil {
					return err
				}
			}
			return fmt.Errorf("the standard repository %s still has enabled entries after %d were disabled", handle, aptDisableLimit)
		})
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to disable the PBS APT standard repository", aptWriteErrorDetail(client, left, err))
		return
	}
	if standard, ok := left.StandardRepository(handle); ok && standard.Status != nil && *standard.Status {
		resp.Diagnostics.AddWarning("PBS APT standard repository still enabled",
			fmt.Sprintf("PBS counts an enabled entry of node %s as the standard repository %s, but the provider cannot "+
				"tell which one, and could not disable it: PBS 4.2.1 and later also count an entry with another URI, "+
				"such as a local mirror or the download server over https://, by the key that signs it. Disable it "+
				"with a pbs_apt_repository or in PBS's interface.", node, handle))
	}
}

// ImportState imports a standard repository by <node>,<handle>, given either
// as the import id or, from Terraform 1.12, as the identity of an import
// block.
func (r *aptStandardRepositoryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, values, byIdentity := importedID(ctx, req, &resp.Diagnostics, "node", "handle")
	if resp.Diagnostics.HasError() {
		return
	}
	var node, handle string
	ok := true
	if byIdentity {
		node, handle = values[0], values[1]
	} else {
		node, handle, ok = strings.Cut(id, aptIDSeparator)
	}
	if !ok || !nodeNamePattern.MatchString(node) || len(node) > 63 || !slices.Contains(aptStandardHandles, handle) {
		resp.Diagnostics.AddError("Unexpected import identifier",
			"Import a PBS APT standard repository by <node>,<handle>, such as localhost,no-subscription, where the "+
				"handle is one of "+strings.Join(aptStandardHandles, ", ")+", got "+
				strconv.Quote(id+strings.Join(values, aptIDSeparator))+".")
		return
	}
	m := aptStandardRepositoryModel{
		ID: types.StringValue(aptStandardRepositoryID(node, handle)), Node: types.StringValue(node),
		Handle: types.StringValue(handle), Enabled: types.BoolNull(), FilePath: types.StringNull(),
		Index: types.Int64Null(), Name: types.StringNull(), Description: types.StringNull(),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	recordAPTStandardRepositoryIdentity(ctx, resp.Identity, m, &resp.Diagnostics)
}
