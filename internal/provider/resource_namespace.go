package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &namespaceResource{}
	_ resource.ResourceWithConfigure   = &namespaceResource{}
	_ resource.ResourceWithIdentity    = &namespaceResource{}
	_ resource.ResourceWithImportState = &namespaceResource{}
)

// NewNamespaceResource returns the pbs_namespace resource.
func NewNamespaceResource() resource.Resource { return &namespaceResource{} }

type namespaceResource struct {
	data *providerData
}

type namespaceModel struct {
	ID               types.String `tfsdk:"id"`
	Store            types.String `tfsdk:"store"`
	Namespace        types.String `tfsdk:"namespace"`
	DeleteGroups     types.Bool   `tfsdk:"delete_groups"`
	ErrorOnProtected types.Bool   `tfsdk:"error_on_protected"`
}

// namespaceIDSeparator separates the datastore from the namespace in the ID
// of a pbs_namespace, store1:dept1/hosts. Neither contains a colon.
const namespaceIDSeparator = ":"

// namespaceID is the ID of a pbs_namespace.
func namespaceID(store, ns string) string {
	return store + namespaceIDSeparator + ns
}

// namespacePrivilege names the privilege a change of namespace ns needs, on
// its parent, for errors.
func namespacePrivilege(store, ns string) string {
	parent, _ := pbsclient.SplitNamespace(ns)
	return "Datastore.Modify on " + namespaceACLPath(store, parent)
}

// namespaceAuditPrivilege names the privileges reading namespace ns needs,
// for errors.
func namespaceAuditPrivilege(store, ns string) string {
	return "Datastore.Audit, Datastore.Modify or Datastore.Backup on " + namespaceACLPath(store, ns)
}

// namespaceACLPath is the ACL path of a namespace, /datastore/<store> for the
// root.
func namespaceACLPath(store, ns string) string {
	if ns == "" {
		return "/datastore/" + store
	}
	return "/datastore/" + store + "/" + ns
}

// maxNamespaceNameLength bounds each name in a namespace.
const maxNamespaceNameLength = 32

func (r *namespaceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_namespace"
}

func (r *namespaceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a namespace of a Proxmox Backup Server datastore: a branch of its tree of " +
			"backups, such as `dept1` or `dept1/hosts`, which keeps backups apart — those of two Proxmox VE " +
			"clusters in one datastore, say — and gives ACL entries and jobs a scope below the whole datastore: " +
			"`/datastore/<store>/<namespace>` as an ACL path, `ns` in prune, verify and sync jobs. Namespaces nest " +
			"up to 7 levels deep.\n\n" +
			"A namespace has no settings: any change replaces it. PBS creates a namespace only below a parent " +
			"that exists, so refer to the parent's `pbs_namespace` in `namespace` for Terraform to create it " +
			"first. Creating a namespace that exists already takes it over, with the backups in it, and warns.\n\n" +
			"~> **Destroying a namespace destroys the namespaces below it too.** PBS deletes only empty ones " +
			"unless `delete_groups` is set: by default, destroying a namespace that holds backups — or whose " +
			"namespaces below do — fails after removing the empty namespaces below it, and keeps the backups. " +
			"With `delete_groups`, the backups are deleted, except protected snapshots.\n\n" +
			"Namespaces live in the datastore's directory, so they follow its chunk store when the datastore is " +
			"replaced — on S3 they live in the bucket, under the datastore's name, and follow that:\n\n" +
			"* Renamed with `reuse_datastore`, the datastore keeps its namespaces and their backups — except on S3, " +
			"where a datastore finds its backups under its name in the bucket, so a new name starts without them — " +
			"but a " +
			"`pbs_namespace` that refers to its name is replaced too, and destroying it in the old datastore " +
			"fails while it holds backups. Take such namespaces out of state first — with `terraform state rm`, " +
			"or a `removed` block with `destroy = false` — and the namespaces of the renamed datastore take them " +
			"over.\n" +
			"* Moved to another `path` or `backing_device`, the datastore starts without namespaces, and " +
			"Terraform creates the ones it manages on the next apply — except on S3, where the datastore, created " +
			"again with the same name and bucket and `reuse_datastore`, reads them from the bucket: all of them " +
			"from PBS 4.1.5, before only those with backups in or below them.\n\n" +
			"Managing a namespace needs `Datastore.Modify` on its parent — `/datastore/<store>` for a namespace " +
			"at the root, `/datastore/<store>/<parent>` below — and reading it `Datastore.Audit`, " +
			"`Datastore.Modify` or `Datastore.Backup` on the namespace itself. PBS does not list the namespaces " +
			"the provider may not read, and a namespace it cannot see is planned to be created again. While a " +
			"removable datastore is not mounted, or a maintenance mode closes the datastore, its namespaces " +
			"cannot be read — a refresh keeps them as they are in state, with a warning — nor created, imported " +
			"or destroyed.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "`<store>:<namespace>`, such as `store1:dept1/hosts`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore. Changing it replaces the namespace.",
				Validators:          safeIDValidators(minSafeIDLength),
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"namespace": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The namespace, with its parents: up to 7 names separated by slashes, such as " +
					"`dept1` or `dept1/hosts`, each up to 32 characters — letters, digits, `_`, `.` and `-`, not " +
					"starting with `.` or `-`. Its parent must exist. Changing it replaces the namespace.",
				Validators: append(namespaceValidators(), stringCheck{
					description: fmt.Sprintf("must have names of at most %d characters each", maxNamespaceNameLength),
					check: func(s string) bool {
						for name := range strings.SplitSeq(s, "/") {
							if len(name) > maxNamespaceNameLength {
								return false
							}
						}
						return true
					},
				}),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"delete_groups": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether destroying the namespace also deletes the backups in it and in the " +
					"namespaces below it. Defaults to `false`: destroying a namespace that holds backups fails, " +
					"and the backups stay. Destroying uses the value in state: set it in an apply before the one " +
					"that destroys or replaces the namespace.",
			},
			"error_on_protected": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				MarkdownDescription: "Whether destroying the namespace fails when PBS cannot delete all of it — " +
					"because of protected snapshots or, without `delete_groups`, backups. Defaults to `true`. " +
					"With `false`, PBS deletes what it can, destroying succeeds, and what PBS kept is no longer " +
					"managed by Terraform, with a warning. Like `delete_groups`, it is read from state.",
			},
		},
	}
}

func (r *namespaceResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(
		identityAttribute{"store", "Name of the datastore, such as `store1`."},
		identityAttribute{"namespace", "The namespace, such as `dept1/hosts`."},
	)
}

func (r *namespaceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// recordNamespaceIdentity records the identity of a namespace.
func recordNamespaceIdentity(ctx context.Context, identity *tfsdk.ResourceIdentity, m namespaceModel, diags *diag.Diagnostics) {
	setIdentity(ctx, identity, "store", m.Store.ValueString(), diags)
	setIdentity(ctx, identity, "namespace", m.Namespace.ValueString(), diags)
}

// fillDefaults sets the attributes that exist only in Terraform to their
// defaults when they are not set, as after an import.
func (m *namespaceModel) fillDefaults() {
	m.ID = types.StringValue(namespaceID(m.Store.ValueString(), m.Namespace.ValueString()))
	if m.DeleteGroups.IsNull() || m.DeleteGroups.IsUnknown() {
		m.DeleteGroups = types.BoolValue(false)
	}
	if m.ErrorOnProtected.IsNull() || m.ErrorOnProtected.IsUnknown() {
		m.ErrorOnProtected = types.BoolValue(true)
	}
}

func (r *namespaceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan namespaceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	store, ns := plan.Store.ValueString(), plan.Namespace.ValueString()
	client := r.data.client

	// PBS creates a namespace that exists without complaint. Whether it did
	// is only for the warning below. The lookup lists the parent, which
	// creating the namespace needs Datastore.Modify on anyway.
	//
	// Opening a datastore takes PBS's lock on datastore.cfg, which a datastore
	// on S3 holds while PBS reads its backups from the bucket — for minutes,
	// when a pbs_datastore takes one over — and PBS gives up after 10
	// seconds: the provider's own lock waits for that instead.
	var existed bool
	err := client.WithConfigLock(pbsclient.ConfigDatastores, func() error {
		var err error
		if existed, err = client.NamespaceExists(ctx, store, ns); err != nil {
			return err
		}
		return client.CreateNamespace(ctx, store, ns)
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create PBS namespace", namespaceErrorDetail(client, store, ns, namespacePrivilege(store, ns), err))
		return
	}
	if existed {
		resp.Diagnostics.AddWarning("PBS namespace already existed",
			fmt.Sprintf("Namespace %q of datastore %q existed already; Terraform manages it from now on, with the "+
				"backups in it, which destroying it with delete_groups = true deletes.", ns, store))
	}

	plan.fillDefaults()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	recordNamespaceIdentity(ctx, resp.Identity, plan, &resp.Diagnostics)

	// PBS lists only the namespaces the caller may read, so a namespace the
	// provider cannot see would be planned again and again.
	if visible, err := client.NamespaceExists(ctx, store, ns); err != nil || !visible {
		detail := fmt.Sprintf("PBS created namespace %q of datastore %q, and it was recorded in state, but the "+
			"provider cannot see it in the namespaces of its parent, so the next plan will create it again. "+
			"Reading it needs %s.", ns, store, namespaceAuditPrivilege(store, ns))
		if err != nil {
			detail += " " + apiErrorDetail(client, namespaceAuditPrivilege(store, ns), err)
		}
		resp.Diagnostics.AddWarning("Unable to read PBS namespace back after creation", detail)
	}
}

// namespaceErrorDetail explains why a call about namespace ns of store
// failed, with advice for the failures PBS answers with text alone.
func namespaceErrorDetail(client *pbsclient.Client, store, ns, privilege string, err error) string {
	message := err.Error()
	switch {
	case pbsclient.IsNotFound(err):
		return fmt.Sprintf("PBS has no datastore %q. %s", store, err)
	case pbsclient.IsDatastoreUnavailable(err):
		return fmt.Sprintf("PBS cannot open datastore %q: a removable datastore must be mounted, and a maintenance "+
			"mode may forbid the operation — \"offline\" any, \"read-only\" changes. %s", store, err)
	case strings.Contains(message, "doesn't already exist"):
		parent, _ := pbsclient.SplitNamespace(ns)
		return fmt.Sprintf("PBS creates a namespace only below a parent that exists, and datastore %q has no "+
			"namespace %q. Create it first: with a pbs_namespace for it, have this namespace refer to that "+
			"resource's namespace attribute, so that Terraform creates them in order. %s", store, parent, err)
	}
	return apiErrorDetail(client, privilege, err)
}

func (r *namespaceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state namespaceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	store, ns := state.Store.ValueString(), state.Namespace.ValueString()
	// Before the lookup, so that a refresh finding the namespace gone still
	// reports one; see setIdentity.
	recordNamespaceIdentity(ctx, resp.Identity, state, &resp.Diagnostics)

	exists, err := r.data.client.NamespaceExists(ctx, store, ns)
	switch {
	case pbsclient.IsNotFound(err):
		// The datastore is gone, and its namespaces with it.
		resp.State.RemoveResource(ctx)
		return
	case pbsclient.IsDatastoreUnavailable(err) && state.DeleteGroups.IsNull() && state.ErrorOnProtected.IsNull():
		// Only an import leaves the options that exist in Terraform alone
		// null: a namespace that cannot be looked up is not imported.
		resp.Diagnostics.AddError("Unable to import PBS namespace",
			fmt.Sprintf("PBS cannot open datastore %q — a removable datastore that is not mounted, or one in "+
				"maintenance mode \"offline\" —, so whether it has namespace %q cannot be checked. Mount the "+
				"datastore or end the maintenance, and import again. %s", store, ns, err))
		return
	case pbsclient.IsDatastoreUnavailable(err):
		tflog.Info(ctx, "PBS cannot open the datastore of the namespace", map[string]any{"store": store, "error": err.Error()})
		resp.Diagnostics.AddWarning("Unable to check PBS namespace",
			fmt.Sprintf("PBS cannot open datastore %q — a removable datastore that is not mounted, or one in "+
				"maintenance mode \"offline\" — so whether namespace %q still exists is unknown; it stays in "+
				"state as it was. %s", store, ns, err))
		state.fillDefaults()
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	case err != nil:
		resp.Diagnostics.AddError("Unable to read PBS namespace",
			apiErrorDetail(r.data.client, namespaceAuditPrivilege(store, ns), err))
		return
	case !exists:
		resp.State.RemoveResource(ctx)
		return
	}
	state.fillDefaults()
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update records a change of delete_groups or error_on_protected, which exist
// only in Terraform; any other change replaces the namespace.
func (r *namespaceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan namespaceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.fillDefaults()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	recordNamespaceIdentity(ctx, resp.Identity, plan, &resp.Diagnostics)
}

// Delete deletes the namespace and those below it as delete_groups and
// error_on_protected in state say.
func (r *namespaceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state namespaceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	store, ns := state.Store.ValueString(), state.Namespace.ValueString()
	client := r.data.client
	deletion := pbsclient.NamespaceDeletion{
		DeleteGroups:    state.DeleteGroups.ValueBool(),
		KeepOnProtected: !state.ErrorOnProtected.IsNull() && !state.ErrorOnProtected.ValueBool(),
	}

	// See Create for the lock.
	var stats pbsclient.NamespaceDeleteStats
	err := client.WithConfigLock(pbsclient.ConfigDatastores, func() error {
		var err error
		stats, err = client.DeleteNamespace(ctx, store, ns, deletion)
		return err
	})
	message := ""
	if err != nil {
		message = err.Error()
	}
	switch {
	case err == nil:
	case pbsclient.IsNotFound(err):
		// The datastore is gone, and the namespace with it.
		return
	case strings.Contains(message, "due to existing groups"):
		resp.Diagnostics.AddError("Unable to delete PBS namespace",
			fmt.Sprintf("Namespace %q of datastore %q, or a namespace below it, holds backups, and PBS deletes "+
				"backups with a namespace only when asked to. It removed the empty namespaces below and kept the "+
				"rest. To delete the backups too, set delete_groups = true and apply that before destroying the "+
				"namespace. To keep them — when the namespace is replaced because its datastore is renamed with "+
				"reuse_datastore, which keeps them anyway, except on S3 —, take the namespace out of state instead, with "+
				"`terraform state rm` or a removed block with destroy = false. %s", ns, store, err))
		return
	case pbsclient.IsDatastoreUnavailable(err):
		resp.Diagnostics.AddError("Unable to delete PBS namespace",
			fmt.Sprintf("PBS cannot open datastore %q — a removable datastore that is not mounted, or one in a "+
				"maintenance mode — to delete namespace %q from it. Mount the datastore or end the maintenance. "+
				"If the disk of a removable datastore is not coming back, take the namespace out of state, with "+
				"`terraform state rm` or a removed block with destroy = false: PBS deletes the datastore itself "+
				"without its disk, as long as destroy_data is false. %s", store, ns, err))
		return
	case strings.Contains(message, "protected snapshots"):
		resp.Diagnostics.AddError("Unable to delete PBS namespace",
			fmt.Sprintf("Namespace %q of datastore %q, or a namespace below it, holds protected snapshots, which "+
				"PBS does not delete. It deleted the other backups and kept the namespaces of those snapshots. "+
				"Remove the protection, or set error_on_protected = false and apply that first, for the "+
				"namespace to leave Terraform with what is left of it. %s", ns, store, err))
		return
	default:
		resp.Diagnostics.AddError("Unable to delete PBS namespace", namespaceErrorDetail(client, store, ns, namespacePrivilege(store, ns), err))
		return
	}
	tflog.Info(ctx, "deleted PBS namespace", map[string]any{
		"store": store, "namespace": ns, "removed_groups": stats.RemovedGroups,
		"removed_snapshots": stats.RemovedSnapshots, "protected_snapshots": stats.ProtectedSnapshots,
	})

	// With error_on_protected = false, PBS answers success also when it
	// kept the namespace.
	if deletion.KeepOnProtected {
		if exists, err := client.NamespaceExists(ctx, store, ns); err == nil && exists {
			resp.Diagnostics.AddWarning("PBS kept the namespace",
				fmt.Sprintf("PBS could not delete all of namespace %q of datastore %q — because of protected "+
					"snapshots or, without delete_groups, backups — and kept what it could not delete. As "+
					"error_on_protected = false asks, it is no longer managed by Terraform. PBS kept %d protected "+
					"snapshots.", ns, store, stats.ProtectedSnapshots))
		}
	}
}

// ImportState imports a namespace by <store>:<namespace>, given either as the
// import id or, from Terraform 1.12, as the identity of an import block. Read
// drops a namespace that does not exist, which Terraform reports.
func (r *namespaceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, values, byIdentity := importedID(ctx, req, &resp.Diagnostics, "store", "namespace")
	if resp.Diagnostics.HasError() {
		return
	}
	var store, ns string
	ok := true
	if byIdentity {
		store, ns = values[0], values[1]
	} else {
		store, ns, ok = strings.Cut(id, namespaceIDSeparator)
	}
	if !ok || !safeIDPattern.MatchString(store) || len(store) < minSafeIDLength || len(store) > maxSafeIDLength ||
		!namespacePattern.MatchString(ns) || len(ns) > maxNamespaceLength {
		resp.Diagnostics.AddError("Unexpected import identifier",
			"Import a PBS namespace by <store>:<namespace>, such as store1:dept1/hosts, got "+
				strconv.Quote(id+strings.Join(values, namespaceIDSeparator))+".")
		return
	}
	m := namespaceModel{
		Store: types.StringValue(store), Namespace: types.StringValue(ns),
		DeleteGroups: types.BoolNull(), ErrorOnProtected: types.BoolNull(),
	}
	m.ID = types.StringValue(namespaceID(store, ns))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	recordNamespaceIdentity(ctx, resp.Identity, m, &resp.Diagnostics)
}
