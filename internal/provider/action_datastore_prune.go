package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &datastorePruneAction{}
	_ action.ActionWithConfigure = &datastorePruneAction{}
)

// NewDatastorePruneAction returns the pbs_datastore_prune action.
func NewDatastorePruneAction() action.Action {
	return &datastorePruneAction{}
}

// datastorePruneAction prunes the backups of a datastore, or of a namespace
// in it, as Prune All under Datastore → Content does. Pruning one backup
// group goes through another call, which answers a dry run without a task
// and logs otherwise; it is left out.
type datastorePruneAction struct {
	actionBase
}

type datastorePruneModel struct {
	Store    types.String `tfsdk:"store"`
	NS       types.String `tfsdk:"ns"`
	MaxDepth types.Int64  `tfsdk:"max_depth"`
	Keep     types.Object `tfsdk:"keep"`
	DryRun   types.Bool   `tfsdk:"dry_run"`
	taskWaitModel
}

func (a *datastorePruneAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore_prune"
}

func (a *datastorePruneAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	keepAttributes := make(map[string]schema.Attribute, len(keepKinds))
	for _, k := range keepKinds {
		keepAttributes[k.attribute] = schema.Int64Attribute{
			Optional:            true,
			MarkdownDescription: "How many backups to keep that are " + k.description + ".",
			Validators:          []validator.Int64{int64validator.AtLeast(1)},
		}
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Prunes the backups of a Proxmox Backup Server datastore, or of a namespace in it, now — " +
			"as **Prune All** under Datastore → Content does, without a prune job: it removes, backup group by " +
			"backup group, the backups that `keep` does not keep, except protected ones. `dry_run` only reports " +
			"what it would remove. The space the removed backups held is freed by a later garbage collection, " +
			"which the `pbs_datastore_gc` action starts.\n\n" +
			"PBS goes through the kinds of `keep` in order — `last`, `hourly`, `daily`, `weekly`, `monthly`, " +
			"`yearly` — and a backup that one of them keeps is not counted again by the next. A backup that none " +
			"keeps is removed, unless it is protected.\n\n" +
			"**Privileges.** `Datastore.Modify` or `Datastore.Prune` on `/datastore/<store>[/<ns>]`; PBS refuses " +
			"the call with neither. It then checks the privileges again in every namespace it prunes: where the " +
			"user or token the provider signs in as holds `Datastore.Modify`, it prunes every backup group; where " +
			"it holds `Datastore.Prune`, only the groups it owns — a user also owns those of its API tokens, a " +
			"token only its own —, skipping the others without a word; elsewhere none. A namespace below `ns` " +
			"gets other privileges than `ns` from an ACL entry of its own that replaces the inherited role, or " +
			"when the entry on `ns` has `propagate = false`, which does not reach the namespaces below.\n\n" +
			"PBS opens the datastore for writing before it starts the task: a removable datastore must be mounted, " +
			"and the maintenance modes `read-only` and `offline` forbid it, as does PBS while it unmounts the " +
			"datastore, refreshes it from S3 or deletes it. The running prune uses the datastore, and an unmount " +
			"(`pbs_datastore_unmount`) waits for it to end. A namespace that does not exist fails the prune with " +
			"`ENOENT: No such file or directory`.\n\n" +
			"Unlike `pbs_prune_job_run`, this runs no job: PBS sends no notification and records no last run, and " +
			"nothing keeps it from running alongside a prune job or a verification, which then reports the " +
			"backups it removes as vanished.\n\n" +
			"~> A prune cannot be stopped once it has started: PBS ignores a request to stop it, and when the " +
			"action stops waiting, the prune goes on to its end. It changes metadata only, and takes seconds to " +
			"minutes.\n\n" +
			"When it waits, the action reports how many backup groups PBS pruned and how many backups it kept and " +
			"removed — or, with `dry_run`, would keep and remove, from the task's log; with `wait = false`, a dry " +
			"run's result is in that log only.\n\n" + actionRequirementNote,
		Attributes: taskWaitAttributes(map[string]schema.Attribute{
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore, such as `pbs_datastore.main.name`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"ns": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Namespace to prune, such as `dept1` or `dept1/hosts`; the datastore's root " +
					"namespace when left out.",
				Validators: namespaceValidators(),
			},
			"max_depth": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many levels of namespaces below `ns` to prune too, from `0`, `ns` alone, to " +
					"`7`; all of them when left out. Namespaces nest at most 7 levels deep, and PBS goes no deeper " +
					"than that below `ns`.",
				Validators: []validator.Int64{int64validator.Between(0, maxNamespaceDepth)},
			},
			"keep": schema.SingleNestedAttribute{
				Required: true,
				MarkdownDescription: "Retention: how many backups of each kind to keep, at least one kind, as `keep` " +
					"of `pbs_prune_job`, which can be assigned here: `keep = pbs_prune_job.daily.keep`. A kind left out " +
					"keeps no backups for its own sake.",
				Attributes: keepAttributes,
				Validators: []validator.Object{nonEmptyObject{}},
			},
			"dry_run": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Whether only to find out what the prune would remove: PBS logs it, which the " +
					"action reports when it waits, and removes nothing. Defaults to `false`.",
			},
		}),
	}
}

func (a *datastorePruneAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config datastorePruneModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	scope := datastoreScope{store: config.Store.ValueString(), ns: config.NS.ValueString()}
	options := pbsclient.PruneDatastoreOptions{
		NS:       scope.ns,
		MaxDepth: config.MaxDepth.ValueInt64Pointer(),
		Keep: pbsclient.KeepOptions{
			KeepLast:    keepValue(config.Keep, "last").ValueInt64Pointer(),
			KeepHourly:  keepValue(config.Keep, "hourly").ValueInt64Pointer(),
			KeepDaily:   keepValue(config.Keep, "daily").ValueInt64Pointer(),
			KeepWeekly:  keepValue(config.Keep, "weekly").ValueInt64Pointer(),
			KeepMonthly: keepValue(config.Keep, "monthly").ValueInt64Pointer(),
			KeepYearly:  keepValue(config.Keep, "yearly").ValueInt64Pointer(),
		},
		DryRun: config.DryRun.ValueBool(),
	}
	progress := newActionProgress(ctx, resp)

	upid, err := client.StartPruneDatastore(ctx, scope.store, options)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Unable to start the prune of %s", scope),
			datastoreTaskErrorDetail(client, scope, fmt.Sprintf("Datastore.Modify on %s, or Datastore.Prune there to "+
				"prune only the backup groups it owns", scope.aclPath()), err))
		return
	}
	what := "Prune of " + scope.String()
	if options.DryRun {
		what = "Dry run of the prune of " + scope.String()
	}
	// The task is left running when the action stops waiting: PBS would
	// not stop it anyway.
	task := actionTask{client: client, upid: upid, what: what}
	if _, finished := task.await(ctx, config.taskWaitModel, progress, &resp.Diagnostics); !finished {
		return
	}
	reportPruneSummary(ctx, client, upid, progress)
}
