package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The actions pbs_sync_job_run, pbs_verify_job_run and pbs_prune_job_run run
// a configured job now, as its "Run now" button in the PBS web interface
// does. They differ in what they say, what the job needs and what they
// report afterwards; jobRunKind holds that. PBS facts are in
// internal/pbsclient/jobs_run.go.

var (
	_ action.Action              = &jobRunAction{}
	_ action.ActionWithConfigure = &jobRunAction{}
)

// NewSyncJobRunAction returns the pbs_sync_job_run action.
func NewSyncJobRunAction() action.Action {
	return &jobRunAction{kind: syncJobRun}
}

// NewVerifyJobRunAction returns the pbs_verify_job_run action.
func NewVerifyJobRunAction() action.Action {
	return &jobRunAction{kind: verifyJobRun}
}

// NewPruneJobRunAction returns the pbs_prune_job_run action.
func NewPruneJobRunAction() action.Action {
	return &jobRunAction{kind: pruneJobRun}
}

// jobRunAction runs a job of one kind now.
type jobRunAction struct {
	actionBase
	kind *jobRunKind
}

type jobRunModel struct {
	ID types.String `tfsdk:"id"`
	taskWaitModel
}

// jobRunKind is what sets the actions apart.
type jobRunKind struct {
	// typeName follows the provider's type name, such as "_sync_job_run".
	typeName string
	// noun names a job of the kind in messages, such as "sync job".
	noun string
	// description is the action's, actionRequirementNote aside.
	description string
	// idDescription describes the id attribute.
	idDescription string
	// start asks PBS to run the job.
	start func(ctx context.Context, client *pbsclient.Client, id string) (pbsclient.UPID, error)
	// privileges names what running the job needs, for errors.
	privileges func(ctx context.Context, client *pbsclient.Client, id string) string
	// report, when set, tells what a run that finished did.
	report func(ctx context.Context, client *pbsclient.Client, upid pbsclient.UPID, progress *actionProgress)
}

// jobRunEffects is what every run does besides its work, for the
// descriptions.
const jobRunEffects = "PBS runs the job as its schedule would: the run becomes the job's last run, in the web " +
	"interface and the job lists, and PBS sends the notification a scheduled run sends. The run leaves the " +
	"schedule as it is, since PBS's scheduler counts the next run from the start of the last one, although the " +
	"job lists show it counted from its end; a scheduled time that passes while the run goes on starts the job " +
	"again within a minute of its end. PBS runs one instance of a job at a time: while the job runs, on its " +
	"schedule or by hand, PBS waits 10 seconds for it, and the action fails."

var syncJobRun = &jobRunKind{
	typeName: "_sync_job_run",
	noun:     "sync job",
	description: "Runs a Proxmox Backup Server sync job now, as **Run now** under Datastore → Sync Jobs does, " +
		"instead of waiting for its `schedule`. The job runs in its direction: a pull copies the backups that " +
		"`store` lacks from `remote_store` — on the remote, or without one a datastore of this server — and a " +
		"push copies the backups of `store` that `remote_store` on the remote lacks. Triggered by the " +
		"`after_create` of a `pbs_sync_job`, it runs the new job at once.\n\n" +
		"**Privileges.** Running a job needs the privileges of changing it, which depend on its direction. To " +
		"pull: `Datastore.Audit` and `Datastore.Backup` on `/datastore/<store>[/<ns>]` — plus `Datastore.Prune` " +
		"for `remove_vanished`, and `Datastore.Modify` unless the job's `owner`, root@pam when it has none, is " +
		"the user or token the provider signs in as, or a token of that user — and `Remote.Read` on " +
		"`/remote/<remote>/<remote_store>`, or, for a local pull, `Datastore.Audit` on " +
		"`/datastore/<remote_store>[/<remote_ns>]` with `Datastore.Read`, or with `Datastore.Backup` for the " +
		"owner's own backups and `Datastore.Modify` there too, unless the job's `owner` is the provider's, as " +
		"above. To push: " +
		"`Remote.DatastoreBackup` on `/remote/<remote>/<remote_store>[/<remote_ns>]` — plus " +
		"`Remote.DatastorePrune` for `remove_vanished` — and `Datastore.Audit` on `/datastore/<store>[/<ns>]` " +
		"with `Datastore.Read`, or with `Datastore.Backup` for the owner's own backups and `Datastore.Modify` " +
		"unless the job's `owner`, root@pam when it has none, is the user or token the provider signs in as, or " +
		"a token of that user. The job's `owner` needs its privileges as for a scheduled run.\n\n" +
		jobRunEffects + " PBS checks the datastores and the remote only once the task runs: a removable " +
		"datastore that is not mounted, a maintenance mode that forbids the sync or a remote that does not " +
		"answer fails the task, and the action with it.\n\n" +
		"A sync can take hours, the first one above all: raise `timeout`, which defaults to the provider's " +
		"`task_timeout`, or set `wait = false`. When the action stops waiting, the sync goes on; Administration → " +
		"Tasks in the web interface can stop it. When it waits, the action reports the summary PBS logs at the " +
		"end: how much the sync copied, and what `remove_vanished` removed.\n\n" +
		"Running the job changes nothing that `pbs_sync_job` manages.",
	idDescription: "ID of the sync job to run, such as `pbs_sync_job.offsite.id`.",
	start: func(ctx context.Context, client *pbsclient.Client, id string) (pbsclient.UPID, error) {
		return client.RunSyncJob(ctx, id)
	},
	privileges: syncJobRunPrivileges,
	report:     reportSyncSummary,
}

var verifyJobRun = &jobRunKind{
	typeName: "_verify_job_run",
	noun:     "verify job",
	description: "Runs a Proxmox Backup Server verify job now, as **Run now** under Datastore → Verify Jobs does, " +
		"instead of waiting for its `schedule`; a job without one runs only by hand. It reads the backups of the " +
		"job's datastore or namespace and checks every chunk against its checksum — skipping, with " +
		"`ignore_verified`, the default, the backups verified before, until `outdated_after` has passed.\n\n" +
		"Needs `Datastore.Verify` on `/datastore/<store>[/<ns>]`, the job's datastore or namespace. PBS opens the " +
		"datastore before it starts the task: a removable datastore must be mounted, and the maintenance mode " +
		"`offline` forbids it, as does PBS while it unmounts the datastore, refreshes it from S3 or deletes it; " +
		"`read-only` does not.\n\n" +
		jobRunEffects + "\n\n" +
		"A verification reads every chunk it checks, which takes hours on a big datastore: raise `timeout`, which " +
		"defaults to the provider's `task_timeout`, or set `wait = false`. When the action stops waiting, the " +
		"verification goes on; Administration → Tasks in the web interface can stop it. A backup that fails " +
		"verification fails the action, which shows the end of the task's log, where PBS lists the backups that " +
		"failed.\n\n" +
		"Running the job changes nothing that `pbs_verify_job` manages.",
	idDescription: "ID of the verify job to run, such as `pbs_verify_job.weekly.id`.",
	start: func(ctx context.Context, client *pbsclient.Client, id string) (pbsclient.UPID, error) {
		return client.RunVerifyJob(ctx, id)
	},
	privileges: func(context.Context, *pbsclient.Client, string) string {
		return "Datastore.Verify on /datastore/<store>[/<ns>], the job's datastore or namespace"
	},
}

var pruneJobRun = &jobRunKind{
	typeName: "_prune_job_run",
	noun:     "prune job",
	description: "Runs a Proxmox Backup Server prune job now, as **Run now** under Datastore → Prune & GC Jobs " +
		"does, instead of waiting for its `schedule`: it removes the backups of the job's datastore or namespace " +
		"that the job's retention options do not keep. A disabled job, with `disable = true`, runs too: `disable` " +
		"only stops the schedule. The space the removed backups held is freed by a later garbage collection, " +
		"which the `pbs_datastore_gc` action starts.\n\n" +
		"Needs `Datastore.Modify` on `/datastore/<store>[/<ns>]`, the job's datastore or namespace. The run prunes " +
		"as the user or token the provider signs in as, where a scheduled run prunes as root@pam, and PBS checks " +
		"its privileges again in each namespace below the job's: where it lacks `Datastore.Modify`, the run " +
		"skips, without a word, the backup groups it may not prune there — all of them, or with " +
		"`Datastore.Prune` those it does not own. An ACL entry on such a namespace that replaces the inherited " +
		"role causes that, and so does a `Datastore.Modify` on the job's path that comes from an entry with " +
		"`propagate = false`, which does not reach the namespaces below. PBS opens the datastore for writing " +
		"before it starts the task: a removable datastore must be mounted, and the maintenance modes " +
		"`read-only` and `offline` forbid it, as does PBS while it unmounts the datastore, refreshes it from S3 " +
		"or deletes it.\n\n" +
		jobRunEffects + "\n\n" +
		"~> A prune cannot be stopped once it has started: PBS ignores a request to stop it, and when the action " +
		"stops waiting, the prune goes on to its end. It changes metadata only, and takes seconds to minutes.\n\n" +
		"When it waits, the action reports how many backups the run kept and removed, from the task's log.\n\n" +
		"Running the job changes nothing that `pbs_prune_job` manages.",
	idDescription: "ID of the prune job to run, such as `pbs_prune_job.daily.id`.",
	start: func(ctx context.Context, client *pbsclient.Client, id string) (pbsclient.UPID, error) {
		return client.RunPruneJob(ctx, id)
	},
	privileges: func(context.Context, *pbsclient.Client, string) string {
		return "Datastore.Modify on /datastore/<store>[/<ns>], the job's datastore or namespace"
	},
	report: reportPruneSummary,
}

func (a *jobRunAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + a.kind.typeName
}

func (a *jobRunAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: a.kind.description + "\n\n" + actionRequirementNote,
		Attributes: taskWaitAttributes(map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: a.kind.idDescription,
				Validators:          safeIDValidators(minSafeIDLength),
			},
		}),
	}
}

func (a *jobRunAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config jobRunModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id := config.ID.ValueString()
	progress := newActionProgress(ctx, resp)

	upid, err := a.kind.start(ctx, client, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to run PBS "+a.kind.noun+" "+id, a.kind.errorDetail(ctx, client, id, err))
		return
	}
	// The task is left running when the action stops waiting: a sync or a
	// verification blocks nothing but the next run of its own job, and a
	// prune does not stop anyway.
	task := actionTask{client: client, upid: upid, what: fmt.Sprintf("PBS %s %q", a.kind.noun, id)}
	if _, finished := task.await(ctx, config.taskWaitModel, progress, &resp.Diagnostics); !finished || a.kind.report == nil {
		return
	}
	a.kind.report(ctx, client, upid, progress)
}

// errorDetail explains why PBS did not run the job.
func (k *jobRunKind) errorDetail(ctx context.Context, client *pbsclient.Client, id string, err error) string {
	var apiErr *pbsclient.Error
	switch {
	case pbsclient.IsNotFound(err) && errors.As(err, &apiErr) && strings.HasPrefix(apiErr.Message, "no such datastore "):
		return fmt.Sprintf("The datastore of PBS %s %q does not exist: PBS keeps the jobs of a datastore deleted "+
			"with `keep_job_configs`. Point the job at another datastore, or delete it. %s", k.noun, id, err)
	case pbsclient.IsNotFound(err):
		return fmt.Sprintf("PBS has no %s %q. Deleting a datastore without `keep_job_configs` deletes its jobs too. "+
			"%s", k.noun, id, err)
	case pbsclient.IsDatastoreUnavailable(err):
		return fmt.Sprintf("PBS cannot open the datastore of %s %q for this: a removable datastore must be "+
			"mounted, and its maintenance mode may forbid it — `offline` everything, `read-only` a prune, and PBS "+
			"blocks the datastore while it unmounts it, refreshes it from S3 or deletes it. %s", k.noun, id, err)
	case pbsclient.IsTaskAlreadyRunning(err):
		return fmt.Sprintf("PBS %s %q is running already, on its schedule or by hand, and PBS runs one instance "+
			"of a job at a time: it waited 10 seconds for the run to end. Administration → Tasks in its web "+
			"interface shows the run. Invoke the action again once it has finished. %s", k.noun, id, err)
	case pbsclient.IsPrivilegeMissing(err) || pbsclient.IsForbidden(err):
		detail := fmt.Sprintf("%q lacks a privilege that running the job needs: %s.", client.AuthID(),
			k.privileges(ctx, client, id))
		if client.UsesAPIToken() {
			detail += " An API token has no privileges of its own: besides its user's ACL entries, it needs " +
				"entries for the token ID itself."
		}
		return detail + " " + err.Error()
	}
	return err.Error()
}

// syncJobRunPrivileges names what running a sync job needs, which depends
// on its direction: what changing it needs. PBS's error names none, so the
// job is read for them; a caller that may not read it either gets both
// directions.
func syncJobRunPrivileges(ctx context.Context, client *pbsclient.Client, id string) string {
	job, err := client.GetSyncJob(ctx, id)
	if err != nil {
		tflog.Debug(ctx, "could not read the PBS sync job to name its privileges", map[string]any{"id": id, "error": err.Error()})
		return "to pull, Datastore.Audit and Datastore.Backup on /datastore/<store>[/<ns>], plus Datastore.Prune " +
			"for remove_vanished and Datastore.Modify unless the job's owner is the user or token the provider " +
			"signs in as, and Remote.Read on /remote/<remote>/<remote_store>, or for a local pull Datastore.Audit " +
			"with Datastore.Read on /datastore/<remote_store>[/<remote_ns>], or Datastore.Backup for the owner's own " +
			"backups, with Datastore.Modify unless owner is the user or token the provider signs in as; to push, " +
			"Remote.DatastoreBackup on /remote/<remote>/<remote_store>[/<remote_ns>], plus Remote.DatastorePrune " +
			"for remove_vanished, and Datastore.Audit with Datastore.Read on /datastore/<store>[/<ns>], or " +
			"Datastore.Backup for the owner's own backups, with Datastore.Modify unless owner is the user or token " +
			"the provider signs in as"
	}
	return syncJobPrivileges(syncJobModel{
		SyncDirection: types.StringValue(job.Direction()),
		Store:         types.StringValue(job.Store),
		NS:            types.StringValue(job.NS),
		Remote:        stringOrNull(job.Remote),
		RemoteStore:   types.StringValue(job.RemoteStore),
		RemoteNS:      types.StringValue(job.RemoteNS),
	})
}

// syncSummaryLines is how many lines at the end of a sync's log hold its
// summary: one or two "Summary:" lines, the job's end and the result.
const syncSummaryLines = 8

// reportSyncSummary forwards the summary a sync logs at its end.
func reportSyncSummary(ctx context.Context, client *pbsclient.Client, upid pbsclient.UPID, progress *actionProgress) {
	lines, err := client.TaskLogTail(ctx, upid, syncSummaryLines)
	if err != nil {
		tflog.Debug(ctx, "could not read the end of the PBS sync task's log", map[string]any{"upid": upid.Raw, "error": err.Error()})
		return
	}
	for _, line := range lines {
		if message := line.Message(); strings.HasPrefix(message, "Summary: ") {
			progress.say("%s", message)
		}
	}
}

// pruneLogPage is how many lines of a prune's log one read fetches: a line
// per backup.
const pruneLogPage = 5000

// pruneMarkLine is a line of a prune's log about one backup: its mark, then
// the backup as <type>/<id>/<time>.
var pruneMarkLine = regexp.MustCompile(`^([a-z][a-z -]*) (vm|ct|host)/[A-Za-z0-9_][A-Za-z0-9._-]*/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// pruneSummary is what a prune's log says it did.
type pruneSummary struct {
	groups, kept, marked, failed int
	// keepAll is a job without retention options, which marks every backup
	// for removal and keeps them all.
	keepAll bool
}

// count takes in a message of the log.
func (s *pruneSummary) count(message string) {
	switch {
	case strings.HasPrefix(message, "Pruning group "):
		s.groups++
	case strings.HasPrefix(message, "No prune selection"):
		s.keepAll = true
	case strings.HasPrefix(message, "failed to remove dir "):
		s.failed++
	default:
		match := pruneMarkLine.FindStringSubmatch(message)
		switch {
		case match == nil:
		case match[1] == "remove":
			s.marked++
		case strings.HasPrefix(match[1], "keep") || strings.HasPrefix(match[1], "protected"):
			s.kept++
		}
	}
}

func (s pruneSummary) String() string {
	if s.groups == 0 {
		return "found no backup groups to prune"
	}
	kept, removed := s.kept+s.failed, s.marked-s.failed
	if s.keepAll {
		kept, removed = s.kept+s.marked, 0
	}
	summary := fmt.Sprintf("pruned %s: kept %s, removed %d", pruneQuantity(s.groups, "backup group"),
		pruneQuantity(kept, "backup"), removed)
	if s.failed > 0 {
		summary += fmt.Sprintf(", failed to remove %d", s.failed)
	}
	return summary
}

// pruneQuantity writes n of a noun, in the plural unless n is 1.
func pruneQuantity(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// reportPruneSummary reads the log of a prune that finished and reports what
// it kept and removed. A log it cannot read reports nothing.
func reportPruneSummary(ctx context.Context, client *pbsclient.Client, upid pbsclient.UPID, progress *actionProgress) {
	var summary pruneSummary
	next := 1
	for {
		lines, total, _, err := client.TaskLog(ctx, upid, next, pruneLogPage)
		if err != nil {
			tflog.Debug(ctx, "could not read the PBS prune task's log", map[string]any{"upid": upid.Raw, "error": err.Error()})
			return
		}
		advanced := false
		for _, line := range lines {
			if line.N >= next {
				summary.count(line.Message())
				next, advanced = line.N+1, true
			}
		}
		if !advanced || next > total {
			break
		}
	}
	progress.say("%s", summary)
}
