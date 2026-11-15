package provider

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The actions pbs_datastore_verify and pbs_datastore_prune verify or prune
// the backups of a datastore now, without a job, as Verify All and Prune
// All under Datastore → Content in the PBS web interface do. PBS facts are
// in internal/pbsclient/datastore_maintenance.go.

var (
	_ action.Action               = &datastoreVerifyAction{}
	_ action.ActionWithConfigure  = &datastoreVerifyAction{}
	_ action.ActionWithModifyPlan = &datastoreVerifyAction{}
)

// NewDatastoreVerifyAction returns the pbs_datastore_verify action.
func NewDatastoreVerifyAction() action.Action {
	return &datastoreVerifyAction{}
}

// datastoreVerifyAction verifies backups of a datastore: all of them, those
// of a namespace, of one backup group or one backup.
type datastoreVerifyAction struct {
	actionBase
}

type datastoreVerifyModel struct {
	Store          types.String `tfsdk:"store"`
	NS             types.String `tfsdk:"ns"`
	MaxDepth       types.Int64  `tfsdk:"max_depth"`
	Group          types.String `tfsdk:"group"`
	Snapshot       types.String `tfsdk:"snapshot"`
	IgnoreVerified types.Bool   `tfsdk:"ignore_verified"`
	OutdatedAfter  types.Int64  `tfsdk:"outdated_after"`
	ReadThreads    types.Int64  `tfsdk:"read_threads"`
	VerifyThreads  types.Int64  `tfsdk:"verify_threads"`
	taskWaitModel
}

// backupGroupPattern is a backup group as PBS names it: <type>/<id>.
var backupGroupPattern = regexp.MustCompile(`^(vm|ct|host)/[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// backupSnapshotPattern is a backup as PBS names it in task logs and
// proxmox-backup-client does: <type>/<id>/<time>, the time in RFC 3339 and
// UTC.
var backupSnapshotPattern = regexp.MustCompile(`^(vm|ct|host)/([A-Za-z0-9_][A-Za-z0-9._-]*)/([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$`)

// parseBackupSnapshot splits the name of a backup into its group's type and
// ID and its time in seconds since the epoch, which PBS takes as
// backup-time, from 1.
func parseBackupSnapshot(s string) (backupType, backupID string, epoch int64, ok bool) {
	match := backupSnapshotPattern.FindStringSubmatch(s)
	if match == nil {
		return "", "", 0, false
	}
	t, err := time.Parse(time.RFC3339, match[3])
	if err != nil || t.Unix() < 1 {
		return "", "", 0, false
	}
	return match[1], match[2], t.Unix(), true
}

// verifyMode is what a verification covers.
type verifyMode int

const (
	// verifyAll covers a datastore or a namespace, with the namespaces
	// below it down to max_depth.
	verifyAll verifyMode = iota
	verifyGroup
	verifySnapshot
)

func (a *datastoreVerifyAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore_verify"
}

func (a *datastoreVerifyAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Verifies backups of a Proxmox Backup Server datastore now, without a verify job: all " +
			"of them, those of a namespace, of one backup group or of one backup — what **Verify All** under " +
			"Datastore → Content and the **Verify** button of a group or a backup there verify. PBS reads every " +
			"chunk of the backups it checks and compares it with its checksum; a backup that fails is marked, and " +
			"the next backup of the same guest uploads its chunks again instead of reusing the damaged ones.\n\n" +
			"With `ignore_verified`, PBS's default, it skips the backups verified before, until `outdated_after` " +
			"has passed. The action sends `outdated_after` only when it is set, and without it PBS never verifies " +
			"a verified backup again: verifying a datastore, a namespace or a group skips every backup verified " +
			"once, where the web interface verifies it again after about a month — **Verify All** sends " +
			"`outdated-after` 30 unless changed, the **Verify** button of a group 29. `outdated_after = 30` does as " +
			"Verify All does. A single `snapshot` is verified again unless `ignore_verified = true` or " +
			"`outdated_after` is set, as the **Verify** button of a backup does.\n\n" +
			"**Privileges.** `Datastore.Verify` on `/datastore/<store>[/<ns>]` verifies everything there: for a whole " +
			"datastore or namespace, PBS verifies every backup group down to `max_depth`, whatever the ACL of the " +
			"namespaces below says. With `Datastore.Backup` there instead, PBS verifies only backups the user or " +
			"token the provider signs in as owns — a user also owns those of its API tokens, a token only its own: " +
			"for a whole datastore or namespace, it verifies, in each namespace, every backup group where the " +
			"provider holds `Datastore.Verify`, its own where it holds `Datastore.Backup`, and none elsewhere, and " +
			"the action's summary says so; a `group` or `snapshot` it does not own fails the action.\n\n" +
			"PBS opens the datastore before it starts the task: a removable datastore must be mounted, and the " +
			"maintenance mode `offline` forbids it, as does PBS while it unmounts the datastore, refreshes it from S3 " +
			"or deletes it; `read-only` does not. The running verification uses the datastore, and an unmount " +
			"(`pbs_datastore_unmount`) waits for it to end. Verifying a whole namespace that does not exist fails " +
			"with `Datastore.Verify`, and with `Datastore.Backup` alone verifies nothing, without an error.\n\n" +
			"Unlike `pbs_verify_job_run`, this runs no job: PBS sends no notification and records no last run, and " +
			"runs it alongside a verify job or another verification.\n\n" +
			"A verification reads every chunk it checks — from the bucket, on an S3 datastore — which takes hours on " +
			"a big datastore: raise `timeout`, which defaults to the provider's `task_timeout`, or set `wait = " +
			"false`. When the action stops waiting, the verification goes on; Administration → Tasks in the web " +
			"interface can stop it. A backup that fails verification fails the action, which shows the end of the " +
			"task's log, where PBS lists the backups that failed. When it waits, the action reports how many " +
			"backups PBS verified and skipped, and warns when `group` or `snapshot` names a backup group or backup " +
			"that does not exist, which PBS does not count as an error.\n\n" + actionRequirementNote,
		Attributes: taskWaitAttributes(map[string]schema.Attribute{
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore, such as `pbs_datastore.main.name`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"ns": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Namespace to verify, or that holds `group` or `snapshot`, such as `dept1` or " +
					"`dept1/hosts`; the datastore's root namespace when left out.",
				Validators: namespaceValidators(),
			},
			"max_depth": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many levels of namespaces below `ns` to verify too, from `0`, `ns` alone, " +
					"to `7`, all of them, which is PBS's default. Namespaces nest at most 7 levels deep, and PBS goes " +
					"no deeper than that. Not with `group` or `snapshot`.",
				Validators: []validator.Int64{
					int64validator.Between(0, maxNamespaceDepth),
					int64validator.ConflictsWith(path.MatchRoot("group"), path.MatchRoot("snapshot")),
				},
			},
			"group": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Verify only this backup group — the backups of one VM, container or host — as " +
					"`<type>/<id>` such as `vm/100` or `host/web1`, in `ns`. Unlike the group's **Verify** button in " +
					"the web interface, which sends `outdated-after` 29, the action keeps PBS's default: without " +
					"`outdated_after`, a backup verified before is skipped for good.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(backupGroupPattern,
						"must be a backup group such as vm/100, ct/200 or host/web1: vm, ct or host, a slash and the backup ID"),
					stringvalidator.ConflictsWith(path.MatchRoot("snapshot")),
				},
			},
			"snapshot": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Verify only this backup, as `<type>/<id>/<time>` such as " +
					"`vm/100/2026-11-14T02:00:05Z`, in `ns`: the time in UTC, as PBS names backups in task logs and " +
					"`proxmox-backup-client snapshot list` does, while the web interface shows local time. Unless " +
					"`ignore_verified = true` or `outdated_after` is set, PBS verifies it even when it was verified " +
					"before.",
				Validators: []validator.String{
					stringCheck{
						description: "must be a backup such as vm/100/2026-11-14T02:00:05Z: vm, ct or host, the backup " +
							"ID and the backup's time in UTC, separated by slashes",
						check: func(s string) bool {
							_, _, _, ok := parseBackupSnapshot(s)
							return ok
						},
					},
				},
			},
			"ignore_verified": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Whether to skip the backups verified before, unless that verification is older " +
					"than `outdated_after`. PBS defaults to `true`; `false` verifies every backup again. For a " +
					"`snapshot`, the action sends `false` unless this or `outdated_after` is set, as the **Verify** " +
					"button of a backup in the web interface does: PBS would skip a backup verified before.",
			},
			"outdated_after": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "With `ignore_verified`, how many days after its last verification a backup " +
					"is verified again; when left out, a verified backup is never verified again, where the web " +
					"interface's **Verify All** sends 30 unless changed and the **Verify** button of a group 29. PBS " +
					"ignores it with `ignore_verified = false`. For a `snapshot`, it keeps PBS's default " +
					"`ignore_verified = true` unless `ignore_verified` is set.",
				Validators: []validator.Int64{int64validator.AtLeast(1)},
			},
			"read_threads": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many threads read chunks, 1 to 32. When left out, the datastore's " +
					"`tuning.default_verification_readers` applies, and 1 without it. Needs PBS 4.1 or newer.",
				Validators: []validator.Int64{int64validator.Between(1, maxVerifyThreads)},
			},
			"verify_threads": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many threads verify chunks, 1 to 32. When left out, the datastore's " +
					"`tuning.default_verification_workers` applies, and 4 without it. Needs PBS 4.1 or newer.",
				Validators: []validator.Int64{int64validator.Between(1, maxVerifyThreads)},
			},
		}),
	}
}

// ModifyPlan refuses the thread counts on a server older than PBS 4.1, as
// pbs_verify_job does. It reads only the version Configure read, and calls
// no PBS.
func (a *datastoreVerifyAction) ModifyPlan(ctx context.Context, req action.ModifyPlanRequest, resp *action.ModifyPlanResponse) {
	if req.Config.Raw.IsNull() {
		return
	}
	var config datastoreVerifyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	a.data.requireRelease(&resp.Diagnostics, path.Root("read_threads"), config.ReadThreads, pbs41)
	a.data.requireRelease(&resp.Diagnostics, path.Root("verify_threads"), config.VerifyThreads, pbs41)
}

func (a *datastoreVerifyAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config datastoreVerifyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	scope := datastoreScope{store: config.Store.ValueString(), ns: config.NS.ValueString()}
	options, summary := config.verifyOptions(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	target := summary.target(scope)
	progress := newActionProgress(ctx, resp)

	upid, err := client.StartVerify(ctx, scope.store, options)
	if err != nil {
		resp.Diagnostics.AddError("Unable to start the verification of "+target,
			verifyStartErrorDetail(client, scope, summary, err))
		return
	}
	// The task is left running when the action stops waiting, as the job
	// runs leave theirs: it holds up only an unmount, which
	// pbs_datastore_unmount stops when it has waited too long.
	task := actionTask{client: client, upid: upid, what: "Verification of " + target}
	if _, finished := task.await(ctx, config.taskWaitModel, progress, &resp.Diagnostics); !finished {
		return
	}
	if err := scanTaskLog(ctx, client, upid, summary.count); err != nil {
		tflog.Debug(ctx, "could not read the PBS verification task's log", map[string]any{"upid": upid.Raw, "error": err.Error()})
		return
	}
	progress.say("%s", summary)
	summary.warn(target, &resp.Diagnostics)
}

// verifyOptions returns what to send PBS, and the summary of a verification
// of the mode the configuration asks for. The validators have checked the
// configuration.
func (m datastoreVerifyModel) verifyOptions(diags *diag.Diagnostics) (pbsclient.VerifyOptions, *verifySummary) {
	options := pbsclient.VerifyOptions{
		NS:            m.NS.ValueString(),
		MaxDepth:      m.MaxDepth.ValueInt64Pointer(),
		OutdatedAfter: m.OutdatedAfter.ValueInt64Pointer(),
		ReadThreads:   m.ReadThreads.ValueInt64Pointer(),
		VerifyThreads: m.VerifyThreads.ValueInt64Pointer(),
	}
	summary := &verifySummary{mode: verifyAll, found: -1, outdatedAfter: !m.OutdatedAfter.IsNull()}
	switch {
	case !m.Snapshot.IsNull():
		backupType, backupID, epoch, ok := parseBackupSnapshot(m.Snapshot.ValueString())
		if !ok {
			diags.AddAttributeError(path.Root("snapshot"), "Invalid backup",
				fmt.Sprintf("%q is not a backup such as vm/100/2026-11-14T02:00:05Z.", m.Snapshot.ValueString()))
			return options, summary
		}
		options.BackupType, options.BackupID, options.BackupTime = backupType, backupID, &epoch
		// As the web interface's Verify button of a backup does: PBS's
		// default would skip a backup verified before, for good. With
		// outdated_after alone, PBS's default true stays: with false, PBS
		// ignores outdated_after (VerifyWorker::verify_filter in
		// src/backup/verify.rs, proxmox-backup 7c86c5ad5).
		if m.IgnoreVerified.IsNull() && m.OutdatedAfter.IsNull() {
			ignoreVerified := false
			options.IgnoreVerified = &ignoreVerified
		}
		summary.mode, summary.name = verifySnapshot, m.Snapshot.ValueString()
	case !m.Group.IsNull():
		options.BackupType, options.BackupID, _ = strings.Cut(m.Group.ValueString(), "/")
		summary.mode, summary.name = verifyGroup, m.Group.ValueString()
	}
	if !m.IgnoreVerified.IsNull() {
		ignoreVerified := m.IgnoreVerified.ValueBool()
		options.IgnoreVerified = &ignoreVerified
	}
	return options, summary
}

// verifyStartErrorDetail explains why PBS refused to start a verification.
func verifyStartErrorDetail(client *pbsclient.Client, scope datastoreScope, summary *verifySummary, err error) string {
	switch {
	case pbsclient.IsBackupOwnerCheckFailed(err):
		return fmt.Sprintf("%q may verify only the backups it owns, holding Datastore.Backup but not "+
			"Datastore.Verify on %s, and does not own %s: a user owns the backups it and its API tokens wrote, a "+
			"token only those it wrote. Datastore.Verify there verifies any backup. %s",
			client.AuthID(), scope.aclPath(), summary.target(scope), err)
	case pbsclient.IsBackupGroupMissing(err):
		return fmt.Sprintf("There is no backup group %q in %s. PBS says so this way to %q, which holds "+
			"Datastore.Backup but not Datastore.Verify on %s, as it reads the owner of the group first. Check "+
			"`group` or `snapshot`, and `ns`. %s", summary.group(), scope, client.AuthID(), scope.aclPath(), err)
	}
	return datastoreTaskErrorDetail(client, scope, fmt.Sprintf("Datastore.Verify on %s, or Datastore.Backup "+
		"there to verify only the backups it owns", scope.aclPath()), err)
}

// verifyFoundLine is how a verification of a datastore or namespace counts
// the backup groups it is going to verify.
var verifyFoundLine = regexp.MustCompile(`^found ([0-9]+) groups$`)

// verifyGroupLine is the line a verification logs before the backups of a
// group: "verify group <store>:<type>/<id> (<n> snapshots)".
var verifyGroupLine = regexp.MustCompile(`^verify group [^ :]+:(vm|ct|host)/[A-Za-z0-9_][A-Za-z0-9._-]* \([0-9]+ snapshots\)$`)

// verifyBackupLine is the line a verification logs when it starts to check
// a backup: "verify <store>:<type>/<id>/<time>". Its lines about a backup
// that fails go on after the time.
var verifyBackupLine = regexp.MustCompile(`^verify [^ :]+:(vm|ct|host)/[A-Za-z0-9_][A-Za-z0-9._-]*/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// verifySummary is what a verification's log says it did.
type verifySummary struct {
	mode verifyMode
	// name is the group or the backup verified, in those modes.
	name string
	// outdatedAfter is whether the verification skips a backup verified
	// before only until outdated_after has passed.
	outdatedAfter bool
	// found is how many groups a verification of a datastore or namespace
	// found to verify; -1 until the log says.
	found int
	// groups are the groups PBS listed the backups of.
	groups int
	// verified, skipped and locked count the backups PBS checked, skipped
	// as verified before, and skipped as in use.
	verified, skipped, locked int
	// owner is the user or token whose backups PBS limited the
	// verification to, where it lacks Datastore.Verify.
	owner string
	// unlisted are the lines about groups PBS could not list, missing
	// those about backups that do not exist.
	unlisted, missing []string
}

// target names what the verification covers, in messages.
func (s *verifySummary) target(scope datastoreScope) string {
	switch s.mode {
	case verifyGroup:
		return fmt.Sprintf("backup group %q in %s", s.name, scope)
	case verifySnapshot:
		return fmt.Sprintf("backup %q in %s", s.name, scope)
	}
	return scope.String()
}

// group is the backup group verified, or the group of the backup verified.
func (s *verifySummary) group() string {
	if s.mode == verifySnapshot {
		return s.name[:strings.LastIndex(s.name, "/")]
	}
	return s.name
}

// count takes in a message of the log.
func (s *verifySummary) count(message string) {
	switch {
	case strings.HasPrefix(message, "limiting to backups owned by "):
		s.owner = strings.TrimPrefix(message, "limiting to backups owned by ")
	case verifyFoundLine.MatchString(message):
		s.found, _ = strconv.Atoi(verifyFoundLine.FindStringSubmatch(message)[1])
	case verifyGroupLine.MatchString(message):
		s.groups++
	case strings.HasPrefix(message, "SKIPPED: verify "):
		switch {
		case strings.HasSuffix(message, " (recently verified)"):
			s.skipped++
		case strings.HasSuffix(message, " - snapshot does not exist (anymore)."):
			s.missing = append(s.missing, message)
		case strings.Contains(message, " - could not acquire snapshot lock: "):
			s.locked++
		}
	case strings.HasPrefix(message, "verify ") && strings.Contains(message, " - unable to list backups: "):
		s.unlisted = append(s.unlisted, message)
	case verifyBackupLine.MatchString(message):
		s.verified++
	}
}

func (s *verifySummary) String() string {
	var summary string
	switch s.mode {
	case verifySnapshot:
		switch {
		case s.verified > 0:
			return "verified backup " + s.name
		case s.skipped > 0 && s.outdatedAfter:
			return fmt.Sprintf("skipped backup %s: verified before, and outdated_after has not passed since", s.name)
		case s.skipped > 0:
			return fmt.Sprintf("skipped backup %s: verified before, and ignore_verified is true", s.name)
		case s.locked > 0:
			return fmt.Sprintf("skipped backup %s: it is in use, and PBS could not lock it", s.name)
		}
		return fmt.Sprintf("found no backup %s to verify", s.name)
	case verifyGroup:
		if s.groups == 0 {
			return fmt.Sprintf("found no backup group %s to verify", s.name)
		}
		summary = fmt.Sprintf("verified %s of backup group %s", pruneQuantity(s.verified, "backup"), s.name)
	default:
		groups := s.found
		if groups < 0 {
			groups = s.groups
		}
		summary = "found no backup groups to verify"
		if groups > 0 {
			summary = fmt.Sprintf("verified %s in %s", pruneQuantity(s.verified, "backup"), pruneQuantity(groups, "backup group"))
		}
	}
	if s.skipped > 0 {
		summary += fmt.Sprintf("; skipped %d verified before", s.skipped)
	}
	if s.locked > 0 {
		summary += fmt.Sprintf("; skipped %d in use", s.locked)
	}
	// A group or a backup the verification found that is gone when it gets
	// to it was pruned or deleted in the meantime.
	var vanished []string
	if s.mode == verifyAll && len(s.unlisted) > 0 {
		vanished = append(vanished, pruneQuantity(len(s.unlisted), "backup group"))
	}
	if len(s.missing) > 0 {
		vanished = append(vanished, pruneQuantity(len(s.missing), "backup"))
	}
	if len(vanished) > 0 {
		summary += "; " + strings.Join(vanished, " and ") + " vanished during the run"
	}
	if s.owner != "" {
		summary += fmt.Sprintf(" (only the backups owned by %s, where it lacks Datastore.Verify)", s.owner)
	}
	return summary
}

// warn adds a warning when the group or the backup the action names does
// not exist, which PBS does not count as an error. In a verification of a
// datastore or namespace, the same lines are about groups and backups that
// vanished during the run, which the summary counts.
func (s *verifySummary) warn(target string, diags *diag.Diagnostics) {
	switch {
	case s.mode == verifyGroup && len(s.unlisted) > 0 && s.groups == 0:
		diags.AddWarning("PBS found no backup group to verify",
			fmt.Sprintf("PBS could not list the backups of %s, so it verified nothing, which it does not count as "+
				"an error: the group does not exist, or PBS cannot read its directory. Check `group` and `ns`. PBS "+
				"logged:\n\n%s", target, indentLines(strings.Join(s.unlisted, "\n"))))
	case s.mode == verifySnapshot && len(s.missing) > 0:
		diags.AddWarning("PBS found no backup to verify",
			fmt.Sprintf("There is no %s, so PBS verified nothing, which it does not count as an error. Check "+
				"`snapshot` and `ns`: `snapshot` gives the backup's time in UTC, as task logs and "+
				"`proxmox-backup-client snapshot list` do, where the web interface shows local time. PBS "+
				"logged:\n\n%s", target, indentLines(strings.Join(s.missing, "\n"))))
	}
}

// datastoreScope is the datastore or namespace a verification or a prune
// covers.
type datastoreScope struct {
	store string
	// ns is the namespace, empty for the root.
	ns string
}

// String names the scope in messages.
func (s datastoreScope) String() string {
	if s.ns == "" {
		return fmt.Sprintf("PBS datastore %q", s.store)
	}
	return fmt.Sprintf("namespace %q of PBS datastore %q", s.ns, s.store)
}

// aclPath is where PBS checks the privileges of a call on the scope.
func (s datastoreScope) aclPath() string {
	if s.ns == "" {
		return "/datastore/" + s.store
	}
	return "/datastore/" + s.store + "/" + s.ns
}

// datastoreTaskErrorDetail explains why PBS refused to start a verification
// or a prune of scope; privileges names what the call needs. PBS refuses a
// verification with a 403 and a prune with a 400 "missing permissions",
// which apiErrorDetail would leave unexplained.
func datastoreTaskErrorDetail(client *pbsclient.Client, scope datastoreScope, privileges string, err error) string {
	if pbsclient.IsPrivilegeMissing(err) || pbsclient.IsForbidden(err) {
		detail := fmt.Sprintf("%q lacks a privilege this needs: %s.", client.AuthID(), privileges)
		if client.UsesAPIToken() {
			detail += " An API token has no privileges of its own: besides its user's ACL entries, it needs " +
				"entries for the token ID itself."
		}
		return detail + " " + err.Error()
	}
	// A missing datastore, one PBS cannot open, or another error: the
	// privilege it would name is handled above.
	return datastoreActionErrorDetail(client, scope.store, "", err)
}
