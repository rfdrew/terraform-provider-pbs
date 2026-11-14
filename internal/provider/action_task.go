package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Actions are one-off operations a configuration asks PBS for — run a job
// now, collect garbage, mount a datastore — which leave nothing in state.
// Terraform 1.14 and later invoke them from `action` blocks: when a
// resource's lifecycle `action_trigger` fires, or with `terraform apply
// -invoke=action.<type>.<name>`. Terraform 1.14.0 ran the actions of
// after_create and after_update before the resource had finished
// (hashicorp/terraform#37930, fixed in 1.14.1), so the documentation asks
// for 1.14.1. OpenTofu has no actions (opentofu/opentofu#3309); it and older
// Terraform never ask for them, and the provider works without them.
//
// Terraform calls PlanAction only while planning, with a configuration that
// may hold values known only after apply, so nothing here checks PBS before
// the invocation: an action triggered by the creation of the job it runs
// would find no job at plan time. Invoke checks what it needs.
//
// Most actions start a worker task. They wait for it by default, within the
// action's `timeout` or the provider's `task_timeout`, and forward the lines
// the task logs as progress messages, which Terraform prints one per line:
// at most one every actionProgressInterval, the latest. A task that fails
// fails the action with the end of its log. Terraform sets no deadline of
// its own, and its first Ctrl-C cancels the context, after which it drops
// whatever the action reports (hashicorp/terraform-plugin-go stream
// handling) — and a progress message sent then would block for good, so
// none is.

// actionRequirementNote ends the description of every action.
const actionRequirementNote = "-> Actions need Terraform 1.14.1 or later. OpenTofu and older Terraform releases " +
	"do not support them, and Terraform 1.13 ignores `action` blocks without a word; set `required_version = " +
	"\">= 1.14.1\"` in configurations that use them. An action runs when a resource's `lifecycle` " +
	"`action_trigger` fires, or with `terraform apply -invoke=action.<type>.<name>`, which also refreshes the " +
	"state of the resources the action's configuration refers to, and of those they depend on, but of no " +
	"other resource."

// actionProgressInterval is how often an action forwards a line of a task's
// log, at most. Terraform prints each message on a line of its own, and a
// verification logs a line per snapshot.
const actionProgressInterval = 5 * time.Second

// actionProgressLength is the longest progress message, in characters.
const actionProgressLength = 200

// actionTaskLogTail is how many lines of a task's log a failed or warning
// action shows.
const actionTaskLogTail = 20

// actionOutageGrace is how long an action goes on polling a task while PBS
// does not answer — a poll that runs into the provider's `request_timeout`
// on a busy server, a reverse proxy that answers 502, 503 or 504 —, before
// it reports that it lost the task: a wait of hours polls thousands of
// times, and one poll that fails must not end it. It outlasts a few request
// timeouts of the default 30 seconds.
const actionOutageGrace = 2 * time.Minute

// actionBase is what every action has: the provider's configuration.
type actionBase struct {
	data *providerData
}

func (a *actionBase) Configure(_ context.Context, req action.ConfigureRequest, resp *action.ConfigureResponse) {
	a.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// client returns the configured client, or adds an error when there is none,
// which Terraform does not let happen for an invocation.
func (a *actionBase) client(diags *diag.Diagnostics) *pbsclient.Client {
	if a.data == nil {
		diags.AddError("Unconfigured PBS provider",
			"The action was invoked before the provider was configured. This is a bug in the provider.")
		return nil
	}
	return a.data.client
}

// taskWaitModel holds the attributes of an action that starts a PBS task.
// Actions embed it in their models.
type taskWaitModel struct {
	Wait    types.Bool   `tfsdk:"wait"`
	Timeout types.String `tfsdk:"timeout"`
}

// taskWaitAttributes are the attributes of an action that starts a PBS
// task, merged with the action's own.
func taskWaitAttributes(own map[string]schema.Attribute) map[string]schema.Attribute {
	attributes := map[string]schema.Attribute{
		"wait": schema.BoolAttribute{
			Optional: true,
			MarkdownDescription: "Whether to wait for the PBS task to finish. Defaults to `true`: the action " +
				"reports the task's progress, and fails when the task fails. With `false`, the action ends as soon " +
				"as PBS has started the task, and the task's outcome is only in PBS (Administration → Tasks).",
		},
		"timeout": actionTimeoutAttribute(),
	}
	maps.Copy(attributes, own)
	return attributes
}

// actionTimeoutAttribute is the `timeout` of an action that waits for a
// task.
func actionTimeoutAttribute() schema.StringAttribute {
	return schema.StringAttribute{
		Optional: true,
		MarkdownDescription: "How long to wait for the PBS task, as a Go duration such as `90m` or `4h`. Defaults " +
			"to the provider's `task_timeout`. When it runs out, the action fails, and the task goes on in PBS.",
		Validators: []validator.String{positiveDurationValidator()},
	}
}

// settings returns whether to wait and for how long; zero means the
// provider's task_timeout. The validator has checked the duration.
func (m taskWaitModel) settings() (wait bool, timeout time.Duration) {
	wait = m.Wait.IsNull() || m.Wait.ValueBool()
	if !m.Timeout.IsNull() {
		timeout, _ = parsePositiveDuration(m.Timeout.ValueString())
	}
	return wait, timeout
}

// actionProgress sends an action's progress messages to Terraform, while
// Terraform still listens.
type actionProgress struct {
	ctx  context.Context
	send func(action.InvokeProgressEvent)
	// lastLog is when a line of a task's log was last forwarded.
	lastLog time.Time
}

func newActionProgress(ctx context.Context, resp *action.InvokeResponse) *actionProgress {
	return &actionProgress{ctx: ctx, send: resp.SendProgress}
}

// say sends a message, shortened to one line.
func (p *actionProgress) say(format string, args ...any) {
	if p == nil || p.send == nil || p.ctx.Err() != nil {
		return
	}
	message := fmt.Sprintf(format, args...)
	if i := strings.IndexByte(message, '\n'); i >= 0 {
		message = message[:i]
	}
	if utf8.RuneCountInString(message) > actionProgressLength {
		runes := []rune(message)
		message = string(runes[:actionProgressLength-1]) + "…"
	}
	p.send(action.InvokeProgressEvent{Message: message})
}

// taskLog forwards the latest of the lines a task logged, at most one every
// actionProgressInterval. The task's final line is left to the outcome.
func (p *actionProgress) taskLog(lines []pbsclient.TaskLogLine) {
	if time.Since(p.lastLog) < actionProgressInterval {
		return
	}
	for i := len(lines) - 1; i >= 0; i-- {
		message := strings.TrimSpace(lines[i].Message())
		if message == "" || strings.HasPrefix(message, "TASK ") {
			continue
		}
		p.lastLog = time.Now()
		p.say("%s", message)
		return
	}
}

// actionTask is a PBS task an action has started, and what the action calls
// it in messages.
type actionTask struct {
	client *pbsclient.Client
	upid   pbsclient.UPID
	// what names the operation, such as `Garbage collection of PBS datastore
	// "store1"`: the summary of the error when the task fails.
	what string
	// abortWhenLeft asks PBS to stop the task when the action stops waiting
	// before it ends, or can no longer follow it: for a task that would
	// otherwise hold something up for good, such as an unmount waiting for
	// the datastore's operations.
	abortWhenLeft bool
}

// taskOutcome is how waiting for a task ended.
type taskOutcome int

const (
	// taskNotWaited: the action's `wait` is false.
	taskNotWaited taskOutcome = iota
	// taskFinished: the task stopped without an error, perhaps with
	// warnings.
	taskFinished
	// taskFailed: the task stopped with an error.
	taskFailed
	// taskLeft: the task was still running when the action stopped
	// waiting, for its timeout or because Terraform stopped it.
	taskLeft
	// taskLost: the action could not follow the task.
	taskLost
)

// await waits for the task as the action's `wait` and `timeout` say,
// reporting progress, and returns whether it finished without an error;
// warnings, a failure, and a wait that ended first are in diags. A task
// the action does not wait for is not finished.
func (t actionTask) await(ctx context.Context, settings taskWaitModel, progress *actionProgress, diags *diag.Diagnostics) (pbsclient.TaskStatus, bool) {
	status, outcome := t.follow(ctx, settings, progress, diags)
	return status, outcome == taskFinished
}

// follow is await, telling how the wait ended.
func (t actionTask) follow(ctx context.Context, settings taskWaitModel, progress *actionProgress, diags *diag.Diagnostics) (pbsclient.TaskStatus, taskOutcome) {
	wait, timeout := settings.settings()
	if !wait {
		progress.say("PBS started task %s; not waiting for it", t.upid.Raw)
		return pbsclient.TaskStatus{}, taskNotWaited
	}
	progress.say("PBS started task %s", t.upid.Raw)
	status, err := t.client.WatchTask(ctx, t.upid, pbsclient.TaskWatch{
		Timeout: timeout, OutageGrace: actionOutageGrace, Progress: progress.taskLog,
	})
	if err != nil {
		return status, t.reportError(ctx, err, diags)
	}
	if status.ExitStatus != "OK" {
		diags.AddWarning(t.what+" ended with warnings",
			fmt.Sprintf("PBS task %s ended with %s.%s", t.upid.Raw, status.ExitStatus, t.logTail(ctx)))
	}
	return status, taskFinished
}

// reportError explains why waiting for the task failed, and returns how the
// wait ended.
func (t actionTask) reportError(ctx context.Context, err error, diags *diag.Diagnostics) taskOutcome {
	var taskErr *pbsclient.TaskError
	switch {
	case errors.As(err, &taskErr):
		diags.AddError(t.what+" failed", fmt.Sprintf("PBS task %s ended with an error: %s%s",
			t.upid.Raw, taskErr.ExitStatus, t.logTail(ctx)))
		return taskFailed
	case pbsclient.IsTaskTimeout(err):
		detail := fmt.Sprintf("The action stopped waiting for PBS task %s, which was still running: %s.", t.upid.Raw, err)
		if ctx.Err() != nil {
			detail = fmt.Sprintf("Terraform stopped the action while PBS task %s was running.", t.upid.Raw)
		}
		if t.abortWhenLeft {
			detail += " " + t.abort()
		} else {
			detail += " The task goes on in PBS; Administration → Tasks in its web interface shows how it ends."
			if ctx.Err() == nil {
				detail += " Raise the action's `timeout` to wait longer, or set `wait = false` not to wait at all."
			}
		}
		diags.AddError(t.what+" did not finish", detail)
		return taskLeft
	default:
		// PBS answered a status poll with an error, or has not answered
		// any for actionOutageGrace.
		cause := apiErrorDetail(t.client, "", err)
		detail := fmt.Sprintf("%s. The task goes on in PBS, whose web interface shows how it ends "+
			"(Administration → Tasks). %s", t.what, cause)
		if t.abortWhenLeft {
			// As when the wait ends first: a task the action can no
			// longer follow must not hold things up either.
			detail = fmt.Sprintf("%s. %s\n\n%s", t.what, cause, t.abort())
		}
		diags.AddError("Unable to follow PBS task "+t.upid.Raw, detail)
		return taskLost
	}
}

// abort asks PBS to stop the task, on a context of its own: the action's
// may be cancelled. It returns what to tell the user.
func (t actionTask) abort() string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := t.client.AbortTask(ctx, t.upid); err != nil {
		return fmt.Sprintf("Asking PBS to stop the task failed, so it goes on; stop it in the web interface "+
			"(Administration → Tasks) or with `proxmox-backup-manager task stop '%s'` on the host: %s", t.upid.Raw, err)
	}
	return "The provider asked PBS to stop the task."
}

// logTail returns the end of the task's log as a paragraph to append to a
// message, or a pointer to it when PBS does not answer.
func (t actionTask) logTail(ctx context.Context) string {
	where := fmt.Sprintf("Administration → Tasks in the web interface, or `proxmox-backup-manager task log '%s'` "+
		"on the host", t.upid.Raw)
	if ctx.Err() != nil {
		return "\n\nThe task's log: " + where + "."
	}
	lines, err := t.client.TaskLogTail(ctx, t.upid, actionTaskLogTail)
	if err != nil || len(lines) == 0 {
		if err != nil {
			tflog.Debug(ctx, "could not read the end of the PBS task log", map[string]any{"upid": t.upid.Raw, "error": err.Error()})
		}
		return "\n\nThe task's log: " + where + "."
	}
	return "\n\nThe end of the task's log:\n\n" + indentLines(pbsclient.FormatTaskLog(lines)) +
		"\n\nThe whole log: " + where + "."
}

// indentLines indents text by four spaces, which keeps the lines of a log as
// they are in Terraform's diagnostics.
func indentLines(text string) string {
	return "    " + strings.ReplaceAll(text, "\n", "\n    ")
}
