package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &aptUpdateAction{}
	_ action.ActionWithConfigure = &aptUpdateAction{}
)

// NewAPTUpdateAction returns the pbs_apt_update action.
func NewAPTUpdateAction() action.Action {
	return &aptUpdateAction{}
}

// aptUpdateAction refreshes the package lists of a node, as the Refresh
// button under Administration → Updates does; see
// internal/pbsclient/apt_update.go for what PBS does.
type aptUpdateAction struct {
	actionBase
}

type aptUpdateModel struct {
	Node   types.String `tfsdk:"node"`
	Notify types.Bool   `tfsdk:"notify"`
	taskWaitModel
}

// aptUpdatesNamed is how many package names the action's report of the
// available updates names.
const aptUpdatesNamed = 5

func (a *aptUpdateAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_apt_update"
}

func (a *aptUpdateAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Refreshes the package lists of a Proxmox Backup Server node — `apt-get update` —, as " +
			"**Refresh** under Administration → Updates does. PBS refreshes them every day on its own; the action " +
			"is for when they must be current now, such as after adding a repository with " +
			"`pbs_apt_standard_repository`. When it waits, the action then reports how many package updates PBS " +
			"lists and names the first few: the list the `pbs_apt_updates` data source reads — which, read while " +
			"planning, shows the refreshed list in the next run only.\n\n" +
			"Needs `" + aptModifyPrivilege + "`; listing the available updates afterwards `" + aptReadPrivilege +
			"`.\n\n" +
			"~> **A failed refresh is a warning, not an error.** When apt-get cannot fetch the package lists of a " +
			"repository, PBS goes on, and the action warns: those lists, and the updates PBS lists from them, stay " +
			"as old as their last successful refresh. The enterprise repository without a subscription (`401 " +
			"Unauthorized`: disable it with `pbs_apt_repository`, or add a subscription) and another apt holding the " +
			"lock of the package lists, such as PBS's daily update, make apt-get fail: PBS logs apt's errors and ends " +
			"the task with warnings, which the action reports with the end of the task's log — PBS takes no lock of " +
			"its own, so of two refreshes at once, one warns. Network trouble — a name that does not resolve, a " +
			"mirror or proxy that refuses the connection or does not answer — apt takes for a passing failure: it " +
			"only warns, PBS drops its warnings and ends the task OK, and the action quotes apt's `Err:` lines from " +
			"the task's log.\n\n" +
			"Before it runs apt-get, PBS rewrites `/etc/apt/apt.conf.d/76pveproxy` from the node's `http_proxy` " +
			"(see `pbs_node_config`): it writes the proxy there, or deletes the file when the node has none — a " +
			"file of that name written by hand is lost.\n\n" + actionRequirementNote,
		Attributes: taskWaitAttributes(map[string]schema.Attribute{
			"node": nodeAttributeOfAction("whose package lists to refresh"),
			"notify": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Whether PBS also sends a notification, of type `package-updates` and severity " +
					"`info`, about the updates it has not notified about before, as its daily update does with an " +
					"active subscription; the notification matchers decide where it goes. Defaults to `false`. PBS " +
					"records the versions it notified about: the daily update does not notify about them again. A " +
					"failure of the notification system fails the task.",
			},
		}),
	}
}

func (a *aptUpdateAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config aptUpdateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	node := invokedNode(client, config.Node)
	progress := newActionProgress(ctx, resp)

	upid, err := client.StartAPTUpdate(ctx, node, config.Notify.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("Unable to refresh the package lists of PBS node "+node,
			apiErrorDetail(client, aptModifyPrivilege, err))
		return
	}
	task := actionTask{client: client, upid: upid, what: "APT update of PBS node " + node}
	status, finished := task.await(ctx, config.taskWaitModel, progress, &resp.Diagnostics)
	if !finished {
		return
	}
	warnStaleAPTLists(ctx, client, node, upid, status, &resp.Diagnostics)

	updates, err := client.APTUpdates(ctx, node)
	if err != nil {
		tflog.Debug(ctx, "could not list the available package updates", map[string]any{"node": node, "error": err.Error()})
		progress.say("listing the available updates failed: %s", err)
		return
	}
	progress.say("%s", describeAPTUpdates(updates))
}

// warnStaleAPTLists warns when the log of a finished APT update shows apt-get
// failing for a repository, whose package lists then stay as they were. When
// apt-get exits with an error, the task ends with warnings and its log has
// apt's errors, which the warning of the task quotes; a log PBS does not
// answer counts as such a failure then. Network trouble apt takes for a
// passing failure, and exits 0: PBS drops its warnings and ends the task OK,
// and only apt's "Err:" lines show it, which this warning quotes.
func warnStaleAPTLists(ctx context.Context, client *pbsclient.Client, node string, upid pbsclient.UPID, status pbsclient.TaskStatus, diags *diag.Diagnostics) {
	lines, _, _, err := client.TaskLog(ctx, upid, 1, 0)
	if err != nil {
		tflog.Debug(ctx, "could not read the PBS task log", map[string]any{"upid": upid.Raw, "error": err.Error()})
	}
	failures := aptFailures(lines)
	switch {
	case status.ExitStatus != "OK" && (err != nil || len(failures) > 0):
		diags.AddWarning("PBS package lists may be stale",
			fmt.Sprintf("apt-get update failed on node %s, and PBS went on, as it does: the package lists of the "+
				"repositories that failed, and the updates PBS lists from them, stay as old as their last successful "+
				"refresh. The end of the task's log, in the warning above, has apt's errors. The usual causes are the "+
				"enterprise repository without a subscription (401 Unauthorized: disable it with pbs_apt_repository, "+
				"or add a subscription) and another apt holding the lock of the package lists, such as PBS's daily "+
				"update; invoke the action again once the cause is gone.", node))
	case status.ExitStatus == "OK" && len(failures) > 0:
		more := ""
		if len(failures) > actionTaskLogTail {
			more = fmt.Sprintf("\n\n… and %d more lines", len(failures)-actionTaskLogTail)
			failures = failures[:actionTaskLogTail]
		}
		diags.AddWarning("PBS package lists may be stale",
			fmt.Sprintf("apt-get update could not fetch the package lists of some repositories on node %s. apt takes "+
				"a name that does not resolve, or a mirror or proxy (http_proxy of pbs_node_config) that refuses the "+
				"connection or does not answer, for a passing failure: it only warns, and PBS, which drops apt's "+
				"warnings when apt-get succeeds, ends the task OK. The package lists of those repositories, and the "+
				"updates PBS lists from them, stay as old as their last successful refresh. apt logged:\n\n%s%s\n\n"+
				"The whole log: Administration → Tasks in the web interface, or `proxmox-backup-manager task log "+
				"'%s'` on the host. Invoke the action again once the node reaches the repositories.",
				node, indentLines(strings.Join(failures, "\n")), more, upid.Raw))
	}
}

// aptFailures returns the lines of an APT update's log that show apt-get
// failing: the "Err:" line of each repository it could not fetch, with the
// reason apt indents below it, and the "E:" and "W:" lines of its error
// output, which PBS logs only when apt-get exits with an error — rather
// than, say, a notification target that did not take the notification.
func aptFailures(lines []pbsclient.TaskLogLine) []string {
	var failures []string
	reason := false
	for _, line := range lines {
		raw := line.Message()
		message := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(message, "Err:"):
			failures = append(failures, message)
			reason = true
		case strings.HasPrefix(message, "E: ") || strings.HasPrefix(message, "W: "):
			failures = append(failures, message)
			reason = false
		case reason && message != "" && strings.HasPrefix(raw, " "):
			failures = append(failures, "  "+message)
		default:
			reason = false
		}
	}
	return failures
}

// describeAPTUpdates says how many package updates PBS lists, and names the
// first few, in alphabetical order.
func describeAPTUpdates(updates []pbsclient.APTUpdate) string {
	var names []string
	for _, update := range updates {
		names = append(names, update.Package)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	switch {
	case len(names) == 0:
		return "PBS lists no package updates"
	case len(names) == 1:
		return "PBS lists 1 package update: " + names[0]
	case len(names) <= aptUpdatesNamed:
		return fmt.Sprintf("PBS lists %d package updates: %s", len(names), strings.Join(names, ", "))
	}
	return fmt.Sprintf("PBS lists %d package updates: %s and %d more", len(names),
		strings.Join(names[:aptUpdatesNamed], ", "), len(names)-aptUpdatesNamed)
}
