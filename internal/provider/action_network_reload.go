package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &networkReloadAction{}
	_ action.ActionWithConfigure = &networkReloadAction{}
)

// NewNetworkReloadAction returns the pbs_network_reload action.
func NewNetworkReloadAction() action.Action {
	return &networkReloadAction{}
}

// networkReloadAction applies the pending network changes of a node, as
// Apply Configuration in the Network Interfaces panel does: the PUT
// pbs_network_apply sends, in a task, srvreload, that moves
// /etc/network/interfaces.new over /etc/network/interfaces and runs
// `ifreload -a`; see pbsclient's network.go and resource_network_apply.go.
//
// It offers no `wait`: the action holds the provider's lock of the network
// configuration until the reload has ended, so that no interface of the same
// run writes interfaces.new while PBS moves it, and a reload that cuts the
// node off must be reported rather than left to be found out.
//
// There is no revert action. DELETE /nodes/{node}/network removes
// interfaces.new, whoever wrote it, and an action cannot tell which pending
// changes are Terraform's own: run from an action_trigger, it would drop the
// interface writes of the very run that triggered it, leaving state with
// interfaces that do not exist, and it would bring back the interfaces
// Terraform deleted in that run — invisibly, as they have left state.
type networkReloadAction struct {
	actionBase
}

type networkReloadModel struct {
	Node    types.String `tfsdk:"node"`
	Force   types.Bool   `tfsdk:"force"`
	Timeout types.String `tfsdk:"timeout"`
}

func (a *networkReloadAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_reload"
}

func (a *networkReloadAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Applies the pending network changes of a Proxmox Backup Server node, as **Apply " +
			"Configuration** in the Network Interfaces panel of its web interface does: PBS moves " +
			"`/etc/network/interfaces.new` over `/etc/network/interfaces` and runs `ifreload -a` (ifupdown2), in a " +
			"task the action waits for. It applies whatever is pending, whoever wrote it, and reports how many lines " +
			"of `/etc/network/interfaces` the changes add and remove.\n\n" +
			"Prefer `pbs_network_apply` in configurations: it applies after the `pbs_network_interface` resources its " +
			"`triggers` refer to, notices changes made elsewhere, and shows them in the plan. The action suits " +
			"`terraform apply -invoke`, to apply what is pending now. Do not trigger it from `pbs_network_interface` " +
			"resources: each would reload an intermediate configuration, between the writes of the others.\n\n" +
			"Unless `force` is set, the action applies nothing when nothing is pending: `ifreload -a` brings every " +
			"interface with an `auto` line in line with the whole of `/etc/network/interfaces`, also when nothing " +
			"changed, which removes addresses added outside the file, such as by hand or by keepalived.\n\n" +
			"!> **PBS does not roll back.** Once the task has moved the file, the previous configuration is gone, " +
			"and when `ifreload` fails, the node may run part of the new one. A change that cuts the node off — a " +
			"new address, gateway or MTU on the interface Terraform reaches PBS through — leaves it cut off: have " +
			"the node's console at hand, and read the guide _Managing the network of a PBS node_. While the reload " +
			"runs, the action waits up to two minutes for an unreachable node to answer again.\n\n" +
			"There is no action that reverts pending changes: it would drop the changes the interfaces of the same " +
			"run have just written, leaving Terraform's state with interfaces that do not exist, and bring back the " +
			"interfaces they deleted without Terraform noticing. Revert changes you do not want in the web " +
			"interface, or with `proxmox-backup-manager network revert` on the node.\n\n" +
			"Needs `" + networkApplyPrivilege + "`, which an API token may have, and, unless `force` is set, `" +
			networkReadPrivilege + "` to see what is pending. The node needs ifupdown2, which an installation from " +
			"the PBS ISO has.\n\n" + actionRequirementNote,
		Attributes: map[string]schema.Attribute{
			"node": nodeAttributeOfAction("whose pending network changes to apply"),
			"force": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Whether to run `ifreload -a` also when nothing is pending, to bring the " +
					"interfaces in line with `/etc/network/interfaces` again — removing the addresses added outside " +
					"it. Defaults to `false`: the action does nothing when nothing is pending.",
			},
			"timeout": actionTimeoutAttribute(),
		},
	}
}

func (a *networkReloadAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config networkReloadModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	node := invokedNode(client, config.Node)
	_, timeout := taskWaitModel{Timeout: config.Timeout}.settings()
	progress := newActionProgress(ctx, resp)

	var upid pbsclient.UPID
	var status pbsclient.TaskStatus
	started, skipped := false, false
	var readErr error
	// changes are the changes the reload applies, when the action looked.
	var changes string
	// Holding the configuration's lock keeps this provider's interface
	// writes out between the look at what is pending and the reload's end.
	err := client.WithConfigLock(pbsclient.ConfigNetwork, func() error {
		if !config.Force.ValueBool() {
			var err error
			changes, err = client.NetworkChanges(ctx, node)
			switch {
			case pbsclient.IsNetworkDiffFailed(err):
				// PBS compares only while changes are pending.
				progress.say("PBS cannot compare the pending changes with /etc/network/interfaces; applying them")
			case err != nil:
				readErr = err
				return err
			case changes == "":
				skipped = true
				return nil
			default:
				progress.say("applying the pending network changes of node %s: %s", node, describeNetworkChanges(changes))
			}
		}
		var err error
		upid, err = client.ReloadNetwork(ctx, node)
		if err != nil {
			return err
		}
		started = true
		progress.say("PBS started task %s", upid.Raw)
		status, err = client.WatchTask(ctx, upid, pbsclient.TaskWatch{
			Timeout: timeout, OutageGrace: reloadOutageGrace, Progress: progress.taskLog,
		})
		return err
	})
	switch {
	case readErr != nil:
		resp.Diagnostics.AddError("Unable to read the pending network changes of PBS node "+node,
			"The action applies only when changes are pending, unless `force` is set, and listing the interfaces "+
				"failed. "+networkErrorDetail(client, readErr))
		return
	case skipped:
		progress.say("nothing is pending on node %s; not reloading (force = true reloads anyway)", node)
		return
	case err != nil:
		a.reportError(ctx, client, node, upid, started, changes, err, &resp.Diagnostics)
		return
	}
	task := actionTask{client: client, upid: upid}
	if status.ExitStatus != "OK" {
		resp.Diagnostics.AddWarning("Network reload of PBS node "+node+" ended with warnings",
			fmt.Sprintf("PBS task %s ended with %s.%s", upid.Raw, status.ExitStatus, task.logTail(ctx)))
	}
	progress.say("PBS applied the network configuration of node %s", node)
}

// reportError explains a reload that failed or was not waited out; changes
// are those it applied, when the action looked.
func (a *networkReloadAction) reportError(ctx context.Context, client *pbsclient.Client, node string,
	upid pbsclient.UPID, started bool, changes string, err error, diags *diag.Diagnostics) {
	summary := "Unable to apply the network changes of PBS node " + node
	task := actionTask{client: client, upid: upid}
	var taskErr *pbsclient.TaskError
	switch {
	case errors.As(err, &taskErr):
		applied := ""
		switch {
		case len(changes) > maxPendingChangesInWarning:
			applied = fmt.Sprintf("\n\nThe changes PBS moved into /etc/network/interfaces make a diff of %s.",
				pbsclient.FormatByteSize(int64(len(changes))))
		case changes != "":
			applied = "\n\nThe changes PBS moved into /etc/network/interfaces:\n\n" + indentLines(strings.TrimRight(changes, "\n"))
		}
		// PBS moved interfaces.new before ifreload failed, so nothing is
		// pending any more, and invoking the action again as it was skips
		// the reload; pbs_network_apply's advice does not fit.
		diags.AddError(summary, fmt.Sprintf("PBS moved the pending configuration over /etc/network/interfaces, "+
			"and ifreload then failed: node %s may run part of the new configuration. PBS keeps no copy of the "+
			"previous one and does not roll back, and nothing is pending any more. Fix the configuration — the "+
			"error names the interface — with pbs_network_interface or in the web interface, which makes the fix "+
			"pending, and invoke the action again; or invoke it with force = true to run ifreload again on "+
			"/etc/network/interfaces as it is. %s", node, err)+applied+task.logTail(ctx))
	case pbsclient.IsTaskTimeout(err) && ctx.Err() != nil:
		diags.AddError("Network reload of PBS node "+node+" did not finish",
			fmt.Sprintf("Terraform stopped the action while PBS task %s was running. The reload goes on in PBS; "+
				"Administration → Tasks in its web interface shows how it ends.", upid.Raw))
	case pbsclient.IsTaskTimeout(err):
		diags.AddError("Network reload of PBS node "+node+" did not finish",
			fmt.Sprintf("The action stopped waiting for PBS task %s, which was still running: %s. The reload goes "+
				"on in PBS; Administration → Tasks in its web interface shows how it ends. Raise the action's "+
				"`timeout` to wait longer.", upid.Raw, err))
	case started && pbsclient.IsUnreachable(err):
		// pbs_network_apply's advice names its pending_changes, which the
		// action's users may not have.
		diags.AddError(summary, fmt.Sprintf("PBS started applying the network changes of node %s (task %s), and "+
			"then the provider lost contact with it while waiting for the task: the new configuration may have cut "+
			"the node off from this address — or the reload ended and the node answers again later. Once it "+
			"answers, `proxmox-backup-manager task log '%s'` on the node, or Administration → Tasks in its web "+
			"interface, shows what the reload did, and the Network Interfaces panel whether anything is still "+
			"pending. If it does not answer at all, check it from its console: PBS does not roll back. %s",
			node, upid.Raw, upid.Raw, err))
	default:
		diags.AddError(summary, networkApplyErrorDetail(client, node, upid, started, err))
	}
}

// describeNetworkChanges says how many lines a unified diff of the network
// configuration adds and removes. The lines that name the two files, at the
// top, are no changes.
func describeNetworkChanges(diff string) string {
	added, removed, header := 0, 0, true
	for line := range strings.SplitSeq(diff, "\n") {
		if header && (strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ ")) {
			continue
		}
		header = false
		switch {
		case strings.HasPrefix(line, "+"):
			added++
		case strings.HasPrefix(line, "-"):
			removed++
		}
	}
	return fmt.Sprintf("%s added, %s removed in /etc/network/interfaces", networkDiffLines(added), networkDiffLines(removed))
}

// networkDiffLines is n lines, in words.
func networkDiffLines(n int) string {
	if n == 1 {
		return "1 line"
	}
	return fmt.Sprintf("%d lines", n)
}
