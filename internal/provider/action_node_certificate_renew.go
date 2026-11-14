package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &nodeCertificateRenewAction{}
	_ action.ActionWithConfigure = &nodeCertificateRenewAction{}
)

// NewNodeCertificateRenewAction returns the pbs_node_certificate_renew
// action.
func NewNodeCertificateRenewAction() action.Action {
	return &nodeCertificateRenewAction{}
}

// nodeCertificateRenewAction has a node renew its certificate with ACME, as
// `proxmox-backup-manager acme cert order` does on the host and PBS's daily
// update does on its own once the certificate is due (see
// internal/pbsclient/acme_renew.go).
//
// The renewal changes the certificate the provider connects to, so it runs
// through ChangeCertificate, as pbs_node_certificate orders one, and reuses
// that resource's checks and messages, which need nothing but the
// provider's configuration: of the node's ACME settings before, of the
// cause of a failed task, and of the certificate PBS's proxy serves after
// (checkProxyLoad).
type nodeCertificateRenewAction struct {
	actionBase
}

// nodeCertificateRenewModel has no `wait`, unlike the actions that start
// other tasks: the provider must wait for the renewal to end, so that it
// reads the new certificate over the connection it trusted before the
// change and trusts it for the rest of the run. An action that did not wait
// would leave the run's later calls failing on a certificate the provider's
// settings do not trust — the refresh of pbs_node_certificate among them —
// and could tell nothing of the outcome, such as the new fingerprint.
type nodeCertificateRenewModel struct {
	Node    types.String `tfsdk:"node"`
	Force   types.Bool   `tfsdk:"force"`
	Timeout types.String `tfsdk:"timeout"`
}

func (a *nodeCertificateRenewAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node_certificate_renew"
}

func (a *nodeCertificateRenewAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	timeout := actionTimeoutAttribute()
	timeout.MarkdownDescription = "How long to wait for the renewal, as a Go duration such as `10m`. Defaults to the " +
		"provider's `task_timeout`. The action always waits: the provider has to read the new certificate before " +
		"it can trust it. When the time runs out, the action fails, and the PBS task goes on — PBS cannot stop an " +
		"ACME order — and installs the certificate if the CA issues it."
	resp.Schema = schema.Schema{
		MarkdownDescription: "Renews the ACME certificate of a Proxmox Backup Server node now: PBS orders a new " +
			"certificate from the CA of the node's ACME account, for the node's ACME domains — both set with " +
			"`pbs_node_acme` —, installs it and has its proxy load it, without restarting; connections open before " +
			"keep the old one. It is what `proxmox-backup-manager acme cert order` does on the host.\n\n" +
			"**PBS renews on its own.** Its daily update renews the certificate once it is due, on a node with ACME " +
			"domains, so this action is for renewing earlier: with `force`, after changing the node's ACME account, " +
			"domains or DNS plugin, or to see that renewal works. Without `force`, PBS renews only a certificate " +
			"that is due — one that expires within a third of its lifetime from PBS 4.1.9 (half of it, for a " +
			"certificate that lives less than ten days, from 4.1.10; three days at least), within 30 days before " +
			"4.1.9 — and the action otherwise succeeds without renewing, saying when the certificate expires. The " +
			"self-signed certificate PBS generates is never due; a forced renewal replaces it with an ACME " +
			"certificate, as `pbs_node_certificate` does when it orders one.\n\n" +
			"Before PBS is asked, the action checks that the node has ACME domains and that its ACME account exists: " +
			"PBS would renew nothing without domains, and fail without the account. A renewal that fails sends " +
			"PBS's ACME error notification, as a failed renewal of the daily update does. While it waits, the " +
			"action reports the lines the task logs; a failure names the cause the task reports, and ends with " +
			"the end of the task's log. PBS writes a renewed certificate even when its proxy cannot load it, and " +
			"ends the task well: the action fails when the proxy still serves the certificate it served before " +
			"the renewal, and warns when that was not the one PBS reported then, as `pbs_node_certificate` " +
			"explains.\n\n" +
			"**The fingerprint changes** with the new certificate. While it renews, the provider keeps a " +
			"connection open that it trusted before, reads the new certificate over it, and trusts it for the rest " +
			"of the run, whatever the provider's TLS settings; it warns when they need changing before the next " +
			"run — a pinned `tls_cert_fingerprint` (or `PBS_TLS_FINGERPRINT`) above all. Whatever else pins the " +
			"old fingerprint fails too: Proxmox VE's PBS storage (`fingerprint` of `proxmox_storage_pbs`), other " +
			"PBS syncing from this one. Trust a certificate of a public CA by the CA instead, as " +
			"`pbs_node_certificate` explains.\n\n" +
			"**With `pbs_node_certificate`.** With `source = \"acme\"`, its next refresh reads the renewed " +
			"certificate into its computed attributes, without planning anything, as after a renewal of the daily " +
			"update. A change of its `triggers` orders a certificate already: do not trigger a forced renewal from " +
			"the same change — new domains, when `triggers` follow them as in its example —, or PBS orders two " +
			"certificates, which both count against the CA's rate limits. Neither PBS nor the provider can tell an " +
			"uploaded certificate from an ordered one — one of a private CA for the node's domains looks the same " +
			"—, and PBS renews whatever certificate the node serves, in its daily update too; so does the " +
			"action:\n\n" +
			"~> On a node with ACME domains that serves a custom certificate — `source = \"custom\"` — a forced " +
			"renewal replaces it with an ACME one, and the next apply of `pbs_node_certificate` uploads the custom " +
			"certificate again. Remove the node's ACME domains to keep a custom certificate, as " +
			"`pbs_node_certificate` warns.\n\n" +
			"Needs `" + certificatesPrivilege + "`, and `" + nodeConfigReadPrivilege + "` to check the node's ACME " +
			"settings.\n\n" + actionRequirementNote,
		Attributes: map[string]schema.Attribute{
			"node": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Node whose certificate to renew: `localhost`, which every PBS answers to, or the " +
					"node's host name. Defaults to the provider's `node`.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 63),
					stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
				},
			},
			"force": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Whether to renew the certificate even when it is not due yet. Defaults to " +
					"`false`: PBS then renews only a certificate that is due, and the action otherwise succeeds without " +
					"renewing. Mind the CA's rate limits.",
			},
			"timeout": timeout,
		},
	}
}

func (a *nodeCertificateRenewAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config nodeCertificateRenewModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = client.Node()
	}
	force := config.Force.ValueBool()
	_, timeout := taskWaitModel{Timeout: config.Timeout}.settings()
	progress := newActionProgress(ctx, resp)

	certificate := &nodeCertificateResource{data: a.data}
	account := certificate.checkACMESettings(ctx, node, "and invoke the action once Terraform has set them: from an "+
		"action_trigger of pbs_node_acme, say, or after an apply.", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// The renewal's task, once PBS has started it, and how waiting for it
	// ended.
	var task *actionTask
	var status pbsclient.TaskStatus
	var waitErr error
	change, err := client.ChangeCertificate(ctx, node, func(ctx context.Context) error {
		upid, err := client.RenewACMECertificate(ctx, node, force)
		if err != nil {
			return err
		}
		task = &actionTask{client: client, upid: upid, what: "Renewal of the certificate of PBS node " + node}
		progress.say("PBS started task %s", upid.Raw)
		status, waitErr = client.WatchTask(ctx, upid, pbsclient.TaskWatch{Timeout: timeout, Progress: progress.taskLog})
		return waitErr
	})

	switch days, notDue := pbsclient.ACMERenewalLeadDays(err); {
	case notDue && !change.Changed() && change.Before.Generated():
		// Valid for a thousand years, it is due only in centuries: PBS's
		// lead time would read as if PBS will see to it.
		progress.say("Not renewed: node %s serves PBS's own self-signed certificate, which is never due; "+
			"force = true orders an ACME one.", node)
		return
	case notDue && !change.Changed():
		validUntil := ""
		if change.Before.NotAfter > 0 {
			validUntil = ", valid until " + time.Unix(change.Before.NotAfter, 0).UTC().Format(time.DateOnly) + ","
		}
		progress.say("Not renewed: the certificate of node %s%s is not due yet; PBS renews it within %d days of its "+
			"expiry. force = true renews it anyway.", node, validUntil, days)
		return
	case err != nil && !change.Changed():
		renewalFailed(ctx, client, task, account.Directory, waitErr, err, &resp.Diagnostics)
		return
	case !change.Changed():
		resp.Diagnostics.AddError("PBS installed no new certificate",
			"PBS renewed the certificate of node "+node+" but still serves the one it had: its ACME domains were "+
				"probably removed meanwhile. Check the task log in PBS (Administration → Tasks).")
		return
	}

	// The proxy checks and warns as for pbs_node_certificate's order: a
	// proxy that kept the certificate it served before fails the action; one
	// that serves what it served before, which PBS did not report then,
	// gets a warning in place of the advice about the provider's TLS
	// settings.
	wrote := "PBS wrote a new certificate for node " + node + ", with SHA-256 fingerprint " + change.After.Fingerprint
	proxy := certificate.checkProxyLoad(ctx, wrote, change, err, "", &resp.Diagnostics)
	if proxy == proxyLoadFailed {
		resp.Diagnostics.AddError("The PBS proxy did not load the renewed certificate", proxyKeptPreviousDetail(wrote))
		return
	}
	if proxy != proxyLoadUnclear {
		// recordChange warns as pbs_node_certificate does after an order:
		// about a certificate the provider could not confirm, a task that
		// failed after it wrote the certificate, and the provider's TLS
		// settings. The state it fills is the resource's, which an action has
		// none of.
		var discarded nodeCertificateModel
		certificate.recordChange(node, change, err, "task", &discarded, &resp.Diagnostics)
	}
	if err == nil && task != nil && status.ExitStatus != "OK" {
		resp.Diagnostics.AddWarning(task.what+" ended with warnings",
			fmt.Sprintf("PBS task %s ended with %s.%s", task.upid.Raw, status.ExitStatus, task.logTail(ctx)))
	}
	if change.Unconfirmed == nil {
		validUntil := ""
		if change.After.NotAfter > 0 {
			validUntil = "; the new one is valid until " + time.Unix(change.After.NotAfter, 0).UTC().Format(time.DateOnly)
		}
		progress.say("PBS renewed the certificate of node %s%s", node, validUntil)
		if proxy != proxyLoadUnclear {
			// The warning names it, with the advice to pin it nowhere yet.
			progress.say("New SHA-256 fingerprint: %s", change.After.Fingerprint)
		}
	}
}

// renewalFailed explains why a renewal changed nothing: PBS refused it, its
// task failed, the action stopped waiting for the task, or the certificate
// could not be read after it. task is nil when PBS started none, and
// waitErr is how waiting for it ended; err is the whole error, and
// directory the CA's, or "". pbs_node_certificate's orderFailed does the
// same for an order.
func renewalFailed(ctx context.Context, client *pbsclient.Client, task *actionTask, directory string, waitErr, err error, diags *diag.Diagnostics) {
	var taskErr *pbsclient.TaskError
	switch {
	case task == nil:
		diags.AddError("Unable to renew the certificate of the PBS node", orderErrorDetail(client, directory, err))
	case errors.As(waitErr, &taskErr):
		// The certificate PBS reports is unchanged: the task failed before
		// PBS wrote a new one — the CA issued none, or PBS could not write
		// it; after "error writing certificate file", PBS had replaced the
		// key only —, or the certificate could not be read after it.
		// orderErrorDetail names the cause from the task's exit status.
		diags.AddError(task.what+" failed", orderErrorDetail(client, directory, err)+task.logTail(ctx))
	case pbsclient.IsTaskTimeout(waitErr):
		// actionTask.reportError would offer `wait = false`, which this
		// action does not have.
		detail := fmt.Sprintf("The action stopped waiting for PBS task %s, which was still running: %s.", task.upid.Raw, waitErr)
		if ctx.Err() != nil {
			detail = fmt.Sprintf("Terraform stopped the action while PBS task %s was running.", task.upid.Raw)
		}
		detail += " The task goes on in PBS, which cannot stop an ACME order, and installs the new certificate if " +
			"the CA issues it; Administration → Tasks in its web interface shows how it ends. The provider then " +
			"trusts the new certificate only as its TLS settings say: calls later in this run may fail, and a " +
			"pinned tls_cert_fingerprint needs the new fingerprint before the next run."
		if ctx.Err() == nil {
			detail += " Raise the action's `timeout` to wait longer."
		}
		diags.AddError(task.what+" did not finish", detail)
	case waitErr != nil:
		task.reportError(ctx, waitErr, diags)
	default:
		// The task ended well, but the certificate could not be read after
		// it, over the connection the provider trusted before.
		diags.AddError("Unable to read the renewed certificate of the PBS node",
			fmt.Sprintf("PBS task %s ended well, but reading the node's certificate afterwards failed, so the "+
				"provider does not know whether PBS installed a new one, and does not trust one: calls later in this "+
				"run may fail. Check the node's certificate (Configuration → Certificates) and the provider's TLS "+
				"settings. %s", task.upid.Raw, apiErrorDetail(client, certificatesPrivilege, err)))
	}
}
