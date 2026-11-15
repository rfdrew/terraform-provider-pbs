package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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

var (
	_ action.Action                   = &serviceAction{}
	_ action.ActionWithConfigure      = &serviceAction{}
	_ action.ActionWithValidateConfig = &serviceAction{}
)

// NewServiceReloadAction returns the pbs_service_reload action.
func NewServiceReloadAction() action.Action { return &serviceAction{kind: serviceReload} }

// NewServiceRestartAction returns the pbs_service_restart action.
func NewServiceRestartAction() action.Action { return &serviceAction{kind: serviceRestart} }

// NewServiceStartAction returns the pbs_service_start action.
func NewServiceStartAction() action.Action { return &serviceAction{kind: serviceStart} }

// serviceAction has PBS reload, restart or start one of the services it
// controls, as the Services panel of its web interface does; see
// internal/pbsclient/services.go for what PBS does.
//
// Reload is the way the documentation leads to, as PBS does: the panel's
// Restart button sends reload "to avoid disruptions" (www/
// ServerAdministration.js), PBS turns a restart of its proxy into a reload,
// and a package upgrade reloads both daemons (debian/postinst). A daemon of
// PBS that reloads hands its listening socket to a new process and lets the
// old one finish its connections and tasks; a restart kills them, since
// neither daemon handles SIGTERM.
//
// There is no stop: PBS cannot disable a service, which starts again at
// boot; a stopped proxy takes the API away for good; and PBS refuses to
// stop its API daemon. Restarting the API daemon is refused too, before
// PBS is asked: PBS runs the command inside that daemon, which the restart
// kills along with the command and every other task it runs, and whose
// task then ends without a result.
//
// The reload of the proxy is the dangerous one, and the one Terraform
// needs: it is how a change of the cipher lists of pbs_node_config takes
// effect. The new proxy loads proxy.pem, proxy.key and the cipher lists
// anew, and does not start when it cannot, which leaves PBS without its API
// until someone fixes the files on the host. So before reloading it the
// action checks what it can see: that the proxy presents the certificate
// of proxy.pem — a proxy that failed to load a new certificate goes on
// presenting the old one (src/bin/proxmox-backup-proxy.rs, the
// reload-certificate command, only logs the failure) —, that OpenSSL takes
// the @ commands and operators of the TLS 1.2 cipher list, and that the
// chain meets the security level that list sets. PBS's API has OpenSSL
// check the rest of the list, such as whether its names match any cipher,
// before it stores it (save_config in pbs-config/src/node.rs,
// src/config/node.rs before 4.1.7); a list written into node.cfg on the
// host gets no such check, and the provider cannot make it, since which
// names match depends on the OpenSSL that reads the list. It holds the lock
// of node.cfg and the client's certificate lock meanwhile, in this order,
// which nothing takes the other way round: no write of the cipher lists and
// no certificate change of the same run may come between the checks and
// the reload, nor run over the connections the reload closes.
type serviceAction struct {
	actionBase
	kind serviceCommand
}

// serviceCommand is what sets the three actions apart.
type serviceCommand struct {
	// name follows the provider's type name: "service_reload".
	name string
	// command is what PBS is asked to run.
	command string
	// verb, title and done say what the action does: "reload", "Reload",
	// "reloaded".
	verb, title, done string
	// checksProxy is set for the commands that reload
	// proxmox-backup-proxy, which the action checks first, and which take
	// the attributes that skip the checks.
	checksProxy bool
}

var (
	serviceReload = serviceCommand{name: "service_reload", command: pbsclient.ServiceReload,
		verb: "reload", title: "Reload", done: "reloaded", checksProxy: true}
	serviceRestart = serviceCommand{name: "service_restart", command: pbsclient.ServiceRestart,
		verb: "restart", title: "Restart", done: "restarted", checksProxy: true}
	serviceStart = serviceCommand{name: "service_start", command: pbsclient.ServiceStart,
		verb: "start", title: "Start", done: "started"}
)

// serviceStartModel is the configuration of pbs_service_start, and the part
// every service action has. None of them has `wait`: the action checks
// afterwards that the service runs, and a reload of the proxy must be
// waited out under the locks it holds.
type serviceStartModel struct {
	Service types.String `tfsdk:"service"`
	Node    types.String `tfsdk:"node"`
	Timeout types.String `tfsdk:"timeout"`
}

// serviceReloadModel is the configuration of pbs_service_reload and
// pbs_service_restart.
type serviceReloadModel struct {
	serviceStartModel
	SkipCertificateMatch types.Bool `tfsdk:"skip_certificate_match"`
	SkipChecks           types.Bool `tfsdk:"skip_checks"`
}

// serviceSettleTime is how long the action waits, once the task has ended,
// for systemd to report the service as running, and serviceSettlePoll how
// often it looks meanwhile: a service that stops right after starting is
// caught then. Variables for tests.
var (
	serviceSettleTime = 15 * time.Second
	serviceSettlePoll = time.Second
)

// serviceHandoverGrace is how long the status polls of a reload of PBS's
// API daemon may fail with an error from PBS before the action gives up on
// the task. The task runs in the old daemon, and the proxy asks that
// daemon, over its command socket, whether the task still runs
// (worker_is_active in proxmox-rest-server/src/worker_task.rs): once the
// task has ended, the old daemon closes the socket (last_worker_future)
// and exits, and a poll in between fails. A variable for tests.
var serviceHandoverGrace = 10 * time.Second

// serviceHandoverPoll is how long the action waits before it polls again
// after such an error.
const serviceHandoverPoll = 500 * time.Millisecond

// debianSecurityLevel is the OpenSSL security level of Debian's
// configuration, which the proxy loads its certificate at unless
// ciphers_tls_1_2 sets another one.
const debianSecurityLevel = 2

// serviceModifyPrivilege and serviceAuditPrivilege are what the commands
// and the state of a service need.
func serviceModifyPrivilege(service string) string {
	return "Sys.Modify on /system/services/" + service
}

func serviceAuditPrivilege(service string) string {
	return "Sys.Audit on /system/services/" + service
}

// The descriptions the three actions share.
const (
	serviceListNote = "PBS controls a fixed set of services: `proxmox-backup`, its API daemon; " +
		"`proxmox-backup-proxy`, the proxy that serves the API and the web interface on port 8007; `sshd`, " +
		"`systemd-journald`, `cron`, `postfix` and `chrony`. The `pbs_services` data source shows their state."

	serviceProxyWarning = "!> **A proxy that cannot start leaves PBS without its API.** The reloaded proxy loads its " +
		"certificate, `/etc/proxmox-backup/proxy.pem` and `proxy.key`, and the cipher lists of `node.cfg` anew, and " +
		"when it cannot, it does not start at all: the web interface and the API, this provider included, are gone " +
		"until the files are fixed on the host, and backups the old process still runs may be stopped with it. " +
		"Before it reloads the proxy, the action therefore checks that the proxy presents the certificate of " +
		"`proxy.pem` — a proxy that failed to load an uploaded or renewed certificate goes on presenting the old one " +
		"— and that every certificate of the chain meets OpenSSL's security level: the last `@SECLEVEL` of " +
		"`ciphers_tls_1_2` of `pbs_node_config`, or 2, Debian's default, when it sets none; OpenSSL ignores " +
		"`@SECLEVEL` in `ciphers_tls_1_3`. Level 2 asks for RSA keys of 2048 bits, EC keys of 224 bits and no SHA-1 " +
		"signatures; level 3 for RSA keys of 3072 bits, EC keys of 256 bits and SHA-256; level 4 for RSA keys of " +
		"7680 bits, EC keys of 384 bits and SHA-384. The action refuses to reload when either check fails, and when " +
		"OpenSSL refuses an `@` command or an operator of `ciphers_tls_1_2`, as it does a level that is not one " +
		"digit from 0 to 5, which keeps the proxy from starting whatever its certificate. PBS's API has OpenSSL " +
		"check the rest of the list, such as whether its names match any cipher, before it stores it; a list " +
		"written into `node.cfg` on the host gets no such check. `skip_certificate_match` skips the first check, " +
		"for a reverse proxy or a load balancer in front of PBS, or a forward proxy that inspects TLS, that " +
		"presents a certificate of its own, and `skip_checks` skips them all. " +
		"No check can see `proxy.key`, nor files changed on the host. While the proxy starts its new process, " +
		"the action waits up to two minutes for it to answer again, and holds back this provider's changes of " +
		"`node.cfg` and of the node's certificate until it does."

	serviceSystemdNote = "Services are systemd units, and PBS controls them through systemd only: PBS in a " +
		"container without systemd, such as the community Docker images, has none to control, and the action " +
		"fails, saying so. It fails the same way where PBS's proxy, which reads the state of services as user " +
		"`backup`, cannot reach systemd: without D-Bus, which `systemctl` needs when it does not run as root. " +
		"There is no action that stops a service: PBS cannot disable one, so it starts again at " +
		"boot; stopping the proxy takes the API away until someone starts it on the host; and PBS refuses to stop " +
		"its API daemon."
)

func (a *serviceAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + a.kind.name
}

func (a *serviceAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	serviceDescription := "ID of the service, as PBS names it: one of `" + strings.Join(pbsclient.ServiceIDs, "`, `") +
		"`, as `pbs_services` lists them. `sshd` is systemd's alias of the unit `ssh.service`."
	var intro string
	switch a.kind.command {
	case pbsclient.ServiceReload:
		intro = "Reloads a system service of a Proxmox Backup Server node, as the **Restart** button of its Services " +
			"panel (Administration → Services) does: PBS runs `systemctl try-reload-or-restart`, which has the " +
			"service read its configuration again where the service can, restarts it where it cannot, and leaves a " +
			"service that is not running stopped — the action then warns, and does nothing. " + serviceListNote +
			"\n\n" +
			"PBS's own daemons reload without dropping work: a new process takes over the listening socket, while " +
			"the old one finishes the connections and tasks it has — backups too. Reloading the proxy, " +
			"`proxmox-backup-proxy`, is how a change of `ciphers_tls_1_2` or `ciphers_tls_1_3` of `pbs_node_config` " +
			"takes effect; the example triggers the reload from them. A reload keeps the environment of the old " +
			"process, so a change to an override of the systemd unit needs `systemctl restart` on the host.\n\n" +
			serviceProxyWarning
	case pbsclient.ServiceRestart:
		serviceDescription += " Not `proxmox-backup`, which the action refuses to restart."
		intro = "Restarts a system service of a Proxmox Backup Server node, as `systemctl restart` does: systemd " +
			"stops the service and starts it again, or starts it when it is not running. " + serviceListNote + "\n\n" +
			"Prefer `pbs_service_reload`, which the **Restart** button of the web interface runs: a restart stops the " +
			"service first, while a reload has a service that can read its configuration again do so without " +
			"stopping. PBS restarts its proxy, `proxmox-backup-proxy`, by reloading it, so that the backups and tasks " +
			"it runs go on, and the action checks the proxy first, as below. The action refuses to restart PBS's API " +
			"daemon, `proxmox-backup`: PBS runs service commands inside that daemon, so the restart would kill the " +
			"command along with every task the daemon runs — creating a datastore, ordering a certificate, updating " +
			"packages —, and its outcome would never be known. Reload it with `pbs_service_reload` instead, or " +
			"restart it on the host.\n\n" + serviceProxyWarning
	default:
		intro = "Starts a system service of a Proxmox Backup Server node that is not running, as `systemctl start` " +
			"does: one stopped on the host, say, or one that failed. A service that runs is left alone, and the " +
			"action says so. " + serviceListNote + "\n\n" +
			"The action cannot bring back PBS's own daemons: the proxy, `proxmox-backup-proxy`, runs whenever the " +
			"API answers, and it hands every service command to the API daemon, `proxmox-backup`, which must run " +
			"for any command to run. When one of them is down, start it on the host."
	}
	checks := "Before PBS is asked, the action reads the state of the service, and fails for a service that is not " +
		"installed (`unit_state` `not-found`) or is masked, which systemd refuses to " + a.kind.verb + ". It waits " +
		"for PBS's task, and then up to 15 seconds for systemd to report the service as running. " +
		"systemd's own messages are not in the task's log but in the journal of PBS's API daemon, which runs " +
		"`systemctl` (`journalctl -u proxmox-backup` on the host)."
	privileges := "Needs `Sys.Modify on /system/services/<service>`, and `Sys.Audit` on the same path to read the " +
		"state of the service before and after; without it, the action runs the command unchecked."
	if a.kind.checksProxy {
		privileges += " Checking the proxy before reloading it needs `" + certificatesPrivilege + "` and `" +
			nodeConfigReadPrivilege + "` too."
	}

	timeout := actionTimeoutAttribute()
	timeout.MarkdownDescription = "How long to wait for PBS's task, as a Go duration such as `5m`. Defaults to the " +
		"provider's `task_timeout`. The action always waits, to check afterwards that the service runs. When the " +
		"time runs out, the action fails, and systemd goes on with the " + a.kind.verb + "."
	attributes := map[string]schema.Attribute{
		"service": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: serviceDescription,
			Validators:          []validator.String{stringvalidator.OneOf(pbsclient.ServiceIDs...)},
		},
		"node":    nodeAttributeOfAction("whose service to " + a.kind.verb),
		"timeout": timeout,
	}
	if a.kind.checksProxy {
		attributes["skip_certificate_match"] = schema.BoolAttribute{
			Optional: true,
			MarkdownDescription: "Whether to reload `proxmox-backup-proxy` even when the certificate it presents is " +
				"not that of `/etc/proxmox-backup/proxy.pem`. Set it when something between the provider and PBS " +
				"presents a certificate of its own — a reverse proxy or a load balancer in front of PBS, or a forward " +
				"proxy the provider reaches PBS through (`HTTPS_PROXY`) that inspects TLS —: the provider then sees that " +
				"one, never PBS's. The check of the security level still runs. Defaults to `false`. Other services " +
				"ignore it.",
		}
		attributes["skip_checks"] = schema.BoolAttribute{
			Optional: true,
			MarkdownDescription: "Whether to reload `proxmox-backup-proxy` without checking its certificate and " +
				"cipher lists first — neither the certificate it presents, nor the `@` commands and operators of " +
				"`ciphers_tls_1_2`, nor the security level of the chain —, and without the privileges the checks " +
				"need. Defaults to `false`. Other services ignore it.",
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: intro + "\n\n" + checks + "\n\n" + serviceSystemdNote + "\n\n" + privileges + "\n\n" +
			actionRequirementNote,
		Attributes: attributes,
	}
}

// ValidateConfig refuses to restart PBS's API daemon, which PBS would do
// from inside it.
func (a *serviceAction) ValidateConfig(ctx context.Context, req action.ValidateConfigRequest, resp *action.ValidateConfigResponse) {
	if a.kind.command != pbsclient.ServiceRestart {
		return
	}
	var service types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("service"), &service)...)
	if !service.IsNull() && !service.IsUnknown() && service.ValueString() == pbsclient.ServiceAPI {
		addAPIDaemonRestartError(&resp.Diagnostics)
	}
}

// addAPIDaemonRestartError explains why the API daemon is not restarted.
func addAPIDaemonRestartError(diags *diag.Diagnostics) {
	diags.AddAttributeError(path.Root("service"), "PBS's API daemon cannot be restarted through its API",
		"PBS runs service commands in its API daemon, proxmox-backup, so restarting it would kill the command along "+
			"with every task the daemon runs — creating a datastore or a ZFS pool, ordering a certificate, updating "+
			"packages —, and the outcome would never be known. Use pbs_service_reload, which starts a new daemon and "+
			"lets the old one finish its tasks, as the Restart button of the web interface does; or run `systemctl "+
			"restart proxmox-backup` on the host.")
}

func (a *serviceAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config serviceReloadModel
	if a.kind.checksProxy {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	} else {
		resp.Diagnostics.Append(req.Config.Get(ctx, &config.serviceStartModel)...)
	}
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	_, timeout := taskWaitModel{Timeout: config.Timeout}.settings()
	s := &serviceInvocation{
		ctx:        ctx,
		client:     client,
		kind:       a.kind,
		node:       invokedNode(client, config.Node),
		service:    config.Service.ValueString(),
		timeout:    timeout,
		skipMatch:  config.SkipCertificateMatch.ValueBool(),
		skipChecks: config.SkipChecks.ValueBool(),
		progress:   newActionProgress(ctx, resp),
		diags:      &resp.Diagnostics,
	}
	s.run()
}

// serviceInvocation is one invocation of a service action.
type serviceInvocation struct {
	ctx        context.Context
	client     *pbsclient.Client
	kind       serviceCommand
	node       string
	service    string
	timeout    time.Duration
	skipMatch  bool
	skipChecks bool
	progress   *actionProgress
	diags      *diag.Diagnostics
	// upid is the command's task, once PBS has started it.
	upid pbsclient.UPID
}

func (s *serviceInvocation) run() {
	switch {
	case !pbsclient.IsServiceID(s.service):
		// A value known only at apply time has passed the validator.
		s.diags.AddAttributeError(path.Root("service"), "Unknown PBS service "+strconv.Quote(s.service),
			"PBS controls the services "+strings.Join(pbsclient.ServiceIDs, ", ")+" only. It hands any other name "+
				"to systemctl as it is, as root, so the provider refuses it.")
		return
	case s.kind.command == pbsclient.ServiceRestart && s.service == pbsclient.ServiceAPI:
		addAPIDaemonRestartError(s.diags)
		return
	}

	before, readable := s.readState()
	if s.diags.HasError() || (readable && !s.precheck(before)) {
		return
	}

	finished := false
	if s.reloadsProxy() {
		// The locks are this provider's only: they keep its own writes of
		// node.cfg and certificate changes out until the proxy answers.
		_ = s.client.WithConfigLock(pbsclient.ConfigNode, func() error {
			return s.client.WithCertificateLock(func() error {
				if s.checkProxy() {
					finished = s.execute()
				}
				return nil
			})
		})
	} else {
		finished = s.execute()
	}
	if finished {
		s.confirm(readable)
	}
}

// reloadsProxy reports whether the command reloads proxmox-backup-proxy:
// a reload, or a restart, which PBS turns into one.
func (s *serviceInvocation) reloadsProxy() bool {
	return s.service == pbsclient.ServiceProxy && s.kind.checksProxy
}

// readState reads the state of the service before the command. readable
// is false when the provider may not read it, and the command runs
// unchecked then; an error is in diags.
func (s *serviceInvocation) readState() (pbsclient.Service, bool) {
	state, ok, err := s.client.ServiceState(s.ctx, s.node, s.service)
	summary := fmt.Sprintf("Unable to read the state of service %s on PBS node %s", s.service, s.node)
	var apiErr *pbsclient.Error
	switch {
	case pbsclient.IsForbidden(err):
		tflog.Debug(s.ctx, "the provider may not read the state of the PBS service", map[string]any{"error": err.Error()})
		s.progress.say("cannot read the state of service %s (needs %s); running the command without checking it",
			s.service, serviceAuditPrivilege(s.service))
		return pbsclient.Service{}, false
	case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest &&
		strings.HasPrefix(apiErr.Message, "unknown service name"):
		s.diags.AddError(summary, fmt.Sprintf("This PBS does not control service %s: %s. PBS 4 controls %s.",
			s.service, apiErr.Message, strings.Join(pbsclient.ServiceIDs, ", ")))
	case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest:
		s.diags.AddError(summary, fmt.Sprintf("PBS asks systemd about its services, and answered: %s. %s",
			apiErr.Message, serviceNoSystemd))
	case err != nil:
		s.diags.AddError(summary, "The action reads the state of the service before it runs the command. "+
			apiErrorDetail(s.client, serviceAuditPrivilege(s.service), err))
	case !ok:
		s.diags.AddError(summary, "PBS answered no state: `systemctl show` gave no description of the unit. "+
			serviceNoSystemd)
	default:
		return state, true
	}
	return pbsclient.Service{}, false
}

// serviceNoSystemd explains what PBS needs to control services. PBS reads
// their state in its proxy, as user backup, with `systemctl show`, whose
// output it parses without looking at its exit status
// (src/api2/node/services.rs, get_full_service_state; proxmox-backup
// 7c86c5ad5, after 4.2.11): systemctl reaches systemd over D-Bus unless it
// runs as root, so without D-Bus PBS reads nothing, as without systemd, and
// answers no state, while the commands, which its API daemon runs as root,
// would work.
const serviceNoSystemd = "PBS controls services through systemd only, and reads their state in its proxy, as " +
	"user backup, with `systemctl show`. Either the node runs without systemd, as PBS in a Docker container may, " +
	"and has no services the provider can control; or systemctl cannot reach systemd for that user — without " +
	"D-Bus, which systemctl needs when it does not run as root (install the `dbus` package, as Debian does by " +
	"default, or run `systemctl status dbus` on the host)."

// precheck decides from the state of the service whether to run the
// command, and says why not.
func (s *serviceInvocation) precheck(before pbsclient.Service) bool {
	switch {
	case before.UnitState == pbsclient.ServiceNotFound:
		s.diags.AddError(fmt.Sprintf("Service %s is not installed on PBS node %s", s.service, s.node),
			fmt.Sprintf("systemd knows no unit for %s (unit state not-found), so there is nothing to %s. %s",
				s.service, s.kind.verb, serviceNotInstalledNote))
	case before.UnitState == pbsclient.ServiceMasked:
		s.diags.AddError(fmt.Sprintf("Service %s is masked on PBS node %s", s.service, s.node),
			fmt.Sprintf("systemd refuses to start, restart or reload a masked unit, so the %s would fail. Unmask it "+
				"on the host first, with `systemctl unmask` and the name of its unit.", s.kind.verb))
	case s.kind.command == pbsclient.ServiceReload && before.Stopped():
		s.diags.AddWarning(fmt.Sprintf("Service %s is not running on PBS node %s", s.service, s.node),
			fmt.Sprintf("systemd reports it as %s. A reload leaves a service that is not running stopped — PBS runs "+
				"`systemctl try-reload-or-restart` —, so the action did nothing. pbs_service_restart or "+
				"pbs_service_start starts it.", before.State))
	case s.kind.command == pbsclient.ServiceStart && before.Running():
		s.progress.say("systemd reports service %s on node %s as %s already; nothing to start", s.service, s.node, before.State)
	default:
		return true
	}
	return false
}

// serviceNotInstalledNote says which services a node may lack.
const serviceNotInstalledNote = "A PBS installed from its ISO has every service PBS lists, as a rule; one installed on Debian " +
	"may lack cron and chrony, which the proxmox-backup-server package does not depend on, and systemd knows sshd, " +
	"an alias of ssh.service, only while ssh.service is enabled."

// checkProxy checks proxmox-backup-proxy before reloading it, as far as the
// configuration asks, and says why it refuses.
func (s *serviceInvocation) checkProxy() bool {
	if s.skipChecks {
		s.progress.say("skip_checks = true: reloading proxmox-backup-proxy without checking its certificate and cipher lists")
		return true
	}
	cert, err := s.client.NodeProxyCertificate(s.ctx, s.node)
	if err != nil {
		s.proxyCheckFailed("reading its certificate", certificatesPrivilege, err)
		return false
	}
	if s.skipMatch {
		s.progress.say("skip_certificate_match = true: not comparing the certificate the proxy presents with proxy.pem")
	} else if !s.matchesPresented(cert) {
		return false
	}
	settings, _, err := s.client.GetNodeSettings(s.ctx, s.node)
	if err != nil {
		s.proxyCheckFailed("reading its cipher lists", nodeConfigReadPrivilege, err)
		return false
	}
	level, command, err := proxySecurityLevel(settings)
	if err != nil {
		s.diags.AddError("OpenSSL refuses PBS's cipher list for TLS 1.2",
			fmt.Sprintf("ciphers-tls-1.2 in /etc/proxmox-backup/node.cfg of node %s is %q, and %s. "+
				"proxmox-backup-proxy sets that list before it loads its certificate, so a reloaded one would not "+
				"start whatever the certificate, leaving PBS without its API and web interface. PBS's API refuses "+
				"such a list, so it was written into node.cfg on the host: fix it there, or set ciphers_tls_1_2 of "+
				"pbs_node_config, before reloading; `skip_checks = true` reloads anyway.",
				s.node, settings.CiphersTLS12, err))
		return false
	}
	chain, err := pbsclient.ParseCertificatesPEM(cert.PEM)
	if err != nil {
		s.diags.AddError("Unable to check PBS's certificate against its cipher lists",
			fmt.Sprintf("The action checks that the certificate chain proxmox-backup-proxy loads anew meets "+
				"OpenSSL's security level, since a proxy that cannot load it does not start again, and the provider "+
				"cannot parse /etc/proxmox-backup/proxy.pem of node %s: %s. Set `skip_checks = true` to reload "+
				"without checking.", s.node, err))
		return false
	}
	if weak := pbsclient.CheckChainSecurityLevel(chain, level); len(weak) > 0 {
		problems := make([]string, 0, len(weak))
		for _, w := range weak {
			problems = append(problems, w.String())
		}
		// Below Debian's default, the provider does not advise lowering the
		// level further.
		remedy := "Install a certificate with stronger keys and signatures"
		if command != "" && level > debianSecurityLevel {
			remedy = "Lower or remove the security level (" + command + " in ciphers_tls_1_2 of pbs_node_config), " +
				"or install a certificate with stronger keys and signatures,"
		}
		s.diags.AddError("PBS's certificate is too weak for the proxy's security level",
			fmt.Sprintf("proxmox-backup-proxy loads its certificate chain at OpenSSL's security level %d (%s), "+
				"which asks for %s. In /etc/proxmox-backup/proxy.pem of node %s, %s. The running proxy loaded its "+
				"certificate before — under the cipher lists it had then, or before proxy.pem changed —; a reloaded "+
				"one would not start with this chain, leaving PBS without its API and web interface. %s before "+
				"reloading; `skip_checks = true` reloads anyway.",
				level, securityLevelSource(command), pbsclient.SecurityLevelRequirement(level), s.node,
				strings.Join(problems, "; "), remedy))
		return false
	}
	s.progress.say("the certificate chain of proxy.pem meets OpenSSL's security level %d (%s)", level,
		securityLevelSource(command))
	return true
}

// matchesPresented checks that the proxy presents the certificate of
// proxy.pem, and says why it refuses otherwise. Without a TLS transport of
// its own, as in tests, the client cannot look, and the check passes.
func (s *serviceInvocation) matchesPresented(cert pbsclient.CertificateInfo) bool {
	file, err := pbsclient.NormaliseFingerprint(cert.Fingerprint)
	if err != nil {
		s.proxyCheckFailed("reading the fingerprint of its certificate", "", err)
		return false
	}
	presented, err := s.client.PresentedFingerprint(s.ctx)
	switch {
	case errors.Is(err, pbsclient.ErrNoTLSTransport):
		tflog.Debug(s.ctx, "cannot look at the certificate the PBS proxy presents", map[string]any{"error": err.Error()})
		return true
	case err != nil:
		s.proxyCheckFailed("looking at the certificate it presents", "", err)
		return false
	case presented != file:
		validUntil := ""
		if cert.NotAfter > 0 {
			validUntil = ", valid until " + time.Unix(cert.NotAfter, 0).UTC().Format(time.DateOnly)
		}
		s.diags.AddError("PBS's proxy presents another certificate than its certificate file",
			fmt.Sprintf("The proxy of node %s presents the certificate with SHA-256 fingerprint %s, but "+
				"/etc/proxmox-backup/proxy.pem holds %s (%s%s). A reload makes the proxy load proxy.pem and proxy.key "+
				"anew. A proxy that fails to load a certificate — a key that is not the certificate's, a key too weak "+
				"for the security level of its cipher lists — goes on presenting the old one, and after a reload it "+
				"does not start at all: PBS is left without its API and web interface until the files are fixed on "+
				"the host. `journalctl -u proxmox-backup-proxy` on the host shows \"error reloading certificate\" "+
				"then; pbs_node_certificate, which checks a certificate and its key, can upload them again. If "+
				"something between the provider and PBS presents a certificate of its own — a reverse proxy or a load "+
				"balancer in front of PBS, or a forward proxy that inspects TLS (HTTPS_PROXY) —, that is the one the "+
				"provider sees: set `skip_certificate_match = true`.",
				s.node, pbsclient.FormatFingerprint(presented), cert.Fingerprint, cert.Subject, validUntil))
		return false
	}
	return true
}

// proxyCheckFailed explains a check of the proxy that could not be made.
func (s *serviceInvocation) proxyCheckFailed(what, privilege string, err error) {
	advice := "Set `skip_checks = true` to reload without checking."
	if pbsclient.IsForbidden(err) {
		advice = "Grant the privilege, or set `skip_checks = true` to reload without checking."
	}
	s.diags.AddError("Unable to check PBS's proxy before reloading it",
		fmt.Sprintf("The action checks the certificate and the cipher lists proxmox-backup-proxy loads anew before "+
			"it reloads the proxy, since a proxy that cannot load them does not start again, and %s failed. %s\n\n%s",
			what, apiErrorDetail(s.client, privilege, err), advice))
}

// proxySecurityLevel returns the OpenSSL security level the proxy loads its
// certificate chain at, and the command that sets it: the last @SECLEVEL of
// ciphers_tls_1_2, or none for Debian's default, when that list sets none.
// The proxy sets the list before it loads proxy.pem
// (TlsAcceptorBuilder::build in proxmox-rest-server/src/connection.rs,
// proxmox 601a11e6), so a level below Debian's is the one the chain must
// meet. ciphers_tls_1_3 never counts: the proxy hands it to
// SSL_CTX_set_ciphersuites, which takes names of cipher suites only and
// skips @SECLEVEL as one it does not know. The error says why OpenSSL
// refuses ciphers_tls_1_2, which keeps the proxy from starting whatever its
// certificate.
func proxySecurityLevel(settings pbsclient.NodeSettings) (level int, command string, err error) {
	level, command, err = pbsclient.CipherListSecurityLevel(settings.CiphersTLS12)
	if err == nil && command == "" {
		level = debianSecurityLevel
	}
	return level, command, err
}

// securityLevelSource says where the level of proxySecurityLevel comes from.
func securityLevelSource(command string) string {
	if command == "" {
		return "Debian's default; ciphers_tls_1_2 of node.cfg sets none"
	}
	return command + " in ciphers_tls_1_2"
}

// execute has PBS run the command and waits for its task. It reports
// whether the task ended without an error; why not is in diags.
func (s *serviceInvocation) execute() bool {
	if s.service == pbsclient.ServiceProxy && s.kind.command == pbsclient.ServiceRestart {
		s.progress.say("PBS reloads proxmox-backup-proxy rather than restarting it, so that the backups and tasks it runs go on")
	}
	upid, err := s.client.StartServiceCommand(s.ctx, s.node, s.service, s.kind.command)
	if err != nil {
		detail := apiErrorDetail(s.client, serviceModifyPrivilege(s.service), err)
		var apiErr *pbsclient.Error
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest {
			detail += "\n\nPBS's proxy hands service commands to its API daemon, proxmox-backup; if the error is " +
				"about a connection, that daemon is not running, and only the host can start it (`systemctl start " +
				"proxmox-backup`)."
		}
		s.diags.AddError(fmt.Sprintf("Unable to %s service %s on PBS node %s", s.kind.verb, s.service, s.node), detail)
		return false
	}
	s.upid = upid
	s.progress.say("PBS started task %s", upid.Raw)
	if s.reloadsProxy() {
		s.progress.say("proxmox-backup-proxy starts a new process; waiting for it to answer again")
	}
	status, err := s.watch()
	if err != nil {
		s.reportError(err)
		return false
	}
	if status.ExitStatus != "OK" {
		task := actionTask{client: s.client, upid: upid}
		s.diags.AddWarning(fmt.Sprintf("%s of service %s on PBS node %s ended with warnings", s.kind.title, s.service, s.node),
			fmt.Sprintf("PBS task %s ended with %s.%s", upid.Raw, status.ExitStatus, task.logTail(s.ctx)))
	}
	return true
}

// watch waits for the command's task, through outages of up to
// actionOutageGrace: the reloaded proxy answers nothing while its new
// process starts. For a reload of PBS's API daemon, it also polls again
// for serviceHandoverGrace when a poll fails with an error from PBS, which
// may add that much to the timeout.
func (s *serviceInvocation) watch() (pbsclient.TaskStatus, error) {
	handover := s.service == pbsclient.ServiceAPI && s.kind.command == pbsclient.ServiceReload
	start := time.Now()
	var failing time.Time
	for {
		timeout := s.timeout
		if timeout > 0 {
			// What is left of it; never zero, which would be the
			// provider's task_timeout.
			timeout = max(s.timeout-time.Since(start), time.Millisecond)
		}
		status, err := s.client.WatchTask(s.ctx, s.upid, pbsclient.TaskWatch{
			Timeout: timeout, OutageGrace: actionOutageGrace, Progress: s.progress.taskLog,
		})
		var apiErr *pbsclient.Error
		if !handover || !errors.As(err, &apiErr) || pbsclient.IsForbidden(err) || pbsclient.IsUnauthorized(err) {
			return status, err
		}
		if failing.IsZero() {
			failing = time.Now()
		}
		if time.Since(failing) >= serviceHandoverGrace {
			return status, err
		}
		tflog.Debug(s.ctx, "PBS could not tell the state of the reload of its API daemon; polling again",
			map[string]any{"upid": s.upid.Raw, "error": err.Error()})
		select {
		case <-time.After(serviceHandoverPoll):
		case <-s.ctx.Done():
			return status, err
		}
	}
}

// reportError explains why waiting for the command's task failed.
func (s *serviceInvocation) reportError(err error) {
	summary := fmt.Sprintf("Unable to %s service %s on PBS node %s", s.kind.verb, s.service, s.node)
	unfinished := fmt.Sprintf("%s of service %s on PBS node %s did not finish", s.kind.title, s.service, s.node)
	task := actionTask{client: s.client, upid: s.upid}
	var taskErr *pbsclient.TaskError
	var untrusted *pbsclient.UntrustedCertificateError
	switch {
	case errors.As(err, &taskErr) && strings.Contains(taskErr.ExitStatus, "exit status: 5"):
		// systemctl's exit status for a unit systemd does not know.
		s.diags.AddError(summary, fmt.Sprintf("PBS task %s ended with an error: %s. systemd knows no unit for %s, "+
			"so there was nothing to %s. %s", s.upid.Raw, taskErr.ExitStatus, s.service, s.kind.verb,
			serviceNotInstalledNote))
	case errors.As(err, &taskErr) && strings.Contains(taskErr.ExitStatus, "os error 2"):
		s.diags.AddError(summary, fmt.Sprintf("PBS task %s ended with an error: %s. PBS found no systemctl to run. %s",
			s.upid.Raw, taskErr.ExitStatus, serviceNoSystemd))
	case errors.As(err, &taskErr):
		s.diags.AddError(summary, fmt.Sprintf("PBS task %s ended with an error: %s. systemd's own message is not in "+
			"the task's log but in the journal of PBS's API daemon, which ran systemctl (`journalctl -u "+
			"proxmox-backup` on the host); `systemctl status` on the host, with the name of the service's unit, "+
			"shows why the service failed.%s", s.upid.Raw, taskErr.ExitStatus, task.logTail(s.ctx)))
	case pbsclient.IsTaskTimeout(err) && s.ctx.Err() != nil:
		s.diags.AddError(unfinished, fmt.Sprintf("Terraform stopped the action while PBS task %s was running. "+
			"systemd goes on with the %s; Administration → Tasks in the web interface shows how it ends.",
			s.upid.Raw, s.kind.verb))
	case pbsclient.IsTaskTimeout(err):
		s.diags.AddError(unfinished, fmt.Sprintf("The action stopped waiting for PBS task %s, which was still "+
			"running: %s. systemd goes on with the %s; Administration → Tasks in the web interface shows how it "+
			"ends. Raise the action's `timeout` to wait longer.", s.upid.Raw, err, s.kind.verb))
	case s.reloadsProxy() && errors.As(err, &untrusted) && untrusted.Presented() != "":
		s.diags.AddError("PBS's proxy presents a certificate the provider does not trust",
			fmt.Sprintf("After the reload, proxmox-backup-proxy of node %s presents the certificate with SHA-256 "+
				"fingerprint %s — the one it loaded from proxy.pem —, which the provider's TLS settings do not "+
				"trust: %s. The reload itself may have worked: update `tls_cert_fingerprint` (PBS_TLS_FINGERPRINT), "+
				"or whatever else pins the previous certificate, and check task %s in the web interface "+
				"(Administration → Tasks).",
				s.node, pbsclient.FormatFingerprint(untrusted.Presented()), untrusted, s.upid.Raw))
	case s.reloadsProxy() && pbsclient.IsUnreachable(err):
		s.diags.AddError("PBS's proxy did not come back",
			fmt.Sprintf("PBS started reloading proxmox-backup-proxy on node %s (task %s), and the proxy has not "+
				"answered since: it probably failed to start with the certificate (/etc/proxmox-backup/proxy.pem, "+
				"proxy.key) or the cipher lists (node.cfg) it loads anew, which leaves PBS without its API and web "+
				"interface. Backups the old process was running may have been stopped with it. On the host, "+
				"`systemctl status proxmox-backup-proxy` and `journalctl -u proxmox-backup-proxy` show why; fix the "+
				"file, then run `systemctl reset-failed proxmox-backup-proxy` and `systemctl start "+
				"proxmox-backup-proxy`. The last poll of the task failed: %s", s.node, s.upid.Raw, err))
	default:
		s.diags.AddError("Unable to follow PBS task "+s.upid.Raw,
			fmt.Sprintf("%s of service %s on PBS node %s. The command goes on in PBS, whose web interface shows how "+
				"it ends (Administration → Tasks). %s", s.kind.title, s.service, s.node, apiErrorDetail(s.client, "", err)))
	}
}

// confirm checks, after the task, that the service runs, when the provider
// may read its state, and reports the outcome.
func (s *serviceInvocation) confirm(readable bool) {
	done := s.kind.done
	if s.reloadsProxy() {
		done = serviceReload.done
	}
	finishing := ""
	if s.reloadsProxy() || (s.service == pbsclient.ServiceAPI && s.kind.command == pbsclient.ServiceReload) {
		finishing = "; the old process finishes the connections and tasks it had"
	}
	if !readable {
		s.progress.say("PBS %s service %s on node %s%s", done, s.service, s.node, finishing)
		return
	}
	state, err := s.awaitRunning()
	switch {
	case err != nil:
		s.diags.AddWarning(fmt.Sprintf("Unable to confirm that service %s runs on PBS node %s", s.service, s.node),
			fmt.Sprintf("PBS task %s ended well, but reading the state of the service afterwards failed. %s",
				s.upid.Raw, apiErrorDetail(s.client, serviceAuditPrivilege(s.service), err)))
	case !state.Running():
		s.diags.AddError(fmt.Sprintf("Service %s is not running on PBS node %s after the %s", s.service, s.node, s.kind.verb),
			fmt.Sprintf("PBS task %s ended well, but systemd reports the service as %s (unit state %s) %s later: it "+
				"may have stopped right after starting. `systemctl status` and `journalctl -u` on the host, with the "+
				"name of the service's unit, show why.", s.upid.Raw, state.State, state.UnitState, serviceSettleTime))
	default:
		s.progress.say("PBS %s service %s on node %s; systemd reports it %s%s", done, s.service, s.node, state.State, finishing)
	}
}

// awaitRunning reads the state of the service until systemd reports it
// running, for up to serviceSettleTime, and returns the last state read,
// or the error of the last read.
func (s *serviceInvocation) awaitRunning() (pbsclient.Service, error) {
	deadline := time.Now().Add(serviceSettleTime)
	for {
		state, ok, err := s.client.ServiceState(s.ctx, s.node, s.service)
		if err == nil && !ok {
			state = pbsclient.Service{Service: s.service, State: servicesUnknownState, UnitState: servicesUnknownState}
		}
		if (err == nil && state.Running()) || !time.Now().Before(deadline) {
			return state, err
		}
		select {
		case <-time.After(serviceSettlePoll):
		case <-s.ctx.Done():
			return state, err
		}
	}
}
