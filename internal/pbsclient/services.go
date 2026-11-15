package pbsclient

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// PBS reports the state of a fixed set of system services, and starts,
// stops, restarts and reloads them. What PBS 4 does, read in its source
// (src/api2/node/services.rs, proxmox-backup 7c86c5ad5, after 4.2.11; the
// file differs from 4.0.11's in formatting only):
//
//   - GET /nodes/{node}/services lists, always in this order,
//     proxmox-backup, proxmox-backup-proxy, sshd, systemd-journald, cron,
//     postfix and chrony (SERVICE_NAME_LIST). For each it runs "systemctl
//     show" as the proxy's user, backup, and reports what systemd says of
//     the unit. It needs Sys.Audit on /system/services.
//   - A service systemctl fails to show, or shows without a Description, is
//     only logged and left out: the answer is a shorter list, not an error.
//     A node without systemd, such as PBS in a Docker container, answers
//     with an empty list.
//   - A unit that is not installed is still listed, with unit-state
//     "not-found" and, usually, state "dead".
//   - The state is the unit's SubState, except for a oneshot unit whose
//     SubState is "dead": the Result of its last run then, such as
//     "success" or "exit-code". PBS fills a missing state or unit file
//     state with "unknown", and a missing Name with the service's ID.
//   - GET /nodes/{node}/services/{service}/state answers one service the
//     same way, with Sys.Audit on /system/services/{service}, or null when
//     systemctl shows no Description. A service that is not in the list is
//     400 "unknown service name '<x>'"; a failing systemctl, as on a node
//     without systemd, 400 "systemctl show failed with exit status: <n>",
//     or the error of starting it when there is no systemctl at all.
//   - POST /nodes/{node}/services/{service}/{start,stop,restart,reload}
//     need Sys.Modify on /system/services/{service} and take no other
//     parameter. They are protected: the proxy hands them to PBS's API
//     daemon, proxmox-backup, which runs them as root. They answer at once
//     with the UPID of a task of type srvstart, srvstop, srvrestart or
//     srvreload, whose worker ID is the service, and which runs `systemctl
//     <command> <service>`; reload runs `systemctl try-reload-or-restart`,
//     which leaves a service that is not running stopped.
//   - The commands do not check the service against the list: any string
//     reaches systemctl, as root. StartServiceCommand refuses what is not in
//     ServiceIDs.
//   - A restart of proxmox-backup-proxy is a reload, "to avoid aborting
//     running tasks": its task is srvreload. PBS refuses to stop
//     proxmox-backup inside the task, which then fails.
//   - systemctl's own output goes to the journal of the API daemon, not to
//     the task's log, which ends with "systemctl <command> failed with exit
//     status: <n>" when systemctl fails.
//   - The answers have the same shape on every PBS 4 release. Before 4.0.4,
//     PBS showed postfix's templated unit, postfix@-, as on Debian bookworm
//     (commit 04c601567).
//
// How the two daemons of PBS reload, read in proxmox-daemon
// (src/server.rs, proxmox 601a11e6) and src/bin/proxmox-backup-proxy.rs:
// on SIGHUP, which their units' ExecReload sends, a daemon stops accepting
// connections, starts its successor from its own executable, handing it
// the listening socket, and finishes the connections and tasks it has
// before it exits; connections that arrive meanwhile wait for the
// successor. The proxy's successor first loads proxy.pem, proxy.key and
// the cipher lists of node.cfg (make_tls_acceptor), and when it cannot, it
// exits, and nothing listens on port 8007 any more.

// The IDs of PBS's own services.
const (
	// ServiceAPI is PBS's API daemon, which runs the protected calls.
	ServiceAPI = "proxmox-backup"
	// ServiceProxy serves the API and the web interface on port 8007.
	ServiceProxy = "proxmox-backup-proxy"
)

// ServiceIDs are the services PBS reports and controls, in its order.
var ServiceIDs = []string{ServiceAPI, ServiceProxy, "sshd", "systemd-journald", "cron", "postfix", "chrony"}

// The commands StartServiceCommand sends. PBS also has stop, which the
// provider does not use.
const (
	ServiceStart   = "start"
	ServiceRestart = "restart"
	ServiceReload  = "reload"
)

// Unit file states of a Service that matter to the commands.
const (
	// ServiceNotFound is the unit state of a service that is not installed.
	ServiceNotFound = "not-found"
	// ServiceMasked is the unit state of a service systemd refuses to
	// start.
	ServiceMasked = "masked"
)

// Service is one service of GET /nodes/{node}/services. PBS sends every
// property.
type Service struct {
	// Service is PBS's ID of the service, such as "proxmox-backup-proxy".
	Service string `json:"service"`
	// Name is meant to be the unit's Name, a property systemctl show does
	// not print, so it is the ID.
	Name string `json:"name"`
	// Description is the unit's Description.
	Description string `json:"desc"`
	// State is the unit's SubState, such as "running" or "dead", or the
	// Result of a oneshot unit that is not running.
	State string `json:"state"`
	// UnitState is the unit file state, such as "enabled" or "static", or
	// "not-found" for a unit that is not installed.
	UnitState string `json:"unit-state"`
}

// Running reports whether systemd reports the service as up: "running", or
// "exited" for a unit that stays active without a process, such as a
// oneshot unit with RemainAfterExit.
func (s Service) Running() bool {
	return s.State == "running" || s.State == "exited"
}

// stoppedStates are the states of a unit that is not active: systemd's
// sub-states of an inactive service, and the results PBS reports instead
// for a oneshot unit that is not running (systemd's service_result_table).
var stoppedStates = []string{
	"dead", "failed",
	"success", "resources", "protocol", "timeout", "exit-code", "signal", "core-dump", "watchdog",
	"start-limit-hit", "oom-kill", "exec-condition",
}

// Stopped reports whether systemd reports the service as not active: a
// reload, `systemctl try-reload-or-restart`, leaves it so. A service that
// is starting, stopping or reloading is neither Running nor Stopped.
func (s Service) Stopped() bool {
	return slices.Contains(stoppedStates, s.State)
}

// IsServiceID reports whether id is one of the services PBS controls.
func IsServiceID(id string) bool {
	return slices.Contains(ServiceIDs, id)
}

// Services reads the state of a node's services, in PBS's order. It needs
// Sys.Audit on /system/services.
func (c *Client) Services(ctx context.Context, node string) ([]Service, error) {
	var services []Service
	if _, err := c.Get(ctx, Path("nodes", node, "services"), nil, &services); err != nil {
		return nil, err
	}
	return services, nil
}

// ServiceState reads the state of one service. ok is false when PBS
// answers null: systemctl described no unit. It needs Sys.Audit on
// /system/services/{service}.
func (c *Client) ServiceState(ctx context.Context, node, service string) (state Service, ok bool, err error) {
	env, err := c.Get(ctx, Path("nodes", node, "services", service, "state"), nil, &state)
	if err != nil {
		return Service{}, false, err
	}
	if data := strings.TrimSpace(string(env.Data)); data == "" || data == "null" {
		return Service{}, false, nil
	}
	return state, true, nil
}

// StartServiceCommand has PBS start, restart or reload a service, and
// returns the UPID of the task that runs systemctl: srvstart, srvrestart or
// srvreload — srvreload for a restart of ServiceProxy too. It needs
// Sys.Modify on /system/services/{service}. It refuses a service that is
// not in ServiceIDs, which PBS would hand to systemctl as it is, and any
// other command.
func (c *Client) StartServiceCommand(ctx context.Context, node, service, command string) (UPID, error) {
	if !IsServiceID(service) {
		return UPID{}, fmt.Errorf("%q is not one of the services PBS controls (%s)", service, strings.Join(ServiceIDs, ", "))
	}
	switch command {
	case ServiceStart, ServiceRestart, ServiceReload:
	default:
		return UPID{}, fmt.Errorf("%q is not a service command the provider sends (start, restart, reload)", command)
	}
	return c.StartTask(ctx, http.MethodPost, Path("nodes", node, "services", service, command), nil)
}

// WithCertificateLock runs fn while no certificate change of the client
// (ChangeCertificate) runs, and keeps any from starting until fn returns:
// for a reload of the proxy, which closes the connection a change runs over
// and loads whatever certificate the change has written by then.
func (c *Client) WithCertificateLock(fn func() error) error {
	c.certificateChange.Lock()
	defer c.certificateChange.Unlock()
	return fn()
}
