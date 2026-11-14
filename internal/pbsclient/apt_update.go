package pbsclient

import (
	"context"
	"net/http"
	"net/url"
)

// What PBS 4.x does when asked to refresh a node's package lists, read in
// its source (src/api2/node/apt.rs apt_update_database and
// update_apt_proxy_config, proxmox-apt cache_api.rs update_database,
// proxmox-apt-api-types APTUpdateOptions, src/server/notifications/mod.rs
// send_updates_available; proxmox-backup 7c86c5ad5, after 4.2.11, the same
// since 4.0):
//
//   - POST /nodes/{node}/apt/update — the Refresh button under
//     Administration → Updates — needs Sys.Modify on / and starts task
//     aptupdate, without a worker ID. It takes notify (default false) and
//     quiet (default false), which leaves apt's output out of the log.
//   - The task first rewrites /etc/apt/apt.conf.d/76pveproxy from the
//     node's http-proxy: Acquire::http::Proxy "<proxy>"; when the node has
//     one, and it deletes the file when it has none — a file of that name
//     written by hand is lost.
//   - Then it runs apt-get update and logs "starting apt-get update" and
//     apt's whole output as one message, which the log holds as lines of
//     their own: apt names each repository it could not fetch in an
//     "Err:<n> <repository>" line, with the reason indented below it. PBS
//     logs apt's error output only when apt-get exits with an error, which
//     does not fail the task either: PBS logs it as a warning — "E: Failed
//     to fetch https://enterprise.proxmox.com/... 401 Unauthorized" without
//     a subscription, "E: Could not get lock /var/lib/apt/lists/lock" while
//     another apt runs, such as the daily update — and the task ends with
//     "WARNINGS: 1". Network trouble — a name that does not resolve, a
//     mirror or proxy that refuses the connection or does not answer — apt
//     takes for a passing failure: it only warns ("W: Failed to fetch ...")
//     and exits 0, PBS drops its error output, and the task ends OK, with
//     the "Err:" lines in the log alone (proxmox-apt cache_api.rs
//     update_database: stderr is logged only when the exit status is not
//     success). Either way the lists of the repositories that failed stay
//     as they were. Only apt-get killed by a signal ("terminated by
//     signal") or not starting at all ("failed to execute ...") fails the
//     task. PBS takes no lock of its own and sets no timeout: apt's own
//     apply.
//   - It then reads APT's cache into /var/lib/proxmox-backup/pkg-state.json,
//     which GET on the same path (APTUpdates) answers from, so a GET after
//     the task lists the fresh updates.
//   - With notify, PBS sends one notification of type package-updates
//     (severity info, fields type and hostname) for the versions it has not
//     notified about before, and records them in pkg-state.json: the daily
//     update, which notifies only with an active subscription, does not
//     notify about them again. A failure of the notification system fails
//     the task.

// StartAPTUpdate starts the task that refreshes a node's package lists,
// apt-get update, and returns its UPID. notify asks PBS to send a
// package-updates notification about updates it has not notified about
// before.
func (c *Client) StartAPTUpdate(ctx context.Context, node string, notify bool) (UPID, error) {
	var params url.Values
	if notify {
		params = url.Values{"notify": {FormatBool(true)}}
	}
	return c.StartTask(ctx, http.MethodPost, Path("nodes", node, "apt", "update"), params)
}
