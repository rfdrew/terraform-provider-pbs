package pbsclient

import "context"

// APT updates are the installed packages of a node whose candidate version
// in APT's package cache differs from the installed one, and what they
// would pull in. What PBS 4 does with them, read in its source
// (src/api2/node/apt.rs) and in the proxmox-apt crates it uses
// (proxmox-apt/src/cache.rs, proxmox-apt/src/cache_api.rs,
// proxmox-apt-api-types):
//
//   - GET /nodes/{node}/apt/update lists every installed package whose
//     candidate version differs from the installed one, then the packages
//     those candidates depend on that are not installed, which an upgrade
//     would install anew, such as the package of a new kernel. The order is
//     that of APT's cache, which is unspecified. It needs Sys.Audit on /.
//   - The GET does not run apt update and makes no network access: it reads
//     APT's cache on disk, and keeps what it found in
//     /var/lib/proxmox-backup/pkg-state.json until /var/cache/apt/pkgcache.bin
//     or /var/lib/dpkg/status is newer than that file. The list is as current
//     as the node's last apt update: PBS's daily update runs one, and so does
//     POST on the same path, which the Refresh button of the web interface
//     sends; it answers the UPID of an apt-get update task.
//   - Because the GET may rewrite pkg-state.json, it is protected: the proxy
//     forwards it to the API daemon, which runs as root.
//   - The keys are PascalCase. From PBS 4.0.20, OldVersion is left out for a
//     package an upgrade would install anew; earlier releases sent "", which
//     a pkg-state.json they wrote may still hold after an upgrade. Title
//     defaults to the package name, Description to "", and Origin, Priority
//     and Section to "unknown". ExtraInfo is never set here.
//   - An image that removed APT's package lists, /var/lib/apt/lists, has no
//     version but the installed one, so the list is empty until apt update
//     runs.

// APTUpdate is one entry of GET /nodes/{node}/apt/update: a package an
// upgrade would change or install.
type APTUpdate struct {
	Package string `json:"Package"`
	// Title is the package's short description, or its name without one.
	Title string `json:"Title"`
	// Arch is the package's architecture, such as "amd64" or "all".
	Arch string `json:"Arch"`
	// Description is the package's long description, which may span
	// several lines.
	Description string `json:"Description"`
	// Version is the candidate version, the one an upgrade installs.
	Version string `json:"Version"`
	// OldVersion is the installed version, empty for a package an upgrade
	// would install anew.
	OldVersion string `json:"OldVersion,omitempty"`
	// Origin is the origin of the candidate's repository, such as
	// "Proxmox" or "Debian".
	Origin   string `json:"Origin"`
	Priority string `json:"Priority"`
	Section  string `json:"Section"`
	// ExtraInfo is set by GET /nodes/{node}/apt/versions, which answers the
	// same type, never by GET /nodes/{node}/apt/update.
	ExtraInfo string `json:"ExtraInfo,omitempty"`
}

// APTUpdates lists the package updates APT's cache on a node has, in the
// cache's order. It needs Sys.Audit on /.
func (c *Client) APTUpdates(ctx context.Context, node string) ([]APTUpdate, error) {
	var updates []APTUpdate
	if _, err := c.Get(ctx, Path("nodes", node, "apt", "update"), nil, &updates); err != nil {
		return nil, err
	}
	return updates, nil
}
