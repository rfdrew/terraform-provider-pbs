package pbsclient

import "context"

// PBS reports the state of a fixed set of system services. What PBS 4 does,
// read in its source (src/api2/node/services.rs):
//
//   - GET /nodes/{node}/services lists, always in this order,
//     proxmox-backup, proxmox-backup-proxy, sshd, systemd-journald, cron,
//     postfix and chrony. For each it runs "systemctl show" as the proxy's
//     user, backup, and reports what systemd says of the unit. It needs
//     Sys.Audit on /system/services.
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
//   - The answer has the same shape on every PBS 4 release. Before 4.0.10
//     PBS showed postfix's templated unit, postfix@-, as on Debian bookworm.

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

// Services reads the state of a node's services, in PBS's order. It needs
// Sys.Audit on /system/services.
func (c *Client) Services(ctx context.Context, node string) ([]Service, error) {
	var services []Service
	if _, err := c.Get(ctx, Path("nodes", node, "services"), nil, &services); err != nil {
		return nil, err
	}
	return services, nil
}
