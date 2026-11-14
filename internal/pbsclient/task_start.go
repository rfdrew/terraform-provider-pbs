package pbsclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// What PBS 4.x does when a call starts a task that is already running, read
// in its source (src/server/jobstate.rs, src/api2/admin/datastore.rs,
// src/api2/access/domain.rs): a job — sync, verification, prune, garbage
// collection, realm sync — holds an exclusive lock on its state file,
// /var/lib/proxmox-backup/jobstates/<type>-<id>.lck, for as long as it runs.
// Starting it again waits up to 10 s for the lock and then answers 400
// "Unable to acquire lock \"<path>\" - Interrupted system call (os error 4)";
// garbage collection says "garbage collection already running" instead, and
// a realm sync "realm sync already running".

// StartTask makes a call that starts a worker task and returns the task's
// UPID. A call that answers anything but a UPID is an error.
func (c *Client) StartTask(ctx context.Context, method, path string, params url.Values) (UPID, error) {
	env, err := c.Call(ctx, method, path, params, nil)
	if err != nil {
		return UPID{}, err
	}
	upid, ok := UPIDFromData(env.Data)
	if !ok {
		return UPID{}, fmt.Errorf("%s %s answered %s instead of a task ID", method, path, truncate(string(env.Data), 200))
	}
	return upid, nil
}

// IsTaskAlreadyRunning reports whether PBS refused to start a job because
// the same job is running.
func IsTaskAlreadyRunning(err error) bool {
	apiErr, ok := asError(err)
	if !ok || apiErr.StatusCode != http.StatusBadRequest {
		return false
	}
	message := apiErr.Message
	return strings.Contains(message, "already running") ||
		(strings.Contains(message, "Unable to acquire lock") && strings.Contains(message, "/jobstates/"))
}

// FormatByteSize writes a number of bytes as PBS shows sizes, in binary
// units with up to two decimals: "512 B", "1.5 KiB", "3.25 GiB".
func FormatByteSize(n int64) string {
	if n < 1024 && n > -1024 {
		return strconv.FormatInt(n, 10) + " B"
	}
	value := float64(n)
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	unit := ""
	for _, u := range units {
		value /= 1024
		unit = u
		if value < 1024 && value > -1024 {
			break
		}
	}
	formatted := strconv.FormatFloat(value, 'f', 2, 64)
	formatted = strings.TrimRight(strings.TrimRight(formatted, "0"), ".")
	return formatted + " " + unit
}
