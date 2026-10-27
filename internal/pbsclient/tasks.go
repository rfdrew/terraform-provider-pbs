package pbsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Long-running operations — creating and deleting a datastore, garbage
// collection, verification, syncing a realm, apt update — run as worker
// tasks. The call answers at once, with the task's UPID as data, and HTTP 200
// even when the task is going to fail: its outcome is only in the task
// status, GET /nodes/{node}/tasks/{upid}/status, once status is "stopped":
// exitstatus "OK", "WARNINGS: <n>", or the error text. A task the server does
// not know also answers 200, with exitstatus "unknown".
//
// A UPID is "UPID:<node>:<pid>:<pstart>:<task id>:<start time>:<worker
// type>:<worker id>:<auth id>:", the numbers as eight hex digits. Proxmox VE
// UPIDs have one field fewer, so a PVE client's parser does not fit.

// UPID is a parsed task ID.
type UPID struct {
	// Raw is the UPID as PBS sent it.
	Raw        string
	Node       string
	WorkerType string
	WorkerID   string
	AuthID     string
}

// ParseUPID parses a PBS UPID. The worker ID is left as PBS writes it, with
// characters such as "-" escaped as \x2d.
func ParseUPID(s string) (UPID, error) {
	fields := strings.Split(s, ":")
	// The trailing colon leaves an empty last field.
	if len(fields) != 10 || fields[0] != "UPID" || fields[9] != "" || fields[1] == "" || fields[6] == "" {
		return UPID{}, fmt.Errorf("%q is not a PBS task ID (UPID:<node>:<pid>:<pstart>:<task id>:<start time>:<type>:<id>:<user>:)", s)
	}
	return UPID{Raw: s, Node: fields[1], WorkerType: fields[6], WorkerID: fields[7], AuthID: fields[8]}, nil
}

// UPIDFromData returns the UPID data holds, if data is a JSON string that
// parses as one. PBS documents some calls as returning null that in fact
// start a task, such as creating a datastore, so callers check the data of
// every such call.
func UPIDFromData(data json.RawMessage) (UPID, bool) {
	var s string
	if json.Unmarshal(data, &s) != nil || !strings.HasPrefix(s, "UPID:") {
		return UPID{}, false
	}
	upid, err := ParseUPID(s)
	return upid, err == nil
}

// TaskStatus is the status of a worker task.
type TaskStatus struct {
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
	Type       string `json:"type"`
	User       string `json:"user"`
}

// Succeeded reports whether a stopped task ended without an error. Warnings
// do not make it fail.
func (s TaskStatus) Succeeded() bool {
	return s.ExitStatus == "OK" || strings.HasPrefix(s.ExitStatus, "WARNINGS")
}

// TaskError is a worker task that ended with an error.
type TaskError struct {
	UPID       UPID
	ExitStatus string
}

func (e *TaskError) Error() string {
	if e.ExitStatus == "unknown" {
		return fmt.Sprintf("PBS does not know task %s", e.UPID.Raw)
	}
	return fmt.Sprintf("PBS task %s (%s) failed: %s", e.UPID.WorkerType, e.UPID.Raw, e.ExitStatus)
}

// ErrTaskTimeout means a task was still running when the wait gave up. The
// task itself goes on.
var ErrTaskTimeout = errors.New("the PBS task did not finish in time")

// Task polling starts fast, because most tasks of a provider — creating a
// datastore, say — take a second or two, and slows down for long ones.
const (
	firstTaskPoll = 250 * time.Millisecond
	maxTaskPoll   = 5 * time.Second
)

// TaskStatus reads the status of a worker task. Its node is the one in the
// UPID, which a single PBS always is itself.
func (c *Client) TaskStatus(ctx context.Context, upid UPID) (TaskStatus, error) {
	var status TaskStatus
	_, err := c.Get(ctx, Path("nodes", upid.Node, "tasks", upid.Raw, "status"), nil, &status)
	return status, err
}

// WaitTask waits until a worker task stops, at most for the client's task
// timeout, and returns its status. It fails with a *TaskError when the task
// ended with an error, and with ErrTaskTimeout when it is still running.
func (c *Client) WaitTask(ctx context.Context, upid UPID) (TaskStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, c.taskTimeout)
	defer cancel()

	delay := firstTaskPoll
	for {
		status, err := c.TaskStatus(ctx, upid)
		if err != nil {
			if isContextError(err) && ctx.Err() != nil {
				return status, fmt.Errorf("%w after %s: %s", ErrTaskTimeout, c.taskTimeout, upid.Raw)
			}
			return status, err
		}
		if status.Status == "stopped" {
			if !status.Succeeded() {
				return status, &TaskError{UPID: upid, ExitStatus: status.ExitStatus}
			}
			if status.ExitStatus != "OK" {
				tflog.Warn(ctx, "PBS task ended with warnings", map[string]any{"upid": upid.Raw, "exitstatus": status.ExitStatus})
			}
			return status, nil
		}

		if err := c.sleep(ctx, delay); err != nil {
			return status, fmt.Errorf("%w after %s: %s", ErrTaskTimeout, c.taskTimeout, upid.Raw)
		}
		delay = min(delay*2, maxTaskPoll)
	}
}

// WaitTaskIn waits for the task in data, when data holds a UPID, and does
// nothing otherwise. It is for calls that may or may not start a task.
func (c *Client) WaitTaskIn(ctx context.Context, data json.RawMessage) error {
	upid, ok := UPIDFromData(data)
	if !ok {
		return nil
	}
	_, err := c.WaitTask(ctx, upid)
	return err
}
