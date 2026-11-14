package pbsclient

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// What PBS 4.x does with a task's log, read in its source
// (src/api2/node/tasks.rs, proxmox-rest-server worker_task.rs, proxmox-log
// file_logger.rs):
//
//   - GET /nodes/{node}/tasks/{upid}/log takes start (default 0) and limit
//     (default 50, 0 for every line to the end) and answers
//     {"data": [{"n": <line number>, "t": "<line>"}], "total": <lines>};
//     with test-status=1 also "active": whether the task still runs. total
//     and active are siblings of data. n counts from 1, and start=k answers
//     the lines with n >= k, so start=0 and start=1 are the same.
//   - The server reads the whole file to count its lines, whatever start
//     and limit say: the tail is two cheap calls, one for total and one for
//     the last lines.
//   - Every line starts with an RFC 3339 timestamp and ": ", 25 characters
//     plus 2; the continuation lines of a message of several lines do not.
//     Warnings and errors carry no level prefix. The last line is
//     "TASK OK", "TASK WARNINGS: <n>" or "TASK ERROR: <error>", the error
//     with its whole chain of causes, which the task status cuts to the
//     first line.
//   - The owner of a task — the user or token that started it, or the user
//     of that token — may always read its status and log; anyone else needs
//     Sys.Audit on /system/tasks or the privileges of the job.
//   - DELETE /nodes/{node}/tasks/{upid} asks the task to stop and answers
//     at once; the task checks the request when it gets to it, and some
//     never do (a prune job, mounting a datastore). It needs to be the
//     task's owner exactly, or Sys.Modify on /system/tasks.

// TaskLogLine is one line of a task's log.
type TaskLogLine struct {
	// N is the line's number, counting from 1.
	N int `json:"n"`
	// Text is the line as PBS wrote it, timestamp included.
	Text string `json:"t"`
}

// taskLogTimestampLength is the length of the timestamp in front of a log
// line, such as "2026-11-14T10:00:00+01:00", followed by ": ".
const taskLogTimestampLength = 25

// Message returns the line without its timestamp.
func (l TaskLogLine) Message() string {
	text := l.Text
	if len(text) > taskLogTimestampLength+1 && text[taskLogTimestampLength] == ':' && text[taskLogTimestampLength+1] == ' ' {
		if _, err := time.Parse(time.RFC3339, text[:taskLogTimestampLength]); err == nil {
			return text[taskLogTimestampLength+2:]
		}
	}
	return text
}

// TaskLog reads the lines of a task's log from line start on, at most limit
// of them, or all to the end with limit 0. It also returns the number of
// lines the log has and whether the task still runs.
func (c *Client) TaskLog(ctx context.Context, upid UPID, start, limit int) (lines []TaskLogLine, total int, active bool, err error) {
	params := url.Values{
		"start":       {strconv.Itoa(max(start, 1))},
		"limit":       {strconv.Itoa(max(limit, 0))},
		"test-status": {"1"},
	}
	env, err := c.Get(ctx, Path("nodes", upid.Node, "tasks", upid.Raw, "log"), params, &lines)
	if err != nil {
		return nil, 0, false, err
	}
	if env.Active != nil {
		active = *env.Active
	}
	return lines, env.Total, active, nil
}

// TaskLogTail returns the last n lines of a task's log.
func (c *Client) TaskLogTail(ctx context.Context, upid UPID, n int) ([]TaskLogLine, error) {
	_, total, _, err := c.TaskLog(ctx, upid, 1, 1)
	if err != nil {
		return nil, err
	}
	lines, _, _, err := c.TaskLog(ctx, upid, max(total-n+1, 1), n)
	return lines, err
}

// AbortTask asks PBS to stop a task. PBS answers before the task stops, and
// some tasks never do; WaitTask tells when it has.
func (c *Client) AbortTask(ctx context.Context, upid UPID) error {
	_, err := c.Delete(ctx, Path("nodes", upid.Node, "tasks", upid.Raw), nil, nil)
	return err
}

// TaskWatch says how WatchTask waits for a task.
type TaskWatch struct {
	// Timeout bounds the wait. Zero means the client's task timeout.
	Timeout time.Duration
	// OutageGrace, when positive, makes the wait outlast a PBS that does
	// not answer for that long — cut off by a network reload, too busy to
	// answer a request in time, behind a reverse proxy that answers 502 —: a
	// status poll that does not reach PBS (IsUnreachable) is tried again
	// until none has for OutageGrace, and that error is returned then, also
	// when the timeout ends the wait first.
	OutageGrace time.Duration
	// Progress, when set, receives the lines the task added to its log since
	// the last call, after each status poll and once more when the task has
	// stopped: all of them, or the last progressLogLimit when there are
	// more, so that the last call ends with the task's result. Reading the
	// log is best effort: a failure skips the call.
	Progress func([]TaskLogLine)
}

// progressLogLimit bounds the lines one progress read fetches. A task can
// log more than that between two polls — a verification logs a line for
// each snapshot it skips as recently verified (src/backup/verify.rs), often
// thousands in a few seconds —: rather than fall further behind the log
// with every poll, a read that leaves lines out is followed by a read of
// the last ones, which are what progress is for, and the lines in between
// are skipped.
const progressLogLimit = 500

// WaitTask waits until a worker task stops, at most for the client's task
// timeout, and returns its status. It fails with a *TaskError when the task
// ended with an error, and with ErrTaskTimeout when it is still running.
func (c *Client) WaitTask(ctx context.Context, upid UPID) (TaskStatus, error) {
	return c.WatchTask(ctx, upid, TaskWatch{})
}

// WaitTaskThroughOutages is WaitTask for a task that may cut the client off
// while it runs, such as a network reload, which rebuilds the path to PBS
// — a bond that takes half a minute to aggregate, a bridge recreated —: a
// status poll that does not reach PBS (IsUnreachable) is tried again until
// none has for grace, and that error is returned then, also when the task
// timeout ends the wait first.
func (c *Client) WaitTaskThroughOutages(ctx context.Context, upid UPID, grace time.Duration) (TaskStatus, error) {
	return c.WatchTask(ctx, upid, TaskWatch{OutageGrace: grace})
}

// WatchTask waits until a worker task stops, as watch says, and returns its
// status. It fails with a *TaskError when the task ended with an error, and
// with ErrTaskTimeout when the wait ended first: the timeout, or ctx, whose
// error the result then wraps too. The task goes on in either case.
func (c *Client) WatchTask(ctx context.Context, upid UPID, watch TaskWatch) (TaskStatus, error) {
	timeout := watch.Timeout
	if timeout <= 0 {
		timeout = c.taskTimeout
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	gaveUp := func() error {
		if err := parent.Err(); err != nil {
			return fmt.Errorf("%w: stopped waiting (%w): %s", ErrTaskTimeout, err, upid.Raw)
		}
		return fmt.Errorf("%w after %s: %s", ErrTaskTimeout, timeout, upid.Raw)
	}

	next := 1
	readLog := func() {
		if watch.Progress == nil || ctx.Err() != nil {
			return
		}
		lines, total, _, err := c.TaskLog(ctx, upid, next, progressLogLimit)
		if err == nil && total >= next+progressLogLimit {
			// More lines are new than one read returns: read the last of
			// the lines the log had then instead. PBS reads the whole file
			// for either read anyway.
			lines, _, _, err = c.TaskLog(ctx, upid, total-progressLogLimit+1, progressLogLimit)
		}
		if err != nil {
			tflog.Debug(ctx, "could not read the PBS task log", map[string]any{"upid": upid.Raw, "error": err.Error()})
			return
		}
		// PBS answers the lines from next on; anything before is dropped
		// in case a server counts differently.
		fresh := lines[:0:0]
		for _, line := range lines {
			if line.N >= next {
				fresh = append(fresh, line)
				next = line.N + 1
			}
		}
		if len(fresh) > 0 {
			watch.Progress(fresh)
		}
	}

	delay := firstTaskPoll
	reached := time.Now()
	var outage error
	for {
		status, err := c.TaskStatus(ctx, upid)
		switch {
		case err == nil:
			reached, outage = time.Now(), nil
			if status.Status == "stopped" {
				// The lines the task wrote between the last read and its
				// end, its result among them.
				readLog()
				return status, c.taskEnded(ctx, upid, status)
			}
			readLog()
		case ctx.Err() != nil && isContextError(err):
			// The wait ended a poll: an outage before it is what the
			// caller needs to know of, otherwise the task is slow.
			if outage != nil {
				return status, outage
			}
			return status, gaveUp()
		case watch.OutageGrace > 0 && IsUnreachable(err):
			outage = err
			if time.Since(reached) >= watch.OutageGrace {
				return status, err
			}
		default:
			return status, err
		}

		if err := c.sleep(ctx, delay); err != nil {
			if outage != nil {
				return status, outage
			}
			return status, gaveUp()
		}
		delay = min(delay*2, maxTaskPoll)
	}
}

// IsTaskTimeout reports whether err is a wait for a task that ended before
// the task did, because of the timeout or because the caller stopped
// waiting.
func IsTaskTimeout(err error) bool {
	return errors.Is(err, ErrTaskTimeout)
}

// FormatTaskLog joins the messages of lines, one per line, without their
// timestamps.
func FormatTaskLog(lines []TaskLogLine) string {
	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line.Message())
	}
	return b.String()
}
