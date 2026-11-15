package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// What PBS 4.x does when it lists and reports tasks, read in its source
// (src/api2/node/tasks.rs, proxmox-backup 7c86c5ad5, after 4.2.11;
// proxmox-rest-server worker_task.rs and pbs-api-types lib.rs, proxmox
// 601a11e6), the same in substance since 4.0.11:
//
//   - GET /nodes/{node}/tasks lists tasks to anybody, without a 403: the
//     tasks the caller may not see are left out. With Sys.Audit on
//     /system/tasks it sees every task; otherwise the tasks it started —
//     a user also those of its API tokens, a token only its own — and those
//     of jobs it holds the privileges of: a verification job's
//     (Datastore.Verify), a sync job's (the privileges of a pull, for push
//     jobs too), garbage collection and prunes (Datastore.Modify).
//   - Its parameters are all optional: start (an offset counted among the
//     tasks that pass every filter), limit (default 50, 0 for no limit),
//     store, running, errors, userfilter and typefilter (both matched as a
//     part of the auth ID and the worker type), since and until (epoch
//     seconds, both compared with the task's start time), and statusfilter,
//     an array of ok, warning, error and unknown sent as the key repeated.
//     A statusfilter leaves out every running task. since also ends the
//     listing at the first finished task that ended before it, which keeps
//     the read short.
//   - store matches by the worker ID: the datastore of a backup, a garbage
//     collection, a prune or a prune job (the ID or its part before ":"), of
//     every verification, and the local datastore of a sync job; no other
//     task, such as a restore, a sync started by hand or the creation of a
//     datastore, belongs to one.
//   - The answer is running tasks first, the most recently started first,
//     then finished tasks, the most recently ended first, with "total" next
//     to data: start plus the tasks listed, plus one when the limit was
//     reached, whether or not more follow.
//   - A task lists its UPID, its start time, worker type, worker ID (null
//     when it has none, unescaped unlike in the UPID) and "user", the whole
//     auth ID, token included; and, once it ended, endtime and status:
//     "OK", "WARNINGS: <n>", "unknown" or the first line of the error,
//     without its "ERROR: " prefix. node is always "localhost".
//   - PBS works out how a task ended from the last line of its log that
//     starts with a time: that time is the end time, and the line "TASK
//     ..." the outcome; a log without one — PBS was stopped while the task
//     ran, say — is "unknown", ending at the time of that last line, or at
//     the start time when no line has one.
//   - GET /nodes/{node}/tasks/{upid}/status answers anybody who may see the
//     task, as the list decides, and 400 "task access not allowed" anyone
//     else. It reports the unescaped worker ID as "id", the user as "user"
//     and the token's name, if a token started the task, as "tokenid";
//     endtime only from 4.2.1 on (commit 2683bca43). A UPID PBS does not
//     know, whose log is missing, is "stopped" with exitstatus "unknown"
//     and no endtime, and its log answers 400 "No such file or directory
//     (os error 2)".
//
// PBS keeps its task archive in files of up to 512 KiB, over 5000 tasks
// each (src/bin/proxmox-backup-proxy.rs): the last 20 or, with
// task_log_max_days in the node's configuration, however many there are
// back to the first whose oldest task ended longer ago than that
// (rotate_task_log_archive). It removes the logs of tasks older than the
// archive's oldest.

// TaskListItem is a task as GET /nodes/{node}/tasks lists it.
type TaskListItem struct {
	// UPID is the task's ID, its worker ID escaped.
	UPID string `json:"upid"`
	// StartTime is when the task started, in seconds since the epoch.
	StartTime  int64  `json:"starttime"`
	WorkerType string `json:"worker_type"`
	// WorkerID is what the task works on, unescaped; "" when the task has
	// none, which PBS sends as null.
	WorkerID string `json:"worker_id"`
	// User is the auth ID that started the task: a user ID, or an API
	// token ID.
	User string `json:"user"`
	// EndTime and Status are nil while the task runs. Status is "OK",
	// "WARNINGS: <n>", "unknown" or the first line of the error.
	EndTime *int64  `json:"endtime,omitempty"`
	Status  *string `json:"status,omitempty"`
}

// Running reports whether the task was running when PBS listed it.
func (t TaskListItem) Running() bool { return t.Status == nil }

// State returns TaskStateRunning for a running task, and how it ended,
// as TaskStateOf says, for a finished one.
func (t TaskListItem) State() string {
	if t.Status == nil {
		return TaskStateRunning
	}
	return TaskStateOf(*t.Status)
}

// TaskListFilter selects the tasks ListTasks lists. Its Limit is always
// sent: 0 lists every task, unlike PBS's default of 50.
type TaskListFilter struct {
	// Store lists the tasks PBS counts as the datastore's.
	Store string
	// TypeFilter and UserFilter list the tasks whose worker type, or auth
	// ID, contains them: PBS matches a part, so "prune" lists prunejob
	// tasks too.
	TypeFilter string
	UserFilter string
	// Statuses lists the finished tasks that ended in one of these ways:
	// TaskStateOK, TaskStateWarning, TaskStateError or TaskStateUnknown.
	// Running tasks are left out when it is set.
	Statuses []string
	// Running lists only running tasks.
	Running bool
	// Since and Until list the tasks that started at or after, and at or
	// before, these times, in seconds since the epoch.
	Since *int64
	Until *int64
	// Start skips that many of the tasks that pass the filters.
	Start int
	// Limit is how many tasks to list at most; 0 lists every one.
	Limit int
}

// taskListPage is the smallest page ListTasksMatching asks PBS for.
const taskListPage = 100

// taskListOverlap is how many tasks at the end of a page ListTasksMatching
// reads again at the start of the next, and so how many may end between two
// calls without a task being missed.
const taskListOverlap = 10

// ListTasks lists the tasks of a node that f selects, in PBS's order. It
// never sends PBS's errors parameter: before 4.2.8 (commit b64a75ac2), it
// listed running tasks too, and Statuses says the same on every release.
func (c *Client) ListTasks(ctx context.Context, node string, f TaskListFilter) ([]TaskListItem, error) {
	params := url.Values{"limit": {strconv.Itoa(max(f.Limit, 0))}}
	if f.Start > 0 {
		params.Set("start", strconv.Itoa(f.Start))
	}
	if f.Store != "" {
		params.Set("store", f.Store)
	}
	if f.TypeFilter != "" {
		params.Set("typefilter", f.TypeFilter)
	}
	if f.UserFilter != "" {
		params.Set("userfilter", f.UserFilter)
	}
	for _, status := range f.Statuses {
		params.Add("statusfilter", status)
	}
	if f.Running {
		params.Set("running", "1")
	}
	if f.Since != nil {
		params.Set("since", strconv.FormatInt(*f.Since, 10))
	}
	if f.Until != nil {
		params.Set("until", strconv.FormatInt(*f.Until, 10))
	}
	tasks := []TaskListItem{}
	if _, err := c.Get(ctx, Path("nodes", node, "tasks"), params, &tasks); err != nil {
		return nil, err
	}
	if tasks == nil {
		tasks = []TaskListItem{}
	}
	return tasks, nil
}

// ListTasksMatching is ListTasks for the tasks match also keeps, such as
// those whose worker type is TypeFilter exactly rather than one that
// contains it; nil keeps every task. f.Limit stays exact: it is the number
// of tasks match keeps.
//
// With a limit, it reads pages of PBS's list until it has that many tasks
// or the list ends: the first max(f.Limit, 100) tasks, and pages twice as
// long each time one comes back full without filling the limit, so that a
// filter PBS matches far more often than match does takes few calls. PBS
// counts start among the tasks that pass its filters (src/api2/node/tasks.rs),
// so the list shifts when a task starts or ends between two calls. A task
// that enters the list — one that starts, or ends while Statuses is set —
// shifts those after it forward, which may then list twice: a UPID seen
// before is skipped. A task that leaves the list, ending while Running is
// set, or moves down it, ending without either and going from the running
// tasks, which PBS lists first, to the head of the finished ones, shifts
// those after it back, and the first task of the next page would fall on
// the page already read. Each page therefore starts taskListOverlap tasks
// before the end of the one before, whose tasks are skipped as seen before,
// so that none is missed unless more than that many end between two calls.
func (c *Client) ListTasksMatching(ctx context.Context, node string, f TaskListFilter, match func(TaskListItem) bool) ([]TaskListItem, error) {
	if match == nil {
		return c.ListTasks(ctx, node, f)
	}
	keep := func(tasks []TaskListItem) []TaskListItem {
		kept := tasks[:0:0]
		for _, task := range tasks {
			if match(task) {
				kept = append(kept, task)
			}
		}
		return kept
	}
	if f.Limit <= 0 {
		f.Limit = 0
		tasks, err := c.ListTasks(ctx, node, f)
		if err != nil {
			return nil, err
		}
		return keep(tasks), nil
	}

	limit := f.Limit
	page := max(limit, taskListPage)
	seen := map[string]bool{}
	kept := []TaskListItem{}
	for {
		f.Limit = page
		tasks, err := c.ListTasks(ctx, node, f)
		if err != nil {
			return nil, err
		}
		for _, task := range tasks {
			if seen[task.UPID] {
				continue
			}
			seen[task.UPID] = true
			if match(task) {
				kept = append(kept, task)
				if len(kept) == limit {
					return kept, nil
				}
			}
		}
		if len(tasks) < page {
			return kept, nil
		}
		// A page that is not the last is full, at least taskListPage
		// tasks long, so the list moves on.
		f.Start += max(len(tasks)-taskListOverlap, 1)
		page *= 2
	}
}

// IsTaskAccessDenied reports whether PBS refused to show a task to the
// caller: 400 "task access not allowed", the answer to anyone who neither
// started the task nor may see it as the task list decides.
func IsTaskAccessDenied(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest && strings.Contains(apiErr.Message, "task access not allowed")
}
