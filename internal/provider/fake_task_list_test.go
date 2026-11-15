package provider

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeTaskList serves a node's task list, GET /nodes/{node}/tasks, as PBS
// 4.x does (list_tasks, src/api2/node/tasks.rs, proxmox-backup 7c86c5ad5):
// the tasks it holds, which are in PBS's order — running tasks first, the
// most recently started first, then finished ones, the most recently ended
// first —, filtered in PBS's order: running, until, since (which ends the
// list at the first finished task that ended before it), userfilter and
// typefilter as a part of the auth ID and the type, store by the worker ID
// as check_job_store does, statusfilter (which leaves out running tasks),
// then start and limit (default 50, 0 for every task), with total next to
// data. It shows every task: what the caller may see is PBS's to decide.
// errors is not served; the provider never sends it.
type fakeTaskList struct {
	mu    sync.Mutex
	tasks []pbsclient.TaskListItem
}

// newFakeTaskList serves tasks as the task list of node.
func newFakeTaskList(fake *fakePBS, node string, tasks ...pbsclient.TaskListItem) *fakeTaskList {
	l := &fakeTaskList{tasks: tasks}
	fake.handle("GET /nodes/"+node+"/tasks", l.serve)
	return l
}

// fakeListedTask is a task as the list holds it: running when status is
// "", finished at end otherwise.
func fakeListedTask(upid string, start int64, workerType, workerID, authID string, end int64, status string) pbsclient.TaskListItem {
	task := pbsclient.TaskListItem{UPID: upid, StartTime: start, WorkerType: workerType, WorkerID: workerID, User: authID}
	if status != "" {
		task.EndTime, task.Status = &end, &status
	}
	return task
}

// fakeVerificationWorkerID is VERIFICATION_JOB_WORKER_ID_REGEX of
// pbs-api-types: a verify job's worker ID, "<datastore>:<job>".
var fakeVerificationWorkerID = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9._-]*):`)

// fakeTaskOfStore is check_job_store: whether PBS counts a task as the
// datastore's.
func fakeTaskOfStore(task pbsclient.TaskListItem, store string) bool {
	id := task.WorkerID
	if id == "" {
		return false
	}
	switch {
	case strings.HasPrefix(task.WorkerType, "verif"):
		if m := fakeVerificationWorkerID.FindStringSubmatch(id); m != nil {
			return m[1] == store
		}
		return id == store
	case task.WorkerType == "syncjob":
		fields := strings.Split(id, ":")
		return len(fields) >= 4 && fields[2] == store
	case slices.Contains([]string{"prune", "prunejob", "backup", "garbage_collection"}, task.WorkerType):
		return id == store || strings.HasPrefix(id, store+":")
	}
	return false
}

func (l *fakeTaskList) serve(w http.ResponseWriter, req *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	query := req.URL.Query()
	start, _ := strconv.Atoi(query.Get("start"))
	limit := 50
	if query.Has("limit") {
		limit, _ = strconv.Atoi(query.Get("limit"))
	}
	optionalTime := func(key string) *int64 {
		if !query.Has(key) {
			return nil
		}
		n, _ := strconv.ParseInt(query.Get(key), 10, 64)
		return &n
	}
	since, until := optionalTime("since"), optionalTime("until")
	running := fakeBool(query.Get("running"))
	statuses := query["statusfilter"]

	data := []map[string]any{}
	skipped := 0
	for _, task := range l.tasks {
		if running && !task.Running() {
			continue
		}
		if until != nil && task.StartTime > *until {
			continue
		}
		if since != nil {
			if task.EndTime != nil && *task.EndTime < *since {
				break
			}
			if task.StartTime < *since {
				continue
			}
		}
		if !strings.Contains(task.User, query.Get("userfilter")) || !strings.Contains(task.WorkerType, query.Get("typefilter")) {
			continue
		}
		if store := query.Get("store"); store != "" && !fakeTaskOfStore(task, store) {
			continue
		}
		if len(statuses) > 0 && (task.Running() || !slices.Contains(statuses, task.State())) {
			continue
		}
		if skipped < start {
			skipped++
			continue
		}
		data = append(data, fakeTaskListJSON(task))
		if limit > 0 && len(data) >= limit {
			break
		}
	}
	total := start + len(data)
	if limit > 0 && len(data) >= limit {
		total++
	}
	body, _ := json.Marshal(map[string]any{"data": data, "total": total})
	writeFakeResponse(w, http.StatusOK, string(body))
}

// fakeTaskListJSON is a task as PBS lists it: node "localhost", a null
// worker_id for a task without one, and no endtime or status while it
// runs.
func fakeTaskListJSON(task pbsclient.TaskListItem) map[string]any {
	item := map[string]any{
		"upid": task.UPID, "node": "localhost", "pid": 2587, "pstart": 123456, "starttime": task.StartTime,
		"worker_type": task.WorkerType, "worker_id": nil, "user": task.User,
	}
	if task.WorkerID != "" {
		item["worker_id"] = task.WorkerID
	}
	if task.Status != nil {
		item["endtime"], item["status"] = *task.EndTime, *task.Status
	}
	return item
}

// fakeTaskLogLines serves a task's log, GET /nodes/{node}/tasks/{upid}/log,
// as PBS does: the lines from start on (counting from 1), at most limit of
// them, or all with 0, with total and active next to data. The lines are
// served as given, timestamps included.
func fakeTaskLogLines(active bool, lines ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		start, _ := strconv.Atoi(req.URL.Query().Get("start"))
		limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
		type line struct {
			N int    `json:"n"`
			T string `json:"t"`
		}
		data := []line{}
		for i, text := range lines {
			if i+1 < start {
				continue
			}
			if limit > 0 && len(data) == limit {
				break
			}
			data = append(data, line{i + 1, text})
		}
		body, _ := json.Marshal(map[string]any{"data": data, "total": len(lines), "active": active, "success": 1})
		writeFakeResponse(w, http.StatusOK, string(body))
	}
}
