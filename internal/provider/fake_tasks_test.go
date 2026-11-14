package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// fakeTasks serves the worker tasks that actions start, as PBS does: GET
// /nodes/{node}/tasks/{upid}/status and …/log, and DELETE
// /nodes/{node}/tasks/{upid}, which asks a task to stop. Its UPIDs carry
// the node fakeTasksNode, which no other fake uses.
//
// A task logs its lines from the start, answers "running" for a number of
// status polls, then stops with its exit status, and its log ends with the
// line PBS writes last: "TASK OK", "TASK WARNINGS: <n>" or "TASK ERROR:
// <error>". A task asked to stop stops at its next poll with "aborted",
// unless it ignores aborts, as a prune job does in PBS.
type fakeTasks struct {
	mu    sync.Mutex
	gen   int
	tasks map[string]*fakeTask
}

// fakeTask is one task of fakeTasks.
type fakeTask struct {
	// workerType and workerID are what the UPID carries.
	workerType string
	workerID   string
	// running is how many status polls answer "running" before the task
	// stops; -1 keeps it running for good.
	running int
	// log are the messages the task logs, without timestamps.
	log []string
	// exit is the exit status: "OK", "WARNINGS: <n>" or an error.
	exit string
	// ignoresAbort makes the task go on when asked to stop.
	ignoresAbort bool
	// onStop, when set, runs when the task stops, for the task's effects
	// on the fake.
	onStop func()

	stopped bool
	aborted bool
	polls   int
}

// fakeTasksNode is the node of fakeTasks' UPIDs.
const fakeTasksNode = "pbs-tasks"

func newFakeTasks(fake *fakePBS) *fakeTasks {
	t := &fakeTasks{tasks: map[string]*fakeTask{}}
	fake.handlePrefix("GET /nodes/"+fakeTasksNode+"/tasks/", t.serve)
	fake.handlePrefix("DELETE /nodes/"+fakeTasksNode+"/tasks/", t.abort)
	return t
}

// start registers task and returns its UPID.
func (t *fakeTasks) start(task *fakeTask) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gen++
	if task.exit == "" {
		task.exit = "OK"
	}
	upid := fmt.Sprintf("UPID:%s:00000001:00000001:%08X:6AE11CDF:%s:%s:%s:", fakeTasksNode, t.gen, task.workerType,
		task.workerID, fakeTokenID)
	t.tasks[upid] = task
	return upid
}

// starter returns a handler that starts the task next makes for each
// request, and answers its UPID as PBS does.
func (t *fakeTasks) starter(next func(req *http.Request) *fakeTask) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		writeData(w, t.start(next(req)), "")
	}
}

// task returns the task of a UPID.
func (t *fakeTasks) task(upid string) *fakeTask {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tasks[upid]
}

// all returns the tasks started so far, in no order.
func (t *fakeTasks) all() []*fakeTask {
	t.mu.Lock()
	defer t.mu.Unlock()
	var tasks []*fakeTask
	for _, task := range t.tasks {
		tasks = append(tasks, task)
	}
	return tasks
}

func (t *fakeTasks) serve(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/nodes/"+fakeTasksNode+"/tasks/")
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case strings.HasSuffix(rest, "/status"):
		upid := strings.TrimSuffix(rest, "/status")
		task, ok := t.tasks[upid]
		if !ok {
			writeData(w, map[string]any{"upid": upid, "status": "stopped", "exitstatus": "unknown"}, "")
			return
		}
		task.polls++
		if !task.stopped {
			switch {
			case task.aborted && !task.ignoresAbort:
				task.exit = "aborted"
				task.stop()
			case task.running == 0:
				task.stop()
			case task.running > 0:
				task.running--
			}
		}
		if !task.stopped {
			writeData(w, map[string]any{"upid": upid, "status": "running"}, "")
			return
		}
		writeData(w, map[string]any{"upid": upid, "status": "stopped", "exitstatus": task.exit}, "")
	case strings.HasSuffix(rest, "/log"):
		task, ok := t.tasks[strings.TrimSuffix(rest, "/log")]
		if !ok {
			writeError(w, "No such file or directory (os error 2)")
			return
		}
		lines := task.lines()
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
			data = append(data, line{i + 1, "2026-11-14T10:00:00+01:00: " + text})
		}
		body, _ := json.Marshal(map[string]any{"data": data, "total": len(lines), "active": !task.stopped, "success": 1})
		writeFakeResponse(w, http.StatusOK, string(body))
	default:
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
	}
}

func (t *fakeTasks) abort(w http.ResponseWriter, req *http.Request) {
	upid := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/nodes/"+fakeTasksNode+"/tasks/")
	t.mu.Lock()
	defer t.mu.Unlock()
	if task, ok := t.tasks[upid]; ok && !task.stopped {
		task.aborted = true
		task.log = append(task.log, "received abort request ...")
	}
	writeData(w, nil, "")
}

// stop ends the task.
func (task *fakeTask) stop() {
	task.stopped = true
	if task.onStop != nil {
		task.onStop()
	}
}

// lines is the task's log as it stands: its messages and, once it stopped,
// its result.
func (task *fakeTask) lines() []string {
	lines := append([]string(nil), task.log...)
	if !task.stopped {
		return lines
	}
	switch {
	case task.exit == "OK":
		lines = append(lines, "TASK OK")
	case strings.HasPrefix(task.exit, "WARNINGS"):
		lines = append(lines, "TASK "+task.exit)
	default:
		lines = append(lines, "TASK ERROR: "+task.exit)
	}
	return lines
}
