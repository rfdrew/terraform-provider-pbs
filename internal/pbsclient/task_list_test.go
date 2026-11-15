package pbsclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The route of the node's task list.
const taskListRoute = "GET /nodes/localhost/tasks"

// Every filter goes to PBS under its own name, a status set as the key
// repeated, and limit always, so that 0 asks for every task rather than
// PBS's default of 50. errors is never sent.
func TestListTasksQuery(t *testing.T) {
	fake := newFakePBS()
	fake.reply(taskListRoute, http.StatusOK, `{"data":[],"total":0}`)
	c := fake.client(t)

	since, until := int64(1794646800), int64(1794650400)
	if _, err := c.ListTasks(context.Background(), "localhost", TaskListFilter{
		Store:      "store1",
		TypeFilter: "garbage_collection",
		UserFilter: "root@pam",
		Statuses:   []string{TaskStateError, TaskStateUnknown},
		Since:      &since,
		Until:      &until,
		Start:      10,
		Limit:      5,
	}); err != nil {
		t.Fatal(err)
	}
	want := url.Values{
		"store": {"store1"}, "typefilter": {"garbage_collection"}, "userfilter": {"root@pam"},
		"statusfilter": {"error", "unknown"}, "since": {"1794646800"}, "until": {"1794650400"},
		"start": {"10"}, "limit": {"5"},
	}
	if got := fake.lastCall(t, taskListRoute).query; !reflect.DeepEqual(got, want) {
		t.Errorf("query = %v, want %v", got, want)
	}

	if _, err := c.ListTasks(context.Background(), "localhost", TaskListFilter{Running: true}); err != nil {
		t.Fatal(err)
	}
	want = url.Values{"running": {"1"}, "limit": {"0"}}
	if got := fake.lastCall(t, taskListRoute).query; !reflect.DeepEqual(got, want) {
		t.Errorf("query = %v, want %v", got, want)
	}
}

// A list as PBS 4.2.8 answers it, total next to data: a running task has
// neither endtime nor status, and a task without a worker ID has null.
func TestListTasksDecodes(t *testing.T) {
	fake := newFakePBS()
	fake.reply(taskListRoute, http.StatusOK, `{"data":[
		{"upid":"UPID:pbs:00000A1B:0001E240:00000010:6AE11CDF:syncjob:offsite\\x3astore2\\x3astore1\\x3a\\x3anightly:root@pam:","node":"localhost","pid":2587,"pstart":123456,"starttime":1793137887,"worker_type":"syncjob","worker_id":"offsite:store2:store1::nightly","user":"root@pam"},
		{"upid":"UPID:pbs:00000A1B:0001E240:0000000F:6AE11C00:garbage_collection:store1:root@pam:","node":"localhost","pid":2587,"pstart":123456,"starttime":1793137664,"worker_type":"garbage_collection","worker_id":"store1","user":"root@pam","endtime":1793137700,"status":"OK"},
		{"upid":"UPID:pbs:00000A1B:0001E240:0000000E:6AE11B00:prunejob:store1:root@pam:","node":"localhost","pid":2587,"pstart":123456,"starttime":1793137408,"worker_type":"prunejob","worker_id":"store1","user":"root@pam","endtime":1793137410,"status":"WARNINGS: 2"},
		{"upid":"UPID:pbs:00000A1B:0001E240:0000000D:6AE11A00:create-datastore:store9:tfacc@pbs!acc:","node":"localhost","pid":2587,"pstart":123456,"starttime":1793137152,"worker_type":"create-datastore","worker_id":"store9","user":"tfacc@pbs!acc","endtime":1793137152,"status":"datastore path not empty"},
		{"upid":"UPID:pbs:00000A1B:0001E240:0000000C:6AE11900:aptupdate::root@pam:","node":"localhost","pid":2587,"pstart":123456,"starttime":1793136896,"worker_type":"aptupdate","worker_id":null,"user":"root@pam","endtime":1793136900,"status":"unknown"}
	],"total":5}`)
	c := fake.client(t)

	tasks, err := c.ListTasks(context.Background(), "localhost", TaskListFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, task := range tasks {
		end, status := "-", "-"
		if task.EndTime != nil {
			end = strconv.FormatInt(*task.EndTime, 10)
		}
		if task.Status != nil {
			status = *task.Status
		}
		got = append(got, fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s|%v", task.WorkerType, task.WorkerID, task.User,
			task.StartTime, end, status, task.State(), task.Running()))
	}
	want := []string{
		"syncjob|offsite:store2:store1::nightly|root@pam|1793137887|-|-|running|true",
		"garbage_collection|store1|root@pam|1793137664|1793137700|OK|ok|false",
		"prunejob|store1|root@pam|1793137408|1793137410|WARNINGS: 2|warning|false",
		"create-datastore|store9|tfacc@pbs!acc|1793137152|1793137152|datastore path not empty|error|false",
		"aptupdate||root@pam|1793136896|1793136900|unknown|unknown|false",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tasks =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// An empty list, or null, is an empty slice.
	for _, body := range []string{`{"data":[],"total":0}`, `{"data":null}`} {
		fake.reply(taskListRoute, http.StatusOK, body)
		if tasks, err := c.ListTasks(context.Background(), "localhost", TaskListFilter{}); err != nil || tasks == nil || len(tasks) != 0 {
			t.Errorf("ListTasks() of %s = %#v, %v", body, tasks, err)
		}
	}
}

func TestTaskStateOf(t *testing.T) {
	for exit, want := range map[string]string{
		"OK":                       TaskStateOK,
		"WARNINGS: 1":              TaskStateWarning,
		"WARNINGS: 12":             TaskStateWarning,
		"unknown":                  TaskStateUnknown,
		"datastore path not empty": TaskStateError,
		"aborted":                  TaskStateError,
		"WARNINGS":                 TaskStateError,
	} {
		if got := TaskStateOf(exit); got != want {
			t.Errorf("TaskStateOf(%q) = %q, want %q", exit, got, want)
		}
	}
}

// fakeTaskListServer serves a fixed task list as PBS does: typefilter
// matched as a part of the type, then start and limit, with total. before
// runs before each answer, with the number of the call, to change the list
// between calls.
type fakeTaskListServer struct {
	mu     sync.Mutex
	tasks  []TaskListItem
	calls  int
	before func(call int, s *fakeTaskListServer)
}

func (s *fakeTaskListServer) serve(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.before != nil {
		s.before(s.calls, s)
	}
	query := req.URL.Query()
	start, _ := strconv.Atoi(query.Get("start"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	data := []TaskListItem{}
	skipped := 0
	for _, task := range s.tasks {
		if !strings.Contains(task.WorkerType, query.Get("typefilter")) {
			continue
		}
		if skipped < start {
			skipped++
			continue
		}
		data = append(data, task)
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

// fakeListedTasks makes n finished tasks of a type, with the given type at
// the given positions instead.
func fakeListedTasks(n int, workerType string, others map[int]string) []TaskListItem {
	tasks := make([]TaskListItem, n)
	for i := range tasks {
		typ := workerType
		if other, ok := others[i]; ok {
			typ = other
		}
		end, status := int64(1793137887-i), "OK"
		tasks[i] = TaskListItem{
			UPID:      fmt.Sprintf("UPID:pbs:00000001:00000001:%08X:6AE11CDF:%s:store1:root@pam:", i, typ),
			StartTime: 1793137887 - int64(i), WorkerType: typ, WorkerID: "store1", User: "root@pam",
			EndTime: &end, Status: &status,
		}
	}
	return tasks
}

// listedPages returns the start and limit of each call to the task list.
func listedPages(fake *fakePBS) []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var pages []string
	for _, call := range fake.calls {
		if call.route == taskListRoute {
			pages = append(pages, call.query.Get("start")+"/"+call.query.Get("limit"))
		}
	}
	return pages
}

func TestListTasksMatching(t *testing.T) {
	exact := func(task TaskListItem) bool { return task.WorkerType == "prune" }
	for name, tc := range map[string]struct {
		tasks []TaskListItem
		limit int
		match func(TaskListItem) bool
		// before changes the list between calls.
		before func(call int, s *fakeTaskListServer)
		// want are the positions in tasks of the tasks listed, pages the
		// start/limit of each call.
		want  []int
		pages []string
	}{
		// PBS's typefilter "prune" lists prunejob tasks too: the first
		// page holds one prune task, so the next, twice as long, is read
		// to fill the limit, from 10 tasks before the end of the first.
		"pages until the limit is filled": {
			tasks: fakeListedTasks(400, "prunejob", map[int]string{5: "prune", 150: "prune", 260: "prune", 390: "prune"}),
			limit: 3, match: exact,
			want:  []int{5, 150, 260},
			pages: []string{"/100", "90/200"},
		},
		"stops at a short page": {
			tasks: fakeListedTasks(400, "prunejob", map[int]string{5: "prune", 150: "prune", 260: "prune", 390: "prune"}),
			limit: 10, match: exact,
			want:  []int{5, 150, 260, 390},
			pages: []string{"/100", "90/200", "280/400"},
		},
		// No exact match at all: the pages grow, so the list takes few
		// calls however long it is.
		"no exact match": {
			tasks: fakeListedTasks(3000, "prunejob", nil),
			limit: 1, match: exact,
			pages: []string{"/100", "90/200", "280/400", "670/800", "1460/1600"},
		},
		// A limit above the smallest page is the first page.
		"a large limit": {
			tasks: fakeListedTasks(300, "prunejob", map[int]string{0: "prune", 299: "prune"}),
			limit: 250, match: exact,
			want:  []int{0, 299},
			pages: []string{"/250", "240/500"},
		},
		// A task starting between two calls shifts the list forward by
		// one: the last task of the first page comes again on the second,
		// after those read again anyway, and is listed once.
		"a task listed twice is kept once": {
			tasks: fakeListedTasks(150, "prunejob", map[int]string{99: "prune"}),
			limit: 5, match: exact,
			before: func(call int, s *fakeTaskListServer) {
				if call == 2 {
					started := fakeListedTasks(1, "prunejob", nil)[0]
					started.UPID = strings.Replace(started.UPID, ":00000000:", ":0000FFFF:", 1)
					started.EndTime, started.Status = nil, nil
					s.tasks = append([]TaskListItem{started}, s.tasks...)
				}
			},
			want:  []int{99},
			pages: []string{"/100", "90/200"},
		},
		// A task of the first page that ends between two calls, with
		// running set, leaves the list, and those after it shift back by
		// one: the match that would start the second page moves to the
		// end of the first, which the second page reads again.
		"a task leaving the list misses none": {
			tasks: fakeListedTasks(150, "prunejob", map[int]string{100: "prune"}),
			limit: 5, match: exact,
			before: func(call int, s *fakeTaskListServer) {
				if call == 2 {
					s.tasks = append(s.tasks[:50:50], s.tasks[51:]...)
				}
			},
			want:  []int{100},
			pages: []string{"/100", "90/200"},
		},
		"limit 0 is one call for every task": {
			tasks: fakeListedTasks(400, "prunejob", map[int]string{5: "prune", 390: "prune"}),
			limit: 0, match: exact,
			want:  []int{5, 390},
			pages: []string{"/0"},
		},
		"without a match, ListTasks": {
			tasks: fakeListedTasks(400, "prunejob", nil),
			limit: 3,
			want:  []int{0, 1, 2},
			pages: []string{"/3"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			server := &fakeTaskListServer{tasks: tc.tasks, before: tc.before}
			fake.handle(taskListRoute, server.serve)
			c := fake.client(t)

			got, err := c.ListTasksMatching(context.Background(), "localhost", TaskListFilter{TypeFilter: "prune", Limit: tc.limit}, tc.match)
			if err != nil {
				t.Fatal(err)
			}
			want := []TaskListItem{}
			for _, i := range tc.want {
				want = append(want, tc.tasks[i])
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("ListTasksMatching() listed %d tasks, want %d: %+v", len(got), len(want), got)
			}
			if pages := listedPages(fake); !reflect.DeepEqual(pages, tc.pages) {
				t.Errorf("pages (start/limit) = %v, want %v", pages, tc.pages)
			}
			for _, call := range fake.calls {
				if call.query.Get("typefilter") != "prune" {
					t.Errorf("a call left out typefilter: %v", call.query)
				}
			}
		})
	}
}

// PBS refuses a task to anyone who may not see it with a 400, which only its
// text tells from other 400s. A missing log is IsNotFound.
func TestIsTaskAccessDenied(t *testing.T) {
	denied := &Error{StatusCode: http.StatusBadRequest, Message: "task access not allowed"}
	if !IsTaskAccessDenied(denied) || !IsTaskAccessDenied(fmt.Errorf("reading: %w", denied)) {
		t.Error("IsTaskAccessDenied() = false for PBS's answer")
	}
	for _, err := range []error{
		&Error{StatusCode: http.StatusBadRequest, Message: "No such file or directory (os error 2)"},
		&Error{StatusCode: http.StatusForbidden, Message: "permission check failed"},
		&Error{StatusCode: http.StatusBadRequest, Message: "parameter verification failed - 'upid': value does not match the regex pattern"},
		nil,
	} {
		if IsTaskAccessDenied(err) {
			t.Errorf("IsTaskAccessDenied(%v) = true", err)
		}
	}
	if !IsNotFound(&Error{StatusCode: http.StatusBadRequest, Message: "No such file or directory (os error 2)"}) {
		t.Error("IsNotFound() = false for the log of a task PBS does not know")
	}
}

// The status of a task a token started, as PBS 4.2.1 and later report it:
// the worker ID unescaped, the token's name apart from its user, and the
// end time.
func TestTaskStatusDecodes(t *testing.T) {
	upid, _ := ParseUPID(sampleUPID)
	fake := newFakePBS()
	fake.reply(sampleStatusRoute, http.StatusOK, `{"data":{"upid":"`+strings.ReplaceAll(sampleUPID, `\`, `\\`)+`",
		"node":"pbs-acc","pid":11,"pstart":4903,"starttime":1793137887,"type":"create-datastore","id":"probe-b",
		"user":"tfacc@pbs","tokenid":"acc","status":"stopped","exitstatus":"OK","endtime":1793137889}}`)
	c := fake.client(t)

	status, err := c.TaskStatus(context.Background(), upid)
	if err != nil {
		t.Fatal(err)
	}
	if status.UPID != sampleUPID || status.StartTime != 1793137887 || status.EndTime == nil || *status.EndTime != 1793137889 ||
		status.ID != "probe-b" || status.Type != "create-datastore" || status.AuthID() != "tfacc@pbs!acc" {
		t.Errorf("TaskStatus() = %+v, auth ID %q", status, status.AuthID())
	}

	// Before 4.2.1, without endtime; a user's own task, without tokenid;
	// a task without a worker ID, with null.
	fake.reply(sampleStatusRoute, http.StatusOK, `{"data":{"starttime":1793137887,"type":"aptupdate","id":null,
		"user":"root@pam","status":"stopped","exitstatus":"OK"}}`)
	status, err = c.TaskStatus(context.Background(), upid)
	if err != nil {
		t.Fatal(err)
	}
	if status.EndTime != nil || status.ID != "" || status.AuthID() != "root@pam" {
		t.Errorf("TaskStatus() = %+v, auth ID %q", status, status.AuthID())
	}
}

func TestTaskLogLineTime(t *testing.T) {
	for _, tc := range []struct {
		text string
		want int64
		ok   bool
	}{
		// 10:00 at +01:00 is 09:00 UTC.
		{"2026-11-14T10:00:00+01:00: TASK OK", 1794646800, true},
		{"2026-11-14T03:30:00-05:30: starting garbage collection on store store1", 1794646800, true},
		{"2026-11-14T09:00:00Z: x", 1794646800, true},
		// A continuation line, and text that only looks like a time.
		{"  check archive.didx", 0, false},
		{"Caused by: no space left", 0, false},
		{"2026-11-14 10:00:00 +01:00: x", 0, false},
		{"", 0, false},
	} {
		got, ok := (TaskLogLine{Text: tc.text}).Time()
		if ok != tc.ok || (ok && got.Unix() != tc.want) {
			t.Errorf("Time(%q) = %v, %v; want %d, %v", tc.text, got, ok, tc.want, tc.ok)
		}
	}
}

func TestTaskEndFromLog(t *testing.T) {
	lines := func(texts ...string) []TaskLogLine {
		out := make([]TaskLogLine, len(texts))
		for i, text := range texts {
			out[i] = TaskLogLine{N: i + 1, Text: text}
		}
		return out
	}
	for name, tc := range map[string]struct {
		lines []TaskLogLine
		want  int64
		ok    bool
	}{
		"last line": {
			lines: lines("2026-11-14T10:00:00+01:00: starting", "2026-11-14T10:00:05+01:00: TASK OK"),
			want:  1794646805, ok: true,
		},
		// An error of several lines goes on below TASK ERROR, without
		// times: the end is the time of TASK ERROR.
		"error of several lines": {
			lines: lines("2026-11-14T10:00:00+01:00: starting",
				"2026-11-14T10:00:05+01:00: TASK ERROR: sync failed",
				"", "Caused by:", "    0: connection refused"),
			want: 1794646805, ok: true,
		},
		"no time at all": {lines: lines("  a", "  b")},
		"no lines":       {},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := TaskEndFromLog(tc.lines)
			if got != tc.want || ok != tc.ok {
				t.Errorf("TaskEndFromLog() = %d, %v; want %d, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
