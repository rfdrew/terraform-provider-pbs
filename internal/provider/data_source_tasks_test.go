package provider

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestTasksDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &tasksDataSource{})
}

// The route of the node's task list, and of the caller's privileges.
const (
	taskListRoute        = "GET /nodes/localhost/tasks"
	taskPermissionsRoute = "GET /access/permissions"
)

// The caller's privileges on /system/tasks, with and without Sys.Audit.
const (
	seesAllTasksJSON = `{"data":{"/system/tasks":{"Sys.Audit":true,"Sys.Modify":true}}}`
	seesOwnTasksJSON = `{"data":{}}`
)

// taskListOfANode are the tasks of a node in PBS's order — a running sync
// job, then finished tasks, the most recently ended first — one of each
// way a task ends, and one without a worker ID. Times are on 2026-11-14,
// from 08:10 to 09:00 UTC.
var taskListOfANode = []pbsclient.TaskListItem{
	fakeListedTask(`UPID:pbs1:00000A1B:0001E240:00000006:6AF82310:syncjob:offsite\x3astore2\x3astore1\x3a\x3anightly:root@pam:`,
		1794646800, "syncjob", "offsite:store2:store1::nightly", "root@pam", 0, ""),
	fakeListedTask(`UPID:pbs1:00000A1B:0001E240:00000005:6AF820B8:garbage_collection:store1:root@pam:`,
		1794646200, "garbage_collection", "store1", "root@pam", 1794646325, "OK"),
	fakeListedTask(`UPID:pbs1:00000A1B:0001E240:00000004:6AF81E60:prunejob:store1:root@pam:`,
		1794645600, "prunejob", "store1", "root@pam", 1794645603, "WARNINGS: 2"),
	fakeListedTask(`UPID:pbs1:00000A1B:0001E240:00000003:6AF81C08:create-datastore:store9:tfacc@pbs!acc:`,
		1794645000, "create-datastore", "store9", "tfacc@pbs!acc", 1794645000,
		`parameter verification failed - 'path': nested datastores not allowed: 'store1' already in "/datastore"`),
	fakeListedTask(`UPID:pbs1:00000A1B:0001E240:00000002:6AF819B0:verificationjob:store1\x3av\x2dweekly:root@pam:`,
		1794644400, "verificationjob", "store1:v-weekly", "root@pam", 1794644700, "unknown"),
	fakeListedTask(`UPID:pbs1:00000A1B:0001E240:00000001:6AF81758:aptupdate::root@pam:`,
		1794643800, "aptupdate", "", "root@pam", 1794643830, "OK"),
}

// pbsTasksElement is a task as pbs_tasks holds it; end "" for a running one.
func pbsTasksElement(upid, workerType string, workerID any, authID, start, end string, duration any, status string, exit any) map[string]any {
	state := map[string]any{
		"upid": upid, "worker_type": workerType, "worker_id": workerID, "auth_id": authID,
		"start_time": start, "end_time": nil, "duration": duration, "status": status, "exit_status": exit,
	}
	if end != "" {
		state["end_time"] = end
	}
	return state
}

// Every task as PBS lists it, in PBS's order, with RFC 3339 times in UTC:
// a running one has no end, duration or exit status, and a task without a
// worker ID none either. Without filters, only limit is sent: PBS's
// default of 50.
func TestTasksDataSourceReadsTheTasks(t *testing.T) {
	fake := newFakePBS()
	newFakeTaskList(fake, "localhost", taskListOfANode...)
	fake.reply(taskPermissionsRoute, http.StatusOK, seesAllTasksJSON)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", map[string]any{}))
	want := h.dataSourceValue(t, "pbs_tasks", map[string]any{
		"node":           "localhost",
		"sees_all_tasks": true,
		"tasks": []any{
			pbsTasksElement(taskListOfANode[0].UPID, "syncjob", "offsite:store2:store1::nightly", "root@pam",
				"2026-11-14T09:00:00Z", "", nil, "running", nil),
			pbsTasksElement(taskListOfANode[1].UPID, "garbage_collection", "store1", "root@pam",
				"2026-11-14T08:50:00Z", "2026-11-14T08:52:05Z", 125, "ok", "OK"),
			pbsTasksElement(taskListOfANode[2].UPID, "prunejob", "store1", "root@pam",
				"2026-11-14T08:40:00Z", "2026-11-14T08:40:03Z", 3, "warning", "WARNINGS: 2"),
			pbsTasksElement(taskListOfANode[3].UPID, "create-datastore", "store9", "tfacc@pbs!acc",
				"2026-11-14T08:30:00Z", "2026-11-14T08:30:00Z", 0, "error",
				`parameter verification failed - 'path': nested datastores not allowed: 'store1' already in "/datastore"`),
			pbsTasksElement(taskListOfANode[4].UPID, "verificationjob", "store1:v-weekly", "root@pam",
				"2026-11-14T08:20:00Z", "2026-11-14T08:25:00Z", 300, "unknown", "unknown"),
			pbsTasksElement(taskListOfANode[5].UPID, "aptupdate", nil, "root@pam",
				"2026-11-14T08:10:00Z", "2026-11-14T08:10:30Z", 30, "ok", "OK"),
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s\nwant %s", state, want)
	}
	if got := fake.lastCall(t, taskListRoute).query; !reflect.DeepEqual(got, url.Values{"limit": {"50"}}) {
		t.Errorf("query = %v, want only limit=50", got)
	}
	if got := fake.lastCall(t, taskPermissionsRoute).query; !reflect.DeepEqual(got, url.Values{"path": {"/system/tasks"}}) {
		t.Errorf("permissions query = %v, want path=/system/tasks", got)
	}
}

// The filters go to PBS: times as seconds since the epoch, since rounded up
// and until down to whole seconds, as PBS keeps start times; the status set
// as statusfilter repeated; limit as configured, 0 included.
func TestTasksDataSourceSendsTheFilters(t *testing.T) {
	for name, tc := range map[string]struct {
		config map[string]any
		query  url.Values
	}{
		"every filter": {
			// 10:00 at +01:00 is 09:00 UTC, 1794646800.
			config: map[string]any{
				"node": "pbs1", "store": "store1", "status": []string{"unknown", "error"},
				"since": "2026-11-14T10:00:00+01:00", "until": "2026-11-14T09:30:00.5Z", "limit": 0,
			},
			query: url.Values{
				"store": {"store1"}, "statusfilter": {"error", "unknown"},
				"since": {"1794646800"}, "until": {"1794648600"}, "limit": {"0"},
			},
		},
		"fractions of a second": {
			config: map[string]any{"node": "pbs1", "since": "2026-11-14T09:00:00.25Z", "until": "2026-11-14T09:30:00Z", "limit": 7},
			query:  url.Values{"since": {"1794646801"}, "until": {"1794648600"}, "limit": {"7"}},
		},
		"running": {
			config: map[string]any{"node": "pbs1", "running": true},
			query:  url.Values{"running": {"1"}, "limit": {"50"}},
		},
		// running = false is no filter, and may be set with status.
		"not running": {
			config: map[string]any{"node": "pbs1", "running": false, "status": []string{"ok"}},
			query:  url.Values{"statusfilter": {"ok"}, "limit": {"50"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			newFakeTaskList(fake, "pbs1")
			fake.reply(taskPermissionsRoute, http.StatusOK, seesAllTasksJSON)
			h := newProtocolHarness(t, fake)

			state := h.readDataSource(t, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", tc.config))
			if got := fake.lastCall(t, "GET /nodes/pbs1/tasks").query; !reflect.DeepEqual(got, tc.query) {
				t.Errorf("query = %v, want %v", got, tc.query)
			}
			// The state keeps the configuration: limit stays null without
			// one, rather than 50.
			if stringAt(t, state, "node") != "pbs1" {
				t.Errorf("node = %s", valueAt(t, state, "node"))
			}
			if _, set := tc.config["limit"]; set == isNullAt(t, state, "limit") {
				t.Errorf("limit = %s, configured %v", valueAt(t, state, "limit"), tc.config["limit"])
			}
		})
	}
}

// listedTasks returns an attribute, such as upid, of each task a pbs_tasks
// state lists, in order.
func listedTasks(t *testing.T, state tftypes.Value, attribute string) []string {
	t.Helper()
	n := lengthAt(t, state, "tasks")
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, stringAt(t, state, "tasks", i, attribute))
	}
	return out
}

// worker_type is matched exactly: PBS's typefilter lists the prune job
// tasks for "prune" too, which the data source leaves out, reading further
// pages of the list until it has limit tasks.
func TestTasksDataSourceMatchesTheWorkerTypeExactly(t *testing.T) {
	var tasks []pbsclient.TaskListItem
	for i := range 150 {
		typ := "prunejob"
		if i == 3 || i == 120 || i == 140 {
			typ = "prune"
		}
		tasks = append(tasks, fakeListedTask(
			"UPID:pbs1:00000A1B:0001E240:"+taskListHex(i)+":6AF82310:"+typ+":store1:root@pam:",
			1794646800-int64(i), typ, "store1", "root@pam", 1794646800-int64(i), "OK"))
	}
	tasks = append(tasks, fakeListedTask("UPID:pbs1:00000A1B:0001E240:0000FFFF:6AF82310:garbage_collection:store1:root@pam:",
		1794640000, "garbage_collection", "store1", "root@pam", 1794640000, "OK"))
	fake := newFakePBS()
	newFakeTaskList(fake, "localhost", tasks...)
	fake.reply(taskPermissionsRoute, http.StatusOK, seesAllTasksJSON)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", map[string]any{"worker_type": "prune", "limit": 2}))
	got := listedTasks(t, state, "upid")
	if want := []string{tasks[3].UPID, tasks[120].UPID}; !reflect.DeepEqual(got, want) {
		t.Errorf("tasks = %v, want %v", got, want)
	}
	var pages []string
	fake.mu.Lock()
	for _, call := range fake.calls {
		if call.route == taskListRoute {
			pages = append(pages, call.query.Encode())
		}
	}
	fake.mu.Unlock()
	// The second page starts 10 tasks before the end of the first, in case
	// tasks ended in between.
	if want := []string{"limit=100&typefilter=prune", "limit=200&start=90&typefilter=prune"}; !reflect.DeepEqual(pages, want) {
		t.Errorf("calls = %v, want %v", pages, want)
	}

	// limit 0 is one call for every task, filtered.
	state = h.readDataSource(t, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", map[string]any{"worker_type": "prune", "limit": 0}))
	got = listedTasks(t, state, "upid")
	if want := []string{tasks[3].UPID, tasks[120].UPID, tasks[140].UPID}; !reflect.DeepEqual(got, want) {
		t.Errorf("tasks = %v, want %v", got, want)
	}
	if got := fake.lastCall(t, taskListRoute).query.Encode(); got != "limit=0&typefilter=prune" {
		t.Errorf("query = %s", got)
	}
}

// taskListHex is n as the eight hexadecimal digits of a UPID.
func taskListHex(n int) string {
	const digits = "0123456789ABCDEF"
	b := []byte("00000000")
	for i := 7; i >= 0 && n > 0; i-- {
		b[i] = digits[n%16]
		n /= 16
	}
	return string(b)
}

// auth_id is matched exactly, a user ID also as the user of a token:
// PBS's userfilter matches a part of the auth ID.
func TestTasksDataSourceMatchesTheAuthID(t *testing.T) {
	var tasks []pbsclient.TaskListItem
	for i, authID := range []string{"u@pbs", "u@pbs!t", "xu@pbs", "u@pbs2", "u@pbs!t2", "a!x@pbs", "a!x@pbs!t", "u@pbsx!t"} {
		tasks = append(tasks, fakeListedTask("UPID:pbs1:00000A1B:0001E240:"+taskListHex(i)+":6AF82310:aptupdate::"+authID+":",
			1794646800-int64(i), "aptupdate", "", authID, 1794646800-int64(i), "OK"))
	}
	for authID, want := range map[string][]string{
		"u@pbs":   {"u@pbs", "u@pbs!t", "u@pbs!t2"},
		"u@pbs!t": {"u@pbs!t"},
		// A user name may contain "!".
		"a!x@pbs": {"a!x@pbs", "a!x@pbs!t"},
	} {
		t.Run(authID, func(t *testing.T) {
			fake := newFakePBS()
			newFakeTaskList(fake, "localhost", tasks...)
			fake.reply(taskPermissionsRoute, http.StatusOK, seesAllTasksJSON)
			h := newProtocolHarness(t, fake)

			state := h.readDataSource(t, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", map[string]any{"auth_id": authID}))
			got := listedTasks(t, state, "auth_id")
			if !reflect.DeepEqual(got, want) {
				t.Errorf("auth IDs = %v, want %v", got, want)
			}
			if got := fake.lastCall(t, taskListRoute).query.Get("userfilter"); got != authID {
				t.Errorf("userfilter = %q, want %q", got, authID)
			}
		})
	}
}

// store, since and status as PBS applies them, through the fake's copy of
// PBS's rules: the sync job of store1 counts, as its local datastore; the
// creation of store9 belongs to no datastore; since ends the list at the
// first task that ended before it.
func TestTasksDataSourceFilters(t *testing.T) {
	for name, tc := range map[string]struct {
		config map[string]any
		want   []int
	}{
		"store":          {config: map[string]any{"store": "store1"}, want: []int{0, 1, 2, 4}},
		"store of none":  {config: map[string]any{"store": "store9"}},
		"since":          {config: map[string]any{"since": "2026-11-14T08:40:00Z"}, want: []int{0, 1, 2}},
		"until":          {config: map[string]any{"until": "2026-11-14T08:30:00Z"}, want: []int{3, 4, 5}},
		"status":         {config: map[string]any{"status": []string{"error", "unknown"}}, want: []int{3, 4}},
		"running":        {config: map[string]any{"running": true}, want: []int{0}},
		"limit":          {config: map[string]any{"limit": 2}, want: []int{0, 1}},
		"type and since": {config: map[string]any{"worker_type": "aptupdate", "since": "2026-11-14T08:40:00Z"}},
		"a token's user": {config: map[string]any{"auth_id": "tfacc@pbs", "status": []string{"error"}}, want: []int{3}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			newFakeTaskList(fake, "localhost", taskListOfANode...)
			fake.reply(taskPermissionsRoute, http.StatusOK, seesAllTasksJSON)
			h := newProtocolHarness(t, fake)

			state := h.readDataSource(t, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", tc.config))
			got := listedTasks(t, state, "upid")
			want := []string{}
			for _, i := range tc.want {
				want = append(want, taskListOfANode[i].UPID)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("tasks = %v, want %v", got, want)
			}
		})
	}
}

// Nothing listed is an empty list, not null, so that length() works on it;
// without Sys.Audit on /system/tasks, sees_all_tasks is false.
func TestTasksDataSourceEmptyAndRestricted(t *testing.T) {
	for name, tc := range map[string]struct {
		list, permissions string
		seesAll           bool
	}{
		"empty list":                   {list: `{"data":[],"total":0}`, permissions: seesAllTasksJSON, seesAll: true},
		"null data":                    {list: `{"data":null}`, permissions: seesAllTasksJSON, seesAll: true},
		"no privilege on the path":     {list: `{"data":[],"total":0}`, permissions: seesOwnTasksJSON},
		"other privileges on the path": {list: `{"data":[],"total":0}`, permissions: `{"data":{"/system/tasks":{"Sys.Modify":false}}}`},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(taskListRoute, http.StatusOK, tc.list)
			fake.reply(taskPermissionsRoute, http.StatusOK, tc.permissions)
			h := newProtocolHarness(t, fake)

			state := h.readDataSource(t, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", map[string]any{}))
			want := h.dataSourceValue(t, "pbs_tasks", map[string]any{"node": "localhost", "sees_all_tasks": tc.seesAll, "tasks": []any{}})
			if !state.Equal(want) {
				t.Errorf("state = %s, want %s", state, want)
			}
		})
	}
}

func TestTasksDataSourceErrors(t *testing.T) {
	fake := newFakePBS()
	fake.reply(taskListRoute, http.StatusBadRequest, "parameter verification failed - 'store': value does not match the regex pattern")
	fake.reply(taskPermissionsRoute, http.StatusOK, seesAllTasksJSON)
	h := newProtocolHarness(t, fake)
	resp := h.readDataSourceResponse(t, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", map[string]any{}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS tasks")
	requireProtocolErrorContaining(t, resp.Diagnostics, "value does not match the regex pattern")

	fake.reply(taskListRoute, http.StatusOK, `{"data":[],"total":0}`)
	fake.reply(taskPermissionsRoute, http.StatusServiceUnavailable, "service unavailable")
	resp = h.readDataSourceResponse(t, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", map[string]any{}))
	requireProtocolErrorContaining(t, resp.Diagnostics, `Unable to read the PBS privileges of "tfacc@pbs!acc"`)
}

// What the schema refuses before anything is read.
func TestTasksDataSourceValidation(t *testing.T) {
	fake := newFakePBS()
	h := newProtocolHarness(t, fake)
	for name, tc := range map[string]struct {
		config map[string]any
		want   string
	}{
		"since not a time":    {config: map[string]any{"since": "yesterday"}, want: "must be a time in RFC 3339 format"},
		"until without zone":  {config: map[string]any{"until": "2026-11-14T10:00:00"}, want: "must be a time in RFC 3339 format"},
		"unknown status":      {config: map[string]any{"status": []string{"failed"}}, want: "value must be one of"},
		"empty status set":    {config: map[string]any{"status": []string{}}, want: "set must contain at least 1 elements"},
		"running with status": {config: map[string]any{"running": true, "status": []string{"error"}}, want: "`running = true` lists running tasks"},
		"negative limit":      {config: map[string]any{"limit": -1}, want: "value must be at least 0"},
		"worker type":         {config: map[string]any{"worker_type": "a:b"}, want: "must be a worker type"},
		"empty worker type":   {config: map[string]any{"worker_type": ""}, want: "string length must be at least 1"},
		"node":                {config: map[string]any{"node": "bad_node"}, want: "must be a node name"},
		"auth ID":             {config: map[string]any{"auth_id": "nobody"}, want: "must be a user ID"},
		"store":               {config: map[string]any{"store": "s"}, want: "string length must be between 3 and 32"},
	} {
		t.Run(name, func(t *testing.T) {
			diags := dataSourceConfigDiagnostics(t, h, "pbs_tasks", h.dataSourceValue(t, "pbs_tasks", tc.config))
			requireProtocolErrorContaining(t, diags, tc.want)
		})
	}
	if n := fake.count(taskListRoute); n != 0 {
		t.Errorf("the task list was read %d times", n)
	}
}
