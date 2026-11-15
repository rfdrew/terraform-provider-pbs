package provider

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestTaskDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &taskDataSource{})
}

// A task a token started, as PBS 4.2 names it: its worker ID escaped in the
// UPID, started 2026-11-14 at 09:00:00 UTC.
const pbsTaskUPID = `UPID:pbs-acc:0000000B:00001327:00000003:6AF82310:create-datastore:probe\x2db:tfacc@pbs!acc:`

// The routes of pbsTaskUPID's status and log: the path as the request
// arrives, unescaped.
const (
	pbsTaskStatusRoute = "GET /nodes/pbs-acc/tasks/" + pbsTaskUPID + "/status"
	pbsTaskLogRoute    = "GET /nodes/pbs-acc/tasks/" + pbsTaskUPID + "/log"
)

// pbsTaskStatusJSON is pbsTaskUPID's status as PBS answers it: running
// without exitstatus, and endtime only when end is not 0, as from 4.2.1.
func pbsTaskStatusJSON(exit string, end int64) string {
	status := map[string]any{
		"upid": pbsTaskUPID, "node": "pbs-acc", "pid": 11, "pstart": 4903, "starttime": 1794646800,
		"type": "create-datastore", "id": "probe-b", "user": "tfacc@pbs", "tokenid": "acc", "status": "running",
	}
	if exit != "" {
		status["status"], status["exitstatus"] = "stopped", exit
	}
	if end != 0 {
		status["endtime"] = end
	}
	body, _ := json.Marshal(map[string]any{"data": status})
	return string(body)
}

// pbsTaskState is pbs_task's state of pbsTaskUPID.
func pbsTaskState(end string, duration any, status string, exit any, logLines any, log any) map[string]any {
	state := map[string]any{
		"upid": pbsTaskUPID, "worker_type": "create-datastore", "worker_id": "probe-b", "auth_id": "tfacc@pbs!acc",
		"start_time": "2026-11-14T09:00:00Z", "end_time": nil, "duration": duration, "status": status,
		"exit_status": exit, "log_lines": logLines, "log": log,
	}
	if end != "" {
		state["end_time"] = end
	}
	return state
}

// The log of a task that failed with an error of several lines, which goes
// on below TASK ERROR without times; 10:00 at +01:00 is 09:00 UTC.
var pbsTaskLog = []string{
	"2026-11-14T10:00:00+01:00: creating datastore 'probe-b' on '/datastore'",
	"2026-11-14T10:00:07+01:00: TASK ERROR: datastore path not empty",
	"",
	"Caused by:",
	"    directory is not empty",
}

func TestTaskDataSourceReads(t *testing.T) {
	for name, tc := range map[string]struct {
		status string
		// log serves the task's log; nil leaves it unrouted.
		log      []string
		logLines any
		want     map[string]any
		// logCalls is how many times the log is read: twice for a tail,
		// once for its length and once for the lines.
		logCalls int
		// tailStart and tailLimit are the last log read's.
		tailStart, tailLimit string
	}{
		// PBS 4.2.1 and later report the end: the log is not read.
		"finished, with endtime": {
			status: pbsTaskStatusJSON("OK", 1794646807),
			want:   pbsTaskState("2026-11-14T09:00:07Z", 7, "ok", "OK", nil, nil),
		},
		// Before 4.2.1, the end is the time of the last line of the log
		// that has one, below which an error of several lines goes on.
		"finished, before 4.2.1": {
			status:   pbsTaskStatusJSON("datastore path not empty", 0),
			log:      pbsTaskLog,
			want:     pbsTaskState("2026-11-14T09:00:07Z", 7, "error", "datastore path not empty", nil, nil),
			logCalls: 2, tailStart: "1", tailLimit: "50",
		},
		"running": {
			status: pbsTaskStatusJSON("", 0),
			want:   pbsTaskState("", nil, "running", nil, nil, nil),
		},
		"running, with its log": {
			status:   pbsTaskStatusJSON("", 0),
			log:      pbsTaskLog[:1],
			logLines: 3,
			want:     pbsTaskState("", nil, "running", nil, 3, pbsTaskLog[:1]),
			logCalls: 2, tailStart: "1", tailLimit: "3",
		},
		// The log as PBS wrote it, times included, and the lines
		// without one.
		"the last lines of the log": {
			status:   pbsTaskStatusJSON("datastore path not empty", 1794646807),
			log:      pbsTaskLog,
			logLines: 3,
			want:     pbsTaskState("2026-11-14T09:00:07Z", 7, "error", "datastore path not empty", 3, pbsTaskLog[2:]),
			logCalls: 2, tailStart: "3", tailLimit: "3",
		},
		"the last lines of the log, before 4.2.1": {
			status:   pbsTaskStatusJSON("datastore path not empty", 0),
			log:      pbsTaskLog,
			logLines: 2,
			want:     pbsTaskState("2026-11-14T09:00:07Z", 7, "error", "datastore path not empty", 2, pbsTaskLog[3:]),
			logCalls: 2, tailStart: "1", tailLimit: "50",
		},
		// A task PBS lost track of: its log has no TASK line. It ends
		// at the last line with a time.
		"unknown": {
			status:   pbsTaskStatusJSON("unknown", 0),
			log:      []string{"2026-11-14T10:00:00+01:00: creating datastore", "2026-11-14T10:01:40+01:00: still creating"},
			want:     pbsTaskState("2026-11-14T09:01:40Z", 100, "unknown", "unknown", nil, nil),
			logCalls: 2, tailStart: "1", tailLimit: "50",
		},
		// ... or at its start, when no line has one.
		"unknown, without a time in its log": {
			status:   pbsTaskStatusJSON("unknown", 0),
			log:      []string{"  a line without a time"},
			want:     pbsTaskState("2026-11-14T09:00:00Z", 0, "unknown", "unknown", nil, nil),
			logCalls: 2, tailStart: "1", tailLimit: "50",
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(pbsTaskStatusRoute, http.StatusOK, tc.status)
			if tc.log != nil {
				fake.handle(pbsTaskLogRoute, fakeTaskLogLines(tc.status == pbsTaskStatusJSON("", 0), tc.log...))
			}
			h := newProtocolHarness(t, fake)

			config := map[string]any{"upid": pbsTaskUPID, "log_lines": tc.logLines}
			state := h.readDataSource(t, "pbs_task", h.dataSourceValue(t, "pbs_task", config))
			if want := h.dataSourceValue(t, "pbs_task", tc.want); !state.Equal(want) {
				t.Errorf("state = %s\nwant %s", state, want)
			}
			if n := fake.count(pbsTaskLogRoute); n != tc.logCalls {
				t.Errorf("the log was read %d times, want %d", n, tc.logCalls)
			}
			if tc.logCalls > 0 {
				query := fake.lastCall(t, pbsTaskLogRoute).query
				if query.Get("start") != tc.tailStart || query.Get("limit") != tc.tailLimit {
					t.Errorf("last log read: %v, want start %s and limit %s", query, tc.tailStart, tc.tailLimit)
				}
			}
		})
	}
}

// PBS answers a UPID it does not know as stopped and unknown, without an
// end; that its log is missing tells it from a task that did end unknown.
func TestTaskDataSourceNotFound(t *testing.T) {
	fake := newFakePBS()
	fake.reply(pbsTaskStatusRoute, http.StatusOK, pbsTaskStatusJSON("unknown", 0))
	fake.reply(pbsTaskLogRoute, http.StatusBadRequest, "No such file or directory (os error 2)")
	h := newProtocolHarness(t, fake)

	resp := h.readDataSourceResponse(t, "pbs_task", h.dataSourceValue(t, "pbs_task", map[string]any{"upid": pbsTaskUPID}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS task not found")
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS has no log of task "+pbsTaskUPID)
	for _, d := range resp.Diagnostics {
		if d.Attribute == nil || d.Attribute.String() != `AttributeName("upid")` {
			t.Errorf("the error is not on upid: %v", d.Attribute)
		}
	}
}

// A task the provider's token may not see is 400 "task access not allowed",
// which the error explains.
func TestTaskDataSourceAccessDenied(t *testing.T) {
	fake := newFakePBS()
	fake.reply(pbsTaskStatusRoute, http.StatusBadRequest, "task access not allowed")
	h := newProtocolHarness(t, fake)

	resp := h.readDataSourceResponse(t, "pbs_task", h.dataSourceValue(t, "pbs_task", map[string]any{"upid": pbsTaskUPID}))
	requireProtocolErrorContaining(t, resp.Diagnostics, `"tfacc@pbs!acc" may not read task `+pbsTaskUPID)
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS shows a task to the user or API token that started it")
	requireProtocolErrorContaining(t, resp.Diagnostics, "task access not allowed")

	fake.reply(pbsTaskStatusRoute, http.StatusOK, pbsTaskStatusJSON("OK", 0))
	fake.reply(pbsTaskLogRoute, http.StatusServiceUnavailable, "service unavailable")
	resp = h.readDataSourceResponse(t, "pbs_task", h.dataSourceValue(t, "pbs_task", map[string]any{"upid": pbsTaskUPID}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to read the log of PBS task")
}

// Only a PBS task ID passes: not a Proxmox VE one, which has a field
// fewer, nor one in lower case.
func TestTaskDataSourceValidation(t *testing.T) {
	fake := newFakePBS()
	h := newProtocolHarness(t, fake)
	for name, config := range map[string]map[string]any{
		"PVE UPID":       {"upid": "UPID:pve1:0000ABCD:0000ABCD:6AE11CDF:vzdump:100:root@pam:"},
		"lower case":     {"upid": "upid:pbs1:00000A1B:0001E240:0000000F:6AE11CDF:garbage_collection:store1:root@pam:"},
		"no final colon": {"upid": "UPID:pbs1:00000A1B:0001E240:0000000F:6AE11CDF:garbage_collection:store1:root@pam"},
		"no log lines":   {"upid": pbsTaskUPID, "log_lines": 0},
		"too many lines": {"upid": pbsTaskUPID, "log_lines": 1001},
	} {
		t.Run(name, func(t *testing.T) {
			diags := dataSourceConfigDiagnostics(t, h, "pbs_task", h.dataSourceValue(t, "pbs_task", config))
			if len(diags) == 0 {
				t.Errorf("config %v was accepted", config)
			}
		})
	}
	diags := dataSourceConfigDiagnostics(t, h, "pbs_task", h.dataSourceValue(t, "pbs_task", map[string]any{
		"upid": "UPID:pbs1:00000A1B:0001E240:0000000F:6AE11CDF:aptupdate::root@pam:", "log_lines": 1000,
	}))
	requireNoProtocolErrors(t, diags)
}
