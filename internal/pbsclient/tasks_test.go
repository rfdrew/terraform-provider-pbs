package pbsclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

// A UPID as PBS 4.2 sends it for creating a datastore named "probe-b".
const sampleUPID = "UPID:pbs-acc:0000000B:00001327:00000003:6AE11CDF:create-datastore:probe\\x2db:tfacc@pbs!acc:"

// The route the fake answers for sampleUPID's status: the path after
// /api2/json, as the request arrives, unescaped.
const sampleStatusRoute = "GET /nodes/pbs-acc/tasks/" + sampleUPID + "/status"

func TestParseUPID(t *testing.T) {
	upid, err := ParseUPID(sampleUPID)
	if err != nil {
		t.Fatal(err)
	}
	want := UPID{Raw: sampleUPID, Node: "pbs-acc", WorkerType: "create-datastore", WorkerID: "probe\\x2db", AuthID: "tfacc@pbs!acc"}
	if upid != want {
		t.Fatalf("ParseUPID() = %+v, want %+v", upid, want)
	}

	for _, bad := range []string{
		"",
		"UPID:pbs-acc:0000000B:00001327:00000003:6AE11CDF:create-datastore:probe:tfacc@pbs!acc",
		// A Proxmox VE UPID has one field fewer.
		"UPID:pve1:0000ABCD:0000ABCD:6AE11CDF:vzdump:100:root@pam:",
		"TASK:pbs-acc:0000000B:00001327:00000003:6AE11CDF:create-datastore:probe:tfacc@pbs!acc:",
	} {
		if _, err := ParseUPID(bad); err == nil {
			t.Errorf("ParseUPID(%q) accepted it", bad)
		}
	}
}

func TestUPIDFromData(t *testing.T) {
	encoded, _ := json.Marshal(sampleUPID)
	if upid, ok := UPIDFromData(encoded); !ok || upid.WorkerType != "create-datastore" {
		t.Fatalf("UPIDFromData() = %+v, %v", upid, ok)
	}
	for _, data := range []string{`null`, `{"name":"x"}`, `"just text"`, ``} {
		if _, ok := UPIDFromData(json.RawMessage(data)); ok {
			t.Errorf("UPIDFromData(%s) found a UPID", data)
		}
	}
}

func taskStatusJSON(status, exitstatus string) string {
	encoded, _ := json.Marshal(map[string]any{"data": map[string]any{
		"status": status, "exitstatus": exitstatus, "type": "create-datastore", "user": "tfacc@pbs!acc",
	}})
	if exitstatus == "" {
		encoded, _ = json.Marshal(map[string]any{"data": map[string]any{"status": status, "type": "create-datastore"}})
	}
	return string(encoded)
}

func TestWaitTask(t *testing.T) {
	upid, _ := ParseUPID(sampleUPID)
	tests := map[string]struct {
		statuses []string
		wantErr  bool
		wantExit string
	}{
		"succeeds after polling": {
			statuses: []string{taskStatusJSON("running", ""), taskStatusJSON("running", ""), taskStatusJSON("stopped", "OK")},
			wantExit: "OK",
		},
		"warnings are a success": {
			statuses: []string{taskStatusJSON("stopped", "WARNINGS: 1")},
			wantExit: "WARNINGS: 1",
		},
		"fails with the task's error": {
			statuses: []string{taskStatusJSON("stopped", "datastore path not empty")},
			wantErr:  true,
			wantExit: "datastore path not empty",
		},
		// A task the server does not know: 200 and "unknown".
		"unknown task": {
			statuses: []string{taskStatusJSON("stopped", "unknown")},
			wantErr:  true,
			wantExit: "unknown",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.replies(sampleStatusRoute, http.StatusOK, tc.statuses...)
			c := fake.client(t)

			status, err := c.WaitTask(context.Background(), upid)
			if status.ExitStatus != tc.wantExit {
				t.Fatalf("exit status = %q, want %q", status.ExitStatus, tc.wantExit)
			}
			var taskErr *TaskError
			if tc.wantErr != errors.As(err, &taskErr) {
				t.Fatalf("WaitTask() error = %v", err)
			}
			if n := fake.count(sampleStatusRoute); n != len(tc.statuses) {
				t.Fatalf("polled %d times, want %d", n, len(tc.statuses))
			}
		})
	}
}

func TestWaitTaskGivesUp(t *testing.T) {
	upid, _ := ParseUPID(sampleUPID)
	fake := newFakePBS()
	fake.reply(sampleStatusRoute, http.StatusOK, taskStatusJSON("running", ""))
	c := fake.client(t)
	c.taskTimeout = 50 * time.Millisecond
	c.sleep = sleepContext

	_, err := c.WaitTask(context.Background(), upid)
	if !errors.Is(err, ErrTaskTimeout) {
		t.Fatalf("WaitTask() error = %v, want ErrTaskTimeout", err)
	}
}

func TestWaitTaskIn(t *testing.T) {
	fake := newFakePBS()
	fake.reply(sampleStatusRoute, http.StatusOK, taskStatusJSON("stopped", "OK"))
	c := fake.client(t)

	if err := c.WaitTaskIn(context.Background(), json.RawMessage(`null`)); err != nil || fake.count(sampleStatusRoute) != 0 {
		t.Fatalf("null data: err = %v, polls = %d", err, fake.count(sampleStatusRoute))
	}
	encoded, _ := json.Marshal(sampleUPID)
	if err := c.WaitTaskIn(context.Background(), encoded); err != nil || fake.count(sampleStatusRoute) != 1 {
		t.Fatalf("UPID data: err = %v, polls = %d", err, fake.count(sampleStatusRoute))
	}
}
