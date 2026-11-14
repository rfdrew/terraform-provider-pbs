package provider

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/action"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Once Terraform has stopped an action it reads no more of its events, and
// a progress message would block the action for good: none is sent then,
// neither a message of the action's own nor a line of a task's log.
func TestActionProgressStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var sent []string
	progress := &actionProgress{ctx: ctx, send: func(event action.InvokeProgressEvent) {
		sent = append(sent, event.Message)
	}}
	line := func(message string) []pbsclient.TaskLogLine {
		return []pbsclient.TaskLogLine{{N: 1, Text: "2026-11-14T10:00:00+01:00: " + message}}
	}

	progress.say("PBS started task %s", "UPID:1")
	progress.taskLog(line("marked 1% (1 of 100 index files)"))
	cancel()
	progress.say("PBS started task %s", "UPID:2")
	progress.lastLog = progress.lastLog.Add(-actionProgressInterval)
	progress.taskLog(line("marked 2% (2 of 100 index files)"))

	if want := []string{"PBS started task UPID:1", "marked 1% (1 of 100 index files)"}; !slices.Equal(sent, want) {
		t.Fatalf("sent %q, want %q", sent, want)
	}
}

// failTaskPolls makes the status polls of fakeTasks' tasks fail with status
// and message, as PBS or a reverse proxy in front of it may answer: the
// first n of them, or all with n < 0. Other calls reach the tasks.
func failTaskPolls(fake *fakePBS, tasks *fakeTasks, n, status int, message string) {
	var mu sync.Mutex
	fake.handlePrefix("GET /nodes/"+fakeTasksNode+"/tasks/UPID:", func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		fail := strings.HasSuffix(req.URL.Path, "/status") && n != 0
		if fail && n > 0 {
			n--
		}
		mu.Unlock()
		if fail {
			writeFakeResponse(w, status, message)
			return
		}
		tasks.serve(w, req)
	})
}

// statusPolls counts the status polls the fake received.
func statusPolls(fake *fakePBS) int {
	polls := 0
	for _, route := range fake.routes() {
		if strings.HasPrefix(route, "GET ") && strings.HasSuffix(route, "/status") {
			polls++
		}
	}
	return polls
}

// A status poll that does not reach PBS — a reverse proxy answering 503
// while PBS is busy, a request that times out — does not end a wait that
// may last hours: the action polls on, for up to actionOutageGrace.
func TestActionTaskWaitsThroughUnansweredPolls(t *testing.T) {
	h, fake, tasks := newGCHarness(t, func() *fakeTask {
		return &fakeTask{log: []string{"marked 100% (2 of 2 index files)"}}
	})
	failTaskPolls(fake, tasks, 2, http.StatusServiceUnavailable, "Service Unavailable")

	got := h.invokeAction(t, "pbs_datastore_gc", map[string]any{"store": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "removed 3 GiB in 1200 chunks")
	if polls := statusPolls(fake); polls != 3 {
		t.Fatalf("%d status polls; routes: %v", polls, fake.routes())
	}
}

// A poll that PBS answers with an error ends the wait; the task goes on.
func TestActionTaskLostGoesOn(t *testing.T) {
	h, fake, tasks := newGCHarness(t, func() *fakeTask { return &fakeTask{running: -1} })
	failTaskPolls(fake, tasks, -1, http.StatusInternalServerError, "internal error")

	got := h.invokeAction(t, "pbs_datastore_gc", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to follow PBS task UPID:pbs-tasks:")
	requireProtocolErrorContaining(t, got.diagnostics, "The task goes on in PBS")
	requireProtocolErrorContaining(t, got.diagnostics, "internal error")
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the garbage collection was asked to stop")
		}
	}
}

// An unmount the action can no longer follow is stopped, as one it stops
// waiting for is: left running, it would go on blocking the datastore. The
// error says whether PBS took the request.
func TestActionTaskLostUnmountIsStopped(t *testing.T) {
	t.Run("stopped", func(t *testing.T) {
		h, fake, tasks := newRemovableActionHarness(t, "unmount", func() *fakeTask { return &fakeTask{running: -1} })
		failTaskPolls(fake, tasks, -1, http.StatusInternalServerError, "internal error")

		got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1"})
		requireProtocolErrorContaining(t, got.diagnostics, "Unable to follow PBS task UPID:pbs-tasks:")
		requireProtocolErrorContaining(t, got.diagnostics, "internal error")
		requireProtocolErrorContaining(t, got.diagnostics, "The provider asked PBS to stop the task.")
		for _, d := range got.diagnostics {
			if strings.Contains(d.Detail, "goes on") {
				t.Fatalf("the error says the unmount goes on: %s", d.Detail)
			}
		}
		if all := tasks.all(); len(all) != 1 || !all[0].aborted {
			t.Fatalf("the unmount was not asked to stop: %+v", all)
		}
	})

	t.Run("refused", func(t *testing.T) {
		h, fake, tasks := newRemovableActionHarness(t, "unmount", func() *fakeTask { return &fakeTask{running: -1} })
		failTaskPolls(fake, tasks, -1, http.StatusInternalServerError, "internal error")
		fake.handlePrefix("DELETE /nodes/"+fakeTasksNode+"/tasks/UPID:", func(w http.ResponseWriter, _ *http.Request) {
			writeFakeResponse(w, http.StatusInternalServerError, "internal error")
		})

		got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1"})
		requireProtocolErrorContaining(t, got.diagnostics, "Unable to follow PBS task UPID:pbs-tasks:")
		requireProtocolErrorContaining(t, got.diagnostics, "Asking PBS to stop the task failed, so it goes on")
		requireProtocolErrorContaining(t, got.diagnostics, "proxmox-backup-manager task stop")
	})
}
