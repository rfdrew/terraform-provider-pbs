package pbsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The route the fake answers for sampleUPID's log.
const sampleLogRoute = "GET /nodes/pbs-acc/tasks/" + sampleUPID + "/log"

// fakeTaskLog serves a task's log as PBS does: the lines from start on, at
// most limit of them (all with 0), with total and active next to data.
type fakeTaskLog struct {
	mu     sync.Mutex
	lines  []string
	active bool
}

func (l *fakeTaskLog) add(active bool, messages ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, message := range messages {
		l.lines = append(l.lines, "2026-11-14T10:00:00+01:00: "+message)
	}
	l.active = active
}

func (l *fakeTaskLog) serve(w http.ResponseWriter, req *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	start, _ := strconv.Atoi(req.URL.Query().Get("start"))
	limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
	type line struct {
		N int    `json:"n"`
		T string `json:"t"`
	}
	data := []line{}
	for i, text := range l.lines {
		n := i + 1
		if n < start {
			continue
		}
		if limit > 0 && len(data) == limit {
			break
		}
		data = append(data, line{n, text})
	}
	body, _ := json.Marshal(map[string]any{"data": data, "total": len(l.lines), "success": 1, "active": l.active})
	writeFakeResponse(w, http.StatusOK, string(body))
}

func TestTaskLogLineMessage(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"2026-11-14T10:00:00+01:00: TASK OK", "TASK OK"},
		{"2026-11-14T10:00:00-05:30: marked 5% (1 of 20 index files)", "marked 5% (1 of 20 index files)"},
		// A continuation line of a message of several lines has no
		// timestamp, and text that only looks like one stays.
		{"  check archive.didx", "  check archive.didx"},
		{"2026-11-14 10:00:00 +01:00: x", "2026-11-14 10:00:00 +01:00: x"},
		{"", ""},
	} {
		if got := (TaskLogLine{Text: tc.text}).Message(); got != tc.want {
			t.Errorf("Message(%q) = %q, want %q", tc.text, got, tc.want)
		}
	}
}

func TestTaskLogAndTail(t *testing.T) {
	upid, _ := ParseUPID(sampleUPID)
	fake := newFakePBS()
	log := &fakeTaskLog{}
	for i := 1; i <= 30; i++ {
		log.add(true, fmt.Sprintf("line %d", i))
	}
	log.add(false, "TASK OK")
	fake.handle(sampleLogRoute, log.serve)
	c := fake.client(t)

	lines, total, active, err := c.TaskLog(context.Background(), upid, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 31 || active || len(lines) != 2 || lines[0].N != 1 || lines[1].Message() != "line 2" {
		t.Fatalf("TaskLog() = %+v, %d, %v", lines, total, active)
	}
	// start=0 is sent as 1, which PBS treats the same.
	if got := fake.lastCall(t, sampleLogRoute).query; got.Get("start") != "1" || got.Get("limit") != "2" || got.Get("test-status") != "1" {
		t.Fatalf("query = %v", got)
	}

	tail, err := c.TaskLogTail(context.Background(), upid, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := FormatTaskLog(tail); got != "line 29\nline 30\nTASK OK" {
		t.Fatalf("TaskLogTail() = %q", got)
	}
	// A log shorter than the tail asked for is answered whole.
	short := &fakeTaskLog{}
	short.add(false, "TASK OK")
	fake.handle(sampleLogRoute, short.serve)
	if tail, err := c.TaskLogTail(context.Background(), upid, 20); err != nil || len(tail) != 1 {
		t.Fatalf("TaskLogTail() of a short log = %+v, %v", tail, err)
	}
}

func TestAbortTask(t *testing.T) {
	upid, _ := ParseUPID(sampleUPID)
	fake := newFakePBS()
	route := "DELETE /nodes/pbs-acc/tasks/" + sampleUPID
	fake.reply(route, http.StatusOK, `{"data":null}`)
	if err := fake.client(t).AbortTask(context.Background(), upid); err != nil {
		t.Fatal(err)
	}
	if fake.count(route) != 1 {
		t.Fatalf("routes = %v", fake.routes())
	}
}

// WatchTask hands the lines a task logs to Progress as they come, each once,
// including those it wrote just before it stopped.
func TestWatchTaskProgress(t *testing.T) {
	upid, _ := ParseUPID(sampleUPID)
	fake := newFakePBS()
	log := &fakeTaskLog{}
	log.add(true, "starting garbage collection on store store1")
	fake.handle(sampleLogRoute, log.serve)
	polls := 0
	fake.handle(sampleStatusRoute, func(w http.ResponseWriter, _ *http.Request) {
		polls++
		switch polls {
		case 1:
			writeFakeResponse(w, http.StatusOK, taskStatusJSON("running", ""))
			log.add(true, "marked 50% (1 of 2 index files)")
		case 2:
			writeFakeResponse(w, http.StatusOK, taskStatusJSON("running", ""))
			log.add(false, "Removed garbage: 0 B", "TASK OK")
		default:
			writeFakeResponse(w, http.StatusOK, taskStatusJSON("stopped", "OK"))
		}
	})
	c := fake.client(t)

	var got []string
	status, err := c.WatchTask(context.Background(), upid, TaskWatch{Progress: func(lines []TaskLogLine) {
		for _, line := range lines {
			got = append(got, line.Message())
		}
	}})
	if err != nil || status.ExitStatus != "OK" {
		t.Fatalf("WatchTask() = %+v, %v", status, err)
	}
	want := []string{"starting garbage collection on store store1", "marked 50% (1 of 2 index files)", "Removed garbage: 0 B", "TASK OK"}
	if !slices.Equal(got, want) {
		t.Fatalf("progress = %q, want %q", got, want)
	}
}

// A task that logs more lines between two polls than one read returns, as a
// verification does that skips snapshots verified recently, does not leave
// the progress further and further behind: a read with more new lines hands
// on the last ones, and the last read reaches the task's result.
func TestWatchTaskProgressKeepsUp(t *testing.T) {
	upid, _ := ParseUPID(sampleUPID)
	fake := newFakePBS()
	log := &fakeTaskLog{}
	skipped := func(from, to int) {
		for i := from; i <= to; i++ {
			log.add(true, fmt.Sprintf("SKIPPED: verify store1:vm/%d (recently verified)", i))
		}
	}
	skipped(1, 2*progressLogLimit+200)
	fake.handle(sampleLogRoute, log.serve)
	polls := 0
	fake.handle(sampleStatusRoute, func(w http.ResponseWriter, _ *http.Request) {
		polls++
		if polls == 1 {
			writeFakeResponse(w, http.StatusOK, taskStatusJSON("running", ""))
			return
		}
		skipped(2*progressLogLimit+201, 5*progressLogLimit)
		log.add(false, "TASK OK")
		writeFakeResponse(w, http.StatusOK, taskStatusJSON("stopped", "OK"))
	})
	c := fake.client(t)

	var batches [][]TaskLogLine
	if _, err := c.WatchTask(context.Background(), upid, TaskWatch{Progress: func(lines []TaskLogLine) {
		batches = append(batches, lines)
	}}); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 {
		t.Fatalf("progress was called %d times", len(batches))
	}
	for i, want := range []struct{ first, last int }{
		{progressLogLimit + 201, 2*progressLogLimit + 200},
		{4*progressLogLimit + 2, 5*progressLogLimit + 1},
	} {
		lines := batches[i]
		if len(lines) != progressLogLimit {
			t.Fatalf("call %d: %d lines", i+1, len(lines))
		}
		if lines[0].N != want.first || lines[len(lines)-1].N != want.last {
			t.Fatalf("call %d: lines %d to %d, want %d to %d", i+1, lines[0].N, lines[len(lines)-1].N, want.first, want.last)
		}
	}
	if last := batches[1][progressLogLimit-1].Message(); last != "TASK OK" {
		t.Fatalf("the last line handed on is %q", last)
	}
}

// A log PBS does not let the client read slows nothing down: the wait goes
// on without progress.
func TestWatchTaskProgressIsBestEffort(t *testing.T) {
	upid, _ := ParseUPID(sampleUPID)
	fake := newFakePBS()
	fake.reply(sampleLogRoute, http.StatusBadRequest, "task access not allowed")
	fake.reply(sampleStatusRoute, http.StatusOK, taskStatusJSON("stopped", "WARNINGS: 1"))
	c := fake.client(t)
	called := false
	if _, err := c.WatchTask(context.Background(), upid, TaskWatch{Progress: func([]TaskLogLine) { called = true }}); err != nil || called {
		t.Fatalf("WatchTask() error = %v, progress called = %v", err, called)
	}
}

// The watch's own timeout replaces the client's, and a caller that stops
// waiting gets an error that says so, not one about time.
func TestWatchTaskGivesUp(t *testing.T) {
	upid, _ := ParseUPID(sampleUPID)
	fake := newFakePBS()
	fake.reply(sampleStatusRoute, http.StatusOK, taskStatusJSON("running", ""))
	c := fake.client(t)
	c.sleep = sleepContext

	_, err := c.WatchTask(context.Background(), upid, TaskWatch{Timeout: 50 * time.Millisecond})
	if !IsTaskTimeout(err) || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "after 50ms") {
		t.Fatalf("WatchTask() with a timeout: error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err = c.WatchTask(ctx, upid, TaskWatch{Timeout: time.Hour})
	if !IsTaskTimeout(err) || !errors.Is(err, context.Canceled) {
		t.Fatalf("WatchTask() cancelled: error = %v", err)
	}
}

func TestWithRequestTimeout(t *testing.T) {
	c := newFakePBS().client(t)
	if got := c.httpClientFor(context.Background()); got != c.httpClient {
		t.Fatal("without an override, calls go through the client's HTTP client")
	}
	got := c.httpClientFor(WithRequestTimeout(context.Background(), 90*time.Second))
	if got.Timeout != 90*time.Second || got.Transport != c.httpClient.Transport {
		t.Fatalf("override: timeout %s, same transport %v", got.Timeout, got.Transport == c.httpClient.Transport)
	}
}
