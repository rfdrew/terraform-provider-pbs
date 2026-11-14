package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newRemovableActionHarness serves POST /admin/datastore/store1/<op>, mount
// or unmount, starting the task next returns, as PBS does.
func newRemovableActionHarness(t *testing.T, op string, next func() *fakeTask) (*protocolHarness, *fakePBS, *fakeTasks) {
	t.Helper()
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	fake.handle("POST /admin/datastore/store1/"+op, tasks.starter(func(*http.Request) *fakeTask {
		task := next()
		task.workerType, task.workerID = op+"-device", "store1"
		return task
	}))
	return newProtocolHarness(t, fake), fake, tasks
}

// The task's own lines reach Terraform; the action says what the mount did.
func TestDatastoreMountActionMounts(t *testing.T) {
	h, fake, _ := newRemovableActionHarness(t, "mount", func() *fakeTask {
		return &fakeTask{log: []string{
			"temporarily mounting '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d' to '/run/proxmox-backup/mount/a1b2'",
			"bind mount 'store1'(store1) to '/mnt/datastore/store1'",
		}}
	})
	got := h.invokeAction(t, "pbs_datastore_mount", map[string]any{"store": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "PBS started task UPID:pbs-tasks:")
	requireProgressContaining(t, got, "bind mount 'store1'")
	requireProgressContaining(t, got, `PBS mounted datastore "store1"`)
	if fake.count("POST /admin/datastore/store1/mount") != 1 {
		t.Fatalf("routes: %v", fake.routes())
	}
}

// PBS mounts a mounted datastore without complaint, and starts no sync
// jobs then.
func TestDatastoreMountActionAlreadyMounted(t *testing.T) {
	h, _, _ := newRemovableActionHarness(t, "mount", func() *fakeTask {
		return &fakeTask{log: []string{"device is already mounted at '/mnt/datastore/store1'"}}
	})
	got := h.invokeAction(t, "pbs_datastore_mount", map[string]any{"store": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, `PBS datastore "store1" was mounted already`)
}

// The sync jobs PBS starts after a mount run in a task of their own, whose
// UPID PBS does not tell; the action says how many there are.
func TestDatastoreMountActionReportsSyncJobs(t *testing.T) {
	h, _, _ := newRemovableActionHarness(t, "mount", func() *fakeTask {
		return &fakeTask{log: []string{"bind mount 'store1'(store1) to '/mnt/datastore/store1'", "starting 2 sync jobs"}}
	})
	got := h.invokeAction(t, "pbs_datastore_mount", map[string]any{"store": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "started its 2 sync jobs with run_on_mount")
	requireProgressContaining(t, got, "mount-sync-jobs")
}

func TestDatastoreMountActionTaskFails(t *testing.T) {
	h, _, _ := newRemovableActionHarness(t, "mount", func() *fakeTask {
		return &fakeTask{
			log:  []string{"temporarily mounting '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d' to '/run/proxmox-backup/mount/a1b2'"},
			exit: `mounting to tmp path failed: command "mount" "UUID=0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d" failed`,
		}
	})
	got := h.invokeAction(t, "pbs_datastore_mount", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, `Mounting PBS datastore "store1" failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "TASK ERROR: mounting to tmp path failed")
	for _, message := range got.progress {
		if strings.Contains(message, "PBS mounted") {
			t.Fatalf("a failed mount was reported as done: %q", got.progress)
		}
	}
}

// PBS cannot abort a mount: a timeout leaves it alone.
func TestDatastoreMountActionTimeout(t *testing.T) {
	h, _, tasks := newRemovableActionHarness(t, "mount", func() *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_datastore_mount", map[string]any{"store": "store1", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "did not finish")
	requireProtocolErrorContaining(t, got.diagnostics, "The task goes on in PBS")
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the mount was asked to stop")
		}
	}
}

func TestDatastoreMountActionWithoutWaiting(t *testing.T) {
	h, fake, _ := newRemovableActionHarness(t, "mount", func() *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_datastore_mount", map[string]any{"store": "store1", "wait": false})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "not waiting for it")
	for _, route := range fake.routes() {
		if strings.Contains(route, "/tasks/") {
			t.Fatalf("followed the task: %v", fake.routes())
		}
	}
}

func TestRemovableActionsStartErrors(t *testing.T) {
	for _, op := range []string{"mount", "unmount"} {
		for _, tc := range []struct {
			name, body, want string
			status           int
		}{
			{"missing", "no such datastore 'store1'", `PBS has no datastore "store1"`, http.StatusBadRequest},
			{"not removable", "datastore 'store1' is not removable", "only datastores on a removable disk", http.StatusBadRequest},
			{"forbidden", "permission check failed", "Datastore.Modify on /datastore/store1 and Sys.Modify on /system/disks", http.StatusForbidden},
		} {
			t.Run(op+" "+tc.name, func(t *testing.T) {
				fake := newFakePBS()
				fake.reply("POST /admin/datastore/store1/"+op, tc.status, tc.body)
				h := newProtocolHarness(t, fake)
				got := h.invokeAction(t, "pbs_datastore_"+op, map[string]any{"store": "store1"})
				requireProtocolErrorContaining(t, got.diagnostics, "Unable to "+op+" PBS datastore store1")
				requireProtocolErrorContaining(t, got.diagnostics, tc.want)
			})
		}
	}
}

func TestDatastoreUnmountActionUnmounts(t *testing.T) {
	h, fake, _ := newRemovableActionHarness(t, "unmount", func() *fakeTask {
		return &fakeTask{running: 1, log: []string{"waiting for active operations to finsish before continuing: read 0, write 1"}}
	})
	got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	// What the unmount waits for is in its log.
	requireProgressContaining(t, got, "waiting for active operations")
	requireProgressContaining(t, got, `PBS unmounted datastore "store1"`)
	if fake.count("POST /admin/datastore/store1/unmount") != 1 {
		t.Fatalf("routes: %v", fake.routes())
	}
}

// A datastore that is not mounted is where the action would leave it.
func TestDatastoreUnmountActionNotMounted(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /admin/datastore/store1/unmount", http.StatusBadRequest, "Datastore 'store1' is not mounted")
	h := newProtocolHarness(t, fake)
	got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, `PBS datastore "store1" is not mounted`)
}

// An unmount that waits for the datastore's operations would block the
// datastore for as long as they run: when the action stops waiting, it asks
// PBS to stop the unmount, and says what held it up.
func TestDatastoreUnmountActionTimeoutStopsTheUnmount(t *testing.T) {
	h, fake, tasks := newRemovableActionHarness(t, "unmount", func() *fakeTask {
		return &fakeTask{running: -1, log: []string{"waiting for active operations to finsish before continuing: read 1, write 2"}}
	})
	fake.reply("GET /admin/datastore/store1/active-operations", http.StatusOK, `{"data":{"read":1,"write":2}}`)
	got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, `Unmounting PBS datastore "store1" did not finish`)
	requireProtocolErrorContaining(t, got.diagnostics, "The provider asked PBS to stop the task.")
	requireProtocolWarningContaining(t, got.diagnostics, "held up the unmount")
	requireProtocolWarningContaining(t, got.diagnostics, "PBS counted 1 reading and 2 writing operations")
	requireProtocolWarningContaining(t, got.diagnostics, "leaves the datastore mounted, in no maintenance mode")
	// The task the action started is the one it asked to stop.
	var upid string
	for _, message := range got.progress {
		if rest, ok := strings.CutPrefix(message, "PBS started task "); ok {
			upid = rest
		}
	}
	if task := tasks.task(upid); task == nil || !task.aborted {
		t.Fatalf("the unmount %q was not asked to stop; progress: %q", upid, got.progress)
	}
}

// Reading the operations needs Datastore.Audit, which unmounting does not.
func TestDatastoreUnmountActionTimeoutWithoutAudit(t *testing.T) {
	h, fake, _ := newRemovableActionHarness(t, "unmount", func() *fakeTask { return &fakeTask{running: -1} })
	fake.reply("GET /admin/datastore/store1/active-operations", http.StatusForbidden, "permission check failed")
	got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "did not finish")
	requireProtocolWarningContaining(t, got.diagnostics, "PBS did not say how many there were")
}

// When Terraform stops the action, the unmount is stopped too.
func TestDatastoreUnmountActionCancelled(t *testing.T) {
	h, _, tasks := newRemovableActionHarness(t, "unmount", func() *fakeTask { return &fakeTask{running: -1} })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	start := time.Now()
	h.invokeActionWith(ctx, t, "pbs_datastore_unmount", h.actionValue(t, "pbs_datastore_unmount", map[string]any{"store": "store1"}))
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the action went on for %s after it was cancelled", elapsed)
	}
	all := tasks.all()
	if len(all) != 1 || !all[0].aborted {
		t.Fatalf("the unmount was not asked to stop: %+v", all)
	}
}

// An umount that fails leaves the datastore in maintenance mode unmount,
// which the action says how to clear.
func TestDatastoreUnmountActionTaskFails(t *testing.T) {
	h, fake, _ := newRemovableActionHarness(t, "unmount", func() *fakeTask {
		return &fakeTask{exit: `command "umount" "/mnt/datastore/store1" failed - status code: 32 - umount: /mnt/datastore/store1: target is busy.`}
	})
	fake.reply("GET /config/datastore/store1", http.StatusOK,
		`{"data":{"name":"store1","path":"store1","backing-device":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","maintenance-mode":"type=unmount"}}`)
	got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, `Unmounting PBS datastore "store1" failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "target is busy")
	requireProtocolWarningContaining(t, got.diagnostics, "left in maintenance mode unmount")
	requireProtocolWarningContaining(t, got.diagnostics, "proxmox-backup-manager datastore update store1 --delete maintenance-mode")
}

// An unmount that someone else stopped leaves no maintenance mode, and the
// action says nothing about one.
func TestDatastoreUnmountActionAbortedElsewhere(t *testing.T) {
	h, fake, _ := newRemovableActionHarness(t, "unmount", func() *fakeTask {
		return &fakeTask{exit: "aborted, due to user request"}
	})
	fake.reply("GET /config/datastore/store1", http.StatusOK,
		`{"data":{"name":"store1","path":"store1","backing-device":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"}}`)
	got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, "aborted, due to user request")
	for _, d := range got.diagnostics {
		if strings.Contains(d.Summary, "maintenance mode") {
			t.Fatalf("unexpected diagnostic %q: %s", d.Summary, d.Detail)
		}
	}
}

// With gc_on_unmount, PBS starts a garbage collection through its proxy
// before it unmounts. When the proxy refuses it, PBS answers with the
// proxy's error, such as that of a maintenance mode, which an unmount meets
// nowhere else.
func TestDatastoreUnmountActionGCDidNotStart(t *testing.T) {
	const removable = `"name":"store1","path":"store1","backing-device":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"`
	for _, tc := range []struct {
		name, answer string
		status       int
		want         []string
	}{
		{"gc_on_unmount", `{"data":{` + removable + `,"gc-on-unmount":true,"maintenance-mode":"type=read-only"}}`,
			http.StatusOK, []string{"could not start the garbage collection", "gc_on_unmount = false",
				"proxmox-backup-manager datastore update store1 --delete maintenance-mode", "read-only maintenance mode"}},
		// Reading the datastore needs Datastore.Audit, which unmounting does
		// not; only gc_on_unmount opens the datastore during the call.
		{"unreadable", "permission check failed", http.StatusForbidden,
			[]string{"could not start the garbage collection", "gc_on_unmount = false"}},
		{"without gc_on_unmount", `{"data":{` + removable + `}}`, http.StatusOK,
			[]string{`PBS cannot open datastore "store1"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("POST /admin/datastore/store1/unmount", http.StatusBadRequest,
				"datastore 'store1' is unavailable: read-only maintenance mode: ")
			fake.reply("GET /config/datastore/store1", tc.status, tc.answer)
			h := newProtocolHarness(t, fake)
			got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1"})
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to unmount PBS datastore store1")
			for _, want := range tc.want {
				requireProtocolErrorContaining(t, got.diagnostics, want)
			}
		})
	}
}

// PBS answers with the context of its garbage collection call only when it
// cannot reach its proxy.
func TestDatastoreUnmountActionGCProxyUnreachable(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /admin/datastore/store1/unmount", http.StatusBadRequest, "unable to start garbage collection before unmount")
	h := newProtocolHarness(t, fake)
	got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to unmount PBS datastore store1")
	requireProtocolErrorContaining(t, got.diagnostics, "proxmox-backup-proxy")
	requireProtocolErrorContaining(t, got.diagnostics, "gc_on_unmount = false")
}

// With gc_on_unmount, the maintenance mode unmount that a failed umount
// leaves behind fails every later unmount, whose garbage collection cannot
// start: the mode must be cleared first.
func TestDatastoreUnmountActionTaskFailsWithGCOnUnmount(t *testing.T) {
	h, fake, _ := newRemovableActionHarness(t, "unmount", func() *fakeTask {
		return &fakeTask{exit: `command "umount" "/mnt/datastore/store1" failed - status code: 32 - umount: /mnt/datastore/store1: target is busy.`}
	})
	fake.reply("GET /config/datastore/store1", http.StatusOK,
		`{"data":{"name":"store1","path":"store1","backing-device":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","gc-on-unmount":true,"maintenance-mode":"type=unmount"}}`)
	got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, "target is busy")
	requireProtocolWarningContaining(t, got.diagnostics, "left in maintenance mode unmount")
	requireProtocolWarningContaining(t, got.diagnostics, "--delete maintenance-mode` on the host, then invoke the action again")
	requireProtocolWarningContaining(t, got.diagnostics, "the action fails until the mode is gone")
	for _, d := range got.diagnostics {
		if strings.Contains(d.Detail, "which clears the mode when it succeeds") {
			t.Fatalf("the warning suggests invoking the action again as it is: %s", d.Detail)
		}
	}
}

// With wait = false the unmount is left to PBS, and not stopped.
func TestDatastoreUnmountActionWithoutWaiting(t *testing.T) {
	h, fake, tasks := newRemovableActionHarness(t, "unmount", func() *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_datastore_unmount", map[string]any{"store": "store1", "wait": false})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "not waiting for it")
	for _, route := range fake.routes() {
		if strings.Contains(route, "/tasks/") {
			t.Fatalf("followed the task: %v", fake.routes())
		}
	}
	if tasks.all()[0].aborted {
		t.Fatal("the unmount was asked to stop")
	}
}

func TestRemovableActionsValidation(t *testing.T) {
	fake := newFakePBS()
	h := newProtocolHarness(t, fake)
	configured := len(fake.routes())
	for _, typeName := range []string{"pbs_datastore_mount", "pbs_datastore_unmount"} {
		for _, tc := range []struct {
			attrs map[string]any
			want  string
		}{
			{map[string]any{"store": "x"}, "store"},
			{map[string]any{"store": "store 1"}, "store"},
			{map[string]any{"store": "store1", "timeout": "0s"}, "positive duration"},
		} {
			requireProtocolErrorContaining(t, h.validateAction(t, typeName, h.actionValue(t, typeName, tc.attrs)), tc.want)
		}
		// Values only known at apply are fine while planning, and planning
		// asks PBS nothing.
		unknown := h.actionValue(t, typeName, map[string]any{"store": tfUnknown, "wait": tfUnknown, "timeout": tfUnknown})
		requireNoProtocolErrors(t, h.validateAction(t, typeName, unknown))
		requireNoProtocolErrors(t, h.planAction(t, typeName, unknown))
	}
	if routes := fake.routes(); len(routes) != configured {
		t.Fatalf("validating and planning called PBS: %v", routes[configured:])
	}
}
