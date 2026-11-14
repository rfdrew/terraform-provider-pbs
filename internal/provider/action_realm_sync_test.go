package provider

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeRealmList is GET /access/domains with the built-in realms, the LDAP
// realm corp, the Active Directory realm ad1 and the OpenID realm oidc.
const fakeRealmList = `{"data":[
	{"realm":"pam","type":"pam","default":true},{"realm":"pbs","type":"pbs"},
	{"realm":"corp","type":"ldap","comment":"Corporate directory"},{"realm":"ad1","type":"ad"},
	{"realm":"oidc","type":"openid"}]}`

// newRealmSyncHarness serves syncs of the realms of fakeRealmList, each a
// task next makes for the realm, and records the forms they were started
// with.
func newRealmSyncHarness(t *testing.T, next func(realm string) *fakeTask, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeTasks) {
	t.Helper()
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	fake.reply("GET /access/domains", http.StatusOK, fakeRealmList)
	for _, realm := range []string{"corp", "ad1", "oidc", "pam"} {
		fake.handle("POST /access/domains/"+realm+"/sync", tasks.starter(func(*http.Request) *fakeTask {
			task := next(realm)
			task.workerType, task.workerID = "realm-sync", realm
			return task
		}))
	}
	return newProtocolHarness(t, fake, opts...), fake, tasks
}

func TestRealmSyncActionWaitsAndReports(t *testing.T) {
	h, fake, tasks := newRealmSyncHarness(t, func(realm string) *fakeTask {
		return &fakeTask{running: 1, log: []string{
			"creating user alice@corp", "updating user bob@corp", "creating user carol@corp", "creating user dave@corp",
			"creating user erin@corp", "deleting user eve@corp",
		}}
	})
	got := h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "corp"})
	requireNoProtocolErrors(t, got.diagnostics)
	if len(got.diagnostics) != 0 {
		t.Fatalf("diagnostics: %v", got.diagnostics)
	}
	requireProgressContaining(t, got, "PBS started task UPID:pbs-tasks:")
	requireProgressContaining(t, got, "realm corp: PBS created 4 users (alice@corp, carol@corp, dave@corp, …), "+
		"updated 1 (bob@corp) and deleted 1 (eve@corp)")
	// The action followed the task the call started to its end.
	var upid string
	for _, message := range got.progress {
		if rest, ok := strings.CutPrefix(message, "PBS started task "); ok {
			upid = rest
		}
	}
	if task := tasks.task(upid); task == nil || !task.stopped || task.workerID != "corp" {
		t.Fatalf("task %q: %+v", upid, task)
	}
	// The realm's own sync defaults apply: nothing is sent.
	if form := fake.lastCall(t, "POST /access/domains/corp/sync").form; len(form) != 0 {
		t.Fatalf("form = %v", form)
	}
}

func TestRealmSyncActionDryRun(t *testing.T) {
	h, fake, _ := newRealmSyncHarness(t, func(string) *fakeTask {
		return &fakeTask{log: []string{"this is a DRY RUN - changes will not be persisted", "creating user alice@ad1"}}
	})
	got := h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "ad1", "dry_run": true})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "dry run of realm ad1: PBS would create 1 user (alice@ad1), update 0 and delete 0; nothing changed")
	if form := fake.lastCall(t, "POST /access/domains/ad1/sync").form; form.Get("dry-run") != "true" {
		t.Fatalf("form = %v", form)
	}
}

// enable_new and remove_vanished override the realm's defaults; an empty
// remove_vanished, which PBS would refuse, is sent as acl, which alone
// removes nothing.
func TestRealmSyncActionOptions(t *testing.T) {
	h, fake, _ := newRealmSyncHarness(t, func(string) *fakeTask { return &fakeTask{} })
	for _, tc := range []struct {
		attrs map[string]any
		want  url.Values
	}{
		{map[string]any{"enable_new": false, "remove_vanished": []any{"properties", "entry", "acl"}},
			url.Values{"enable-new": {"false"}, "remove-vanished": {"acl;entry;properties"}}},
		{map[string]any{"enable_new": true, "remove_vanished": []any{}},
			url.Values{"enable-new": {"true"}, "remove-vanished": {"acl"}}},
		{map[string]any{"dry_run": false}, url.Values{}},
	} {
		tc.attrs["realm"] = "corp"
		got := h.invokeAction(t, "pbs_realm_sync", tc.attrs)
		requireNoProtocolErrors(t, got.diagnostics)
		requireProgressContaining(t, got, "realm corp: PBS created 0 users, updated 0 and deleted 0")
		if form := fake.lastCall(t, "POST /access/domains/corp/sync").form; !reflect.DeepEqual(form, tc.want) {
			t.Fatalf("%v: form = %v, want %v", tc.attrs, form, tc.want)
		}
	}
}

// Entries PBS could not make users of are information in its log, not
// warnings; the action warns about them.
func TestRealmSyncActionSkippedEntries(t *testing.T) {
	log := []string{"creating user alice@corp"}
	for range 12 {
		log = append(log, "could not create/update user: userid attribute `uid` not in LDAP search result")
	}
	h, _, _ := newRealmSyncHarness(t, func(string) *fakeTask { return &fakeTask{log: log} })
	got := h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "corp"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "PBS skipped entries of the directory")
	requireProtocolWarningContaining(t, got.diagnostics, "found 12 entries")
	requireProtocolWarningContaining(t, got.diagnostics, "    userid attribute `uid` not in LDAP search result")
	requireProtocolWarningContaining(t, got.diagnostics, "… and 2 more")
	requireProgressContaining(t, got, "realm corp: PBS created 1 user (alice@corp)")
}

// The realm is checked before the sync starts: PBS would start a sync of a
// realm of another type and fail it.
func TestRealmSyncActionChecksRealm(t *testing.T) {
	h, fake, _ := newRealmSyncHarness(t, func(string) *fakeTask { return &fakeTask{} })
	got := h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "nosuch"})
	requireProtocolErrorContaining(t, got.diagnostics, "PBS realm not found")
	requireProtocolErrorContaining(t, got.diagnostics, `PBS has no realm "nosuch"`)

	got = h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "oidc"})
	requireProtocolErrorContaining(t, got.diagnostics, "Cannot sync PBS realm oidc")
	requireProtocolErrorContaining(t, got.diagnostics, `cannot sync realm oidc of type openid`)
	for _, route := range fake.routes() {
		if strings.HasPrefix(route, "POST ") {
			t.Fatalf("started a sync: %v", fake.routes())
		}
	}

	fake.reply("GET /access/domains", http.StatusServiceUnavailable, "service unavailable")
	got = h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "corp"})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to read the realms of PBS")
}

func TestRealmSyncActionTaskFails(t *testing.T) {
	h, _, _ := newRealmSyncHarness(t, func(string) *fakeTask {
		return &fakeTask{exit: "LDAP bind failed, bind_dn or password could be incorrect"}
	})
	got := h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "corp"})
	requireProtocolErrorContaining(t, got.diagnostics, `Sync of PBS realm "corp" failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "TASK ERROR: LDAP bind failed")
	for _, message := range got.progress {
		if strings.Contains(message, "PBS created") {
			t.Fatalf("a failed sync reported a summary: %q", got.progress)
		}
	}
	got = h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "corp", "dry_run": true})
	requireProtocolErrorContaining(t, got.diagnostics, `Dry run of the sync of PBS realm "corp" failed`)
}

func TestRealmSyncActionWithoutWaitingAndTimeout(t *testing.T) {
	h, fake, tasks := newRealmSyncHarness(t, func(string) *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "corp", "wait": false})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "not waiting for it")
	for _, route := range fake.routes() {
		if strings.Contains(route, "/tasks/") {
			t.Fatalf("waited: %v", fake.routes())
		}
	}

	got = h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "corp", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, `Sync of PBS realm "corp" did not finish`)
	requireProtocolErrorContaining(t, got.diagnostics, "Raise the action's `timeout`")
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the task was asked to stop")
		}
	}
}

func TestRealmSyncActionStartErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"forbidden", http.StatusForbidden, "permission check failed", "Permissions.Modify on /access/users"},
		{"starting", http.StatusBadRequest, "realm sync already running", "another sync of realm"},
		{"deleted", http.StatusBadRequest, "unable to find realm corp", "any more"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /access/domains", http.StatusOK, fakeRealmList)
			fake.reply("POST /access/domains/corp/sync", tc.status, tc.body)
			h := newProtocolHarness(t, fake)
			got := h.invokeAction(t, "pbs_realm_sync", map[string]any{"realm": "corp"})
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to start the sync of PBS realm corp")
			requireProtocolErrorContaining(t, got.diagnostics, tc.want)
		})
	}
}

func TestRealmSyncActionValidation(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"realm": "pam"}, "realm"},
		{map[string]any{"realm": "x"}, "realm"},
		{map[string]any{"realm": "corp", "remove_vanished": []any{"users"}}, "remove_vanished"},
		{map[string]any{"realm": "corp", "timeout": "0s"}, "positive duration"},
	} {
		requireProtocolErrorContaining(t, h.validateAction(t, "pbs_realm_sync", h.actionValue(t, "pbs_realm_sync", tc.attrs)), tc.want)
	}
	unknown := h.actionValue(t, "pbs_realm_sync", map[string]any{
		"realm": tfUnknown, "dry_run": tfUnknown, "enable_new": tfUnknown, "remove_vanished": tfUnknown,
	})
	requireNoProtocolErrors(t, h.validateAction(t, "pbs_realm_sync", unknown))
	requireNoProtocolErrors(t, h.planAction(t, "pbs_realm_sync", unknown))
}

func TestDescribeRealmSync(t *testing.T) {
	summary := pbsclient.RealmSyncSummary{Deleted: []string{"a@corp", "b@corp", "c@corp", "d@corp"}}
	got := describeRealmSync("corp", false, summary)
	if want := "realm corp: PBS created 0 users, updated 0 and deleted 4 (a@corp, b@corp, c@corp, …)"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
