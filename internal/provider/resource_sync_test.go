package provider

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestRemoteAndSyncResourceSchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, &remoteResource{})
	requireValidResourceSchema(t, &syncJobResource{})
}

// newSyncHarness is a fake PBS with the remote, sync job and datastore API
// and a provider signed in to it. version, when set, is what GET /version
// answers.
func newSyncHarness(t *testing.T, version ...string) (*protocolHarness, *fakePBS, *fakeSync, *fakeDatastores) {
	t.Helper()
	fake := newFakePBS()
	if len(version) > 0 {
		fake.reply("GET /version", http.StatusOK, version[0])
	}
	datastores := newFakeDatastores(fake)
	syncs := newFakeSync(fake, datastores)
	return newProtocolHarness(t, fake), fake, syncs, datastores
}

// testRemoteFingerprint is a certificate fingerprint as PBS shows it.
const testRemoteFingerprint = "64:d3:ff:3a:50:38:53:5a:9e:2b:1f:6a:5a:1d:4a:42:7c:61:4b:01:f2:15:97:9a:2e:1d:ac:1b:7d:0e:aa:17"

// remoteConfig is the configuration of a remote "offsite", with attrs on
// top of what it needs.
func remoteConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"name": "offsite", "host": "pbs2.example.com", "auth_id": "sync@pbs!offsite"}
	for k, v := range attrs {
		config[k] = v
	}
	return h.resourceValue(t, "pbs_remote", config)
}

func TestRemoteResourceLifecycle(t *testing.T) {
	h, fake, syncs, _ := newSyncHarness(t)

	// The fingerprint as OpenSSL prints it: upper case. PBS gets it as it
	// shows it, and state keeps the configuration's spelling.
	upper := strings.ToUpper(testRemoteFingerprint)
	config := remoteConfig(t, h, map[string]any{
		"password_wo":         "first-secret",
		"password_wo_version": 1,
		"fingerprint":         upper,
	})
	inst := h.create(t, "pbs_remote", config)

	created := fake.lastCall(t, "POST /config/remote")
	for name, want := range map[string]string{"name": "offsite", "host": "pbs2.example.com", "auth-id": "sync@pbs!offsite",
		"password": "first-secret", "fingerprint": testRemoteFingerprint} {
		if got := created.form.Get(name); got != want {
			t.Errorf("POST %s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"port", "use-node-proxy", "comment"} {
		if _, sent := created.form[name]; sent {
			t.Errorf("POST sent %s: %v", name, created.form)
		}
	}
	if stringAt(t, inst.state, "id") != "offsite" || stringAt(t, inst.state, "fingerprint") != upper ||
		boolAt(t, inst.state, "use_node_proxy") || !isNullAt(t, inst.state, "port") || !isNullAt(t, inst.state, "password_wo") ||
		int64At(t, inst.state, "password_wo_version") != 1 {
		t.Errorf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_remote", inst.identity), "name"); got != "offsite" {
		t.Errorf("identity name = %q", got)
	}
	replan := h.plan(t, "pbs_remote", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_remote", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	// The same fingerprint, spelt as PBS shows it, sends nothing.
	puts := fake.count("PUT /config/remote/offsite")
	inst = h.update(t, inst, remoteConfig(t, h, map[string]any{
		"password_wo":         "first-secret",
		"password_wo_version": 1,
		"fingerprint":         strings.ReplaceAll(testRemoteFingerprint, ":", ""),
	}))
	if fake.count("PUT /config/remote/offsite") != puts {
		t.Error("a new spelling of the same fingerprint was sent")
	}

	// Other properties change in place; the password stays as long as its
	// version does.
	inst = h.update(t, inst, remoteConfig(t, h, map[string]any{
		"host":                "192.0.2.7",
		"port":                8008,
		"use_node_proxy":      true,
		"comment":             "Offsite copy",
		"fingerprint":         testRemoteFingerprint,
		"password_wo":         "first-secret",
		"password_wo_version": 1,
	}))
	updated := fake.lastCall(t, "PUT /config/remote/offsite")
	for name, want := range map[string]string{"host": "192.0.2.7", "port": "8008", "use-node-proxy": "true", "comment": "Offsite copy"} {
		if got := updated.form.Get(name); got != want {
			t.Errorf("PUT %s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"password", "fingerprint", "delete"} {
		if _, sent := updated.form[name]; sent {
			t.Errorf("PUT sent %s: %v", name, updated.form)
		}
	}

	// A new version sends the new password.
	inst = h.update(t, inst, remoteConfig(t, h, map[string]any{
		"host":                "192.0.2.7",
		"port":                8008,
		"use_node_proxy":      true,
		"comment":             "Offsite copy",
		"fingerprint":         testRemoteFingerprint,
		"password_wo":         "second-secret",
		"password_wo_version": 2,
	}))
	if got := syncs.remotePassword("offsite"); got != "second-secret" {
		t.Errorf("password = %q after a new version", got)
	}

	// Back to the defaults: deleted, not written; the password stays.
	inst = h.update(t, inst, remoteConfig(t, h, map[string]any{"host": "192.0.2.7"}))
	updated = fake.lastCall(t, "PUT /config/remote/offsite")
	if got := strings.Join(updated.form["delete"], ","); got != "comment,fingerprint,port,use-node-proxy" {
		t.Errorf("delete = %q", got)
	}
	if len(updated.form) != 1 {
		t.Errorf("PUT form = %v, want only deletions", updated.form)
	}
	if remote, _ := syncs.remote("offsite"); len(remote) != 3 || syncs.remotePassword("offsite") != "second-secret" {
		t.Errorf("stored remote = %v, password %q", remote, syncs.remotePassword("offsite"))
	}
	if !isNullAt(t, inst.state, "password_wo_version") {
		t.Errorf("state = %s", inst.state)
	}

	// A remote deleted outside Terraform is gone from state.
	syncs.mu.Lock()
	delete(syncs.remotes, "offsite")
	syncs.mu.Unlock()
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept a deleted remote: %s", refreshed.state)
	}
	// Destroying a remote that is gone is no error.
	h.destroy(t, inst)
}

func TestRemoteResourceImportAndErrors(t *testing.T) {
	h, _, syncs, _ := newSyncHarness(t)
	syncs.addRemote("lab", fakeProperties{"host": "lab.example.com", "auth-id": "root@pam", "port": int64(8007),
		"fingerprint": testRemoteFingerprint}, "lab-secret")

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_remote", "lab"),
		"identity": h.importByIdentity(t, "pbs_remote", map[string]any{"name": "lab"}),
	} {
		if stringAt(t, inst.state, "host") != "lab.example.com" || int64At(t, inst.state, "port") != 8007 ||
			stringAt(t, inst.state, "fingerprint") != testRemoteFingerprint || !isNullAt(t, inst.state, "password_wo_version") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
	}

	// After an import, the password may stay out of the configuration.
	inst := h.importByID(t, "pbs_remote", "lab")
	config := h.resourceValue(t, "pbs_remote", map[string]any{"name": "lab", "host": "lab.example.com", "auth_id": "root@pam",
		"port": 8007, "fingerprint": testRemoteFingerprint})
	planned := h.plan(t, "pbs_remote", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)

	// Creating one needs the password, and a new name creates one.
	planned = h.plan(t, "pbs_remote", nil, remoteConfig(t, h, nil))
	requireProtocolErrorContaining(t, planned.Diagnostics, "password_wo")
	planned = h.plan(t, "pbs_remote", inst, h.resourceValue(t, "pbs_remote", map[string]any{"name": "lab2",
		"host": "lab.example.com", "auth_id": "root@pam"}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "password_wo")

	// A remote that exists is imported, not created.
	config = h.resourceValue(t, "pbs_remote", map[string]any{"name": "lab", "host": "lab.example.com", "auth_id": "root@pam",
		"password_wo": "remote-secret", "password_wo_version": 1})
	planned = h.plan(t, "pbs_remote", nil, config)
	applied := h.apply(t, "pbs_remote", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "import it")

	// PBS refuses to delete a remote a sync job uses.
	syncs.addSyncJob("pull-lab", fakeProperties{"store": "store1", "remote": "lab", "remote-store": "store2"})
	resp := syncDestroyResponse(t, h, inst)
	requireProtocolErrorContaining(t, resp.Diagnostics, "create_before_destroy")
	if _, exists := syncs.remote("lab"); !exists {
		t.Error("the remote was deleted")
	}

	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"host with port":     {map[string]any{"host": "pbs2.example.com:8007"}, "host"},
		"bracketed IPv6":     {map[string]any{"host": "[2001:db8::2]"}, "host"},
		"URL":                {map[string]any{"host": "https://pbs2.example.com"}, "host"},
		"zone":               {map[string]any{"host": "fe80::1%eth0"}, "host"},
		"bad auth id":        {map[string]any{"auth_id": "sync"}, "auth_id"},
		"port 0":             {map[string]any{"port": 0}, "port"},
		"short fingerprint":  {map[string]any{"fingerprint": "64:d3:ff"}, "fingerprint"},
		"short name":         {map[string]any{"name": "ab"}, "name"},
		"password, no vers":  {map[string]any{"password_wo": "remote-secret"}, "password_wo_version"},
		"control characters": {map[string]any{"password_wo": "a\nb", "password_wo_version": 1}, "password_wo"},
		"long password":      {map[string]any{"password_wo": strings.Repeat("x", 769), "password_wo_version": 1}, "768 bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			diags := h.validateResource(t, "pbs_remote", remoteConfig(t, h, tc.attrs))
			requireProtocolErrorContaining(t, diags, tc.want)
			for _, d := range diags {
				if strings.Contains(d.Detail, "a\nb") || strings.Contains(d.Detail, strings.Repeat("x", 769)) {
					t.Errorf("the error repeats the password: %s", d.Detail)
				}
			}
		})
	}
	for _, host := range []string{"pbs2.example.com", "pbs2", "192.0.2.7", "2001:db8::2", "::1"} {
		requireNoProtocolErrors(t, h.validateResource(t, "pbs_remote", remoteConfig(t, h, map[string]any{"host": host})))
	}
}

// use_node_proxy needs PBS 4.2.
func TestRemoteResourceNodeProxyNeedsPBS42(t *testing.T) {
	h, _, _, _ := newSyncHarness(t, fakeVersion40)
	planned := h.plan(t, "pbs_remote", nil, remoteConfig(t, h, map[string]any{
		"use_node_proxy": true, "password_wo": "remote-secret", "password_wo_version": 1,
	}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "use_node_proxy needs PBS 4.2 or newer")
	planned = h.plan(t, "pbs_remote", nil, remoteConfig(t, h, map[string]any{
		"use_node_proxy": false, "password_wo": "remote-secret", "password_wo_version": 1,
	}))
	requireNoProtocolErrors(t, planned.Diagnostics)
}

// pullJobConfig is the configuration of a pull job "pull-offsite", with attrs
// on top of what it needs.
func pullJobConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"id": "pull-offsite", "store": "store1", "remote": "offsite", "remote_store": "store2"}
	for k, v := range attrs {
		if v == nil {
			delete(config, k)
			continue
		}
		config[k] = v
	}
	return h.resourceValue(t, "pbs_sync_job", config)
}

func TestSyncJobResourceLifecycle(t *testing.T) {
	h, fake, syncs, _ := newSyncHarness(t)

	// PBS reads a pull job created with what it needs alone as just that.
	inst := h.create(t, "pbs_sync_job", pullJobConfig(t, h, nil))
	if created := fake.lastCall(t, "POST /config/sync"); len(created.form) != 4 {
		t.Errorf("POST form = %v, want id, store, remote and remote-store only", created.form)
	}
	if stringAt(t, inst.state, "sync_direction") != "pull" || boolAt(t, inst.state, "remove_vanished") ||
		boolAt(t, inst.state, "resync_corrupt") || !isNullAt(t, inst.state, "max_depth") || !isNullAt(t, inst.state, "rate_in") {
		t.Errorf("state = %s, want PBS's defaults", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_sync_job", inst.identity), "id"); got != "pull-offsite" {
		t.Errorf("identity id = %q", got)
	}

	every := pullJobConfig(t, h, map[string]any{
		"ns":              "site-a",
		"remote_ns":       "dept1",
		"max_depth":       3,
		"schedule":        "hourly",
		"owner":           "sync@pbs",
		"remove_vanished": true,
		"group_filter":    []any{"type:vm", "exclude:group:vm/100"},
		"transfer_last":   5,
		"encrypted_only":  true,
		"verified_only":   true,
		"resync_corrupt":  true,
		"run_on_mount":    true,
		"unmount_on_done": true,
		"worker_threads":  4,
		"rate_in":         "10MiB",
		"burst_in":        "20mib",
		"comment":         "Offsite copy",
	})
	inst = h.update(t, inst, every)
	updated := fake.lastCall(t, "PUT /config/sync/pull-offsite")
	for name, want := range map[string]string{"ns": "site-a", "remote-ns": "dept1", "max-depth": "3", "schedule": "hourly",
		"owner": "sync@pbs", "remove-vanished": "true", "transfer-last": "5", "encrypted-only": "true",
		"verified-only": "true", "resync-corrupt": "true", "run-on-mount": "true", "unmount-on-done": "true",
		"worker-threads": "4", "rate-in": "10MiB", "burst-in": "20mib", "comment": "Offsite copy"} {
		if got := updated.form.Get(name); got != want {
			t.Errorf("PUT %s = %q, want %q", name, got, want)
		}
	}
	if got := strings.Join(updated.form["group-filter"], ","); got != "exclude:group:vm/100,type:vm" {
		t.Errorf("PUT group-filter = %q", got)
	}
	// PBS writes sizes back its own way, which state does not show.
	if job, _ := syncs.syncJob("pull-offsite"); job["rate-in"] != "10 MiB" || job["burst-in"] != "20 MiB" {
		t.Errorf("stored job = %v", job)
	}
	if stringAt(t, inst.state, "rate_in") != "10MiB" || stringAt(t, inst.state, "burst_in") != "20mib" {
		t.Errorf("state = %s", inst.state)
	}
	replan := h.plan(t, "pbs_sync_job", inst, every)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_sync_job", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}
	refreshed := h.refresh(t, inst)
	if stringAt(t, refreshed.state, "rate_in") != "10MiB" {
		t.Errorf("refresh changed rate_in to %q", stringAt(t, refreshed.state, "rate_in"))
	}

	// Another spelling of the same size sends nothing, another size does.
	puts := fake.count("PUT /config/sync/pull-offsite")
	respelt := pullJobConfig(t, h, map[string]any{
		"ns": "site-a", "remote_ns": "dept1", "max_depth": 3, "schedule": "hourly", "owner": "sync@pbs",
		"remove_vanished": true, "group_filter": []any{"type:vm", "exclude:group:vm/100"}, "transfer_last": 5,
		"encrypted_only": true, "verified_only": true, "resync_corrupt": true, "run_on_mount": true, "unmount_on_done": true,
		"worker_threads": 4, "rate_in": "10 MiB", "burst_in": "20971520", "comment": "Offsite copy",
	})
	inst = h.update(t, inst, respelt)
	if fake.count("PUT /config/sync/pull-offsite") != puts {
		t.Errorf("a new spelling of the same sizes was sent: %v", fake.lastCall(t, "PUT /config/sync/pull-offsite").form)
	}

	// Back to the defaults: deleted, except resync-corrupt, which PBS cannot
	// delete and gets false.
	inst = h.update(t, inst, pullJobConfig(t, h, nil))
	updated = fake.lastCall(t, "PUT /config/sync/pull-offsite")
	want := "burst-in,comment,encrypted-only,group-filter,max-depth,ns,owner,rate-in,remote-ns,remove-vanished," +
		"run-on-mount,schedule,transfer-last,unmount-on-done,verified-only,worker-threads"
	if got := strings.Join(updated.form["delete"], ","); got != want {
		t.Errorf("delete = %q, want %q", got, want)
	}
	if updated.form.Get("resync-corrupt") != "false" || len(updated.form) != 2 {
		t.Errorf("PUT form = %v, want the deletions and resync-corrupt=false", updated.form)
	}
	if job, _ := syncs.syncJob("pull-offsite"); len(job) != 5 {
		t.Errorf("stored job = %v, want id, store, remote, remote-store and resync-corrupt", job)
	}

	// Without remote, it pulls from a local datastore.
	inst = h.update(t, inst, pullJobConfig(t, h, map[string]any{"remote": nil}))
	if got := strings.Join(fake.lastCall(t, "PUT /config/sync/pull-offsite").form["delete"], ","); got != "remote" {
		t.Errorf("delete = %q, want remote", got)
	}
	if !isNullAt(t, inst.state, "remote") {
		t.Errorf("state = %s", inst.state)
	}

	// A job deleted with its datastore is gone from state.
	syncs.mu.Lock()
	delete(syncs.syncJobs, "pull-offsite")
	syncs.mu.Unlock()
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept a deleted job: %s", refreshed.state)
	}
	h.destroy(t, inst)
}

// A push job is created with its direction, reads and imports like a pull
// job, and a new direction replaces the job.
func TestSyncJobResourcePush(t *testing.T) {
	h, fake, syncs, _ := newSyncHarness(t)

	config := h.resourceValue(t, "pbs_sync_job", map[string]any{
		"id": "push-offsite", "sync_direction": "push", "store": "store1", "remote": "offsite", "remote_store": "store2",
		"rate_out": "1.5GB",
	})
	inst := h.create(t, "pbs_sync_job", config)
	created := fake.lastCall(t, "POST /config/sync")
	if created.form.Get("sync-direction") != "push" || created.form.Get("rate-out") != "1.5GB" {
		t.Errorf("POST form = %v", created.form)
	}
	if _, sent := created.form["resync-corrupt"]; sent {
		t.Error("a push job was sent resync-corrupt, which PBS refuses")
	}
	if stringAt(t, inst.state, "sync_direction") != "push" {
		t.Errorf("state = %s", inst.state)
	}

	for name, imported := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_sync_job", "push-offsite"),
		"identity": h.importByIdentity(t, "pbs_sync_job", map[string]any{"id": "push-offsite"}),
	} {
		if stringAt(t, imported.state, "sync_direction") != "push" || stringAt(t, imported.state, "rate_out") != "1.5 GB" {
			t.Errorf("import by %s = %s", name, imported.state)
		}
	}

	pull := h.resourceValue(t, "pbs_sync_job", map[string]any{
		"id": "push-offsite", "store": "store1", "remote": "offsite", "remote_store": "store2", "rate_out": "1.5GB",
	})
	planned := h.plan(t, "pbs_sync_job", inst, pull)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 1 || !strings.Contains(planned.RequiresReplace[0].String(), "sync_direction") {
		t.Errorf("RequiresReplace = %v, want sync_direction", planned.RequiresReplace)
	}

	// The list returns pull jobs alone unless asked for both; the provider
	// always asks.
	syncs.addSyncJob("pull-local", fakeProperties{"store": "store3", "remote-store": "store1"})
	jobs := h.readDataSource(t, "pbs_sync_jobs", h.dataSourceValue(t, "pbs_sync_jobs", map[string]any{}))
	if lengthAt(t, jobs, "jobs") != 2 || stringAt(t, jobs, "jobs", 1, "id") != "push-offsite" ||
		stringAt(t, jobs, "jobs", 1, "sync_direction") != "push" || !isNullAt(t, jobs, "jobs", 0, "remote") {
		t.Errorf("pbs_sync_jobs = %s", jobs)
	}
	h.destroy(t, inst)
	if _, exists := syncs.syncJob("push-offsite"); exists {
		t.Error("the job still exists")
	}
}

// PBS deletes a datastore's sync jobs with it. A job whose store follows a
// datastore replaced by a new name is created again, as the plan says.
func TestSyncJobResourceFollowsReplacedDatastore(t *testing.T) {
	h, fake, syncs, datastores := newSyncHarness(t)
	datastores.addDatastore("store1", fakeProperties{"path": "/mnt/store1"})
	datastores.addDatastore("store3", fakeProperties{"path": "/mnt/store3"})
	inst := h.create(t, "pbs_sync_job", pullJobConfig(t, h, map[string]any{"schedule": "daily"}))

	resp := syncDestroyResponse(t, h, &resourceInstance{typeName: "pbs_datastore", state: h.resourceValue(t, "pbs_datastore",
		map[string]any{"id": "store1", "name": "store1", "path": "/mnt/store1", "destroy_data": true})})
	requireNoProtocolErrors(t, resp.Diagnostics)
	if _, exists := syncs.syncJob("pull-offsite"); exists {
		t.Fatal("deleting the datastore kept its sync job")
	}

	inst = h.update(t, inst, pullJobConfig(t, h, map[string]any{"store": "store3", "schedule": "daily"}))
	created := fake.lastCall(t, "POST /config/sync")
	if created.form.Get("store") != "store3" || created.form.Get("schedule") != "daily" {
		t.Errorf("POST form = %v, want the job as planned", created.form)
	}
	if job, _ := syncs.syncJob("pull-offsite"); job["store"] != "store3" {
		t.Errorf("job = %v", job)
	}
	if stringAt(t, inst.state, "store") != "store3" {
		t.Errorf("state = %s", inst.state)
	}
}

func TestSyncJobResourceValidation(t *testing.T) {
	h, _, syncs, _ := newSyncHarness(t)
	syncs.addSyncJob("taken", fakeProperties{"store": "store1", "remote": "offsite", "remote-store": "store2"})

	config := h.resourceValue(t, "pbs_sync_job", map[string]any{"id": "taken", "store": "store1", "remote": "offsite", "remote_store": "store2"})
	planned := h.plan(t, "pbs_sync_job", nil, config)
	applied := h.apply(t, "pbs_sync_job", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "import it")

	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"push without remote": {map[string]any{"sync_direction": "push", "remote": nil}, "Push needs a remote"},
		"push resync":         {map[string]any{"sync_direction": "push", "resync_corrupt": true}, "resync_corrupt"},
		"local into itself":   {map[string]any{"remote": nil, "remote_store": "store1"}, "same"},
		"unmount alone":       {map[string]any{"unmount_on_done": true}, "run_on_mount"},
		"deep ns":             {map[string]any{"ns": "a/b/c", "max_depth": 5}, "Lower max_depth to 4"},
		"deep remote ns":      {map[string]any{"remote_ns": "a/b/c/d/e/f/g", "max_depth": 1}, "Lower max_depth to 0"},
		"include prefix":      {map[string]any{"group_filter": []any{"include:type:vm"}}, "include:"},
		"bad type":            {map[string]any{"group_filter": []any{"type:qemu"}}, "group_filter"},
		"bad group":           {map[string]any{"group_filter": []any{"group:100"}}, "group_filter"},
		"empty regex":         {map[string]any{"group_filter": []any{"regex:"}}, "group_filter"},
		"empty filters":       {map[string]any{"group_filter": []any{}}, "group_filter"},
		"bad size":            {map[string]any{"rate_in": "10MIB"}, "rate_in"},
		"many decimals":       {map[string]any{"rate_out": "1.2345GiB"}, "three decimals"},
		"threads":             {map[string]any{"worker_threads": 33}, "worker_threads"},
		"transfer last":       {map[string]any{"transfer_last": 0}, "transfer_last"},
		"direction":           {map[string]any{"sync_direction": "both"}, "sync_direction"},
		"owner":               {map[string]any{"owner": "sync"}, "owner"},
		"ns slash":            {map[string]any{"ns": "/dept1"}, "namespace"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_sync_job", pullJobConfig(t, h, tc.attrs)), tc.want)
		})
	}
	for name, attrs := range map[string]map[string]any{
		"push":         {"sync_direction": "push"},
		"local":        {"remote": nil, "remote_store": "store3"},
		"filters":      {"group_filter": []any{"type:ct", "group:host/web-1", "regex:^vm/1[0-9]{2}$", "exclude:regex:test"}},
		"full depth":   {"ns": "a/b", "max_depth": 5},
		"sizes":        {"rate_in": "500", "burst_in": "64KiB", "rate_out": "1.5 GB", "burst_out": "2Ti"},
		"unmount pair": {"run_on_mount": true, "unmount_on_done": true},
	} {
		t.Run("valid "+name, func(t *testing.T) {
			requireNoProtocolErrors(t, h.validateResource(t, "pbs_sync_job", pullJobConfig(t, h, attrs)))
		})
	}
}

// unmount_on_done needs PBS 4.1, worker_threads 4.2.
func TestSyncJobResourceVersionGates(t *testing.T) {
	h, _, _, _ := newSyncHarness(t, fakeVersion40)
	for attribute, value := range map[string]any{"worker_threads": 2, "unmount_on_done": true} {
		attrs := map[string]any{attribute: value}
		if attribute == "unmount_on_done" {
			attrs["run_on_mount"] = true
		}
		planned := h.plan(t, "pbs_sync_job", nil, pullJobConfig(t, h, attrs))
		requireProtocolErrorContaining(t, planned.Diagnostics, attribute+" needs PBS")
	}
	planned := h.plan(t, "pbs_sync_job", nil, pullJobConfig(t, h, map[string]any{"run_on_mount": true, "unmount_on_done": false}))
	requireNoProtocolErrors(t, planned.Diagnostics)
}

// syncDestroyResponse plans and applies the destruction of inst, and returns
// the apply's answer, errors and all.
func syncDestroyResponse(t *testing.T, h *protocolHarness, inst *resourceInstance) *tfprotov6.ApplyResourceChangeResponse {
	t.Helper()
	null := tftypes.NewValue(h.resourceType(t, inst.typeName), nil)
	planned := h.plan(t, inst.typeName, inst, null)
	requireNoProtocolErrors(t, planned.Diagnostics)
	return h.apply(t, inst.typeName, inst, null, planned)
}
