package provider

import (
	"strings"
	"testing"
)

func TestRemoteAndJobDataSourceSchemasAreValid(t *testing.T) {
	requireValidDataSourceSchema(t, &remoteDataSource{})
	requireValidDataSourceSchema(t, &remotesDataSource{})
	requireValidDataSourceSchema(t, &remoteDatastoresDataSource{})
	requireValidDataSourceSchema(t, &remoteNamespacesDataSource{})
	requireValidDataSourceSchema(t, &syncJobDataSource{})
	requireValidDataSourceSchema(t, &syncJobsDataSource{})
	requireValidDataSourceSchema(t, &verifyJobDataSource{})
	requireValidDataSourceSchema(t, &verifyJobsDataSource{})
	requireValidDataSourceSchema(t, &pruneJobDataSource{})
	requireValidDataSourceSchema(t, &pruneJobsDataSource{})
}

// The remote data sources never show the password, which PBS does not
// return, and show fingerprints as pbs_fingerprint does.
func TestRemoteDataSources(t *testing.T) {
	h, _, syncs, _ := newSyncHarness(t)
	syncs.addRemote("offsite", fakeProperties{"host": "pbs2.example.com", "auth-id": "sync@pbs!offsite",
		"fingerprint": strings.ToUpper(testRemoteFingerprint), "comment": "Offsite"}, "offsite-secret")
	syncs.addRemote("lab", fakeProperties{"host": "192.0.2.7", "port": int64(8008), "auth-id": "root@pam",
		"use-node-proxy": true}, "lab-secret")

	remote := h.readDataSource(t, "pbs_remote", h.dataSourceValue(t, "pbs_remote", map[string]any{"name": "offsite"}))
	if stringAt(t, remote, "host") != "pbs2.example.com" || stringAt(t, remote, "auth_id") != "sync@pbs!offsite" ||
		stringAt(t, remote, "fingerprint") != testRemoteFingerprint || !isNullAt(t, remote, "port") ||
		boolAt(t, remote, "use_node_proxy") || stringAt(t, remote, "comment") != "Offsite" {
		t.Errorf("pbs_remote = %s", remote)
	}
	if strings.Contains(remote.String(), "secret") {
		t.Errorf("pbs_remote shows the password: %s", remote)
	}

	remotes := h.readDataSource(t, "pbs_remotes", h.dataSourceValue(t, "pbs_remotes", map[string]any{}))
	if lengthAt(t, remotes, "remotes") != 2 || stringAt(t, remotes, "remotes", 0, "name") != "lab" ||
		int64At(t, remotes, "remotes", 0, "port") != 8008 || !boolAt(t, remotes, "remotes", 0, "use_node_proxy") ||
		!isNullAt(t, remotes, "remotes", 0, "fingerprint") || stringAt(t, remotes, "remotes", 1, "name") != "offsite" {
		t.Errorf("pbs_remotes = %s", remotes)
	}

	resp := h.readDataSourceResponse(t, "pbs_remote", h.dataSourceValue(t, "pbs_remote", map[string]any{"name": "missing"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS has no remote "missing"`)
}

// A scan answers what the remote's auth ID sees there, sorted; a remote that
// cannot be reached fails it with advice.
func TestRemoteScanDataSources(t *testing.T) {
	h, _, syncs, _ := newSyncHarness(t)
	syncs.addRemote("offsite", fakeProperties{"host": "pbs2.example.com", "auth-id": "sync@pbs"}, "secret")
	syncs.addRemote("down", fakeProperties{"host": "pbs3.example.com", "auth-id": "sync@pbs"}, "secret")
	syncs.setUnreachable("down")
	syncs.addRemoteDatastore("offsite", fakeProperties{"store": "store2", "comment": nil, "mount-status": "mounted",
		"backend-type": "filesystem", "maintenance": "read-only,message=moving disks"})
	syncs.addRemoteDatastore("offsite", fakeProperties{"store": "store1", "comment": "Backups"})
	for _, ns := range []string{"dept1/hosts", "", "dept1", "dept2"} {
		syncs.addRemoteNamespace("offsite", "store1", ns)
	}

	datastores := h.readDataSource(t, "pbs_remote_datastores", h.dataSourceValue(t, "pbs_remote_datastores", map[string]any{"remote": "offsite"}))
	if lengthAt(t, datastores, "datastores") != 2 || stringAt(t, datastores, "datastores", 0, "store") != "store1" ||
		stringAt(t, datastores, "datastores", 0, "comment") != "Backups" ||
		stringAt(t, datastores, "datastores", 0, "mount_status") != "nonremovable" ||
		stringAt(t, datastores, "datastores", 0, "backend_type") != "filesystem" ||
		!isNullAt(t, datastores, "datastores", 0, "maintenance_mode") ||
		!isNullAt(t, datastores, "datastores", 1, "comment") ||
		stringAt(t, datastores, "datastores", 1, "mount_status") != "mounted" ||
		stringAt(t, datastores, "datastores", 1, "maintenance_mode", "type") != "read-only" ||
		stringAt(t, datastores, "datastores", 1, "maintenance_mode", "message") != "moving disks" {
		t.Errorf("pbs_remote_datastores = %s", datastores)
	}

	namespaces := h.readDataSource(t, "pbs_remote_namespaces", h.dataSourceValue(t, "pbs_remote_namespaces",
		map[string]any{"remote": "offsite", "store": "store1"}))
	var got []string
	for i := range lengthAt(t, namespaces, "namespaces") {
		got = append(got, stringAt(t, namespaces, "namespaces", i, "ns"))
	}
	if strings.Join(got, ",") != ",dept1,dept1/hosts,dept2" {
		t.Errorf("namespaces = %q, want the root first, each after its parent", got)
	}

	for typeName, config := range map[string]map[string]any{
		"pbs_remote_datastores": {"remote": "down"},
		"pbs_remote_namespaces": {"remote": "down", "store": "store1"},
	} {
		resp := h.readDataSourceResponse(t, typeName, h.dataSourceValue(t, typeName, config))
		requireProtocolErrorContaining(t, resp.Diagnostics, "could not reach remote")
	}
	resp := h.readDataSourceResponse(t, "pbs_remote_datastores", h.dataSourceValue(t, "pbs_remote_datastores", map[string]any{"remote": "missing"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS has no remote "missing"`)
	resp = h.readDataSourceResponse(t, "pbs_remote_namespaces", h.dataSourceValue(t, "pbs_remote_namespaces",
		map[string]any{"remote": "missing", "store": "store1"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS has no remote "missing"`)
	resp = h.readDataSourceResponse(t, "pbs_remote_namespaces", h.dataSourceValue(t, "pbs_remote_namespaces",
		map[string]any{"remote": "offsite", "store": "store9"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to scan PBS remote")
}

// The job data sources report jobs as their resources do, defaults
// included.
func TestJobDataSources(t *testing.T) {
	h, _, syncs, datastores := newSyncHarness(t)
	datastores.addPruneJob("daily-store1", fakeProperties{"store": "store1", "schedule": "daily", "keep-daily": int64(7)})
	datastores.addPruneJob("weekly-store2", fakeProperties{"store": "store2", "schedule": "sun 02:00", "keep-weekly": int64(4), "disable": true})
	datastores.addVerifyJob("verify-store1", fakeProperties{"store": "store1"})
	datastores.addVerifyJob("verify-store2", fakeProperties{"store": "store2", "schedule": "sat 03:00", "ignore-verified": false})
	syncs.addSyncJob("pull-offsite", fakeProperties{"store": "store1", "remote": "offsite", "remote-store": "store2",
		"rate-in": "10 MiB", "group-filter": []string{"type:vm"}})
	syncs.addSyncJob("push-offsite", fakeProperties{"store": "store1", "remote": "offsite", "remote-store": "store3",
		"sync-direction": "push", "remove-vanished": true})
	syncs.addSyncJob("local", fakeProperties{"store": "store2", "remote-store": "store1"})

	prune := h.readDataSource(t, "pbs_prune_job", h.dataSourceValue(t, "pbs_prune_job", map[string]any{"id": "daily-store1"}))
	if int64At(t, prune, "keep", "daily") != 7 || !isNullAt(t, prune, "keep", "last") || boolAt(t, prune, "disable") {
		t.Errorf("pbs_prune_job = %s", prune)
	}
	pruneJobs := h.readDataSource(t, "pbs_prune_jobs", h.dataSourceValue(t, "pbs_prune_jobs", map[string]any{"store": "store2"}))
	if lengthAt(t, pruneJobs, "jobs") != 1 || stringAt(t, pruneJobs, "jobs", 0, "id") != "weekly-store2" ||
		!boolAt(t, pruneJobs, "jobs", 0, "disable") {
		t.Errorf("pbs_prune_jobs = %s", pruneJobs)
	}

	verify := h.readDataSource(t, "pbs_verify_job", h.dataSourceValue(t, "pbs_verify_job", map[string]any{"id": "verify-store1"}))
	if int64At(t, verify, "max_depth") != 7 || !boolAt(t, verify, "ignore_verified") || !isNullAt(t, verify, "schedule") {
		t.Errorf("pbs_verify_job = %s", verify)
	}
	verifyJobs := h.readDataSource(t, "pbs_verify_jobs", h.dataSourceValue(t, "pbs_verify_jobs", map[string]any{}))
	if lengthAt(t, verifyJobs, "jobs") != 2 || stringAt(t, verifyJobs, "jobs", 1, "schedule") != "sat 03:00" ||
		boolAt(t, verifyJobs, "jobs", 1, "ignore_verified") {
		t.Errorf("pbs_verify_jobs = %s", verifyJobs)
	}

	push := h.readDataSource(t, "pbs_sync_job", h.dataSourceValue(t, "pbs_sync_job", map[string]any{"id": "push-offsite"}))
	if stringAt(t, push, "sync_direction") != "push" || !boolAt(t, push, "remove_vanished") || boolAt(t, push, "resync_corrupt") {
		t.Errorf("pbs_sync_job = %s", push)
	}
	pulls := h.readDataSource(t, "pbs_sync_jobs", h.dataSourceValue(t, "pbs_sync_jobs", map[string]any{"sync_direction": "pull"}))
	if lengthAt(t, pulls, "jobs") != 2 || stringAt(t, pulls, "jobs", 1, "id") != "pull-offsite" ||
		stringAt(t, pulls, "jobs", 1, "rate_in") != "10 MiB" || lengthAt(t, pulls, "jobs", 1, "group_filter") != 1 {
		t.Errorf("pbs_sync_jobs = %s", pulls)
	}
	ofStore1 := h.readDataSource(t, "pbs_sync_jobs", h.dataSourceValue(t, "pbs_sync_jobs", map[string]any{"store": "store1"}))
	if lengthAt(t, ofStore1, "jobs") != 2 || stringAt(t, ofStore1, "jobs", 1, "sync_direction") != "push" {
		t.Errorf("pbs_sync_jobs of store1 = %s", ofStore1)
	}

	for typeName, want := range map[string]string{
		"pbs_prune_job":  `PBS has no prune job "missing"`,
		"pbs_verify_job": `PBS has no verify job "missing"`,
		"pbs_sync_job":   `PBS has no sync job "missing"`,
	} {
		resp := h.readDataSourceResponse(t, typeName, h.dataSourceValue(t, typeName, map[string]any{"id": "missing"}))
		requireProtocolErrorContaining(t, resp.Diagnostics, want)
	}
}
