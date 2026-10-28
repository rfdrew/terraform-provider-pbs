package provider

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Failures of the remote's calls, and those after a write took effect: the
// remote is recorded all the same, so that Terraform does not lose track of
// it.
func TestRemoteResourceFailures(t *testing.T) {
	h, fake, syncs, _ := newSyncHarness(t)
	config := remoteConfig(t, h, map[string]any{"password_wo": "remote-secret", "password_wo_version": 1})

	fake.reply("POST /config/remote", http.StatusForbidden, "permission check failed")
	applied := h.apply(t, "pbs_remote", nil, config, h.plan(t, "pbs_remote", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "Remote.Modify on /remote")
	fake.handle("POST /config/remote", syncs.createRemote)

	// Created, but not read back: recorded and tainted.
	fake.reply("GET /config/remote/offsite", http.StatusForbidden, "permission check failed")
	applied = h.apply(t, "pbs_remote", nil, config, h.plan(t, "pbs_remote", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "marked tainted")
	inst := &resourceInstance{typeName: "pbs_remote", state: h.decodeResource(t, "pbs_remote", applied.NewState), identity: applied.NewIdentity}
	if stringAt(t, inst.state, "id") != "offsite" {
		t.Fatalf("state = %s", inst.state)
	}
	requireProtocolErrorContaining(t, h.read(t, inst).Diagnostics, "Remote.Audit on /remote/offsite")

	// The update fails, or succeeds without being read back.
	fake.handle("GET /config/remote/offsite", nil)
	fake.reply("PUT /config/remote/offsite", http.StatusForbidden, "permission check failed")
	changed := remoteConfig(t, h, map[string]any{"password_wo": "remote-secret", "password_wo_version": 1, "comment": "new"})
	updated := h.apply(t, "pbs_remote", inst, changed, h.plan(t, "pbs_remote", inst, changed))
	requireProtocolErrorContaining(t, updated.Diagnostics, "Unable to update PBS remote")
	fake.handle("PUT /config/remote/offsite", nil)
	fake.reply("GET /config/remote/offsite", http.StatusForbidden, "permission check failed")
	updated = h.apply(t, "pbs_remote", inst, changed, h.plan(t, "pbs_remote", inst, changed))
	requireProtocolErrorContaining(t, updated.Diagnostics, "updated remote")
	fake.handle("GET /config/remote/offsite", nil)

	fake.reply("DELETE /config/remote/offsite", http.StatusForbidden, "permission check failed")
	resp := syncDestroyResponse(t, h, inst)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Remote.Modify on /remote/offsite")

	requireProtocolErrorContaining(t, h.importResource(t, "pbs_remote", "bad name", nil).Diagnostics, "by its name")
}

// PBS answers a missing privilege of a sync job with 400 "permission check
// failed"; the error names what the job needs, by direction.
func TestSyncJobResourceFailures(t *testing.T) {
	h, fake, syncs, _ := newSyncHarness(t)

	fake.reply("POST /config/sync", http.StatusBadRequest, "permission check failed")
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"pull":  {nil, "Remote.Read on /remote/offsite/store2"},
		"local": {map[string]any{"remote": nil, "remote_store": "store3", "remote_ns": "dept1"}, "Datastore.Read on /datastore/store3/dept1"},
		"push": {map[string]any{"sync_direction": "push", "remote_ns": "site-a", "ns": "dept1"},
			"RemoteDatastore.Backup on /remote/offsite/store2/site-a, plus RemoteDatastore.Prune for remove_vanished, " +
				"and Datastore.Audit with Datastore.Read on /datastore/store1/dept1"},
	} {
		t.Run(name, func(t *testing.T) {
			config := pullJobConfig(t, h, tc.attrs)
			applied := h.apply(t, "pbs_sync_job", nil, config, h.plan(t, "pbs_sync_job", nil, config))
			requireProtocolErrorContaining(t, applied.Diagnostics, tc.want)
			requireProtocolErrorContaining(t, applied.Diagnostics, "An API token has no privileges of its own")
		})
	}
	fake.handle("POST /config/sync", syncs.createSyncJob)

	// Created, but not read back: recorded and tainted, with what reading
	// needs.
	fake.reply("GET /config/sync/pull-offsite", http.StatusBadRequest, "permission check failed")
	config := pullJobConfig(t, h, nil)
	applied := h.apply(t, "pbs_sync_job", nil, config, h.plan(t, "pbs_sync_job", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "marked tainted")
	requireProtocolErrorContaining(t, applied.Diagnostics, "Remote.Audit on /remote/offsite")
	inst := &resourceInstance{typeName: "pbs_sync_job", state: h.decodeResource(t, "pbs_sync_job", applied.NewState), identity: applied.NewIdentity}
	requireProtocolErrorContaining(t, h.read(t, inst).Diagnostics, "Unable to read PBS sync job")

	// The update fails, or succeeds without being read back.
	fake.handle("GET /config/sync/pull-offsite", nil)
	fake.reply("PUT /config/sync/pull-offsite", http.StatusForbidden, "permission check failed")
	changed := pullJobConfig(t, h, map[string]any{"comment": "new"})
	updated := h.apply(t, "pbs_sync_job", inst, changed, h.plan(t, "pbs_sync_job", inst, changed))
	requireProtocolErrorContaining(t, updated.Diagnostics, "Unable to update PBS sync job")
	fake.handle("PUT /config/sync/pull-offsite", nil)
	fake.reply("GET /config/sync/pull-offsite", http.StatusForbidden, "permission check failed")
	updated = h.apply(t, "pbs_sync_job", inst, changed, h.plan(t, "pbs_sync_job", inst, changed))
	requireProtocolErrorContaining(t, updated.Diagnostics, "updated sync job")
	fake.handle("GET /config/sync/pull-offsite", nil)

	fake.reply("DELETE /config/sync/pull-offsite", http.StatusForbidden, "permission check failed")
	requireProtocolErrorContaining(t, syncDestroyResponse(t, h, inst).Diagnostics, "Unable to delete PBS sync job")

	requireProtocolErrorContaining(t, h.importResource(t, "pbs_sync_job", "-bad", nil).Diagnostics, "by its id")
}

// A new owner that may not use the job's encryption keys fails the update
// with "no such key"; the job is still there, so it is not created again.
func TestSyncJobResourceUpdateKeyError(t *testing.T) {
	h, fake, syncs, _ := newSyncHarness(t)
	inst := h.create(t, "pbs_sync_job", pullJobConfig(t, h, nil))
	posts := fake.count("POST /config/sync")

	fake.reply("PUT /config/sync/pull-offsite", http.StatusBadRequest, "no such key or cannot access key 'k1'")
	changed := pullJobConfig(t, h, map[string]any{"owner": "sync@pbs"})
	updated := h.apply(t, "pbs_sync_job", inst, changed, h.plan(t, "pbs_sync_job", inst, changed))
	requireProtocolErrorContaining(t, updated.Diagnostics, "no such key or cannot access key 'k1'")
	if fake.count("POST /config/sync") != posts {
		t.Error("the job was created again although it exists")
	}
	if job, _ := syncs.syncJob("pull-offsite"); job["owner"] != nil {
		t.Errorf("job = %v", job)
	}
}

// Reading a job needs other privileges for each direction.
func TestSyncJobReadPrivileges(t *testing.T) {
	for want, m := range map[string]syncJobModel{
		"Datastore.Audit on /datastore/store1 and Remote.Audit on /remote/offsite": {
			SyncDirection: types.StringValue("pull"), Store: types.StringValue("store1"), Remote: types.StringValue("offsite"),
			RemoteStore: types.StringValue("store2"),
		},
		"Datastore.Audit on /datastore/store1/dept1 and on /datastore/store2": {
			SyncDirection: types.StringValue("pull"), Store: types.StringValue("store1"), NS: types.StringValue("dept1"),
			Remote: types.StringNull(), RemoteStore: types.StringValue("store2"),
		},
		"Datastore.Audit on /datastore/store1 and Remote.Audit on /remote/offsite/store2/site-a": {
			SyncDirection: types.StringValue("push"), Store: types.StringValue("store1"), Remote: types.StringValue("offsite"),
			RemoteStore: types.StringValue("store2"), RemoteNS: types.StringValue("site-a"),
		},
	} {
		if got := syncJobReadPrivileges(m); got != want {
			t.Errorf("syncJobReadPrivileges() = %q, want %q", got, want)
		}
	}
}

// The data sources fail with what reading needs.
func TestRemoteAndJobDataSourceFailures(t *testing.T) {
	h, fake, _, _ := newSyncHarness(t)
	for _, route := range []string{"GET /config/remote", "GET /config/remote/offsite", "GET /config/remote/offsite/scan",
		"GET /config/remote/offsite/scan/store1/namespaces", "GET /config/sync", "GET /config/sync/job1",
		"GET /config/verify", "GET /config/verify/job1", "GET /config/prune", "GET /config/prune/job1"} {
		fake.reply(route, http.StatusForbidden, "permission check failed")
	}
	for typeName, tc := range map[string]struct {
		config map[string]any
		want   string
	}{
		"pbs_remotes":           {map[string]any{}, "Remote.Audit on /remote"},
		"pbs_remote":            {map[string]any{"name": "offsite"}, "Remote.Audit on /remote/offsite"},
		"pbs_remote_datastores": {map[string]any{"remote": "offsite"}, "Remote.Audit on /remote/offsite"},
		"pbs_remote_namespaces": {map[string]any{"remote": "offsite", "store": "store1"}, "Remote.Audit on /remote/offsite"},
		"pbs_sync_jobs":         {map[string]any{}, "Unable to list PBS sync jobs"},
		"pbs_sync_job":          {map[string]any{"id": "job1"}, "Unable to read PBS sync job"},
		"pbs_verify_jobs":       {map[string]any{}, "Unable to list PBS verify jobs"},
		"pbs_verify_job":        {map[string]any{"id": "job1"}, "Datastore.Audit"},
		"pbs_prune_jobs":        {map[string]any{}, "Unable to list PBS prune jobs"},
		"pbs_prune_job":         {map[string]any{"id": "job1"}, "Datastore.Audit"},
	} {
		t.Run(typeName, func(t *testing.T) {
			resp := h.readDataSourceResponse(t, typeName, h.dataSourceValue(t, typeName, tc.config))
			requireProtocolErrorContaining(t, resp.Diagnostics, tc.want)
		})
	}
}

// A maintenance mode the provider cannot read is reported, not fatal.
func TestRemoteMaintenanceModeUnreadable(t *testing.T) {
	h, _, syncs, _ := newSyncHarness(t)
	syncs.addRemote("offsite", fakeProperties{"host": "pbs2.example.com", "auth-id": "sync@pbs"}, "secret")
	syncs.addRemoteDatastore("offsite", fakeProperties{"store": "store1", "maintenance": `read-only,message="unterminated`})
	resp := h.readDataSourceResponse(t, "pbs_remote_datastores", h.dataSourceValue(t, "pbs_remote_datastores", map[string]any{"remote": "offsite"}))
	requireNoProtocolErrors(t, resp.Diagnostics)
	requireProtocolWarningContaining(t, resp.Diagnostics, "Unexpected maintenance mode")
}

// The custom string types behave as the framework expects of them.
func TestSemanticStringTypes(t *testing.T) {
	ctx := context.Background()
	if (byteSizeType{}).String() != "byteSizeType" || (fingerprintType{}).String() != "fingerprintType" {
		t.Error("String")
	}
	if !(byteSizeType{}).Equal(byteSizeType{}) || (byteSizeType{}).Equal(fingerprintType{}) || (byteSizeType{}).Equal(types.StringType) {
		t.Error("type Equal")
	}
	if _, ok := (byteSizeType{}).ValueType(ctx).(byteSizeValue); !ok {
		t.Error("ValueType")
	}
	value, diags := (byteSizeType{}).ValueFromString(ctx, types.StringValue("10MiB"))
	if diags.HasError() || value.(byteSizeValue).ValueString() != "10MiB" {
		t.Errorf("ValueFromString = %v, %v", value, diags)
	}
	if _, err := (byteSizeType{}).ValueFromTerraform(ctx, tftypes.NewValue(tftypes.Number, 1)); err == nil {
		t.Error("ValueFromTerraform accepted a number")
	}
	v := byteSizeOrNull("10MiB")
	if !v.Equal(byteSizeOrNull("10MiB")) || v.Equal(byteSizeOrNull("10 MiB")) || v.Equal(types.StringValue("10MiB")) {
		t.Error("value Equal")
	}
	if _, ok := v.Type(ctx).(byteSizeType); !ok {
		t.Error("Type")
	}
	if same, _ := v.StringSemanticEquals(ctx, byteSizeOrNull("10 MiB")); !same {
		t.Error("10MiB and 10 MiB differ")
	}
	if same, _ := v.StringSemanticEquals(ctx, byteSizeOrNull("10MB")); same {
		t.Error("10MiB and 10MB are the same")
	}
	if _, diags := v.StringSemanticEquals(ctx, types.StringValue("10MiB")); !diags.HasError() {
		t.Error("StringSemanticEquals accepted another type")
	}
	fp := fingerprintOrNull(testRemoteFingerprint)
	for other, want := range map[string]bool{
		testRemoteFingerprint: true,
		"64D3FF3A5038535A9E2B1F6A5A1D4A427C614B01F215979A2E1DAC1B7D0EAA17":                                true,
		"00:d3:ff:3a:50:38:53:5a:9e:2b:1f:6a:5a:1d:4a:42:7c:61:4b:01:f2:15:97:9a:2e:1d:ac:1b:7d:0e:aa:17": false,
		"not a fingerprint": false,
	} {
		if same, _ := fp.StringSemanticEquals(ctx, fingerprintOrNull(other)); same != want {
			t.Errorf("fingerprint equals %q = %v, want %v", other, same, want)
		}
	}
	if got := pbsFingerprint(fingerprintOrNull("not a fingerprint")); got.ValueString() != "not a fingerprint" {
		t.Errorf("pbsFingerprint kept %q", got.ValueString())
	}
}
