package provider

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// pushJobConfig is the configuration of a push job "push-offsite", with
// attrs on top of what it needs; a nil value leaves an attribute out.
func pushJobConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"id": "push-offsite", "sync_direction": "push", "store": "store1", "remote": "offsite",
		"remote_store": "store2"}
	for k, v := range attrs {
		if v == nil {
			delete(config, k)
			continue
		}
		config[k] = v
	}
	return h.resourceValue(t, "pbs_sync_job", config)
}

// newSyncKeysHarness is newKeysHarness with the keys key-a, key-b, key-c
// and key-x, in use, and key-old, archived.
func newSyncKeysHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeSync, *fakeEncryptionKeys) {
	t.Helper()
	h, fake, syncs, keys := newKeysHarness(t)
	for _, id := range []string{"key-a", "key-b", "key-c", "key-x"} {
		keys.addKey(id, nil)
	}
	keys.addKey("key-old", fakeProperties{"archived-at": int64(1793000000)})
	return h, fake, syncs, keys
}

// formsSince returns the forms of the requests to route after the first
// skip requests the fake received.
func formsSince(fake *fakePBS, route string, skip int) []url.Values {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var forms []url.Values
	for _, c := range fake.calls[skip:] {
		if c.route == route {
			forms = append(forms, c.form)
		}
	}
	return forms
}

// hasProtocolWarning reports whether diags hold a warning containing want.
func hasProtocolWarning(diags []*tfprotov6.Diagnostic, want string) bool {
	return slices.ContainsFunc(diags, func(d *tfprotov6.Diagnostic) bool {
		return d.Severity == tfprotov6.DiagnosticSeverityWarning && (strings.Contains(d.Summary, want) || strings.Contains(d.Detail, want))
	})
}

// fakeJobKeys returns the active key of the job id and its associated keys,
// sorted, as PBS holds them.
func fakeJobKeys(t *testing.T, syncs *fakeSync, id string) (string, []string) {
	t.Helper()
	job, ok := syncs.syncJob(id)
	if !ok {
		t.Fatalf("PBS has no sync job %s", id)
	}
	active, _ := job["active-encryption-key"].(string)
	associated := fakeKeyList(job)
	slices.Sort(associated)
	return active, associated
}

// Only a push job encrypts; key IDs are checked as PBS checks them.
func TestSyncJobKeysValidation(t *testing.T) {
	h, _, _, _ := newKeysHarness(t)
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_sync_job",
		pullJobConfig(t, h, map[string]any{"active_encryption_key": "key-a"})), "Push jobs only")
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_sync_job",
		pullJobConfig(t, h, map[string]any{"sync_direction": "pull", "active_encryption_key": "key-a"})), "Push jobs only")
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"short active key":       {map[string]any{"active_encryption_key": "ab"}, "active_encryption_key"},
		"active key with slash":  {map[string]any{"active_encryption_key": "keys/a"}, "active_encryption_key"},
		"associated key":         {map[string]any{"associated_key": []any{"key-a", ".hidden"}}, "associated_key"},
		"null associated key":    {map[string]any{"associated_key": []any{"key-a", nil}}, "null value"},
		"long associated key ID": {map[string]any{"associated_key": []any{strings.Repeat("k", 33)}}, "associated_key"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_sync_job", pushJobConfig(t, h, tc.attrs)), tc.want)
		})
	}
	for name, config := range map[string]tftypes.Value{
		"push":                 pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-a", "associated_key": []any{"key-b"}}),
		"pull with decryption": pullJobConfig(t, h, map[string]any{"associated_key": []any{"key-a", "key-b"}}),
		"direction unknown":    pullJobConfig(t, h, map[string]any{"sync_direction": tfUnknown, "active_encryption_key": "key-a"}),
	} {
		t.Run("valid "+name, func(t *testing.T) {
			requireNoProtocolErrors(t, h.validateResource(t, "pbs_sync_job", config))
		})
	}
}

// Both key attributes need PBS 4.2; an empty associated_key sends nothing,
// so it does not.
func TestSyncJobKeysNeedPBS42(t *testing.T) {
	h, _, _, _ := newKeysHarness(t, fakeVersionBeforeKeys)
	planned := h.plan(t, "pbs_sync_job", nil, pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-a"}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "active_encryption_key needs PBS 4.2 or newer")
	planned = h.plan(t, "pbs_sync_job", nil, pullJobConfig(t, h, map[string]any{"associated_key": []any{"key-a"}}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "associated_key needs PBS 4.2 or newer")
	for _, config := range []tftypes.Value{
		pullJobConfig(t, h, map[string]any{"associated_key": []any{}}),
		pushJobConfig(t, h, nil),
	} {
		requireNoProtocolErrors(t, h.plan(t, "pbs_sync_job", nil, config).Diagnostics)
	}
}

// A create sends the keys as configured, and PBS stores them so: no
// rotation happens on create. PBS checks a push job's active key, which must
// not be archived, and a pull job's associated keys, which may be.
func TestSyncJobKeysCreate(t *testing.T) {
	h, fake, syncs, _ := newSyncKeysHarness(t)

	config := pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-a"})
	planned := h.decodeResource(t, "pbs_sync_job", h.plan(t, "pbs_sync_job", nil, config).PlannedState)
	if !isNullAt(t, planned, "associated_key") {
		t.Errorf("plan = %s, want associated_key null", planned)
	}
	inst := h.create(t, "pbs_sync_job", config)
	created := fake.lastCall(t, "POST /config/sync")
	if created.form.Get("active-encryption-key") != "key-a" || created.form.Has("associated-key") {
		t.Errorf("POST form = %v", created.form)
	}
	if active, associated := fakeJobKeys(t, syncs, "push-offsite"); active != "key-a" || len(associated) != 0 {
		t.Errorf("PBS holds %q, %v", active, associated)
	}
	if stringAt(t, inst.state, "active_encryption_key") != "key-a" || !isNullAt(t, inst.state, "associated_key") {
		t.Errorf("state = %s", inst.state)
	}
	replan := h.plan(t, "pbs_sync_job", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_sync_job", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	pull := pullJobConfig(t, h, map[string]any{"associated_key": []any{"key-old", "key-a"}})
	inst = h.create(t, "pbs_sync_job", pull)
	if got := fake.lastCall(t, "POST /config/sync").form["associated-key"]; !slices.Equal(got, []string{"key-a", "key-old"}) {
		t.Errorf("POST associated-key = %v, want each key as a parameter of its own", got)
	}
	if got := setStringsAt(t, inst.state, "associated_key"); !slices.Equal(got, []string{"key-a", "key-old"}) {
		t.Errorf("associated_key = %v", got)
	}

	for name, tc := range map[string]struct {
		id     string
		config tftypes.Value
		key    string
	}{
		"archived active key": {"push-offsite-2", pushJobConfig(t, h, map[string]any{"id": "push-offsite-2", "active_encryption_key": "key-old"}), "key-old"},
		"missing active key":  {"push-offsite-3", pushJobConfig(t, h, map[string]any{"id": "push-offsite-3", "active_encryption_key": "ghost"}), "ghost"},
		"missing decryption key": {"pull-offsite-2", pullJobConfig(t, h, map[string]any{"id": "pull-offsite-2",
			"associated_key": []any{"key-a", "ghost"}}), "ghost"},
	} {
		t.Run(name, func(t *testing.T) {
			applied := h.apply(t, "pbs_sync_job", nil, tc.config, h.plan(t, "pbs_sync_job", nil, tc.config))
			requireProtocolErrorContaining(t, applied.Diagnostics, "PBS cannot use a sync encryption key of the job")
			requireProtocolErrorContaining(t, applied.Diagnostics, "no such key or cannot access key '"+tc.key+"'")
			if _, exists := syncs.syncJob(tc.id); exists {
				t.Error("PBS stored the job")
			}
		})
	}
}

// When the active key changes or goes, PBS appends the key before to
// associated-key. With associated_key left out, the plan says so; with it
// set, PBS ends up holding exactly what it says, a second update removing
// what PBS added, and the plan warns of a key it no longer protects. An
// active key that does not change is never sent: PBS would append it too.
func TestSyncJobKeyRotation(t *testing.T) {
	for name, tc := range map[string]struct {
		before, after map[string]any
		// planned is the planned associated_key, nil for null.
		planned []string
		warning bool
		puts    int
		// active and associated are what PBS then holds.
		active     string
		associated []string
	}{
		"rotation, associated_key left out": {
			before: map[string]any{"active_encryption_key": "key-a"}, after: map[string]any{"active_encryption_key": "key-b"},
			planned: []string{"key-a"}, puts: 1, active: "key-b", associated: []string{"key-a"},
		},
		"rotation, associated_key left out, keys before": {
			before:  map[string]any{"active_encryption_key": "key-a", "associated_key": []any{"key-x"}},
			after:   map[string]any{"active_encryption_key": "key-b"},
			planned: []string{"key-a", "key-x"}, puts: 1, active: "key-b", associated: []string{"key-a", "key-x"},
		},
		"rotation, associated_key = []": {
			before:  map[string]any{"active_encryption_key": "key-a"},
			after:   map[string]any{"active_encryption_key": "key-b", "associated_key": []any{}},
			planned: []string{}, warning: true, puts: 2, active: "key-b",
		},
		"rotation, associated_key keeps the key before": {
			before:  map[string]any{"active_encryption_key": "key-a"},
			after:   map[string]any{"active_encryption_key": "key-b", "associated_key": []any{"key-a"}},
			planned: []string{"key-a"}, puts: 1, active: "key-b", associated: []string{"key-a"},
		},
		"rotation, associated_key without the key before": {
			before:  map[string]any{"active_encryption_key": "key-a", "associated_key": []any{"key-x"}},
			after:   map[string]any{"active_encryption_key": "key-b", "associated_key": []any{"key-c"}},
			planned: []string{"key-c"}, warning: true, puts: 2, active: "key-b", associated: []string{"key-c"},
		},
		"removal, associated_key left out": {
			before:  map[string]any{"active_encryption_key": "key-a"},
			after:   map[string]any{},
			planned: []string{"key-a"}, puts: 1, associated: []string{"key-a"},
		},
		"removal, associated_key = []": {
			before:  map[string]any{"active_encryption_key": "key-a"},
			after:   map[string]any{"associated_key": []any{}},
			planned: []string{}, warning: true, puts: 2,
		},
		"first active key": {
			before: map[string]any{}, after: map[string]any{"active_encryption_key": "key-a"},
			puts: 1, active: "key-a",
		},
		"active key unchanged": {
			before:  map[string]any{"active_encryption_key": "key-a"},
			after:   map[string]any{"active_encryption_key": "key-a", "comment": "Offsite"},
			puts:    1,
			active:  "key-a",
			planned: nil,
		},
		"associated_key added": {
			before:  map[string]any{"active_encryption_key": "key-a"},
			after:   map[string]any{"active_encryption_key": "key-a", "associated_key": []any{"key-old"}},
			planned: []string{"key-old"}, puts: 1, active: "key-a", associated: []string{"key-old"},
		},
		"associated_key = [] on a job without any": {
			before:  map[string]any{"active_encryption_key": "key-a"},
			after:   map[string]any{"active_encryption_key": "key-a", "associated_key": []any{}},
			planned: []string{}, active: "key-a",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, fake, syncs, _ := newSyncKeysHarness(t)
			inst := h.create(t, "pbs_sync_job", pushJobConfig(t, h, tc.before))
			config := pushJobConfig(t, h, tc.after)

			plan := h.plan(t, "pbs_sync_job", inst, config)
			requireNoProtocolErrors(t, plan.Diagnostics)
			if got := hasProtocolWarning(plan.Diagnostics, "Previous encryption key dropped"); got != tc.warning {
				t.Errorf("warning %v, want %v: %v", got, tc.warning, plan.Diagnostics)
			}
			planned := h.decodeResource(t, "pbs_sync_job", plan.PlannedState)
			if tc.planned == nil {
				if !isNullAt(t, planned, "associated_key") {
					t.Errorf("associated_key planned as %s, want null", valueAt(t, planned, "associated_key"))
				}
			} else if got := setStringsAt(t, planned, "associated_key"); !slices.Equal(got, tc.planned) {
				t.Errorf("associated_key planned as %v, want %v", got, tc.planned)
			}

			skip := len(fake.routes())
			inst = h.update(t, inst, config)
			puts := formsSince(fake, "PUT /config/sync/push-offsite", skip)
			if len(puts) != tc.puts {
				t.Errorf("%d PUTs, want %d: %v", len(puts), tc.puts, puts)
			}
			if tc.before["active_encryption_key"] == tc.after["active_encryption_key"] {
				for _, put := range puts {
					if put.Has("active-encryption-key") {
						t.Errorf("PUT %v sends the active key, which did not change", put)
					}
				}
			}
			if active, associated := fakeJobKeys(t, syncs, "push-offsite"); active != tc.active || !slices.Equal(associated, tc.associated) {
				t.Errorf("PBS holds %q, %v, want %q, %v", active, associated, tc.active, tc.associated)
			}

			replan := h.plan(t, "pbs_sync_job", inst, config)
			requireNoProtocolErrors(t, replan.Diagnostics)
			if got := h.decodeResource(t, "pbs_sync_job", replan.PlannedState); !got.Equal(inst.state) {
				diffs, _ := got.Diff(inst.state)
				t.Errorf("plan after apply changes %v", diffs)
			}
			if refreshed := h.refresh(t, inst); !refreshed.state.Equal(inst.state) {
				diffs, _ := refreshed.state.Diff(inst.state)
				t.Errorf("refresh changes %v", diffs)
			}
		})
	}
}

// A new owner makes PBS check every associated key the update leaves out as
// an active key, which fails for an archived one; the provider sends them
// along, and PBS then lets archived keys be.
func TestSyncJobKeysOwnerChange(t *testing.T) {
	for name, keys := range map[string]any{
		"associated_key set":      []any{"key-old"},
		"associated_key left out": nil,
	} {
		t.Run(name, func(t *testing.T) {
			h, fake, syncs, _ := newSyncKeysHarness(t)
			// PBS does not check the associated keys of a push job it creates.
			inst := h.create(t, "pbs_sync_job", pushJobConfig(t, h, map[string]any{
				"active_encryption_key": "key-a", "associated_key": []any{"key-old"},
			}))
			err := fake.configured(t).client.UpdateSyncJob(context.Background(), "push-offsite", url.Values{"owner": {"sync@pbs"}})
			if err == nil || !strings.Contains(err.Error(), "no such key or cannot access key 'key-old'") {
				t.Fatalf("a change of the owner alone = %v, want the archived key refused", err)
			}

			inst = h.update(t, inst, pushJobConfig(t, h, map[string]any{
				"active_encryption_key": "key-a", "associated_key": keys, "owner": "sync@pbs",
			}))
			put := fake.lastCall(t, "PUT /config/sync/push-offsite").form
			if put.Get("owner") != "sync@pbs" || !slices.Equal(put["associated-key"], []string{"key-old"}) || put.Has("active-encryption-key") {
				t.Errorf("PUT form = %v, want the owner and the associated keys", put)
			}
			job, _ := syncs.syncJob("push-offsite")
			if active, associated := fakeJobKeys(t, syncs, "push-offsite"); job["owner"] != "sync@pbs" || active != "key-a" ||
				!slices.Equal(associated, []string{"key-old"}) {
				t.Errorf("job = %v", job)
			}
			if got := setStringsAt(t, inst.state, "associated_key"); !slices.Equal(got, []string{"key-old"}) {
				t.Errorf("associated_key = %v", got)
			}
		})
	}
}

// "no such key or cannot access key" reads like a missing job, but the job
// is there: the update fails with what the key needs, and creates nothing.
func TestSyncJobKeysRefusedOnUpdate(t *testing.T) {
	h, fake, syncs, _ := newSyncKeysHarness(t)
	inst := h.create(t, "pbs_sync_job", pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-a"}))
	for _, key := range []string{"ghost", "key-old"} {
		config := pushJobConfig(t, h, map[string]any{"active_encryption_key": key})
		plan := h.plan(t, "pbs_sync_job", inst, config)
		requireNoProtocolErrors(t, plan.Diagnostics)
		applied := h.apply(t, "pbs_sync_job", inst, config, plan)
		requireProtocolErrorContaining(t, applied.Diagnostics, "PBS cannot use a sync encryption key of the job")
		requireProtocolErrorContaining(t, applied.Diagnostics, "no such key or cannot access key '"+key+"'")
		if n := fake.count("POST /config/sync"); n != 1 {
			t.Errorf("%d creates, want the first alone", n)
		}
		if active, associated := fakeJobKeys(t, syncs, "push-offsite"); active != "key-a" || len(associated) != 0 {
			t.Errorf("PBS holds %q, %v, want the job as it was", active, associated)
		}
	}
}

// Rotating a job's key and destroying the key before in one apply works only
// when associated_key drops it: Terraform updates the job first, and PBS
// keeps the key before associated, which then stops its deletion.
func TestSyncJobKeyRotationWithKeyDestroyed(t *testing.T) {
	for name, tc := range map[string]struct {
		associated any
		wantError  string
	}{
		"associated_key left out": {nil, "encryption key in use by sync job: 'push-offsite'"},
		"associated_key = []":     {[]any{}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			h, _, _, keys := newKeysHarness(t)
			oldKey := h.create(t, "pbs_sync_encryption_key", keyConfig(t, h, map[string]any{"id": "key-a"}))
			h.create(t, "pbs_sync_encryption_key", keyConfig(t, h, map[string]any{"id": "key-b"}))
			job := h.create(t, "pbs_sync_job", pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-a"}))

			h.update(t, job, pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-b", "associated_key": tc.associated}))
			resp := syncDestroyResponse(t, h, oldKey)
			stored, exists := keys.key("key-a")
			if tc.wantError == "" {
				requireNoProtocolErrors(t, resp.Diagnostics)
				if exists {
					t.Errorf("key-a still exists: %v", stored)
				}
				return
			}
			requireProtocolErrorContaining(t, resp.Diagnostics, tc.wantError)
			if !exists || stored["archived-at"] != nil {
				t.Errorf("key-a = %v, exists %v, want it in use still", stored, exists)
			}
		})
	}
}

// A job's keys import with it, and the job data sources show them.
func TestSyncJobKeysImportAndDataSources(t *testing.T) {
	h, _, syncs, _ := newSyncKeysHarness(t)
	syncs.addSyncJob("push-offsite", fakeProperties{"store": "store1", "remote": "offsite", "remote-store": "store2",
		"sync-direction": "push", "active-encryption-key": "key-b", "associated-key": []string{"key-a"}})
	syncs.addSyncJob("pull-offsite", fakeProperties{"store": "store1", "remote": "offsite", "remote-store": "store3",
		"associated-key": []string{"key-old", "key-a"}})
	syncs.addSyncJob("pull-plain", fakeProperties{"store": "store1", "remote": "offsite", "remote-store": "store4"})

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_sync_job", "push-offsite"),
		"identity": h.importByIdentity(t, "pbs_sync_job", map[string]any{"id": "push-offsite"}),
	} {
		if stringAt(t, inst.state, "active_encryption_key") != "key-b" ||
			!slices.Equal(setStringsAt(t, inst.state, "associated_key"), []string{"key-a"}) {
			t.Errorf("import by %s = %s", name, inst.state)
		}
		planned := h.plan(t, "pbs_sync_job", inst, pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-b"}))
		requireNoProtocolErrors(t, planned.Diagnostics)
		if got := h.decodeResource(t, "pbs_sync_job", planned.PlannedState); !got.Equal(inst.state) {
			diffs, _ := got.Diff(inst.state)
			t.Errorf("plan after import by %s changes %v", name, diffs)
		}
	}

	push := h.readDataSource(t, "pbs_sync_job", h.dataSourceValue(t, "pbs_sync_job", map[string]any{"id": "push-offsite"}))
	if stringAt(t, push, "active_encryption_key") != "key-b" || !slices.Equal(setStringsAt(t, push, "associated_key"), []string{"key-a"}) {
		t.Errorf("pbs_sync_job = %s", push)
	}
	plain := h.readDataSource(t, "pbs_sync_job", h.dataSourceValue(t, "pbs_sync_job", map[string]any{"id": "pull-plain"}))
	if !isNullAt(t, plain, "active_encryption_key") || !isNullAt(t, plain, "associated_key") {
		t.Errorf("pbs_sync_job = %s", plain)
	}
	jobs := h.readDataSource(t, "pbs_sync_jobs", h.dataSourceValue(t, "pbs_sync_jobs", map[string]any{}))
	if lengthAt(t, jobs, "jobs") != 3 || stringAt(t, jobs, "jobs", 0, "id") != "pull-offsite" ||
		!isNullAt(t, jobs, "jobs", 0, "active_encryption_key") ||
		!slices.Equal(setStringsAt(t, jobs, "jobs", 0, "associated_key"), []string{"key-a", "key-old"}) ||
		!isNullAt(t, jobs, "jobs", 1, "associated_key") || stringAt(t, jobs, "jobs", 2, "active_encryption_key") != "key-b" {
		t.Errorf("pbs_sync_jobs = %s", jobs)
	}
}

// With associated_key left out, a rotation leaves the associated keys to
// PBS, which appends the replaced key itself: sending them would make PBS
// check every one of them again. A new owner sends them, so that PBS checks
// them as keys to decrypt with, archived ones included; removing the owner
// checks no key, and sends nothing.
func TestSyncJobKeysWhatUpdatesSend(t *testing.T) {
	h, fake, syncs, _ := newSyncKeysHarness(t)
	syncs.addRemote("offsite", fakeProperties{"host": "pbs2.example.com", "auth-id": "sync@pbs"}, "secret")
	inst := h.create(t, "pbs_sync_job", pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-a"}))
	inst = h.update(t, inst, pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-b"}))

	skip := len(fake.routes())
	inst = h.update(t, inst, pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-c"}))
	forms := formsSince(fake, "PUT /config/sync/push-offsite", skip)
	if len(forms) != 1 || forms[0].Has("associated-key") || forms[0].Get("active-encryption-key") != "key-c" {
		t.Errorf("rotation PUTs = %v, want one with the active key alone", forms)
	}
	if active, associated := fakeJobKeys(t, syncs, "push-offsite"); active != "key-c" || strings.Join(associated, ",") != "key-a,key-b" {
		t.Errorf("PBS holds %s and %v", active, associated)
	}

	skip = len(fake.routes())
	inst = h.update(t, inst, pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-c", "owner": "sync@pbs"}))
	forms = formsSince(fake, "PUT /config/sync/push-offsite", skip)
	if len(forms) != 1 || strings.Join(forms[0]["associated-key"], ",") != "key-a,key-b" {
		t.Errorf("owner PUTs = %v, want the associated keys with the owner", forms)
	}

	skip = len(fake.routes())
	h.update(t, inst, pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-c"}))
	forms = formsSince(fake, "PUT /config/sync/push-offsite", skip)
	if len(forms) != 1 || forms[0].Has("associated-key") {
		t.Errorf("removing the owner PUTs = %v, want no associated keys", forms)
	}
}

// Replacing a job with a new ID creates it with the configured keys only, so
// the plan warns about the keys the old job held that the new one will not.
func TestSyncJobKeysReplacementWarns(t *testing.T) {
	h, _, syncs, _ := newSyncKeysHarness(t)
	syncs.addRemote("offsite", fakeProperties{"host": "pbs2.example.com", "auth-id": "sync@pbs"}, "secret")
	inst := h.create(t, "pbs_sync_job", pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-a"}))
	inst = h.update(t, inst, pushJobConfig(t, h, map[string]any{"active_encryption_key": "key-b"}))

	planned := h.plan(t, "pbs_sync_job", inst, pushJobConfig(t, h, map[string]any{"id": "push-renamed", "active_encryption_key": "key-b"}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "Encryption keys dropped by the replacement")
	requireProtocolWarningContaining(t, planned.Diagnostics, "key-a")

	planned = h.plan(t, "pbs_sync_job", inst, pushJobConfig(t, h, map[string]any{
		"id": "push-renamed", "active_encryption_key": "key-b", "associated_key": []string{"key-a"},
	}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	if hasProtocolWarning(planned.Diagnostics, "Encryption keys dropped") {
		t.Errorf("keeping the keys warns: %v", planned.Diagnostics)
	}
}
