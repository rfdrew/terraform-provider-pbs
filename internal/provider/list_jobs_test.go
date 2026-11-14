package provider

import (
	"slices"
	"testing"
)

func TestPruneAndVerifyJobListResources(t *testing.T) {
	h, fake, _, _ := newSyncHarness(t)
	for _, job := range []map[string]any{
		{"id": "daily-store2", "store": "store2", "schedule": "daily", "keep": map[string]any{"daily": 7}},
		{"id": "hourly-store1", "store": "store1", "schedule": "hourly", "ns": "dept1", "max_depth": 2, "disable": true,
			"keep": map[string]any{"last": 3, "hourly": 24}, "comment": "Keep a day"},
		{"id": "weekly-store1", "store": "store1", "schedule": "sun 02:00", "keep": map[string]any{"weekly": 4}},
	} {
		h.create(t, "pbs_prune_job", h.resourceValue(t, "pbs_prune_job", job))
	}
	for _, job := range []map[string]any{
		{"id": "verify-store1", "store": "store1"},
		{"id": "verify-store2", "store": "store2", "schedule": "sat 03:00", "ignore_verified": true, "outdated_after": 30,
			"comment": "Weekly"},
	} {
		h.create(t, "pbs_verify_job", h.resourceValue(t, "pbs_verify_job", job))
	}

	// Without resources, each list costs one call; store selects the jobs
	// of one datastore.
	for _, tc := range []struct {
		typeName, route string
		config          map[string]any
		want            []string
	}{
		{"pbs_prune_job", "GET /config/prune", nil, []string{"daily-store2", "hourly-store1 — Keep a day", "weekly-store1"}},
		{"pbs_prune_job", "GET /config/prune", map[string]any{"store": "store1"}, []string{"hourly-store1 — Keep a day", "weekly-store1"}},
		{"pbs_prune_job", "GET /config/prune", map[string]any{"store": "store3"}, nil},
		{"pbs_verify_job", "GET /config/verify", nil, []string{"verify-store1", "verify-store2 — Weekly"}},
		{"pbs_verify_job", "GET /config/verify", map[string]any{"store": "store2"}, []string{"verify-store2 — Weekly"}},
	} {
		before := len(fake.routes())
		results := h.listedObjects(t, tc.typeName, listRequest{config: tc.config})
		if got := resultDisplayNames(results); !slices.Equal(got, tc.want) {
			t.Fatalf("%s with %v: listed %q, want %q", tc.typeName, tc.config, got, tc.want)
		}
		if got := fake.routes()[before:]; !slices.Equal(got, []string{tc.route}) {
			t.Fatalf("%s: calls %q", tc.typeName, got)
		}
	}

	// With resources, each is what importing it gives, and the
	// configuration generated from it plans nothing.
	for typeName, count := range map[string]int{"pbs_prune_job": 3, "pbs_verify_job": 2} {
		results := h.listedObjects(t, typeName, listRequest{includeResource: true})
		if len(results) != count {
			t.Fatalf("listed %d of %s with resources", len(results), typeName)
		}
		for _, result := range results {
			h.requireListedLikeImport(t, typeName, result)
		}
	}
	prune := h.listedObjects(t, "pbs_prune_job", listRequest{config: map[string]any{"store": "store1"}, includeResource: true})
	if hourly := prune[0].resource; stringAt(t, hourly, "ns") != "dept1" || !boolAt(t, hourly, "disable") ||
		int64At(t, hourly, "keep", "hourly") != 24 || int64At(t, hourly, "max_depth") != 2 {
		t.Fatalf("listed hourly-store1: %s", hourly)
	}
	verify := h.listedObjects(t, "pbs_verify_job", listRequest{config: map[string]any{"store": "store2"}, includeResource: true})
	if weekly := verify[0].resource; !boolAt(t, weekly, "ignore_verified") || int64At(t, weekly, "outdated_after") != 30 {
		t.Fatalf("listed verify-store2: %s", weekly)
	}
}

// A job that disappears between the listing and its read is left out
// without an error, and one PBS will not show with a warning.
func TestPruneJobListResourceJobGoneOrUnreadable(t *testing.T) {
	h, fake, _, datastores := newSyncHarness(t)
	for _, id := range []string{"gone", "hidden", "kept"} {
		datastores.addPruneJob(id, fakeProperties{"store": "store1", "schedule": "daily", "keep-last": int64(1)})
	}
	fake.reply("GET /config/prune/gone", 400, "no such prune 'gone'")
	fake.reply("GET /config/prune/hidden", 403, "permission check failed")
	var listed []string
	warned := false
	for _, result := range h.listResources(t, "pbs_prune_job", listRequest{includeResource: true}) {
		requireNoProtocolErrors(t, result.diagnostics)
		if result.identity.IsNull() {
			requireProtocolWarningContaining(t, result.diagnostics, "Left out hidden: Unable to read PBS prune job")
			warned = true
			continue
		}
		listed = append(listed, stringAt(t, result.identity, "id"))
	}
	if !warned || !slices.Equal(listed, []string{"kept"}) {
		t.Fatalf("listed %q, warned %v", listed, warned)
	}
}

func TestJobListResourcesListFails(t *testing.T) {
	fake := newFakePBS()
	for _, route := range []string{"GET /config/prune", "GET /config/verify", "GET /config/sync"} {
		fake.reply(route, 500, "the configuration is broken")
	}
	h := newProtocolHarness(t, fake)
	for typeName, want := range map[string]string{
		"pbs_prune_job":  "Unable to list PBS prune jobs",
		"pbs_verify_job": "Unable to list PBS verify jobs",
		"pbs_sync_job":   "Unable to list PBS sync jobs",
	} {
		results := h.listResources(t, typeName, listRequest{})
		if len(results) != 1 {
			t.Fatalf("%s: got %d results", typeName, len(results))
		}
		requireProtocolErrorContaining(t, results[0].diagnostics, want)
	}
}

func TestSyncJobListResource(t *testing.T) {
	h, fake, syncs, _ := newSyncHarness(t)
	syncs.addRemote("offsite", fakeProperties{"host": "pbs2.example.com", "auth-id": "sync@pbs!offsite"}, "secret")
	h.create(t, "pbs_sync_job", pullJobConfig(t, h, map[string]any{
		"ns": "site-a", "remote_ns": "dept1", "max_depth": 3, "schedule": "hourly", "owner": "sync@pbs",
		"remove_vanished": true, "group_filter": []any{"type:vm", "exclude:group:vm/100"}, "rate_in": "10MiB",
		"comment": "Offsite copy",
	}))
	h.create(t, "pbs_sync_job", h.resourceValue(t, "pbs_sync_job", map[string]any{
		"id": "push-offsite", "sync_direction": "push", "store": "store1", "remote": "offsite", "remote_store": "store2",
		"rate_out": "1.5 GB",
	}))
	h.create(t, "pbs_sync_job", h.resourceValue(t, "pbs_sync_job", map[string]any{
		"id": "local-copy", "store": "store3", "remote_store": "store1",
	}))

	// Without resources, the list costs one call, for jobs of both
	// directions, and names every job.
	before := len(fake.routes())
	results := h.listedObjects(t, "pbs_sync_job", listRequest{})
	if got, want := resultDisplayNames(results), []string{"local-copy", "pull-offsite — Offsite copy", "push-offsite"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	if got := fake.routes()[before:]; !slices.Equal(got, []string{"GET /config/sync"}) ||
		fake.lastCall(t, "GET /config/sync").query.Get("sync-direction") != "all" {
		t.Fatalf("calls %q, query %v", got, fake.lastCall(t, "GET /config/sync").query)
	}

	// store and sync_direction select jobs, alone or together.
	for _, tc := range []struct {
		config map[string]any
		want   []string
	}{
		{map[string]any{"store": "store1"}, []string{"pull-offsite", "push-offsite"}},
		{map[string]any{"sync_direction": "pull"}, []string{"local-copy", "pull-offsite"}},
		{map[string]any{"sync_direction": "push"}, []string{"push-offsite"}},
		{map[string]any{"store": "store3", "sync_direction": "push"}, nil},
	} {
		results := h.listedObjects(t, "pbs_sync_job", listRequest{config: tc.config})
		if got := listedIdentities(t, results, "id"); !slices.Equal(got, tc.want) {
			t.Fatalf("with %v: listed %q, want %q", tc.config, got, tc.want)
		}
	}

	// With resources, each is what importing it gives, and the
	// configuration generated from it plans nothing.
	results = h.listedObjects(t, "pbs_sync_job", listRequest{includeResource: true})
	if len(results) != 3 {
		t.Fatalf("listed %d sync jobs with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_sync_job", result)
	}
	local, pull, push := results[0].resource, results[1].resource, results[2].resource
	if !isNullAt(t, local, "remote") || stringAt(t, local, "sync_direction") != "pull" {
		t.Fatalf("listed local-copy: %s", local)
	}
	if stringAt(t, pull, "remote_ns") != "dept1" || !boolAt(t, pull, "remove_vanished") || lengthAt(t, pull, "group_filter") != 2 {
		t.Fatalf("listed pull-offsite: %s", pull)
	}
	if stringAt(t, push, "sync_direction") != "push" || isNullAt(t, push, "rate_out") {
		t.Fatalf("listed push-offsite: %s", push)
	}
}

func TestSyncJobListResourceValidation(t *testing.T) {
	h, _, _, _ := newSyncHarness(t)
	requireProtocolErrorContaining(t, listConfigDiagnostics(t, h, "pbs_sync_job", map[string]any{"sync_direction": "both"}),
		"value must be one of")
	requireProtocolErrorContaining(t, listConfigDiagnostics(t, h, "pbs_prune_job", map[string]any{"store": "x"}),
		"string length must be between 3 and 32")
}
