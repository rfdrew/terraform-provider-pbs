package provider

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The S3 endpoint and the bucket of the tests' datastores on S3.
const (
	s3StoreEndpoint = "minio"
	s3StoreBucket   = "pbs-backups"
)

// newS3DatastoreHarness is newDatastoreHarness with an S3 endpoint that
// reaches a bucket. version, when set, is what GET /version answers.
func newS3DatastoreHarness(t *testing.T, version ...string) (*protocolHarness, *fakePBS, *fakeDatastores) {
	t.Helper()
	h, fake, datastores := newDatastoreHarness(t, version...)
	datastores.addS3Bucket(s3StoreEndpoint, s3StoreBucket)
	return h, fake, datastores
}

// s3StoreBackend is a backend on the tests' endpoint; maxCacheSize nil leaves
// max_cache_size out.
func s3StoreBackend(client, bucket string, maxCacheSize any) map[string]any {
	return map[string]any{"type": "s3", "client": client, "bucket": bucket, "max_cache_size": maxCacheSize}
}

// s3StoreAttributes are the attributes of datastore s3store on the tests'
// bucket, with extra ones added or replacing them.
func s3StoreAttributes(extra map[string]any) map[string]any {
	attrs := map[string]any{
		"name":    "s3store",
		"path":    "/mnt/datastore/s3-cache",
		"backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, nil),
	}
	maps.Copy(attrs, extra)
	return attrs
}

// datastoreDiagnosticsMention reports whether a diagnostic's summary or
// detail contains text.
func datastoreDiagnosticsMention(diags []*tfprotov6.Diagnostic, text string) bool {
	return slices.ContainsFunc(diags, func(d *tfprotov6.Diagnostic) bool {
		return strings.Contains(d.Summary, text) || strings.Contains(d.Detail, text)
	})
}

// A datastore on S3 is created with its backend, which PBS stores as sent,
// and with the thresholds and reset schedule of its request counters, which
// change in place; destroying it without destroy_data deletes only its
// in-use mark in the bucket.
func TestDatastoreResourceS3Lifecycle(t *testing.T) {
	h, fake, datastores := newS3DatastoreHarness(t)
	attrs := s3StoreAttributes(map[string]any{
		"backend":                 s3StoreBackend(s3StoreEndpoint, s3StoreBucket, "64GiB"),
		"notification_thresholds": map[string]any{"s3_put": 100000, "s3_get": 5000, "s3_upload": "500GiB"},
		"counter_reset_schedule":  "monthly",
	})
	config := h.resourceValue(t, "pbs_datastore", attrs)
	inst := h.create(t, "pbs_datastore", config)

	const backend = "bucket=pbs-backups,client=minio,max-cache-size=64GiB,type=s3"
	created := fake.lastCall(t, "POST /config/datastore")
	for name, want := range map[string]string{
		"path":                    "/mnt/datastore/s3-cache",
		"backend":                 backend,
		"notification-thresholds": "s3-get=5000,s3-put=100000,s3-upload=500GiB",
		"counter-reset-schedule":  "monthly",
	} {
		if got := created.form.Get(name); got != want {
			t.Errorf("POST %s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"overwrite-in-use", "reuse-datastore", "maintenance-mode", "backing-device"} {
		if _, sent := created.form[name]; sent {
			t.Errorf("POST sent %s: %v", name, created.form)
		}
	}
	if stored, _ := datastores.datastore("s3store"); stored["backend"] != backend {
		t.Errorf("stored backend = %v", stored["backend"])
	}
	if host, marked := datastores.s3Marker(s3StoreBucket, "s3store"); !marked || host != fakeTaskNode {
		t.Errorf("in-use mark = %q, %v, want this host", host, marked)
	}
	if stringAt(t, inst.state, "backend", "type") != "s3" || stringAt(t, inst.state, "backend", "client") != s3StoreEndpoint ||
		stringAt(t, inst.state, "backend", "bucket") != s3StoreBucket || stringAt(t, inst.state, "backend", "max_cache_size") != "64GiB" ||
		stringAt(t, inst.state, "mount_status") != pbsclient.MountStatusNonRemovable || boolAt(t, inst.state, "overwrite_in_use") ||
		boolAt(t, inst.state, "reuse_datastore") || !isNullAt(t, inst.state, "maintenance_mode") {
		t.Errorf("state = %s", inst.state)
	}
	if int64At(t, inst.state, "notification_thresholds", "s3_put") != 100000 ||
		stringAt(t, inst.state, "notification_thresholds", "s3_upload") != "500GiB" ||
		!isNullAt(t, inst.state, "notification_thresholds", "s3_head") || stringAt(t, inst.state, "counter_reset_schedule") != "monthly" {
		t.Errorf("state = %s", inst.state)
	}

	// A plan against the unchanged configuration changes nothing.
	replan := h.plan(t, "pbs_datastore", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_datastore", replan.PlannedState); !planned.Equal(inst.state) || len(replan.RequiresReplace) != 0 {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v, replacing for %v", diffs, replan.RequiresReplace)
	}

	// The thresholds and the schedule change in place, the thresholds
	// written as a whole, their keys sorted.
	attrs["notification_thresholds"] = map[string]any{"s3_put": 200000, "s3_delete": 0, "s3_download": "1TiB"}
	attrs["counter_reset_schedule"] = "sat 05:00"
	config = h.resourceValue(t, "pbs_datastore", attrs)
	if planned := h.plan(t, "pbs_datastore", inst, config); len(planned.RequiresReplace) != 0 {
		t.Errorf("changing the thresholds replaces the datastore: %v", planned.RequiresReplace)
	}
	inst = h.update(t, inst, config)
	updated := fake.lastCall(t, "PUT /config/datastore/s3store")
	if got := updated.form.Get("notification-thresholds"); got != "s3-delete=0,s3-download=1TiB,s3-put=200000" {
		t.Errorf("PUT notification-thresholds = %q", got)
	}
	if got := updated.form.Get("counter-reset-schedule"); got != "sat 05:00" || len(updated.form) != 2 {
		t.Errorf("PUT form = %v, want the thresholds and the schedule only", updated.form)
	}
	if int64At(t, inst.state, "notification_thresholds", "s3_delete") != 0 || !isNullAt(t, inst.state, "notification_thresholds", "s3_get") ||
		stringAt(t, inst.state, "notification_thresholds", "s3_download") != "1TiB" {
		t.Errorf("state = %s", inst.state)
	}

	// Leaving them out deletes them.
	delete(attrs, "notification_thresholds")
	delete(attrs, "counter_reset_schedule")
	inst = h.update(t, inst, h.resourceValue(t, "pbs_datastore", attrs))
	updated = fake.lastCall(t, "PUT /config/datastore/s3store")
	if got := strings.Join(updated.form["delete"], ","); got != "counter-reset-schedule,notification-thresholds" || len(updated.form) != 1 {
		t.Errorf("PUT form = %v, want the two deletions only", updated.form)
	}
	if stored, _ := datastores.datastore("s3store"); stored["notification-thresholds"] != nil || stored["counter-reset-schedule"] != nil {
		t.Errorf("stored datastore = %v", stored)
	}
	if !isNullAt(t, inst.state, "notification_thresholds") || !isNullAt(t, inst.state, "counter_reset_schedule") {
		t.Errorf("state = %s", inst.state)
	}

	// Without destroy_data, destroying deletes the in-use mark alone: the
	// backups stay in the bucket, and the local cache in its directory.
	datastores.addS3Backups(s3StoreBucket, "s3store")
	h.destroy(t, inst)
	if deleted := fake.lastCall(t, "DELETE /config/datastore/s3store"); deleted.query.Has("destroy-data") {
		t.Errorf("DELETE query = %v", deleted.query)
	}
	if _, exists := datastores.datastore("s3store"); exists {
		t.Error("the datastore still exists")
	}
	if _, marked := datastores.s3Marker(s3StoreBucket, "s3store"); marked {
		t.Error("the in-use mark is still in the bucket")
	}
	if !datastores.hasS3Backups(s3StoreBucket, "s3store") || !datastores.hasChunkStore("/mnt/datastore/s3-cache") {
		t.Error("destroying without destroy_data deleted the backups or the local cache")
	}
}

// PBS cannot change a datastore's backend, so any change of it, putting a
// datastore on S3 or taking one off it replaces the datastore — but not a new
// spelling of the same max_cache_size, which PBS stores as written.
func TestDatastoreResourceS3BackendChangeReplaces(t *testing.T) {
	h, fake, _ := newS3DatastoreHarness(t)
	onS3 := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, "64GiB"),
	})))
	inDirectory := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/datastore/store1",
	}))

	for name, tc := range map[string]struct {
		prior *resourceInstance
		attrs map[string]any
	}{
		"bucket":                 {onS3, map[string]any{"backend": s3StoreBackend(s3StoreEndpoint, "other-bucket", "64GiB")}},
		"client":                 {onS3, map[string]any{"backend": s3StoreBackend("ceph", s3StoreBucket, "64GiB")}},
		"max_cache_size changed": {onS3, map[string]any{"backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, "128GiB")}},
		"max_cache_size removed": {onS3, map[string]any{"backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, nil)}},
		"backend removed":        {onS3, map[string]any{"backend": nil, "path": "/mnt/datastore/s3store-dir"}},
		"backend added": {inDirectory, map[string]any{
			"name": "store1", "path": "/mnt/datastore/store1-cache", "backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, nil),
		}},
	} {
		t.Run(name, func(t *testing.T) {
			// reuse_datastore keeps the replacement in the same directory
			// from failing the plan.
			attrs := s3StoreAttributes(tc.attrs)
			attrs["reuse_datastore"] = true
			planned := h.plan(t, "pbs_datastore", tc.prior, h.resourceValue(t, "pbs_datastore", attrs))
			requireNoProtocolErrors(t, planned.Diagnostics)
			replaced := false
			for _, p := range planned.RequiresReplace {
				replaced = replaced || strings.Contains(p.String(), "backend")
			}
			if !replaced {
				t.Errorf("RequiresReplace = %v, want backend", planned.RequiresReplace)
			}
		})
	}

	// Moving a datastore to S3 or off it in the same directory fails the
	// plan, reuse_datastore or not: PBS would empty the chunk store, or the
	// new datastore could not use it.
	for name, tc := range map[string]struct {
		prior *resourceInstance
		attrs map[string]any
	}{
		"backend removed": {onS3, map[string]any{"backend": nil}},
		"backend added": {inDirectory, map[string]any{
			"name": "store1", "path": "/mnt/datastore/store1", "backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, nil),
		}},
	} {
		for _, reuse := range []bool{false, true} {
			attrs := s3StoreAttributes(tc.attrs)
			attrs["reuse_datastore"] = reuse
			planned := h.plan(t, "pbs_datastore", tc.prior, h.resourceValue(t, "pbs_datastore", attrs))
			requireProtocolErrorContaining(t, planned.Diagnostics, "Moving the datastore to or from S3 needs another path")
			if datastoreDiagnosticsMention(planned.Diagnostics, "keeping the backups") {
				t.Errorf("%s, reuse %v: the plan advises reuse_datastore: %v", name, reuse, planned.Diagnostics)
			}
		}
	}

	// The same size in another spelling is no change.
	for _, spelling := range []string{"64 GiB", "65536MiB"} {
		planned := h.plan(t, "pbs_datastore", onS3, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
			"backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, spelling),
		})))
		requireNoProtocolErrors(t, planned.Diagnostics)
		if len(planned.RequiresReplace) != 0 {
			t.Errorf("max_cache_size %q: RequiresReplace = %v", spelling, planned.RequiresReplace)
		}
	}
	// Applied, it sends nothing, and state keeps the configuration's
	// spelling.
	calls := len(fake.routes())
	onS3 = h.update(t, onS3, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, "64 GiB"),
	})))
	for _, route := range fake.routes()[calls:] {
		if !strings.HasPrefix(route, "GET ") {
			t.Errorf("a new spelling of max_cache_size sent %s", route)
		}
	}
	if got := stringAt(t, onS3.state, "backend", "max_cache_size"); got != "64 GiB" {
		t.Errorf("state max_cache_size = %q, want the configuration's spelling", got)
	}
}

// Replacing a datastore on S3 warns what becomes of its backups in the
// bucket: destroy_data deletes them, and a datastore of another name does
// not find them. In the same directory, without reuse_datastore, the plan
// fails as for any datastore, and so it does in another directory when the
// new datastore would find the backups, by its name and backend.
func TestDatastoreResourceS3ReplacePlanChecks(t *testing.T) {
	h, _, _ := newS3DatastoreHarness(t)
	inst := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", s3StoreAttributes(nil)))
	const startsEmpty, deletesBackups = "The new datastore starts without the backups", "Replacing the datastore deletes its backups in the bucket"

	planned := h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{"name": "s3store2"})))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Renaming the datastore needs reuse_datastore")
	requireProtocolErrorContaining(t, planned.Diagnostics, "under s3store2/, not those of \"s3store\"")
	if datastoreDiagnosticsMention(planned.Diagnostics, "reads its backups from the bucket again") {
		t.Errorf("a rename is told it reads its backups again: %v", planned.Diagnostics)
	}
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, "128GiB"),
	})))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Replacing the datastore in place needs reuse_datastore")
	requireProtocolErrorContaining(t, planned.Diagnostics, "which then reads its backups from the bucket again")
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"backend": s3StoreBackend(s3StoreEndpoint, "other-bucket", nil),
	})))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Replacing the datastore in place needs reuse_datastore")
	requireProtocolErrorContaining(t, planned.Diagnostics, "or change its backend")

	// A new name, with reuse_datastore, plans, and warns that the backups
	// stay under the old name.
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"name": "s3store2", "reuse_datastore": true,
	})))
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, startsEmpty)
	requireProtocolWarningContaining(t, planned.Diagnostics, "under s3store/")
	requireProtocolWarningContaining(t, planned.Diagnostics, "deletes its jobs and ACL entries")

	// In a new directory, the datastore keeps its name and backend, and so
	// finds its backups, which it must reuse: created empty, its garbage
	// collection would delete their chunks.
	moved := s3StoreAttributes(map[string]any{"path": "/mnt/datastore/s3-cache2"})
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", moved))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Replacing the datastore on S3 needs reuse_datastore")
	requireProtocolErrorContaining(t, planned.Diagnostics, "its first garbage collection deletes their chunks")
	moved["reuse_datastore"] = true
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", moved))
	requireNoProtocolErrors(t, planned.Diagnostics)
	if datastoreDiagnosticsMention(planned.Diagnostics, startsEmpty) || datastoreDiagnosticsMention(planned.Diagnostics, deletesBackups) {
		t.Errorf("moving the cache warns about the backups: %v", planned.Diagnostics)
	}
	// So it does with another cache size, or through another endpoint,
	// which may reach the same object store.
	for name, backend := range map[string]map[string]any{
		"max_cache_size": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, "128GiB"),
		"client":         s3StoreBackend("ceph", s3StoreBucket, nil),
	} {
		planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
			"path": "/mnt/datastore/s3-cache2", "backend": backend,
		})))
		requireProtocolErrorContaining(t, planned.Diagnostics, "Replacing the datastore on S3 needs reuse_datastore")
		if datastoreDiagnosticsMention(planned.Diagnostics, startsEmpty) {
			t.Errorf("a new %s is told the datastore starts without the backups: %v", name, planned.Diagnostics)
		}
	}

	// With destroy_data in state, any replacement deletes them, and the
	// plan says so.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{"destroy_data": true})))
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"path": "/mnt/datastore/s3-cache2", "destroy_data": true,
	})))
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, deletesBackups)
	requireProtocolWarningContaining(t, planned.Diagnostics, "every object under s3store/ in its bucket")
	if datastoreDiagnosticsMention(planned.Diagnostics, startsEmpty) {
		t.Errorf("plan = %v, want the warning that the backups are deleted alone", planned.Diagnostics)
	}
}

// The guards that keep the backups take a value known only during apply for
// the worst it may turn out to be — the same bucket, the same name, no
// reuse_datastore, another backend in the same directory —, as nothing
// checks them again during apply.
func TestDatastoreResourceS3UnknownValuesPlanChecks(t *testing.T) {
	h, _, _ := newS3DatastoreHarness(t)
	onS3 := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", s3StoreAttributes(nil)))
	inDirectory := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/datastore/store1",
	}))
	const needsKnown, startsEmpty = "Replacing the datastore on S3 needs known values", "The new datastore starts without the backups"
	const mayStartEmpty, adviseReuse = "The new datastore may start without the backups", "set reuse_datastore = true"
	unknownBucket := map[string]any{"type": "s3", "client": s3StoreEndpoint, "bucket": tfUnknown, "max_cache_size": nil}
	moved := func(extra map[string]any) tftypes.Value {
		attrs := s3StoreAttributes(map[string]any{"path": "/mnt/datastore/s3-cache2"})
		maps.Copy(attrs, extra)
		return h.resourceValue(t, "pbs_datastore", attrs)
	}

	// Moved to another directory without reuse_datastore, a datastore on S3
	// whose bucket, backend, name or reuse_datastore is not known yet may
	// start without its backups and have its garbage collection delete them.
	for name, tc := range map[string]struct {
		extra   map[string]any
		unknown string
		reuse   bool // whether the plan may advise reuse_datastore
	}{
		"bucket":          {map[string]any{"backend": unknownBucket}, "whose backend.bucket Terraform", true},
		"backend":         {map[string]any{"backend": tfUnknown}, "whose backend Terraform", false},
		"name":            {map[string]any{"name": tfUnknown}, "whose name Terraform", true},
		"reuse_datastore": {map[string]any{"reuse_datastore": tfUnknown}, "whose reuse_datastore Terraform", false},
		"name and bucket": {map[string]any{"name": tfUnknown, "backend": unknownBucket}, "whose name, backend.bucket Terraform", true},
	} {
		planned := h.plan(t, "pbs_datastore", onS3, moved(tc.extra))
		requireProtocolErrorContaining(t, planned.Diagnostics, needsKnown)
		requireProtocolErrorContaining(t, planned.Diagnostics, tc.unknown)
		requireProtocolErrorContaining(t, planned.Diagnostics, "its first garbage collection deletes their chunks")
		if advises := datastoreDiagnosticsMention(planned.Diagnostics, adviseReuse); advises != tc.reuse {
			t.Errorf("%s: the plan advises reuse_datastore: %v, want %v: %v", name, advises, tc.reuse, planned.Diagnostics)
		}
		if datastoreDiagnosticsMention(planned.Diagnostics, startsEmpty) || datastoreDiagnosticsMention(planned.Diagnostics, mayStartEmpty) {
			t.Errorf("%s: the plan fails and warns: %v", name, planned.Diagnostics)
		}
	}

	// Advising reuse_datastore, the plan says what it keeps the backups with.
	planned := h.plan(t, "pbs_datastore", onS3, moved(map[string]any{"name": tfUnknown}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "keeps the backups if the name and bucket are the same")
	planned = h.plan(t, "pbs_datastore", onS3, moved(map[string]any{"backend": unknownBucket}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "keeps the backups if the bucket is the same")
	// A path not known yet changes nothing for the backups, which stay in
	// the bucket wherever the cache is: the plan fails as with a known path.
	planned = h.plan(t, "pbs_datastore", onS3, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{"path": tfUnknown})))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Replacing the datastore on S3 needs reuse_datastore")
	requireProtocolErrorContaining(t, planned.Diagnostics, "same name and bucket, in a directory known only during apply.")

	// With reuse_datastore, it plans, warning that the backups are kept only
	// with the same name and bucket.
	for name, extra := range map[string]map[string]any{
		"bucket":  {"backend": unknownBucket},
		"backend": {"backend": tfUnknown},
		"name":    {"name": tfUnknown},
	} {
		extra["reuse_datastore"] = true
		planned = h.plan(t, "pbs_datastore", onS3, moved(extra))
		requireNoProtocolErrors(t, planned.Diagnostics)
		requireProtocolWarningContaining(t, planned.Diagnostics, mayStartEmpty)
		if datastoreDiagnosticsMention(planned.Diagnostics, startsEmpty) {
			t.Errorf("%s: the plan says the datastore starts without the backups: %v", name, planned.Diagnostics)
		}
	}
	// A new name never finds them, whatever the bucket.
	planned = h.plan(t, "pbs_datastore", onS3, moved(map[string]any{"name": "s3store2", "backend": unknownBucket}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, startsEmpty)

	// In the same directory, the bucket not known yet, the plan fails as for
	// any replacement in place, and says the backups are read again only from
	// the same bucket.
	planned = h.plan(t, "pbs_datastore", onS3, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"backend": unknownBucket,
	})))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Replacing the datastore in place needs reuse_datastore")
	requireProtocolErrorContaining(t, planned.Diagnostics, "if the bucket, known only during apply, is the same")

	// A backend not known yet may be the other kind, whose datastore cannot
	// take over the chunk store in the same directory: the plan fails, and
	// does not advise reuse_datastore, which on S3 empties it.
	for name, tc := range map[string]struct {
		prior *resourceInstance
		attrs map[string]any
	}{
		"in a directory": {inDirectory, map[string]any{"name": "store1", "path": "/mnt/datastore/store1"}},
		"on S3":          {onS3, s3StoreAttributes(nil)},
	} {
		for _, reuse := range []bool{false, true} {
			attrs := maps.Clone(tc.attrs)
			attrs["backend"], attrs["reuse_datastore"] = tfUnknown, reuse
			planned := h.plan(t, "pbs_datastore", tc.prior, h.resourceValue(t, "pbs_datastore", attrs))
			requireProtocolErrorContaining(t, planned.Diagnostics, "The datastore's new backend is not known yet")
			if datastoreDiagnosticsMention(planned.Diagnostics, "keeping the backups") ||
				datastoreDiagnosticsMention(planned.Diagnostics, adviseReuse) {
				t.Errorf("%s, reuse %v: the plan advises reuse_datastore: %v", name, reuse, planned.Diagnostics)
			}
		}
	}
	// So does a change of backend in a directory not known yet, which may
	// be the same.
	planned = h.plan(t, "pbs_datastore", inDirectory, h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": tfUnknown, "reuse_datastore": true, "backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, nil),
	}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Moving the datastore to or from S3 needs another path")
	requireProtocolErrorContaining(t, planned.Diagnostics, "which may be the same directory, /mnt/datastore/store1")

	// A name not known yet in the same directory needs reuse_datastore as any
	// other: PBS refuses the chunk store the old datastore leaves there.
	planned = h.plan(t, "pbs_datastore", inDirectory, h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": tfUnknown, "path": "/mnt/datastore/store1",
	}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Replacing the datastore in place needs reuse_datastore")
	requireProtocolErrorContaining(t, planned.Diagnostics, "creates a datastore whose name is known only during apply in the same directory")
	planned = h.plan(t, "pbs_datastore", onS3, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{"name": tfUnknown})))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Replacing the datastore in place needs reuse_datastore")
	requireProtocolErrorContaining(t, planned.Diagnostics, `those of "s3store" only if the name and bucket stay the same`)

	// A path spelled another way is the same directory to PBS.
	planned = h.plan(t, "pbs_datastore", inDirectory, h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/datastore//store1/", "reuse_datastore": true,
		"backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, nil),
	}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Moving the datastore to or from S3 needs another path")

	// A datastore in a directory, put elsewhere with a backend not known
	// yet, leaves its chunk store alone: the plan only warns about the jobs.
	planned = h.plan(t, "pbs_datastore", inDirectory, h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/datastore/store1-new", "backend": tfUnknown,
	}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "deletes its jobs and ACL entries")
}

// A datastore on S3 imports with its backend however PBS stores it — keys
// in any order, the type bare or not — and with the flags that exist only in
// Terraform at their defaults; a datastore whose backend is PBS's default
// type has none, and one of a type the provider does not know is an error.
func TestDatastoreResourceS3Import(t *testing.T) {
	h, _, datastores := newS3DatastoreHarness(t)
	datastores.addDatastore("bare", fakeProperties{
		"path":                    "/mnt/datastore/bare",
		"backend":                 "s3,client=minio,bucket=pbs-backups",
		"notification-thresholds": "s3-upload=10GiB,s3-get=1000",
		"counter-reset-schedule":  "monthly",
	})
	datastores.addDatastore("sorted", fakeProperties{
		"path": "/mnt/datastore/sorted", "backend": "bucket=pbs-backups,client=minio,max-cache-size=1G,type=s3",
	})
	datastores.addDatastore("named", fakeProperties{"path": "/mnt/datastore/named", "backend": "type=filesystem"})
	datastores.addDatastore("plain", fakeProperties{"path": "/mnt/datastore/plain", "backend": "filesystem"})
	datastores.addDatastore("odd", fakeProperties{"path": "/mnt/datastore/odd", "backend": "type=zfs"})

	configs := map[string]map[string]any{
		"bare": s3StoreAttributes(map[string]any{
			"name": "bare", "path": "/mnt/datastore/bare",
			"notification_thresholds": map[string]any{"s3_get": 1000, "s3_upload": "10GiB"},
			"counter_reset_schedule":  "monthly",
		}),
		"sorted": s3StoreAttributes(map[string]any{
			"name": "sorted", "path": "/mnt/datastore/sorted", "backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, "1G"),
		}),
	}
	for _, name := range []string{"bare", "sorted"} {
		for by, inst := range map[string]*resourceInstance{
			"id":       h.importByID(t, "pbs_datastore", name),
			"identity": h.importByIdentity(t, "pbs_datastore", map[string]any{"name": name}),
		} {
			if stringAt(t, inst.state, "backend", "type") != "s3" || stringAt(t, inst.state, "backend", "client") != s3StoreEndpoint ||
				stringAt(t, inst.state, "backend", "bucket") != s3StoreBucket || stringAt(t, inst.state, "mount_status") != "nonremovable" {
				t.Errorf("import of %s by %s = %s", name, by, inst.state)
			}
			for _, flag := range []string{"reuse_datastore", "overwrite_in_use", "destroy_data", "keep_job_configs"} {
				if boolAt(t, inst.state, flag) {
					t.Errorf("import of %s by %s: %s = true", name, by, flag)
				}
			}
			// The configuration that matches what PBS has plans no change.
			planned := h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", configs[name]))
			requireNoProtocolErrors(t, planned.Diagnostics)
			if state := h.decodeResource(t, "pbs_datastore", planned.PlannedState); !state.Equal(inst.state) || len(planned.RequiresReplace) != 0 {
				diffs, _ := state.Diff(inst.state)
				t.Errorf("plan after the import of %s by %s changes %v, replacing for %v", name, by, diffs, planned.RequiresReplace)
			}
		}
	}
	bare := h.importByID(t, "pbs_datastore", "bare")
	if !isNullAt(t, bare.state, "backend", "max_cache_size") || int64At(t, bare.state, "notification_thresholds", "s3_get") != 1000 ||
		stringAt(t, bare.state, "notification_thresholds", "s3_upload") != "10GiB" || stringAt(t, bare.state, "counter_reset_schedule") != "monthly" {
		t.Errorf("import of bare = %s", bare.state)
	}
	if sorted := h.importByID(t, "pbs_datastore", "sorted"); stringAt(t, sorted.state, "backend", "max_cache_size") != "1G" {
		t.Errorf("import of sorted = %s", sorted.state)
	}

	for _, name := range []string{"named", "plain"} {
		inst := h.importByID(t, "pbs_datastore", name)
		if !isNullAt(t, inst.state, "backend") {
			t.Errorf("import of %s = %s, want no backend", name, inst.state)
		}
		planned := h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", map[string]any{
			"name": name, "path": "/mnt/datastore/" + name,
		}))
		requireNoProtocolErrors(t, planned.Diagnostics)
		if len(planned.RequiresReplace) != 0 {
			t.Errorf("plan after the import of %s replaces it for %v", name, planned.RequiresReplace)
		}
	}

	resp := h.importResource(t, "pbs_datastore", "odd", nil)
	requireNoProtocolErrors(t, resp.Diagnostics)
	imported := resp.ImportedResources[0]
	read := h.read(t, &resourceInstance{typeName: "pbs_datastore", state: h.decodeResource(t, "pbs_datastore", imported.State), identity: imported.Identity})
	requireProtocolErrorContaining(t, read.Diagnostics, `a backend of type "zfs", which the provider does not know`)
}

func TestDatastoreResourceS3Validation(t *testing.T) {
	h, _, _ := newS3DatastoreHarness(t)
	bucket := func(name string) map[string]any {
		return s3StoreAttributes(map[string]any{"backend": s3StoreBackend(s3StoreEndpoint, name, nil)})
	}
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"backend and backing_device": {s3StoreAttributes(map[string]any{"path": "pbs/s3", "backing_device": testDeviceUUID}), "either removable, with backing_device, or on S3"},
		"gc_on_unmount":              {s3StoreAttributes(map[string]any{"gc_on_unmount": true}), "needs backing_device"},
		"thresholds without backend": {map[string]any{"name": "store1", "path": "/mnt/s1", "notification_thresholds": map[string]any{"s3_get": 1}}, "notification_thresholds counts the requests to a datastore's bucket"},
		"schedule without backend":   {map[string]any{"name": "store1", "path": "/mnt/s1", "counter_reset_schedule": "monthly"}, "counter_reset_schedule counts the requests to a datastore's bucket"},
		"overwrite without reuse":    {s3StoreAttributes(map[string]any{"overwrite_in_use": true}), "needs backend and reuse_datastore = true"},
		"overwrite without backend":  {map[string]any{"name": "store1", "path": "/mnt/s1", "overwrite_in_use": true, "reuse_datastore": true}, "needs backend and reuse_datastore = true"},
		"dot in bucket":              {bucket("pbs.backups"), "must be lower-case letters, digits and hyphens"},
		"upper-case bucket":          {bucket("PBS-backups"), "must be lower-case letters, digits and hyphens"},
		"leading hyphen":             {bucket("-pbs"), "must be lower-case letters, digits and hyphens"},
		"xn-- prefix":                {bucket("xn--pbs"), "must not start with xn--"},
		"--ol-s3 suffix":             {bucket("pbs--ol-s3"), "nor end with --ol-s3"},
		"2 characters":               {bucket("pb"), "backend.bucket string length must be between 3 and 63"},
		"64 characters":              {bucket(strings.Repeat("p", 64)), "backend.bucket string length must be between 3 and 63"},
		"type filesystem":            {s3StoreAttributes(map[string]any{"backend": map[string]any{"type": "filesystem", "client": s3StoreEndpoint, "bucket": s3StoreBucket}}), "backend.type value must be one of"},
		"short client":               {s3StoreAttributes(map[string]any{"backend": s3StoreBackend("s3", s3StoreBucket, nil)}), "backend.client"},
		"cache size":                 {s3StoreAttributes(map[string]any{"backend": s3StoreBackend(s3StoreEndpoint, s3StoreBucket, "lots")}), "must be a byte size"},
		"negative threshold":         {s3StoreAttributes(map[string]any{"notification_thresholds": map[string]any{"s3_get": -1}}), "notification_thresholds.s3_get value must be at least 0"},
		"traffic threshold":          {s3StoreAttributes(map[string]any{"notification_thresholds": map[string]any{"s3_upload": "1 lot"}}), "must be a byte size"},
		"empty thresholds":           {s3StoreAttributes(map[string]any{"notification_thresholds": map[string]any{}}), "must set at least one attribute"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", tc.attrs)), tc.want)
		})
	}

	// A takeover with both flags, the thresholds and the schedule, and the
	// shortest and longest bucket names, are valid.
	for _, attrs := range []map[string]any{
		s3StoreAttributes(map[string]any{
			"reuse_datastore": true, "overwrite_in_use": true, "counter_reset_schedule": "monthly",
			"notification_thresholds": map[string]any{"s3_get": 0, "s3_download": "1.5TiB"},
		}),
		bucket("p-b"),
		bucket(strings.Repeat("p", 63)),
	} {
		requireNoProtocolErrors(t, h.validateResource(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", attrs)))
	}
}

// The thresholds and the reset schedule of the request counters need PBS
// 4.2; a datastore on S3 without them plans on an older server.
func TestDatastoreResourceS3NeedsPBS42(t *testing.T) {
	h, _, _ := newS3DatastoreHarness(t, `{"data":{"release":"9","repoid":"0123456789abcdef","version":"4.1"}}`)
	for attribute, value := range map[string]any{
		"notification_thresholds": map[string]any{"s3_get": 1000},
		"counter_reset_schedule":  "monthly",
	} {
		planned := h.plan(t, "pbs_datastore", nil, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{attribute: value})))
		requireProtocolErrorContaining(t, planned.Diagnostics, attribute+" needs PBS 4.2 or newer")
	}
	h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", s3StoreAttributes(nil)))
}

// What PBS checks before its task — the endpoint and the bucket — and the
// task's failures on the bucket's in-use mark and on the local cache become
// the provider's explanations, and leave nothing behind; the mark of another
// host is taken over with reuse_datastore and overwrite_in_use.
func TestDatastoreResourceS3CreateErrors(t *testing.T) {
	h, fake, datastores := newS3DatastoreHarness(t)
	datastores.addS3Bucket(s3StoreEndpoint, "gone")
	datastores.setBucketReachable(s3StoreEndpoint, "gone", false)
	datastores.addS3Marker(s3StoreBucket, "taken", "pbs-old")
	datastores.addChunkStore("/mnt/datastore/used-cache", true)

	for name, tc := range map[string]struct {
		attrs map[string]any
		want  []string
	}{
		"unknown endpoint": {
			s3StoreAttributes(map[string]any{"backend": s3StoreBackend("nowhere", s3StoreBucket, nil)}),
			[]string{`PBS has no S3 endpoint "nowhere", which backend.client names`, "no 'nowhere' in config"},
		},
		"missing bucket": {
			s3StoreAttributes(map[string]any{"backend": s3StoreBackend(s3StoreEndpoint, "missing", nil)}),
			[]string{`PBS could not reach bucket "missing" through S3 endpoint "minio"`, "failed to access bucket: bucket does not exist or no permission to access it"},
		},
		"unreachable bucket": {
			s3StoreAttributes(map[string]any{"backend": s3StoreBackend(s3StoreEndpoint, "gone", nil)}),
			[]string{`PBS could not reach bucket "gone"`, "PBS does not create it"},
		},
		"in use by another host": {
			s3StoreAttributes(map[string]any{"name": "taken"}),
			[]string{"Bucket already contains datastore in use by host pbs-old", "with reuse_datastore = true and overwrite_in_use = true"},
		},
		"chunk store in the cache": {
			s3StoreAttributes(map[string]any{"path": "/mnt/datastore/used-cache"}),
			[]string{"its local cache, /mnt/datastore/used-cache, already holds a chunk store", "reuse_datastore would delete that datastore's backups", "EEXIST"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := h.resourceValue(t, "pbs_datastore", tc.attrs)
			planned := h.plan(t, "pbs_datastore", nil, config)
			requireNoProtocolErrors(t, planned.Diagnostics)
			applied := h.apply(t, "pbs_datastore", nil, config, planned)
			for _, want := range tc.want {
				requireProtocolErrorContaining(t, applied.Diagnostics, want)
			}
			if state := h.decodeResource(t, "pbs_datastore", applied.NewState); !state.IsNull() {
				t.Errorf("a failed create left state %s", state)
			}
			if _, exists := datastores.datastore(tc.attrs["name"].(string)); exists {
				t.Error("the failed create left a datastore")
			}
		})
	}
	if host, _ := datastores.s3Marker(s3StoreBucket, "taken"); host != "pbs-old" {
		t.Errorf("in-use mark = %q, want the other host's still", host)
	}

	// Taking the datastore over needs both flags; PBS then marks it in use
	// by this host, and refreshes it from the bucket.
	inst := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"name": "taken", "reuse_datastore": true, "overwrite_in_use": true,
	})))
	created := fake.lastCall(t, "POST /config/datastore")
	if created.form.Get("reuse-datastore") != "true" || created.form.Get("overwrite-in-use") != "true" {
		t.Errorf("POST form = %v", created.form)
	}
	if host, _ := datastores.s3Marker(s3StoreBucket, "taken"); host != fakeTaskNode {
		t.Errorf("in-use mark = %q, want this host", host)
	}
	if stored, _ := datastores.datastore("taken"); stored["maintenance-mode"] != nil {
		t.Errorf("maintenance-mode after the refresh = %v", stored["maintenance-mode"])
	}
	if !boolAt(t, inst.state, "overwrite_in_use") || !boolAt(t, inst.state, "reuse_datastore") || !isNullAt(t, inst.state, "maintenance_mode") {
		t.Errorf("state = %s", inst.state)
	}
}

// Taking over a datastore on S3, PBS replaces any maintenance mode with
// s3-refresh while it reads the backups from the bucket, and clears it
// after, so the configured mode is set by an update once the task is done.
// A refresh started later in PBS clears it too, which the next apply sets
// again.
func TestDatastoreResourceS3ReuseWithMaintenanceMode(t *testing.T) {
	h, fake, datastores := newS3DatastoreHarness(t)
	datastores.addS3Backups(s3StoreBucket, "s3store")
	config := h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"reuse_datastore": true, "maintenance_mode": map[string]any{"type": "read-only"},
	}))
	inst := h.create(t, "pbs_datastore", config)

	created := fake.lastCall(t, "POST /config/datastore")
	if created.form.Has("maintenance-mode") || created.form.Get("reuse-datastore") != "true" || created.form.Has("overwrite-in-use") {
		t.Errorf("POST form = %v", created.form)
	}
	routes := fake.routes()
	post, put := slices.Index(routes, "POST /config/datastore"), slices.Index(routes, "PUT /config/datastore/s3store")
	if put < post || countPrefix(fake, taskStatusRoutes) != 1 || !strings.HasPrefix(routes[post+1], taskStatusRoutes) {
		t.Fatalf("routes = %v, want the PUT after the create task", routes)
	}
	if got := fake.lastCall(t, "PUT /config/datastore/s3store").form; got.Get("maintenance-mode") != "read-only" || len(got) != 1 {
		t.Errorf("PUT form = %v, want the maintenance mode only", got)
	}
	if stored, _ := datastores.datastore("s3store"); stored["maintenance-mode"] != "read-only" {
		t.Errorf("stored maintenance-mode = %v", stored["maintenance-mode"])
	}
	if stringAt(t, inst.state, "maintenance_mode", "type") != "read-only" {
		t.Errorf("state = %s", inst.state)
	}

	// While PBS refreshes the datastore, a refresh warns and changes
	// nothing; after it, the mode is gone, and the next apply sets it.
	datastores.setDatastoreProperty("s3store", "maintenance-mode", pbsclient.MaintenanceS3Refresh)
	read := h.read(t, inst)
	requireNoProtocolErrors(t, read.Diagnostics)
	requireProtocolWarningContaining(t, read.Diagnostics, "PBS datastore in maintenance mode s3-refresh")
	if refreshed := h.decodeResource(t, "pbs_datastore", read.NewState); !refreshed.Equal(inst.state) {
		diffs, _ := refreshed.Diff(inst.state)
		t.Errorf("refresh during s3-refresh changed %v", diffs)
	}
	datastores.setDatastoreProperty("s3store", "maintenance-mode", nil)
	inst = h.refresh(t, inst)
	if !isNullAt(t, inst.state, "maintenance_mode") {
		t.Errorf("state = %s", inst.state)
	}
	h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /config/datastore/s3store").form.Get("maintenance-mode"); got != "read-only" {
		t.Errorf("PUT maintenance-mode = %q", got)
	}

	// Without reuse_datastore, PBS keeps the mode the POST carries.
	h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"name": "s3other", "path": "/mnt/datastore/s3-other", "maintenance_mode": map[string]any{"type": "offline"},
	})))
	if got := fake.lastCall(t, "POST /config/datastore").form.Get("maintenance-mode"); got != "offline" || fake.count("PUT /config/datastore/s3other") != 0 {
		t.Errorf("POST maintenance-mode = %q, PUTs %d", got, fake.count("PUT /config/datastore/s3other"))
	}
}

// When the refresh of a datastore on S3 that PBS takes over fails, PBS keeps
// the datastore, in maintenance mode s3-refresh. It is recorded in state with
// a warning and no error, so that Terraform does not replace it, and the
// configured maintenance mode, which PBS did not get, is set once a refresh
// succeeds.
func TestDatastoreResourceS3FailedRefresh(t *testing.T) {
	h, fake, datastores := newS3DatastoreHarness(t)
	datastores.failRefresh = true
	config := h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"reuse_datastore": true, "maintenance_mode": map[string]any{"type": "offline"},
	}))
	planned := h.plan(t, "pbs_datastore", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, "pbs_datastore", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "PBS datastore created, but its task failed")
	requireProtocolWarningContaining(t, applied.Diagnostics, "maintenance mode s3-refresh")
	requireProtocolWarningContaining(t, applied.Diagnostics, "proxmox-backup-manager datastore s3-refresh s3store")
	requireProtocolWarningContaining(t, applied.Diagnostics, "failed to list object")
	state := h.decodeResource(t, "pbs_datastore", applied.NewState)
	requireAppliedCompatible(t, h.decodeResource(t, "pbs_datastore", planned.PlannedState), state)
	if state.IsNull() || stringAt(t, state, "id") != "s3store" || stringAt(t, state, "backend", "bucket") != s3StoreBucket {
		t.Fatalf("state = %s", state)
	}
	inst := &resourceInstance{typeName: "pbs_datastore", state: state, identity: applied.NewIdentity, private: applied.Private}
	if got := stringAt(t, h.identityValue(t, "pbs_datastore", inst.identity), "name"); got != "s3store" {
		t.Errorf("identity name = %q", got)
	}
	if n := fake.count("PUT /config/datastore/s3store"); n != 0 {
		t.Errorf("set the maintenance mode %d times during the failed refresh", n)
	}
	if stored, _ := datastores.datastore("s3store"); stored["maintenance-mode"] != pbsclient.MaintenanceS3Refresh {
		t.Errorf("stored maintenance-mode = %v", stored["maintenance-mode"])
	}

	// While the mode stays, a refresh warns and a plan changes nothing.
	read := h.read(t, inst)
	requireNoProtocolErrors(t, read.Diagnostics)
	requireProtocolWarningContaining(t, read.Diagnostics, "Should the mode stay, the refresh failed")
	if refreshed := h.decodeResource(t, "pbs_datastore", read.NewState); !refreshed.Equal(state) {
		diffs, _ := refreshed.Diff(state)
		t.Errorf("refresh changed %v", diffs)
	}
	replan := h.plan(t, "pbs_datastore", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_datastore", replan.PlannedState); !planned.Equal(state) || len(replan.RequiresReplace) != 0 {
		diffs, _ := planned.Diff(state)
		t.Errorf("plan during s3-refresh changes %v, replacing for %v", diffs, replan.RequiresReplace)
	}

	// A refresh that succeeds clears the mode, and the next apply sets the
	// configured one.
	datastores.setDatastoreProperty("s3store", "maintenance-mode", nil)
	inst = h.refresh(t, inst)
	inst = h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /config/datastore/s3store").form.Get("maintenance-mode"); got != "offline" {
		t.Errorf("PUT maintenance-mode = %q", got)
	}
	if stringAt(t, inst.state, "maintenance_mode", "type") != "offline" {
		t.Errorf("state = %s", inst.state)
	}
}

// Destroying a datastore on S3 needs its bucket reachable: otherwise the
// task fails, and PBS keeps the datastore in maintenance mode "delete".
// Destroying it again then deletes it, and with destroy_data its backups in
// the bucket.
func TestDatastoreResourceS3Delete(t *testing.T) {
	h, fake, datastores := newS3DatastoreHarness(t)
	inst := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{"destroy_data": true})))
	datastores.addS3Backups(s3StoreBucket, "s3store")
	datastores.setBucketReachable(s3StoreEndpoint, s3StoreBucket, false)

	null := tftypes.NewValue(h.resourceType(t, "pbs_datastore"), nil)
	planned := h.plan(t, "pbs_datastore", inst, null)
	applied := h.apply(t, "pbs_datastore", inst, null, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "A datastore on S3 is deleted only while its bucket is reachable")
	requireProtocolErrorContaining(t, applied.Diagnostics, `"delete" maintenance mode`)
	if stored, exists := datastores.datastore("s3store"); !exists || stored["maintenance-mode"] != pbsclient.MaintenanceDelete {
		t.Errorf("datastore after the failed task = %v, %v", stored, exists)
	}
	if !datastores.hasS3Backups(s3StoreBucket, "s3store") {
		t.Error("the failed task deleted the backups")
	}

	datastores.setBucketReachable(s3StoreEndpoint, s3StoreBucket, true)
	inst = h.refresh(t, inst)
	h.destroy(t, inst)
	if got := fake.lastCall(t, "DELETE /config/datastore/s3store").query; got.Get("destroy-data") != "true" {
		t.Errorf("DELETE query = %v", got)
	}
	if _, exists := datastores.datastore("s3store"); exists {
		t.Error("the datastore still exists")
	}
	if _, marked := datastores.s3Marker(s3StoreBucket, "s3store"); marked || datastores.hasS3Backups(s3StoreBucket, "s3store") {
		t.Error("destroy_data left the in-use mark or the backups in the bucket")
	}
	if datastores.hasChunkStore("/mnt/datastore/s3-cache") {
		t.Error("destroy_data left the local cache")
	}
}

// A maintenance mode PBS set itself, such as s3-refresh while it reads the
// backups from the bucket, is not replaced by the configured one, which
// waits for the next apply; the other changes go through, with a warning.
func TestDatastoreResourceS3UpdateKeepsRefresh(t *testing.T) {
	h, fake, datastores := newS3DatastoreHarness(t)
	inst := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", s3StoreAttributes(nil)))
	datastores.setDatastoreProperty("s3store", "maintenance-mode", "s3-refresh")

	config := h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{
		"comment":          "Being refreshed",
		"maintenance_mode": map[string]any{"type": "read-only"},
	}))
	planned := h.plan(t, "pbs_datastore", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, "pbs_datastore", inst, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "maintenance mode s3-refresh")

	updated := fake.lastCall(t, "PUT /config/datastore/s3store")
	if updated.form.Get("comment") != "Being refreshed" || updated.form.Has("maintenance-mode") {
		t.Errorf("PUT form = %v, want the comment without the maintenance mode", updated.form)
	}
	if props, _ := datastores.datastore("s3store"); props["maintenance-mode"] != "s3-refresh" {
		t.Errorf("maintenance mode = %v, want s3-refresh kept", props["maintenance-mode"])
	}

	// Removing the configured mode deletes nothing while PBS refreshes,
	// and a change of the mode alone sends nothing at all.
	inst = &resourceInstance{typeName: "pbs_datastore", state: h.decodeResource(t, "pbs_datastore", applied.NewState), identity: applied.NewIdentity}
	puts := fake.count("PUT /config/datastore/s3store")
	inst = h.update(t, inst, h.resourceValue(t, "pbs_datastore", s3StoreAttributes(map[string]any{"comment": "Being refreshed"})))
	if fake.count("PUT /config/datastore/s3store") != puts {
		t.Errorf("deleting the maintenance mode during s3-refresh sent %v", fake.lastCall(t, "PUT /config/datastore/s3store").form)
	}
	if !isNullAt(t, inst.state, "maintenance_mode") {
		t.Errorf("state = %s", inst.state)
	}
}
