package provider

import (
	"net/http"
	"slices"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestDatastoreListResource(t *testing.T) {
	h, fake, datastores := newRemovableHarness(t)
	datastores.addS3Bucket(s3StoreEndpoint, s3StoreBucket)
	h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/datastore/store1", "comment": "Main backups", "gc_schedule": "daily",
		"tuning":           map[string]any{"sync_level": "file"},
		"maintenance_mode": map[string]any{"type": "read-only", "message": "Moving"},
		"destroy_data":     true, "keep_job_configs": true,
	}))
	h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "usb", "path": "pbs/usb", "backing_device": testDeviceUUID,
	}))
	h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", s3StoreAttributes(nil)))
	// Unmounted, the removable datastore is still listed.
	datastores.setMounted("usb", false)

	// Without resources, the list costs one call and names every
	// datastore, of whichever kind.
	before := len(fake.routes())
	results := h.listedObjects(t, "pbs_datastore", listRequest{})
	if got, want := listedIdentities(t, results, "name"), []string{"s3store", "store1", "usb"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	if got := fake.routes()[before:]; !slices.Equal(got, []string{"GET /config/datastore"}) {
		t.Fatalf("calls %q", got)
	}
	if results[1].displayName != "store1 — Main backups" || results[2].displayName != "usb" {
		t.Fatalf("display names %q, %q", results[1].displayName, results[2].displayName)
	}

	// With resources, each is what importing it gives, with the attributes
	// that exist only in Terraform at their defaults, and the configuration
	// generated from it plans nothing.
	results = h.listedObjects(t, "pbs_datastore", listRequest{includeResource: true})
	if len(results) != 3 {
		t.Fatalf("listed %d datastores with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_datastore", result)
		for _, flag := range []string{"reuse_datastore", "overwrite_in_use", "destroy_data", "keep_job_configs"} {
			if boolAt(t, result.resource, flag) {
				t.Fatalf("listed %s with %s: %s", result.displayName, flag, result.resource)
			}
		}
	}
	store1, usb, s3 := results[1].resource, results[2].resource, results[0].resource
	if stringAt(t, store1, "maintenance_mode", "type") != "read-only" || stringAt(t, store1, "tuning", "sync_level") != "file" {
		t.Fatalf("listed store1: %s", store1)
	}
	if stringAt(t, usb, "mount_status") != pbsclient.MountStatusNotMounted || stringAt(t, usb, "backing_device") != testDeviceUUID {
		t.Fatalf("listed usb: %s", usb)
	}
	if stringAt(t, s3, "backend", "bucket") != s3StoreBucket {
		t.Fatalf("listed s3store: %s", s3)
	}
}

// A datastore PBS has in a maintenance mode of its own, as while it
// unmounts one, is listed without it, as an import reads it.
func TestDatastoreListResourceInternalMaintenance(t *testing.T) {
	h, _, datastores := newRemovableHarness(t)
	datastores.addDatastore("usb", fakeProperties{"path": "pbs/usb", "backing-device": testDeviceUUID, "maintenance-mode": "type=unmount"})
	datastores.setMounted("usb", true)
	results := h.listedObjects(t, "pbs_datastore", listRequest{includeResource: true})
	if len(results) != 1 || !isNullAt(t, results[0].resource, "maintenance_mode") {
		t.Fatalf("listed %d datastores: %v", len(results), results)
	}
	h.requireListedLikeImport(t, "pbs_datastore", results[0])
}

// A datastore of a backend the provider does not know is left out with a
// warning, and the others are still listed.
func TestDatastoreListResourceUnsupportedBackend(t *testing.T) {
	h, _, datastores := newRemovableHarness(t)
	datastores.addDatastore("odd", fakeProperties{"path": "/mnt/datastore/odd", "backend": "type=tape"})
	datastores.addDatastore("store1", fakeProperties{"path": "/mnt/datastore/store1"})
	var listed []string
	warned := false
	for _, result := range h.listResources(t, "pbs_datastore", listRequest{includeResource: true}) {
		requireNoProtocolErrors(t, result.diagnostics)
		if result.identity.IsNull() {
			requireProtocolWarningContaining(t, result.diagnostics, "Left out odd: Unsupported PBS datastore")
			warned = true
			continue
		}
		listed = append(listed, stringAt(t, result.identity, "name"))
	}
	if !warned || !slices.Equal(listed, []string{"store1"}) {
		t.Fatalf("listed %q, warned %v", listed, warned)
	}
}

func TestDatastoreListResourceListFails(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/datastore", 500, "datastore.cfg is broken")
	h := newProtocolHarness(t, fake)
	results := h.listResources(t, "pbs_datastore", listRequest{})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS datastores")
}

// newNamespaceListHarness is newNamespaceHarness with the list of
// datastores, and a datastore store2 next to store1.
func newNamespaceListHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeNamespaces) {
	t.Helper()
	h, fake, namespaces := newNamespaceHarness(t)
	newFakeDatastoreStatus(namespaces.datastores)
	namespaces.datastores.addDatastore("store2", fakeProperties{"path": "/mnt/datastore/store2"})
	return h, fake, namespaces
}

func TestNamespaceListResource(t *testing.T) {
	h, fake, namespaces := newNamespaceListHarness(t)
	for _, ns := range []string{"dept1", "dept1/hosts", "dept2"} {
		h.create(t, "pbs_namespace", h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": ns}))
	}
	namespaces.addNamespace("store2", "a")
	namespaces.addNamespace("store2", "a/b/c")
	// PBS leaves out the namespaces the caller has no privilege on.
	namespaces.addNamespace("store2", "secret")
	namespaces.hide("store2", "secret")

	// Without resources, the list costs one call for the datastores and one
	// for the namespaces of each, which start with the root, which is no
	// namespace to list.
	before := len(fake.routes())
	results := h.listedObjects(t, "pbs_namespace", listRequest{})
	want := []string{"store1:dept1", "store1:dept1/hosts", "store1:dept2", "store2:a", "store2:a/b/c"}
	if got := resultDisplayNames(results); !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	calls := fake.routes()[before:]
	slices.Sort(calls)
	if want := []string{"GET /admin/datastore", fakeNamespaceRoute("GET", "store1"), fakeNamespaceRoute("GET", "store2")}; !slices.Equal(calls, want) {
		t.Fatalf("calls %q, want %q", calls, want)
	}
	if query := fake.lastCall(t, fakeNamespaceRoute("GET", "store1")).query; len(query) != 0 {
		t.Fatalf("namespace list query %v, want the whole tree from the root", query)
	}
	if stringAt(t, results[1].identity, "store") != "store1" || stringAt(t, results[1].identity, "namespace") != "dept1/hosts" {
		t.Fatalf("identity %s", results[1].identity)
	}

	// store selects one datastore, without listing the datastores.
	before = len(fake.routes())
	results = h.listedObjects(t, "pbs_namespace", listRequest{config: map[string]any{"store": "store2"}})
	if got := listedIdentities(t, results, "namespace"); !slices.Equal(got, []string{"a", "a/b/c"}) {
		t.Fatalf("listed %q in store2", got)
	}
	if got := fake.routes()[before:]; !slices.Equal(got, []string{fakeNamespaceRoute("GET", "store2")}) {
		t.Fatalf("calls %q", got)
	}

	// With resources, each is what importing it gives, with the attributes
	// that exist only in Terraform at their defaults, and the configuration
	// generated from it plans nothing.
	results = h.listedObjects(t, "pbs_namespace", listRequest{includeResource: true})
	if len(results) != len(want) {
		t.Fatalf("listed %d namespaces with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_namespace", result)
		if boolAt(t, result.resource, "delete_groups") || !boolAt(t, result.resource, "error_on_protected") {
			t.Fatalf("listed state: %s", result.resource)
		}
	}

	if got := h.listedObjects(t, "pbs_namespace", listRequest{limit: 2}); len(got) != 2 {
		t.Fatalf("a limit of 2 listed %d", len(got))
	}
}

// A datastore PBS cannot open is left out with a warning, with store or
// without, and the namespaces of the others are still listed.
func TestNamespaceListResourceUnavailableDatastore(t *testing.T) {
	h, _, namespaces := newNamespaceListHarness(t)
	namespaces.addNamespace("store1", "dept1")
	namespaces.addNamespace("store2", "a")
	namespaces.setUnavailable("store2", "datastore 'store2' is not mounted")

	for _, config := range []map[string]any{nil, {"store": "store2"}} {
		var listed []string
		warned := false
		for _, result := range h.listResources(t, "pbs_namespace", listRequest{config: config, includeResource: true}) {
			requireNoProtocolErrors(t, result.diagnostics)
			if result.identity.IsNull() {
				requireProtocolWarningContaining(t, result.diagnostics, "Left out the namespaces of datastore store2")
				warned = true
				continue
			}
			listed = append(listed, result.displayName)
		}
		want := []string{"store1:dept1"}
		if config != nil {
			want = nil
		}
		if !warned || !slices.Equal(listed, want) {
			t.Fatalf("with %v: listed %q, warned %v", config, listed, warned)
		}
	}
}

// Without store, a datastore PBS fails to open in another way — here one
// whose file system did not mount — is left out with a warning, and the
// namespaces of the others are listed; asked for by name, it fails the
// list. A PBS that does not answer fails the list either way.
func TestNamespaceListResourceDatastoreFails(t *testing.T) {
	h, fake, namespaces := newNamespaceListHarness(t)
	namespaces.addNamespace("store1", "dept1")
	namespaces.addNamespace("store2", "a")
	const openFailed = `unable to open chunk store at "/mnt/disk1/store2/.chunks" - No such file or directory (os error 2)`
	fake.reply(fakeNamespaceRoute("GET", "store2"), http.StatusBadRequest, openFailed)

	var listed []string
	warned := false
	for _, result := range h.listResources(t, "pbs_namespace", listRequest{includeResource: true}) {
		requireNoProtocolErrors(t, result.diagnostics)
		if result.identity.IsNull() {
			requireProtocolWarningContaining(t, result.diagnostics, "Left out the namespaces of datastore store2")
			requireProtocolWarningContaining(t, result.diagnostics, openFailed)
			warned = true
			continue
		}
		h.requireListedLikeImport(t, "pbs_namespace", result)
		listed = append(listed, result.displayName)
	}
	if !warned || !slices.Equal(listed, []string{"store1:dept1"}) {
		t.Fatalf("listed %q, warned %v", listed, warned)
	}

	results := h.listResources(t, "pbs_namespace", listRequest{config: map[string]any{"store": "store2"}})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS namespaces")
	requireProtocolErrorContaining(t, results[0].diagnostics, openFailed)

	fake.reply(fakeNamespaceRoute("GET", "store2"), http.StatusBadGateway, "bad gateway")
	results = h.listResources(t, "pbs_namespace", listRequest{})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS namespaces")
}

// A datastore that goes between the two lists is left out; one PBS
// forbids, because the caller has privileges only on a namespace of it that
// does not exist, has nothing to list.
func TestNamespaceListResourceDatastoreGoneOrForbidden(t *testing.T) {
	h, fake, namespaces := newNamespaceListHarness(t)
	namespaces.addNamespace("store1", "dept1")
	namespaces.addNamespace("store2", "a")
	fake.reply(fakeNamespaceRoute("GET", "store1"), http.StatusBadRequest, "no such datastore 'store1'")
	fake.reply(fakeNamespaceRoute("GET", "store2"), http.StatusForbidden, "permission check failed")
	results := h.listResources(t, "pbs_namespace", listRequest{})
	if len(results) != 0 {
		t.Fatalf("got %d results", len(results))
	}

	// Asked for by name, either is an error.
	results = h.listResources(t, "pbs_namespace", listRequest{config: map[string]any{"store": "store1"}})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, `PBS has no datastore "store1"`)
	results = h.listResources(t, "pbs_namespace", listRequest{config: map[string]any{"store": "store2"}})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Datastore.Audit, Datastore.Modify or Datastore.Backup on /datastore/store2")
}

// A namespace that goes between the listing and its read is left out
// without an error.
func TestNamespaceListResourceNamespaceGone(t *testing.T) {
	h, fake, namespaces := newNamespaceListHarness(t)
	namespaces.addNamespace("store1", "dept1")
	namespaces.addNamespace("store1", "dept2")
	fake.handle(fakeNamespaceRoute("GET", "store1"), func(w http.ResponseWriter, req *http.Request) {
		// The read of dept1 is a list of the root's children, without it.
		if req.URL.Query().Get("max-depth") == "1" {
			writeData(w, []map[string]any{{"ns": ""}, {"ns": "dept2"}}, "")
			return
		}
		namespaces.serve(w, req)
	})
	results := h.listedObjects(t, "pbs_namespace", listRequest{config: map[string]any{"store": "store1"}, includeResource: true})
	if got := listedIdentities(t, results, "namespace"); !slices.Equal(got, []string{"dept2"}) {
		t.Fatalf("listed %q", got)
	}
}

func TestNamespaceListResourceValidation(t *testing.T) {
	h, _, _ := newNamespaceListHarness(t)
	requireProtocolErrorContaining(t, listConfigDiagnostics(t, h, "pbs_namespace", map[string]any{"store": "-bad"}), "must start with")
}
