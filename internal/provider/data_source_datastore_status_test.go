package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The routes of the status of the harness's datastores.
const (
	store1StatusRoute  = "GET /admin/datastore/store1/status"
	s3StoreStatusRoute = "GET /admin/datastore/s3store/status"
)

// newDatastoreStatusHarness is newDatastoreDataHarness with figures for
// every datastore, and store1 out of maintenance.
func newDatastoreStatusHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeDatastores, *fakeDatastoreStatus) {
	t.Helper()
	h, fake, datastores, status := newDatastoreDataHarness(t)
	datastores.setDatastoreProperty("store1", "maintenance-mode", nil)
	status.setUsage("store1", 1000, 400, 600)
	status.setUsage("s3store", 2000, 500, 1500)
	status.setUsage("usb", 3000, 100, 2900)
	return h, fake, datastores, status
}

// For a datastore on S3, the status of the datastore adds its request
// statistics, zeros included, in one more call without verbose; a datastore
// on a file system costs no call, and PBS 4.1.6, which has no statistics
// yet, leaves them null.
func TestDatastoreStatusDataSourceS3Statistics(t *testing.T) {
	h, fake, _, status := newDatastoreStatusHarness(t)
	status.setS3Statistics("s3store", map[string]any{"get": 1, "put": 3, "head": 4, "uploaded": 2048, "downloaded": 10})

	config := h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "s3store"})
	state := h.readDataSource(t, "pbs_datastore_status", config)
	want := h.dataSourceValue(t, "pbs_datastore_status", map[string]any{
		"store": "s3store", "mount_status": "nonremovable", "backend_type": "s3",
		"total": 2000, "used": 500, "avail": 1500,
		"s3_statistics": map[string]any{"get": 1, "put": 3, "post": 0, "head": 4, "delete": 0,
			"uploaded": 2048, "downloaded": 10},
	})
	if !state.Equal(want) {
		diffs, _ := state.Diff(want)
		t.Errorf("state differs: %v", diffs)
	}
	if n := fake.count(s3StoreStatusRoute); n != 1 {
		t.Errorf("read the status %d times, want once", n)
	}
	if query := fake.lastCall(t, s3StoreStatusRoute).query; len(query) != 0 {
		t.Errorf("status query = %v, want none", query)
	}

	// Fresh counters are zeros, not null.
	status.setS3Statistics("s3store", nil)
	state = h.readDataSource(t, "pbs_datastore_status", config)
	if isNullAt(t, state, "s3_statistics") || int64At(t, state, "s3_statistics", "put") != 0 ||
		int64At(t, state, "s3_statistics", "uploaded") != 0 {
		t.Errorf("fresh counters = %s", state)
	}

	// PBS 4.1.6 lists the backend type, but has no statistics.
	status.setRelease(pbs416)
	state = h.readDataSource(t, "pbs_datastore_status", config)
	if !isNullAt(t, state, "s3_statistics") || stringAt(t, state, "backend_type") != "s3" || int64At(t, state, "total") != 2000 {
		t.Errorf("on PBS 4.1.6 = %s", state)
	}

	state = h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "store1"}))
	if !isNullAt(t, state, "s3_statistics") || !isNullAt(t, state, "counts") || !isNullAt(t, state, "count_backups") {
		t.Errorf("store1 = %s", state)
	}
	if n := fake.count(store1StatusRoute); n != 0 {
		t.Errorf("read the status of a datastore on a file system %d times without count_backups", n)
	}
}

// count_backups has PBS count the backups, verbose: types without backups
// count zero, and other is left out; without it, no call is made for a
// datastore on a file system.
func TestDatastoreStatusDataSourceCountBackups(t *testing.T) {
	h, fake, _, status := newDatastoreStatusHarness(t)
	status.setCounts("store1", map[string]any{"vm": map[string]any{"groups": 2, "snapshots": 10},
		"other": map[string]any{"groups": 9, "snapshots": 9}})

	state := h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status",
		map[string]any{"store": "store1", "count_backups": true}))
	want := h.dataSourceValue(t, "pbs_datastore_status", map[string]any{
		"store": "store1", "count_backups": true, "mount_status": "nonremovable", "backend_type": "filesystem",
		"total": 1000, "used": 400, "avail": 600,
		"counts": map[string]any{
			"vm":   map[string]any{"groups": 2, "snapshots": 10},
			"ct":   map[string]any{"groups": 0, "snapshots": 0},
			"host": map[string]any{"groups": 0, "snapshots": 0},
		},
	})
	if !state.Equal(want) {
		diffs, _ := state.Diff(want)
		t.Errorf("state differs: %v", diffs)
	}
	if verbose := fake.lastCall(t, store1StatusRoute).query.Get("verbose"); verbose != "true" {
		t.Errorf("verbose = %q, want true", verbose)
	}

	state = h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status",
		map[string]any{"store": "store1", "count_backups": false}))
	if !isNullAt(t, state, "counts") || boolAt(t, state, "count_backups") {
		t.Errorf("without count_backups = %s", state)
	}
	if n := fake.count(store1StatusRoute); n != 1 {
		t.Errorf("read the status %d times, want once", n)
	}

	// A datastore on S3 gets both from the one call.
	status.setCounts("s3store", map[string]any{"host": map[string]any{"groups": 1, "snapshots": 3}})
	state = h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status",
		map[string]any{"store": "s3store", "count_backups": true}))
	if int64At(t, state, "counts", "host", "snapshots") != 3 || int64At(t, state, "counts", "vm", "groups") != 0 ||
		isNullAt(t, state, "s3_statistics") {
		t.Errorf("s3store = %s", state)
	}
	if n := fake.count(s3StoreStatusRoute); n != 1 {
		t.Errorf("read the status of s3store %d times, want once", n)
	}
}

// The fakes of a datastore's namespaces and of its status share the routes
// below /admin/datastore/{store}/, whichever starts last.
func TestFakeDatastoreAdminRoutes(t *testing.T) {
	h, _, datastores, _ := newDatastoreStatusHarness(t)
	newFakeNamespaces(datastores).addNamespace("store1", "dept1")

	state := h.readDataSource(t, "pbs_namespaces", h.dataSourceValue(t, "pbs_namespaces", map[string]any{"store": "store1"}))
	if lengthAt(t, state, "namespaces") != 1 || stringAt(t, state, "namespaces", 0) != "dept1" {
		t.Errorf("namespaces = %s", state)
	}
	state = h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status",
		map[string]any{"store": "store1", "count_backups": true}))
	if isNullAt(t, state, "counts") {
		t.Errorf("status = %s", state)
	}
}

// A datastore the list has no figures of — not mounted, offline, or one the
// provider may see a namespace of only — gets no status either, and that is
// no error.
func TestDatastoreStatusDataSourceWithoutFigures(t *testing.T) {
	h, fake, datastores, status := newDatastoreStatusHarness(t)
	datastores.setMounted("usb", false)
	datastores.setDatastoreProperty("store1", "maintenance-mode", "offline")
	status.hideFigures("s3store")

	for _, store := range []string{"usb", "store1", "s3store"} {
		state := h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status",
			map[string]any{"store": store, "count_backups": true}))
		if !isNullAt(t, state, "total") || !isNullAt(t, state, "counts") || !isNullAt(t, state, "s3_statistics") {
			t.Errorf("%s = %s", store, state)
		}
		if n := fake.count("GET /admin/datastore/" + store + "/status"); n != 0 {
			t.Errorf("read the status of %s %d times", store, n)
		}
	}
}

// PBS before 4.1.6 lists no backend type: it comes from the datastore's
// configuration, or stays null without Datastore.Audit; the status is read
// for the counts only, which every release has.
func TestDatastoreStatusDataSourceBackendTypeBeforePBS416(t *testing.T) {
	h, fake, _, status := newDatastoreStatusHarness(t)
	status.setRelease(pbsRelease{4, 0, 22})
	status.setCounts("store1", map[string]any{"ct": map[string]any{"groups": 1, "snapshots": 1}})

	state := h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "s3store"}))
	if stringAt(t, state, "backend_type") != "s3" || !isNullAt(t, state, "s3_statistics") {
		t.Errorf("s3store = %s", state)
	}
	if n := fake.count(s3StoreStatusRoute); n != 0 {
		t.Errorf("read the status %d times on a release without statistics", n)
	}

	state = h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status",
		map[string]any{"store": "store1", "count_backups": true}))
	if stringAt(t, state, "backend_type") != "filesystem" || int64At(t, state, "counts", "ct", "snapshots") != 1 {
		t.Errorf("store1 = %s", state)
	}
	if verbose := fake.lastCall(t, store1StatusRoute).query.Get("verbose"); verbose != "true" {
		t.Errorf("verbose = %q, want true", verbose)
	}

	fake.reply("GET /config/datastore/s3store", http.StatusForbidden, "permission check failed")
	state = h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "s3store"}))
	if !isNullAt(t, state, "backend_type") || int64At(t, state, "total") != 2000 {
		t.Errorf("without Datastore.Audit = %s", state)
	}

	fake.reply("GET /config/datastore/s3store", http.StatusInternalServerError, "unable to parse datastore.cfg")
	resp := h.readDataSourceResponse(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "s3store"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "without its backend type")
	requireProtocolErrorContaining(t, resp.Diagnostics, "unable to parse datastore.cfg")
}

// A datastore that became unavailable or went away since the list leaves
// the status null; any other failure is an error, a timeout of the count
// with advice on request_timeout.
func TestDatastoreStatusDataSourceStatusFailures(t *testing.T) {
	h, fake, _, _ := newDatastoreStatusHarness(t)
	config := h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "s3store"})

	for _, body := range []string{"datastore 's3store' is unavailable: offline maintenance mode: ", "no such datastore 's3store'"} {
		fake.reply(s3StoreStatusRoute, http.StatusBadRequest, body)
		state := h.readDataSource(t, "pbs_datastore_status", config)
		if !isNullAt(t, state, "s3_statistics") || int64At(t, state, "total") != 2000 {
			t.Errorf("after %q = %s", body, state)
		}
	}

	fake.reply(s3StoreStatusRoute, http.StatusForbidden, "permission check failed")
	resp := h.readDataSourceResponse(t, "pbs_datastore_status", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to read PBS datastore status")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Datastore.Audit or Datastore.Backup on /datastore/s3store")

	fake.reply(s3StoreStatusRoute, http.StatusBadRequest, "unable to open dir: EIO")
	resp = h.readDataSourceResponse(t, "pbs_datastore_status", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "unable to open dir: EIO")
}

// timingOutStatus is a PBS that does not answer the status of a datastore
// before the provider's request_timeout runs out, as with very many
// snapshots to count.
type timingOutStatus struct {
	fake *fakePBS
}

func (s timingOutStatus) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.Path, fakeAPIPrefix+"/admin/datastore/") && strings.HasSuffix(req.URL.Path, "/status") {
		return nil, fakeClientTimeout{}
	}
	return s.fake.RoundTrip(req)
}

// fakeClientTimeout is the error net/http's client fails with when its
// Timeout runs out.
type fakeClientTimeout struct{}

func (fakeClientTimeout) Error() string {
	return "net/http: request canceled (Client.Timeout exceeded while awaiting headers)"
}
func (fakeClientTimeout) Timeout() bool { return true }

func TestDatastoreStatusDataSourceCountTimeout(t *testing.T) {
	fake := newFakePBS()
	datastores := newFakeDatastores(fake)
	status := newFakeDatastoreStatus(datastores)
	datastores.addDatastore("store1", fakeProperties{"path": "/mnt/datastore/store1"})
	datastores.addDatastore("s3store", fakeProperties{"path": "/mnt/cache", "backend": "type=s3,client=minio,bucket=pbs"})
	status.setUsage("store1", 1000, 400, 600)
	status.setUsage("s3store", 2000, 500, 1500)
	h := newProtocolHarness(t, fake, withTransport(timingOutStatus{fake}))

	resp := h.readDataSourceResponse(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status",
		map[string]any{"store": "store1", "count_backups": true}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to read PBS datastore status")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Raise request_timeout, or leave count_backups out")

	resp = h.readDataSourceResponse(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "s3store"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Client.Timeout exceeded")
	for _, d := range resp.Diagnostics {
		if strings.Contains(d.Detail, "count_backups") {
			t.Errorf("advice on count_backups without it: %s", d.Detail)
		}
	}
}

// A datastore PBS could not open because a task held the lock of its
// datastore configuration has PBS's refusal as error, with a warning that
// says which tasks hold the lock; one PBS could not open for another reason
// has its error without a warning.
func TestDatastoreStatusDataSourceLocked(t *testing.T) {
	h, fake, _, _ := newDatastoreDataHarness(t)
	usage := func(store, openError string) string {
		return fmt.Sprintf(`{"data":[{"store":%q,"mount-status":"nonremovable","backend-type":"filesystem","error":%q}]}`,
			store, openError)
	}
	config := h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "store1"})
	schemaType := h.dataSourceSchema(t, "pbs_datastore_status").ValueType()

	fake.reply("GET /status/datastore-usage", http.StatusOK, usage("store1", datastoreConfigLockedText))
	resp := h.readDataSourceResponse(t, "pbs_datastore_status", config)
	requireNoProtocolErrors(t, resp.Diagnostics)
	for _, want := range []string{
		`PBS could not open datastore "store1"`, pbsclient.DatastoreConfigLockFile, "task s3-refresh",
		"create-datastore task holds it while it creates the chunk store", "Administration → Tasks",
	} {
		requireProtocolWarningContaining(t, resp.Diagnostics, want)
	}
	state := decodeDynamicValue(t, resp.State, schemaType)
	if stringAt(t, state, "error") != datastoreConfigLockedText || !isNullAt(t, state, "total") {
		t.Errorf("locked = %s", state)
	}

	offline := "datastore 'store1' is unavailable: offline maintenance mode"
	fake.reply("GET /status/datastore-usage", http.StatusOK, usage("store1", offline))
	resp = h.readDataSourceResponse(t, "pbs_datastore_status", config)
	for _, d := range resp.Diagnostics {
		t.Errorf("offline: unexpected %s: %s: %s", d.Severity, d.Summary, d.Detail)
	}
	if state := decodeDynamicValue(t, resp.State, schemaType); stringAt(t, state, "error") != offline {
		t.Errorf("offline = %s", state)
	}

	// PBS leaves out a datastore it cannot open for a caller with privileges
	// on its namespaces only.
	fake.reply("GET /status/datastore-usage", http.StatusOK, `{"data":[]}`)
	resp = h.readDataSourceResponse(t, "pbs_datastore_status", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS also leaves out a datastore it cannot open, such as "+
		"while a task holds the lock of its datastore configuration ("+pbsclient.DatastoreConfigLockFile+")")
}

// blockingTransport answers no request: each ends with its context, as one
// does that PBS takes longer than the request timeout to answer.
type blockingTransport struct{}

func (blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// A list of datastore usage that timed out says that a task holding the lock
// of PBS's datastore configuration can be why; another failure does not.
func TestDatastoreUsageFailedDetail(t *testing.T) {
	client, err := pbsclient.New(pbsclient.Options{Endpoint: "https://pbs.test:8007", APIToken: fakeAPIToken,
		Transport: blockingTransport{}, Timeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListDatastoreUsage(context.Background())
	if err == nil {
		t.Fatal("the list did not time out")
	}
	detail := datastoreUsageFailedDetail(client, err)
	for _, want := range []string{
		err.Error(), "waits up to 10 seconds for the lock of its datastore configuration (" +
			pbsclient.DatastoreConfigLockFile + ") to open each", "10 seconds per datastore", "`request_timeout`",
		"task s3-refresh", "Administration → Tasks",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("timed out: %q lacks %q", detail, want)
		}
	}

	failed := &pbsclient.Error{Method: http.MethodGet, Path: "/status/datastore-usage",
		StatusCode: http.StatusInternalServerError, Message: "unable to read rrd"}
	if detail := datastoreUsageFailedDetail(client, failed); detail != failed.Error() {
		t.Errorf("failed: %q, want PBS's error alone", detail)
	}
}
