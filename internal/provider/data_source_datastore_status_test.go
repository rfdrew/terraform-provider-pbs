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
