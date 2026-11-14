package provider

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestS3EndpointCheckActionPasses(t *testing.T) {
	fake := newFakePBS()
	const route = "PUT /admin/s3/ep1/check"
	fake.reply(route, http.StatusOK, `{"data":null}`)
	h := newProtocolHarness(t, fake)
	got := h.invokeAction(t, "pbs_s3_endpoint_check", map[string]any{"s3_endpoint": "ep1", "bucket": "backups", "store_prefix": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, `wrote, read and deleted object "store1/.s3-client-test"`)
	call := fake.lastCall(t, route)
	if call.form.Get("bucket") != "backups" || call.form.Get("store-prefix") != "store1" {
		t.Fatalf("form = %v", call.form)
	}

	// Without a prefix, the object is at the top of the bucket.
	got = h.invokeAction(t, "pbs_s3_endpoint_check", map[string]any{"s3_endpoint": "ep1", "bucket": "backups"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, `object ".s3-client-test"`)
	if fake.lastCall(t, route).form.Has("store-prefix") {
		t.Fatalf("form = %v", fake.lastCall(t, route).form)
	}
}

// PBS names the step that failed, and nothing else: the action says what
// usually causes it.
func TestS3EndpointCheckActionFailures(t *testing.T) {
	for _, tc := range []struct {
		body, summary, want string
		status              int
	}{
		{"config lookup failed", "Unable to check PBS S3 endpoint ep1", `PBS has no S3 endpoint "ep1"`, http.StatusBadRequest},
		{"client creation failed", "PBS S3 endpoint check failed", "could not open its request counters under /var/lib/proxmox-backup/s3-statistics", http.StatusBadRequest},
		{"head object failed", "PBS S3 endpoint check failed", `could not reach bucket "backups"`, http.StatusBadRequest},
		{"put object failed", "PBS S3 endpoint check failed", "s3:PutObject", http.StatusBadRequest},
		{"get object failed", "PBS S3 endpoint check failed", "s3:GetObject", http.StatusBadRequest},
		{"delete object failed", "PBS S3 endpoint check failed", `could not delete it: the access key may not delete objects (s3:DeleteObject)`, http.StatusBadRequest},
		{"permission check failed", "Unable to check PBS S3 endpoint ep1", "Sys.Modify on /", http.StatusForbidden},
	} {
		t.Run(tc.body, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("PUT /admin/s3/ep1/check", tc.status, tc.body)
			h := newProtocolHarness(t, fake)
			got := h.invokeAction(t, "pbs_s3_endpoint_check", map[string]any{"s3_endpoint": "ep1", "bucket": "backups", "store_prefix": "store1"})
			requireProtocolErrorContaining(t, got.diagnostics, tc.summary)
			requireProtocolErrorContaining(t, got.diagnostics, tc.want)
			if tc.status == http.StatusBadRequest && tc.body != "config lookup failed" {
				requireProtocolErrorContaining(t, got.diagnostics, "`proxmox-backup-manager s3 check ep1 backups`")
			}
		})
	}
}

// hangingS3Check is a PBS whose S3 check does not answer before the
// request's time runs out, as with an object store that does not answer.
type hangingS3Check struct {
	fake *fakePBS
}

func (h hangingS3Check) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPut && strings.HasSuffix(req.URL.Path, "/admin/s3/ep1/check") {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	return h.fake.RoundTrip(req)
}

// The check takes PBS over half a minute to fail when the object store does
// not answer, longer than the provider's request timeout: the action waits
// as long as its own timeout says.
func TestS3EndpointCheckActionTimeout(t *testing.T) {
	fake := newFakePBS()
	h := newProtocolHarness(t, fake, withTransport(hangingS3Check{fake}))
	start := time.Now()
	got := h.invokeAction(t, "pbs_s3_endpoint_check", map[string]any{"s3_endpoint": "ep1", "bucket": "backups", "timeout": "1s"})
	if elapsed := time.Since(start); elapsed < time.Second || elapsed > 10*time.Second {
		t.Fatalf("the check took %s, with a timeout of 1s", elapsed)
	}
	requireProtocolErrorContaining(t, got.diagnostics, "PBS S3 endpoint check did not finish")
	requireProtocolErrorContaining(t, got.diagnostics, "PBS did not answer within 1s")
	requireProtocolErrorContaining(t, got.diagnostics, "raise the action's `timeout`")
}

func TestS3EndpointCheckActionValidation(t *testing.T) {
	fake := newFakePBS()
	h := newProtocolHarness(t, fake)
	configured := len(fake.routes())
	valid := map[string]any{"s3_endpoint": "ep1", "bucket": "backups"}
	with := func(key string, value any) map[string]any {
		attrs := map[string]any{}
		for k, v := range valid {
			attrs[k] = v
		}
		attrs[key] = value
		return attrs
	}
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{with("s3_endpoint", "e"), "s3_endpoint"},
		{with("bucket", "Backups"), "lower-case"},
		{with("bucket", "xn--backups"), "must not start with xn--"},
		{with("store_prefix", ""), "store_prefix"},
		{with("store_prefix", "store1/"), "slash"},
		{with("store_prefix", " store1"), "white space"},
		{with("timeout", "-1m"), "positive duration"},
	} {
		requireProtocolErrorContaining(t, h.validateAction(t, "pbs_s3_endpoint_check", h.actionValue(t, "pbs_s3_endpoint_check", tc.attrs)), tc.want)
	}
	unknown := h.actionValue(t, "pbs_s3_endpoint_check", map[string]any{
		"s3_endpoint": tfUnknown, "bucket": tfUnknown, "store_prefix": tfUnknown, "timeout": tfUnknown,
	})
	requireNoProtocolErrors(t, h.validateAction(t, "pbs_s3_endpoint_check", unknown))
	requireNoProtocolErrors(t, h.planAction(t, "pbs_s3_endpoint_check", unknown))
	if routes := fake.routes(); len(routes) != configured {
		t.Fatalf("validating and planning called PBS: %v", routes[configured:])
	}
}
