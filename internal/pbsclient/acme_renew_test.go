package pbsclient

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

const renewRoute = "PUT /nodes/localhost/certificates/acme/certificate"

// A renewal answers the UPID of its task, and sends force only when asked
// to: PBS's daily update renews without it.
func TestRenewACMECertificate(t *testing.T) {
	fake := newFakePBS()
	const upid = "UPID:pbs-acc:00000002:00000002:00000001:6AE11CDF:acme-renew-cert::tfacc@pbs!acc:"
	fake.reply(renewRoute, http.StatusOK, `{"data":"`+upid+`"}`)
	c := fake.client(t)

	for _, force := range []bool{false, true} {
		got, err := c.RenewACMECertificate(context.Background(), "localhost", force)
		if err != nil {
			t.Fatal(err)
		}
		if got.Raw != upid || got.WorkerType != "acme-renew-cert" {
			t.Fatalf("UPID = %+v", got)
		}
		sent := fake.lastCall(t, renewRoute).form
		if force && sent.Get("force") != "true" || !force && sent.Has("force") {
			t.Fatalf("force %v sent %v", force, sent)
		}
	}
}

// PBS refuses to renew a certificate that is not due, without force, with a
// 400 that names the lead time: 30 days before PBS 4.1.9, a share of the
// certificate's lifetime since.
func TestIsACMENotDue(t *testing.T) {
	fake := newFakePBS()
	fake.replies(renewRoute, http.StatusBadRequest,
		"Certificate does not expire within the next 30 days and 'force' is not set.",
		"Certificate does not expire within the next 121666 days and 'force' is not set.\n")
	c := fake.client(t)
	for _, want := range []int64{30, 121666} {
		_, err := c.RenewACMECertificate(context.Background(), "localhost", false)
		if !IsACMENotDue(err) {
			t.Fatalf("IsACMENotDue(%v) = false", err)
		}
		if days, ok := ACMERenewalLeadDays(err); !ok || days != want {
			t.Fatalf("ACMERenewalLeadDays(%v) = %d, %v; want %d", err, days, ok, want)
		}
	}

	for _, err := range []error{
		nil,
		errors.New("Certificate does not expire within the next 30 days and 'force' is not set."),
		&Error{StatusCode: http.StatusForbidden, Message: "permission check failed"},
		&Error{StatusCode: http.StatusBadRequest, Message: "acme account 'default' does not exist"},
		&Error{StatusCode: http.StatusInternalServerError, Message: "Certificate does not expire within the next 30 days and 'force' is not set."},
	} {
		if IsACMENotDue(err) {
			t.Errorf("IsACMENotDue(%v) = true", err)
		}
	}
}
