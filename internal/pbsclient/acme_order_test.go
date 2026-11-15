package pbsclient

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// The exit statuses are those PBS writes (see acme_order.go), but for
// "client error (Connect)", which is inferred.
func TestACMEOrderFailureOf(t *testing.T) {
	upid, err := ParseUPID("UPID:localhost:00000A1B:00001C2D:00000004:6AE11CDF:acme-new-cert::tfacc@pbs!acc:")
	if err != nil {
		t.Fatal(err)
	}
	failed := func(exit string) error { return &TaskError{UPID: upid, ExitStatus: exit} }
	for _, tc := range []struct {
		exit string
		want ACMEOrderFailure
	}{
		{"unknown", ACMEOrderFailure{Cause: ACMEOrderNoResult}},
		{"acme account 'default' does not exist", ACMEOrderFailure{Cause: ACMEOrderAccountUnreadable}},
		{`failed to load acme account from "/etc/proxmox-backup/acme/accounts/default" - Permission denied (os error 13)`,
			ACMEOrderFailure{Cause: ACMEOrderAccountUnreadable}},
		{"failed to parse acme account from '/etc/proxmox-backup/acme/accounts/le' - EOF while parsing a value at line 1 column 0",
			ACMEOrderFailure{Cause: ACMEOrderAccountUnreadable}},
		{"plugin 'cf' for domain 'pbs.example.org' not found!", ACMEOrderFailure{Cause: ACMEOrderPluginMissing, Plugin: "cf", Domain: "pbs.example.org"}},
		{"no supported challenge type (http-01) found", ACMEOrderFailure{Cause: ACMEOrderNoHTTPChallenge}},
		{"no supported challenge type (dns-01) found", ACMEOrderFailure{Cause: ACMEOrderNoDNSChallenge}},
		{"'/usr/share/proxmox-acme/proxmox-acme setup' exited with error (1)", ACMEOrderFailure{Cause: ACMEOrderDNSPluginFailed}},
		{"'/usr/share/proxmox-acme/proxmox-acme' failed: Broken pipe (os error 32)", ACMEOrderFailure{Cause: ACMEOrderDNSPluginFailed}},
		{"Address already in use (os error 98)", ACMEOrderFailure{Cause: ACMEOrderPort80InUse}},
		{"client error (Connect)", ACMEOrderFailure{Cause: ACMEOrderCAUnreachable}},
		{"failed to retrieve response body: error reading a body from connection", ACMEOrderFailure{Cause: ACMEOrderCAUnreachable}},
		{"error status with improper error ACME response: expected value at line 1 column 1", ACMEOrderFailure{Cause: ACMEOrderCAUnreachable}},
		{"urn:ietf:params:acme:error:rateLimited: too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s",
			ACMEOrderFailure{Cause: ACMEOrderRateLimited, CAError: "rateLimited"}},
		{"urn:ietf:params:acme:error:accountDoesNotExist: unable to find existing account for only-return-existing request",
			ACMEOrderFailure{Cause: ACMEOrderAccountRefused, CAError: "accountDoesNotExist"}},
		{"urn:ietf:params:acme:error:userActionRequired: please agree to the new terms of service",
			ACMEOrderFailure{Cause: ACMEOrderAccountRefused, CAError: "userActionRequired"}},
		// An account the CA deactivated or revoked, in Boulder's words and
		// Pebble's (see acme_order.go); the last one is made up, to show
		// that case does not matter.
		{`urn:ietf:params:acme:error:unauthorized: Account is not valid, has status "deactivated"`,
			ACMEOrderFailure{Cause: ACMEOrderAccountRefused, CAError: "unauthorized"}},
		{`urn:ietf:params:acme:error:unauthorized: Account is not valid, has status "revoked"`,
			ACMEOrderFailure{Cause: ACMEOrderAccountRefused, CAError: "unauthorized"}},
		{"urn:ietf:params:acme:error:unauthorized: Account has been deactivated",
			ACMEOrderFailure{Cause: ACMEOrderAccountRefused, CAError: "unauthorized"}},
		{`urn:ietf:params:acme:error:unauthorized: account has status "Revoked"`,
			ACMEOrderFailure{Cause: ACMEOrderAccountRefused, CAError: "unauthorized"}},
		// Any other refusal as unauthorized is the order's, also when it
		// names the account (Pebble's FinalizeOrder).
		{"urn:ietf:params:acme:error:unauthorized: Account that authenticated the request does not own the specified order",
			ACMEOrderFailure{Cause: ACMEOrderRefused, CAError: "unauthorized"}},
		{"urn:ietf:params:acme:error:unauthorized", ACMEOrderFailure{Cause: ACMEOrderRefused, CAError: "unauthorized"}},
		{"urn:ietf:params:acme:error:caa: CAA record for pbs.example.org prevents issuance",
			ACMEOrderFailure{Cause: ACMEOrderRefused, CAError: "caa"}},
		{"urn:ietf:params:acme:error:rejectedIdentifier", ACMEOrderFailure{Cause: ACMEOrderRefused, CAError: "rejectedIdentifier"}},
		{"validating challenge 'https://acme-v02.api.letsencrypt.org/acme/chall/1/2/abc' failed - status: Invalid",
			ACMEOrderFailure{Cause: ACMEOrderValidationFailed, Status: "Invalid"}},
		{"ACME validation for 'pbs.example.org' timed out", ACMEOrderFailure{Cause: ACMEOrderValidationFailed, Domain: "pbs.example.org"}},
		{"order status: Invalid", ACMEOrderFailure{Cause: ACMEOrderRefused, Status: "Invalid"}},
		{"kept getting a badNonce error!", ACMEOrderFailure{Cause: ACMEOrderCAMisbehaved}},
		{"Acme Server API misbehaved: badNonce without a new Replay-Nonce header", ACMEOrderFailure{Cause: ACMEOrderCAMisbehaved}},
		{"missing certificate url in finalized order", ACMEOrderFailure{Cause: ACMEOrderCAMisbehaved}},
		{"no config for domain 'www.example.org'", ACMEOrderFailure{Cause: ACMEOrderCAMisbehaved}},
		{"ACME order finalization timed out", ACMEOrderFailure{Cause: ACMEOrderCAMisbehaved}},
		{"configuration directory '/etc/proxmox-backup' permission problem - wrong permission (755 != 700)",
			ACMEOrderFailure{Cause: ACMEOrderNotWritten, ConfigDirectory: true}},
		{"unable to create configuration directory '/etc/proxmox-backup' - EROFS: Read-only file system",
			ACMEOrderFailure{Cause: ACMEOrderNotWritten, ConfigDirectory: true}},
		{"error writing certificate private key - No space left on device (os error 28)", ACMEOrderFailure{Cause: ACMEOrderNotWritten}},
		{"error writing certificate file - No space left on device (os error 28)", ACMEOrderFailure{Cause: ACMEOrderNotWritten, KeyReplaced: true}},
		{"Could not instantiate notification bus: x", ACMEOrderFailure{Cause: ACMEOrderFailed}},
		{"TXT record _acme-challenge.pbs.example.org not found", ACMEOrderFailure{Cause: ACMEOrderFailed}},
	} {
		tc.want.ExitStatus = tc.exit
		got, ok := ACMEOrderFailureOf(fmt.Errorf("ordering: %w", failed(tc.exit)))
		if !ok || got != tc.want {
			t.Errorf("ACMEOrderFailureOf(%q) = %+v, %v, want %+v", tc.exit, got, ok, tc.want)
		}
	}

	// The task's error is found where ChangeCertificate puts it, next to a
	// failed read of the certificate afterwards.
	joined := errors.Join(failed("Address already in use (os error 98)"), &CertificateReadError{After: true, Err: errors.New("connection reset")})
	if got, ok := ACMEOrderFailureOf(joined); !ok || got.Cause != ACMEOrderPort80InUse {
		t.Errorf("ACMEOrderFailureOf(joined) = %+v, %v", got, ok)
	}
	if _, ok := ACMEOrderFailureOf(&Error{StatusCode: http.StatusForbidden, Message: "permission check failed"}); ok {
		t.Error("ACMEOrderFailureOf() read a cause from an HTTP error")
	}
	if _, ok := ACMEOrderFailureOf(nil); ok {
		t.Error("ACMEOrderFailureOf(nil) read a cause")
	}
}
