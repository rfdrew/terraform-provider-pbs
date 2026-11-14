package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// What PBS 4.x does when asked to renew its certificate, read in its source
// (src/api2/node/certificates.rs: renew_acme_cert, check_renewal_needed,
// cert_renew_lead_time, spawn_certificate_worker;
// src/bin/proxmox-daily-update.rs: check_acme_certificates;
// src/server/notifications/mod.rs: send_certificate_renewal_mail;
// proxmox-backup 7c86c5ad5, after 4.2.11, and the tags v4.1.8 to v4.2.10):
//
//   - PUT /nodes/{node}/certificates/acme/certificate renews the certificate
//     the proxy serves, proxy.pem, whatever it is: PBS cannot tell an ACME
//     certificate from an uploaded one, or from the self-signed one it
//     generated. It needs Sys.Modify on /system/certificates.
//   - Without force, PBS first checks whether the certificate is due and,
//     when it is not, answers 400 "Certificate does not expire within the
//     next {days} days and 'force' is not set." at once, without a task.
//     The certificate is due once it expires within the renewal lead time:
//     30 days before 4.1.9; from 4.1.9 a third of its lifetime, at least 3
//     days; from 4.1.10 half of it for a certificate that lives less than
//     10 days. days is the lead time, rounded down. A certificate whose
//     dates PBS cannot read falls back to 30 days. The self-signed
//     certificate PBS generates lives 1000 years, so it is never due.
//   - Otherwise, or with force, which only skips that check, it answers the
//     UPID of an acme-renew-cert task, which does what the acme-new-cert
//     task of POST does (see certificates.go): it orders a certificate for
//     the node's ACME domains with its ACME account, writes it to proxy.pem
//     and has the proxy load it; for a node without domains it logs "No
//     domains configured to be ordered from an ACME server." and ends OK
//     with the certificate unchanged. A missing account or plugin fails the
//     task. Released PBS cannot stop the task: it polls the CA for as long
//     as the CA keeps the order pending.
//   - A task that fails sends PBS's acme-err notification, with severity
//     error from 4.2.6.
//   - The daily update, proxmox-daily-update, makes the same call without
//     force, on a node with ACME domains, so PBS renews a certificate once it
//     is due without anyone asking.

// acmeNotDuePattern is PBS's refusal to renew a certificate that is not due.
var acmeNotDuePattern = regexp.MustCompile(`^Certificate does not expire within the next (-?\d+) days and 'force' is not set\.?$`)

// RenewACMECertificate has a node renew its certificate with ACME — only when
// it is due, unless force is set — and returns the UPID of the task that
// orders the new certificate. Run it through ChangeCertificate, and wait for
// the task within the change. A certificate that is not due is an error
// IsACMENotDue reports.
func (c *Client) RenewACMECertificate(ctx context.Context, node string, force bool) (UPID, error) {
	var params url.Values
	if force {
		params = url.Values{"force": {FormatBool(true)}}
	}
	return c.StartTask(ctx, http.MethodPut, Path("nodes", node, "certificates", "acme", "certificate"), params)
}

// IsACMENotDue reports whether PBS refused to renew a certificate because it
// is not due yet and force was not set.
func IsACMENotDue(err error) bool {
	_, ok := ACMERenewalLeadDays(err)
	return ok
}

// ACMERenewalLeadDays returns, from PBS's refusal to renew a certificate that
// is not due, the renewal lead time it named, in days: PBS renews the
// certificate once it expires within that many days. ok is false for any
// other error.
func ACMERenewalLeadDays(err error) (days int64, ok bool) {
	apiErr, isAPIError := asError(err)
	if !isAPIError || apiErr.StatusCode != http.StatusBadRequest {
		return 0, false
	}
	match := acmeNotDuePattern.FindStringSubmatch(apiErr.Message)
	if match == nil {
		return 0, false
	}
	days, parseErr := strconv.ParseInt(match[1], 10, 64)
	return days, parseErr == nil
}
