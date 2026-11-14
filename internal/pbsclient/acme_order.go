package pbsclient

import (
	"errors"
	"regexp"
	"strings"
)

// Why an ACME order task of PBS fails — acme-new-cert, which POST
// /nodes/{node}/certificates/acme/certificate starts, or acme-renew-cert,
// PUT's —, read in its source: proxmox-backup src/api2/node/certificates.rs
// (spawn_certificate_worker) and src/config/mod.rs (set_proxy_certificate,
// create_configdir), 7c86c5ad5, after 4.2.11; the order itself, from PBS
// 4.1.2 on, in proxmox-acme-api (src/certificate_helpers.rs,
// account_config.rs, acme_plugin.rs) and proxmox-acme (async_client.rs,
// error.rs), proxmox 601a11e6, with the texts of the released
// proxmox-acme-api 1.0.2 (09a1f406), which PBS pins; before 4.1.2, PBS's own
// src/api2/node/certificates.rs, src/acme/client.rs and src/acme/plugin.rs,
// with the same texts (v4.0.11):
//
//   - The task's exit status is the first line of its error, `{err:#}`
//     (proxmox-rest-server worker_task.rs), and PBS adds no context to the
//     errors of an order: it is the text of the step that failed. A task
//     whose process ended without writing a result — it crashed or was
//     killed, systemd killed it after its stop timeout, the host rebooted —
//     reads "unknown". Upgrading the package reloads the API daemon, and
//     both reload and stop wait for the tasks that run (src/bin/
//     proxmox-backup-api.rs).
//   - PBS loads the node's ACME account before it asks the CA anything:
//     "acme account '<name>' does not exist", "failed to load acme account
//     from <path> - <error>", "failed to parse acme account from <path> -
//     <error>" (account_config.rs). The provider reads the same file through
//     the same function before it orders, so these mean the account went
//     away in between.
//   - PBS then places the order, and for each authorization the CA has not
//     validated yet looks up the domain's plugin — "plugin '<id>' for domain
//     '<domain>' not found!" — and the plugin's challenge: "no supported
//     challenge type (dns-01) found", or "(http-01)" (acme_plugin.rs). A
//     domain whose authorization the CA reuses needs no plugin at all.
//   - A DNS plugin runs `/usr/share/proxmox-acme/proxmox-acme setup <api>
//     <domain>`, whose output goes to the task log, and fails "'/usr/share/
//     proxmox-acme/proxmox-acme setup' exited with error (<code>)", or
//     "'/usr/share/proxmox-acme/proxmox-acme' failed: <error>" when PBS could
//     not talk to it — after waiting the plugin's validation delay all the
//     same. A domain without a plugin is validated by the standalone plugin,
//     which listens on port 80, [::]:80 and then 0.0.0.0:80, and fails with
//     the bare error of the second: "Address already in use (os error 98)"
//     when another process holds the port — another order too: PBS's daily
//     update renews the certificate without a lock
//     (src/bin/proxmox-daily-update.rs).
//   - The CA's refusals read "urn:ietf:params:acme:error:<type>: <detail>"
//     (proxmox-acme error.rs): rateLimited, caa, rejectedIdentifier,
//     accountDoesNotExist, userActionRequired and the others of RFC 8555.
//     An account deactivated — by a client holding its key — or revoked by
//     the CA is refused as unauthorized (RFC 8555, 7.1.2 and 7.3.6), with a
//     detail that names its status: Boulder's, Let's Encrypt's, "Account is
//     not valid, has status \"deactivated\"" (or "revoked"; wfe2/verify.go,
//     lookupJWK, 3fbb18e7), Pebble's "Account has been deactivated"
//     (wfe/wfe.go, getAcctByKey, b8fcbe41). PBS places the order with the
//     account it stored without looking at its status (proxmox-acme-api
//     certificate_helpers.rs, order_certificate), so the CA is the one to
//     refuse it.
//   - A challenge the CA does not accept ends "validating challenge '<url>'
//     failed - status: Invalid" (or Expired, Revoked, Deactivated): PBS
//     drops the CA's reason, and does not name the domain. An order the CA
//     turns invalid after the domains were validated ends "order status:
//     Invalid".
//   - A CA that answers what PBS cannot use: "kept getting a badNonce
//     error!", "Acme Server API misbehaved: <error>", "missing 'finalize'
//     URL in order", "missing certificate url in finalized order", "no
//     config for domain '<domain>'" (the CA named a domain PBS did not ask
//     for).
//   - Not reaching the CA: proxmox-acme keeps only the outermost text of its
//     HTTP client's error, hyper-util's "client error (Connect)" for a
//     connection that could not be made — inferred, hyper-util is not among
//     these sources —; "failed to retrieve response body: <error>"; and
//     "error status with improper error ACME response: <error>" when
//     something other than an ACME server answers with an error. The client
//     connects directly, without the node's http_proxy: proxmox-acme builds
//     it with proxy_config None (async_client.rs), PBS 4.0 with
//     pbs_simple_http(None) (src/acme/client.rs, v4.0.11).
//   - Once the CA has issued the certificate, PBS writes it
//     (set_proxy_certificate): first its configuration directory is checked
//     — "configuration directory '/etc/proxmox-backup' permission problem -
//     wrong user|group|permission (...)", "unable to create configuration
//     directory '...' - ...", "unable to set configuration directory '...'
//     permissions - ..." —, with nothing written; then the key, proxy.key —
//     "error writing certificate private key - <error>", with the key
//     unchanged, since each file is written to a temporary file renamed
//     into place (proxmox-sys replace_file) —; then the certificate,
//     proxy.pem — "error writing certificate file - <error>", after the key
//     was replaced, so that the key no longer matches the certificate the
//     proxy serves, and the proxy would refuse the pair at its next start
//     (proxmox-rest-server connection.rs, check_private_key). The CA counts
//     the certificate against its rate limits all the same.
//   - Having the proxy load the certificate comes after proxy.pem is
//     written, so a failure there leaves a changed certificate, which
//     ChangeCertificate reports. A failure to send PBS's acme-err
//     notification replaces the order's error ("Could not instantiate
//     notification bus: ...", or a parse error of notifications.cfg).
//   - Unreleased proxmox-acme-api (511d6678, e5b0d1cb, after 1.0.2) gives up
//     on a validation or a finalization after five minutes: "ACME validation
//     for '<domain>' timed out", "ACME order finalization timed out".

// ACMEOrderCause is why an ACME order or renewal task failed.
type ACMEOrderCause int

const (
	// ACMEOrderFailed: an exit status the provider does not know.
	ACMEOrderFailed ACMEOrderCause = iota
	// ACMEOrderNoResult: exit status "unknown", the process that ran the
	// task ended mid-task.
	ACMEOrderNoResult
	// ACMEOrderAccountUnreadable: PBS could not load the node's ACME
	// account, and asked the CA nothing.
	ACMEOrderAccountUnreadable
	// ACMEOrderPluginMissing: a domain names a plugin PBS does not have;
	// Plugin and Domain name them.
	ACMEOrderPluginMissing
	// ACMEOrderNoHTTPChallenge: the CA offers no HTTP challenge for a domain
	// without a DNS plugin.
	ACMEOrderNoHTTPChallenge
	// ACMEOrderNoDNSChallenge: the CA offers no DNS challenge for a domain
	// with a DNS plugin.
	ACMEOrderNoDNSChallenge
	// ACMEOrderDNSPluginFailed: the DNS plugin's script failed to set the
	// TXT record; its output is in the task log.
	ACMEOrderDNSPluginFailed
	// ACMEOrderPort80InUse: PBS could not listen on port 80 for an HTTP
	// challenge.
	ACMEOrderPort80InUse
	// ACMEOrderCAUnreachable: PBS could not talk to the CA.
	ACMEOrderCAUnreachable
	// ACMEOrderAccountRefused: the CA refused the account, CAError says how:
	// accountDoesNotExist, userActionRequired, or unauthorized for an
	// account deactivated or revoked.
	ACMEOrderAccountRefused
	// ACMEOrderRateLimited: the CA refused the order for its rate limits.
	ACMEOrderRateLimited
	// ACMEOrderValidationFailed: the CA did not validate a domain; Status is
	// the challenge's status, or Domain the domain whose validation timed
	// out.
	ACMEOrderValidationFailed
	// ACMEOrderRefused: the CA refused the order, with the error CAError, or
	// turned it to Status after validation.
	ACMEOrderRefused
	// ACMEOrderCAMisbehaved: the CA answered what PBS cannot use.
	ACMEOrderCAMisbehaved
	// ACMEOrderNotWritten: the CA issued a certificate, but PBS could not
	// write it; KeyReplaced and ConfigDirectory say how far it got.
	ACMEOrderNotWritten
)

// ACMEOrderFailure is why an ACME order or renewal task failed, read from
// its exit status.
type ACMEOrderFailure struct {
	Cause ACMEOrderCause
	// ExitStatus is the task's exit status, as PBS wrote it.
	ExitStatus string
	// CAError is the type of the CA's error, without its URN prefix, such as
	// "rateLimited" or "caa".
	CAError string
	// Status is the status PBS named, as it writes it: "Invalid".
	Status string
	// Plugin and Domain are the plugin and domain the exit status names.
	Plugin, Domain string
	// KeyReplaced is set for ACMEOrderNotWritten when PBS had written the
	// new key, proxy.key, but not the certificate.
	KeyReplaced bool
	// ConfigDirectory is set for ACMEOrderNotWritten when PBS's
	// configuration directory stopped it before it wrote anything.
	ConfigDirectory bool
}

// The exit statuses ACMEOrderFailureOf matches in full, or in part.
var (
	acmeAccountMissingPattern  = regexp.MustCompile(`^acme account '[^']*' does not exist$`)
	acmePluginMissingPattern   = regexp.MustCompile(`^plugin '([^']*)' for domain '([^']*)' not found!$`)
	acmeNoChallengePattern     = regexp.MustCompile(`^no supported challenge type \((http-01|dns-01)\) found$`)
	acmeCAErrorPattern         = regexp.MustCompile(`urn:ietf:params:acme:error:([A-Za-z]+)`)
	acmeAccountInvalidPattern  = regexp.MustCompile(`(?i)account is not valid|account has been deactivated|has status "(?:deactivated|revoked)"`)
	acmeChallengeFailedPattern = regexp.MustCompile(`^validating challenge '[^']*' failed - status: (\w+)$`)
	acmeValidationTimedOut     = regexp.MustCompile(`^ACME validation for '([^']*)' timed out$`)
	acmeOrderStatusPattern     = regexp.MustCompile(`^order status: (\w+)$`)
)

// acmeDNSPluginScript is the script PBS runs for a DNS plugin.
const acmeDNSPluginScript = "/usr/share/proxmox-acme/proxmox-acme"

// ACMEOrderFailureOf reads why an ACME order or renewal task failed from
// the *TaskError in err, which errors.As finds also in an error joined with
// others, as ChangeCertificate joins it with a failed read. ok is false
// without a task error. The first rule that matches wins.
func ACMEOrderFailureOf(err error) (failure ACMEOrderFailure, ok bool) {
	var taskErr *TaskError
	if !errors.As(err, &taskErr) {
		return ACMEOrderFailure{}, false
	}
	exit := strings.TrimSpace(taskErr.ExitStatus)
	failure = ACMEOrderFailure{ExitStatus: taskErr.ExitStatus}
	hasPrefix := func(prefixes ...string) bool {
		for _, prefix := range prefixes {
			if strings.HasPrefix(exit, prefix) {
				return true
			}
		}
		return false
	}
	switch {
	case exit == "unknown":
		failure.Cause = ACMEOrderNoResult
	case acmeAccountMissingPattern.MatchString(exit),
		hasPrefix("failed to load acme account from ", "failed to parse acme account from "):
		failure.Cause = ACMEOrderAccountUnreadable
	case acmePluginMissingPattern.MatchString(exit):
		match := acmePluginMissingPattern.FindStringSubmatch(exit)
		failure.Cause, failure.Plugin, failure.Domain = ACMEOrderPluginMissing, match[1], match[2]
	case acmeNoChallengePattern.MatchString(exit):
		failure.Cause = ACMEOrderNoDNSChallenge
		if acmeNoChallengePattern.FindStringSubmatch(exit)[1] == "http-01" {
			failure.Cause = ACMEOrderNoHTTPChallenge
		}
	case hasPrefix("'"+acmeDNSPluginScript+" setup' exited with error (", "'"+acmeDNSPluginScript+"' failed: "):
		failure.Cause = ACMEOrderDNSPluginFailed
	case strings.HasSuffix(exit, "(os error 98)"):
		// EADDRINUSE: the standalone plugin's listener is the only socket
		// an order binds.
		failure.Cause = ACMEOrderPort80InUse
	case acmeCAErrorPattern.MatchString(exit):
		failure.CAError = acmeCAErrorPattern.FindStringSubmatch(exit)[1]
		switch failure.CAError {
		case "rateLimited":
			failure.Cause = ACMEOrderRateLimited
		case "accountDoesNotExist", "userActionRequired":
			failure.Cause = ACMEOrderAccountRefused
		case "unauthorized":
			// The CA refuses other requests as unauthorized too, such as
			// one for an order of another account.
			failure.Cause = ACMEOrderRefused
			if acmeAccountInvalidPattern.MatchString(exit) {
				failure.Cause = ACMEOrderAccountRefused
			}
		default:
			failure.Cause = ACMEOrderRefused
		}
	case acmeChallengeFailedPattern.MatchString(exit):
		failure.Cause, failure.Status = ACMEOrderValidationFailed, acmeChallengeFailedPattern.FindStringSubmatch(exit)[1]
	case acmeValidationTimedOut.MatchString(exit):
		failure.Cause, failure.Domain = ACMEOrderValidationFailed, acmeValidationTimedOut.FindStringSubmatch(exit)[1]
	case acmeOrderStatusPattern.MatchString(exit):
		failure.Cause, failure.Status = ACMEOrderRefused, acmeOrderStatusPattern.FindStringSubmatch(exit)[1]
	case exit == "kept getting a badNonce error!", exit == "ACME order finalization timed out",
		hasPrefix("Acme Server API misbehaved: ", "missing 'finalize' URL", "missing certificate url", "no config for domain '"):
		failure.Cause = ACMEOrderCAMisbehaved
	case hasPrefix("client error (", "failed to retrieve response body: ", "error status with improper error ACME response: "):
		failure.Cause = ACMEOrderCAUnreachable
	case strings.HasPrefix(exit, "configuration directory '") && strings.Contains(exit, "' permission problem - "),
		hasPrefix("unable to create configuration directory '", "unable to set configuration directory '"):
		failure.Cause, failure.ConfigDirectory = ACMEOrderNotWritten, true
	case hasPrefix("error writing certificate private key - "):
		failure.Cause = ACMEOrderNotWritten
	case hasPrefix("error writing certificate file - "):
		failure.Cause, failure.KeyReplaced = ACMEOrderNotWritten, true
	default:
		failure.Cause = ACMEOrderFailed
	}
	return failure, true
}
