package pbsclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// The proxy, proxmox-backup-proxy, serves the API and the web interface on
// port 8007 with one certificate, proxy.pem. What PBS 4.0 and 4.2 do with it,
// read in their source (src/api2/node/certificates.rs, proxmox-acme-api):
//
//   - GET /nodes/{node}/certificates/info describes it: the first
//     certificate of proxy.pem, with its fingerprint, and the PEM of the
//     whole file. It needs Sys.Modify on /system/certificates.
//   - POST /nodes/{node}/certificates/acme/certificate answers with the
//     UPID of an acme-new-cert task, which orders a certificate for the
//     node's ACME domains with its ACME account, writes it to proxy.pem and
//     has the proxy load it. A node without domains is no error: the task
//     logs "No domains configured" and ends OK without a new certificate.
//   - DELETE /nodes/{node}/certificates/custom deletes proxy.pem, generates
//     a new self-signed certificate — with a new key, so a new fingerprint
//     — and has the proxy load it, before it answers; there is no task.
//   - The proxy loads a new certificate by a command on its control socket,
//     without restarting: it keeps listening, and connections already open
//     keep the certificate they started with. Only new connections get the
//     new one.
//
// PBS also renews an ACME certificate on its own, in its daily update, once
// two thirds of its lifetime have passed (30 days before it expires before
// PBS 4.1.9), so the certificate — and its fingerprint — changes without
// anyone asking.

// ProxyCertificateFile is the certificate the PBS proxy serves on port 8007,
// the one clients pin.
const ProxyCertificateFile = "proxy.pem"

// CertificateInfo is one entry of GET /nodes/{node}/certificates/info.
type CertificateInfo struct {
	Filename string `json:"filename"`
	// Fingerprint is the SHA-256 fingerprint, as colon-separated lower-case
	// hex pairs.
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   int64  `json:"notbefore"`
	NotAfter    int64  `json:"notafter"`
	// SAN are the DNS names among the subject alternative names.
	SAN []string `json:"san"`
	// PEM is the whole file: the certificate and the chain after it.
	PEM string `json:"pem"`
	// PublicKeyType is e.g. "rsaEncryption", PublicKeyBits its size.
	PublicKeyType string `json:"public-key-type"`
	PublicKeyBits int64  `json:"public-key-bits"`
}

// SelfSigned reports whether the certificate names itself as its issuer, as
// the one PBS generates does.
func (i CertificateInfo) SelfSigned() bool { return i.Issuer == i.Subject }

// Certificates reads the certificates of the client's node. It needs
// Sys.Modify on /system/certificates.
func (c *Client) Certificates(ctx context.Context) ([]CertificateInfo, error) {
	return c.NodeCertificates(ctx, c.node)
}

// NodeCertificates reads the certificates of a node.
func (c *Client) NodeCertificates(ctx context.Context, node string) ([]CertificateInfo, error) {
	var certs []CertificateInfo
	if _, err := c.Get(ctx, Path("nodes", node, "certificates", "info"), nil, &certs); err != nil {
		return nil, err
	}
	return certs, nil
}

// ProxyCertificate returns the certificate the proxy of the client's node
// serves.
func (c *Client) ProxyCertificate(ctx context.Context) (CertificateInfo, error) {
	return c.NodeProxyCertificate(ctx, c.node)
}

// NodeProxyCertificate returns the certificate the proxy of a node serves.
func (c *Client) NodeProxyCertificate(ctx context.Context, node string) (CertificateInfo, error) {
	certs, err := c.NodeCertificates(ctx, node)
	if err != nil {
		return CertificateInfo{}, err
	}
	for _, cert := range certs {
		if cert.Filename == ProxyCertificateFile {
			return cert, nil
		}
	}
	return CertificateInfo{}, fmt.Errorf("GET %s lists no %s", Path("nodes", node, "certificates", "info"), ProxyCertificateFile)
}

// OrderACMECertificate has a node order a certificate for its ACME domains
// and waits for the task, whose error, such as a failed validation, is a
// *TaskError. Run it through ChangeCertificate.
func (c *Client) OrderACMECertificate(ctx context.Context, node string) error {
	env, err := c.Post(ctx, Path("nodes", node, "certificates", "acme", "certificate"), nil, nil)
	if err != nil {
		return err
	}
	return c.WaitTaskIn(ctx, env.Data)
}

// DeleteCustomCertificate has a node replace its certificate with a new
// self-signed one. Run it through ChangeCertificate.
func (c *Client) DeleteCustomCertificate(ctx context.Context, node string) error {
	_, err := c.Delete(ctx, Path("nodes", node, "certificates", "custom"), nil, nil)
	return err
}

// --- changing the certificate under the client ------------------------------

// When the client has the server change its certificate, the server presents
// another one from then on, which the client's settings may not trust: a
// pinned fingerprint never matches it, and a self-signed certificate never
// verifies against CAs. Every later call would fail, for this resource and
// every other one of the same run.
//
// ChangeCertificate prevents that without trusting whatever the server
// presents next. It makes the change over a connection of its own, opened
// and verified before the change, which keeps the old certificate since the
// proxy does not touch open connections, and over the same connection reads
// what PBS now serves. That answer comes over a connection the client
// trusted, so the client may trust the certificate it describes, and does,
// for the rest of its life. Calls that meet the new certificate while the
// change runs wait for it to end and try again.

// connectionKey is the context key of the HTTP client a call should use
// instead of the client's own: the dedicated connection of a certificate
// change.
type connectionKey struct{}

// httpClientFor returns the HTTP client a call with ctx goes through.
func (c *Client) httpClientFor(ctx context.Context) *http.Client {
	if hc, ok := ctx.Value(connectionKey{}).(*http.Client); ok {
		return hc
	}
	return c.httpClient
}

// dedicatedConnection returns an HTTP client that keeps to one connection,
// and a function that closes it. A test transport, which has no
// connections, is shared.
func (c *Client) dedicatedConnection() (*http.Client, func()) {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return &http.Client{Timeout: c.httpClient.Timeout, Transport: c.httpClient.Transport, CheckRedirect: c.httpClient.CheckRedirect}, func() {}
	}
	single := transport.Clone()
	single.MaxConnsPerHost = 1
	single.MaxIdleConnsPerHost = 1
	return &http.Client{Timeout: c.httpClient.Timeout, Transport: single, CheckRedirect: c.httpClient.CheckRedirect}, single.CloseIdleConnections
}

// awaitCertificateChange decides whether a call that failed with err should
// be tried again: when err is a certificate the client does not trust, a
// certificate change is under way or has made the client trust a new
// certificate since generation. It waits for a change under way to end. A
// call on the change's own connection is never tried again: it would wait
// for itself.
func (c *Client) awaitCertificateChange(ctx context.Context, err error, generation uint64) bool {
	var untrusted *UntrustedCertificateError
	if !errors.As(err, &untrusted) {
		return false
	}
	if _, dedicated := ctx.Value(connectionKey{}).(*http.Client); dedicated {
		return false
	}
	c.changingMu.Lock()
	changing := c.changing
	c.changingMu.Unlock()
	if changing != nil {
		tflog.Debug(ctx, "the PBS certificate is being changed; waiting for the change before trying again")
		select {
		case <-changing:
		case <-ctx.Done():
			return false
		}
	}
	return c.trust.currentGeneration() != generation
}

// UnconfirmedCertificateError means the server's certificate changed, but
// the client could not read the new one over a connection it trusted before
// — the connection of the change closed — so it does not trust it.
type UnconfirmedCertificateError struct {
	// Presented is the fingerprint of the certificate the server presents
	// now, normalised.
	Presented string
	// Err is the failed attempt to read the certificate.
	Err error
}

func (e *UnconfirmedCertificateError) Error() string {
	return fmt.Sprintf("the server now presents a certificate with SHA-256 fingerprint %s, which could not be "+
		"confirmed to be PBS's over a connection trusted before the change: %s", FormatFingerprint(e.Presented), e.Err)
}

func (e *UnconfirmedCertificateError) Unwrap() error { return e.Err }

// CertificateChange is the certificate of the proxy before and after a
// change.
type CertificateChange struct {
	Before CertificateInfo
	// After is empty when the new certificate could not be confirmed.
	After CertificateInfo
	// Unconfirmed is set when the proxy presents another certificate, which
	// could not be read over the connection of the change.
	Unconfirmed *UnconfirmedCertificateError
}

// Changed reports whether the proxy serves another certificate now.
func (c CertificateChange) Changed() bool {
	return c.Unconfirmed != nil || (c.After.Fingerprint != "" && c.Before.Fingerprint != c.After.Fingerprint)
}

// The new certificate is read again after a network error this many times,
// starting this far apart and doubling, in case the proxy was briefly not
// answering.
const (
	certificateReadAttempts = 5
	certificateReadInterval = 250 * time.Millisecond
)

// ChangeCertificate runs change, which has a node change the certificate of
// its proxy — OrderACMECertificate or DeleteCustomCertificate, called with
// the context it is given —, and returns the certificate before and after.
// The client trusts the new certificate from then on, whatever its
// settings say (see above). Certificate changes of one client run one at a
// time.
//
// The certificate is read after change even when change fails, since a task
// may fail after it installed the new certificate; the error is then
// change's. When the proxy presents another certificate that cannot be read
// over the connection of the change, the result's Unconfirmed says so and
// the client does not trust it.
func (c *Client) ChangeCertificate(ctx context.Context, node string, change func(ctx context.Context) error) (CertificateChange, error) {
	c.certificateChange.Lock()
	defer c.certificateChange.Unlock()

	changing := make(chan struct{})
	c.changingMu.Lock()
	c.changing = changing
	c.changingMu.Unlock()
	defer func() {
		c.changingMu.Lock()
		c.changing = nil
		c.changingMu.Unlock()
		close(changing)
	}()

	conn, closeConn := c.dedicatedConnection()
	defer closeConn()
	connCtx := context.WithValue(ctx, connectionKey{}, conn)

	var result CertificateChange
	before, err := c.NodeProxyCertificate(connCtx, node)
	if err != nil {
		return result, fmt.Errorf("reading the certificate before changing it: %w", err)
	}
	result.Before = before

	changeErr := change(connCtx)

	after, readErr := c.readChangedCertificate(connCtx, node)
	var untrusted *UntrustedCertificateError
	switch {
	case errors.As(readErr, &untrusted) && untrusted.Presented() != "":
		result.Unconfirmed = &UnconfirmedCertificateError{Presented: untrusted.Presented(), Err: readErr}
		readErr = nil
	case readErr != nil:
		readErr = fmt.Errorf("reading the certificate after changing it: %w", readErr)
	default:
		// Read over the connection the client trusted before the change:
		// what PBS says it serves now is what the client may trust.
		result.After = after
		if result.Changed() {
			if err := c.TrustCertificate(after.Fingerprint); err != nil {
				readErr = fmt.Errorf("PBS reported the new certificate's fingerprint as %q: %w", after.Fingerprint, err)
			} else {
				tflog.Info(ctx, "PBS changed its certificate; trusting the new one", map[string]any{
					"before": before.Fingerprint, "after": after.Fingerprint,
				})
			}
		}
	}
	return result, errors.Join(changeErr, readErr)
}

// readChangedCertificate reads the proxy's certificate after a change,
// again after a network error: the proxy may not have answered for a moment.
// An error from PBS or a certificate the client does not trust is not tried
// again.
func (c *Client) readChangedCertificate(ctx context.Context, node string) (CertificateInfo, error) {
	delay := certificateReadInterval
	for attempt := 1; ; attempt++ {
		info, err := c.NodeProxyCertificate(ctx, node)
		var apiErr *Error
		var untrusted *UntrustedCertificateError
		if err == nil || errors.As(err, &apiErr) || errors.As(err, &untrusted) || isContextError(err) || attempt >= certificateReadAttempts {
			return info, err
		}
		tflog.Debug(ctx, "reading the PBS certificate after the change failed; trying again", map[string]any{"error": err.Error()})
		if err := c.sleep(ctx, delay); err != nil {
			return info, err
		}
		delay *= 2
	}
}
