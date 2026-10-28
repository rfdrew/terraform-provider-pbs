// Package pbsclient is a thin HTTP client for the REST API of Proxmox Backup
// Server (PBS).
//
// PBS serves its API under https://<host>:8007/api2/json/. Every answer is
// wrapped in an envelope, {"data": ..., "digest": ...}, where the digest — the
// SHA-256 of the configuration file the object lives in — sits next to data
// rather than inside it; Call returns both. Parameters travel as a form:
// in the query string for GET and DELETE, in an
// application/x-www-form-urlencoded body for POST and PUT, and an array is the
// same key repeated (delete=a&delete=b).
//
// The client authenticates either with an API token, sent with every request,
// or with a username and password, exchanged for a ticket; session.go covers
// the ticket. Long-running operations answer with the UPID of a worker task;
// tasks.go waits for them. Everything here is written against the wire
// behaviour of the PBS 4.0 and 4.2 releases, as observed on real servers.
package pbsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/net/idna"
)

// DefaultNode is the node every PBS answers for: a PBS is a single node, and
// it accepts localhost as the name of itself.
const DefaultNode = "localhost"

// DefaultTimeout bounds a single HTTP request when Options.Timeout is unset.
const DefaultTimeout = 30 * time.Second

// DefaultTaskTimeout bounds the wait for a worker task when
// Options.TaskTimeout is unset.
const DefaultTaskTimeout = 30 * time.Minute

// apiPrefix is the path every API call starts with.
const apiPrefix = "/api2/json"

// Client talks to a single PBS. It is safe for concurrent use, which matters
// because Terraform calls resources in parallel.
type Client struct {
	baseURL string
	// tokenAuth and authID say how the client signs in and as whom; they
	// never change.
	tokenAuth bool
	authID    string
	username  string
	// credMu guards apiToken and password, which change when the provider
	// regenerates its own token's secret or changes its own password.
	credMu   sync.Mutex
	apiToken string
	password string
	// passwordChange serialises ChangePassword, whose confirmation is the
	// client's own password: a change of that password must not overtake a
	// confirmation already on its way.
	passwordChange sync.Mutex

	node        string
	userAgent   string
	taskTimeout time.Duration
	httpClient  *http.Client
	// trust decides which server certificates the client accepts; see
	// tls.go.
	trust *trust

	// certificateChange serialises ChangeCertificate, and changing is the
	// change in progress, if any: calls that meet a certificate they do not
	// trust while it runs wait for it and try again. See certificate.go.
	certificateChange sync.Mutex
	changingMu        sync.Mutex
	changing          chan struct{}

	// The ticket session, when the client signs in with a password; see
	// session.go. mu guards every field below it.
	mu       sync.Mutex
	current  *ticket
	gen      uint64
	inflight *loginCall

	// configLocks serialise writes to one configuration file; see
	// WithConfigLock.
	configLocks configLocks

	// sleep waits between task polls; tests replace it.
	sleep func(context.Context, time.Duration) error
}

// Options configures a Client.
type Options struct {
	// Endpoint is the server's root address, e.g. https://pbs.example.com:8007.
	// A trailing slash is trimmed. A path is kept, for a server behind a
	// reverse proxy that serves it under a prefix.
	Endpoint string
	// APIToken is an API token as PBS prints it on creation,
	// "<user>@<realm>!<name>:<secret>". It excludes Username and Password.
	APIToken string
	// Username and Password sign in with a ticket instead, as
	// "<user>@<realm>". A few calls — changing a password, creating a network
	// interface — are closed to API tokens and need this.
	Username string
	Password string
	// CertFingerprint pins the server's certificate by the SHA-256 of its DER
	// encoding, in any form NormaliseFingerprint accepts.
	CertFingerprint string
	// CAFile is a PEM bundle used instead of the system roots.
	CAFile string
	// InsecureSkipVerify disables TLS certificate verification.
	InsecureSkipVerify bool
	// Node is the node name used in /nodes/{node} paths. Defaults to
	// DefaultNode.
	Node string
	// Timeout bounds a single HTTP request. Defaults to DefaultTimeout.
	Timeout time.Duration
	// TaskTimeout bounds the wait for a worker task. Defaults to
	// DefaultTaskTimeout.
	TaskTimeout time.Duration
	// UserAgent is sent with every request.
	UserAgent string
	// Transport replaces the HTTP transport, and with it every TLS setting
	// above, which is still validated. Tests use it to answer requests in
	// process instead of over a socket.
	Transport http.RoundTripper
}

// New builds a Client from Options. It does not contact the server: a
// password session starts with the first request.
func New(opts Options) (*Client, error) {
	base := strings.TrimRight(opts.Endpoint, "/")
	if base == "" {
		return nil, errors.New("the PBS endpoint must not be empty")
	}
	parsed, err := url.Parse(base)
	if err != nil {
		// url.Error repeats the URL, which may hold a password, so only
		// the reason is kept.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("the PBS endpoint is not a valid URL: %w", err)
	}
	if parsed.User != nil {
		return nil, errors.New("the PBS endpoint must not contain credentials; set the API token or the username and password separately")
	}
	// PBS serves its API over HTTPS only; the proxy does not listen on plain
	// HTTP at all.
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("the PBS endpoint must be an https:// URL with a host, got %q", opts.Endpoint)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("the PBS endpoint must not contain a query or fragment, got %q", opts.Endpoint)
	}

	switch {
	case opts.APIToken != "" && (opts.Username != "" || opts.Password != ""):
		return nil, errors.New("an API token and a username and password are mutually exclusive; set only one of them")
	case opts.APIToken != "":
		if _, _, err := SplitAPIToken(opts.APIToken); err != nil {
			return nil, err
		}
	case opts.Username == "" || opts.Password == "":
		return nil, errors.New("set either an API token or both a username and a password")
	}

	// The host name as net/http and crypto/tls send it in the TLS handshake
	// and Go verifies it: an internationalised name in its ASCII form,
	// without a trailing dot.
	host := parsed.Hostname()
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		host = ascii
	}
	host = strings.TrimRight(host, ".")
	trust, err := newTrust(opts, host)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	taskTimeout := opts.TaskTimeout
	if taskTimeout <= 0 {
		taskTimeout = DefaultTaskTimeout
	}
	node := opts.Node
	if node == "" {
		node = DefaultNode
	}

	transport := opts.Transport
	if transport == nil {
		defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
		defaultTransport.TLSClientConfig = trust.tlsConfig()
		transport = defaultTransport
	}

	ua := opts.UserAgent
	if ua == "" {
		ua = "terraform-provider-pbs"
	}

	authID := opts.Username
	if opts.APIToken != "" {
		authID, _, _ = SplitAPIToken(opts.APIToken)
	}

	return &Client{
		baseURL:     base,
		tokenAuth:   opts.APIToken != "",
		authID:      authID,
		apiToken:    opts.APIToken,
		username:    opts.Username,
		password:    opts.Password,
		node:        node,
		userAgent:   ua,
		taskTimeout: taskTimeout,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// PBS never redirects an API call. A redirect means the endpoint
			// points somewhere else, and following it would replay a PUT or
			// POST as a GET, so it is reported instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		trust: trust,
		sleep: sleepContext,
	}, nil
}

// SplitAPIToken splits an API token in the form PBS prints it on creation,
// "<user>@<realm>!<name>:<secret>", into the token ID and the secret.
func SplitAPIToken(token string) (id, secret string, err error) {
	id, secret, ok := strings.Cut(token, ":")
	user, name, hasName := strings.Cut(id, "!")
	if !ok || !hasName || secret == "" || name == "" || !strings.Contains(user, "@") {
		// The token itself is left out of the message: it is a secret.
		return "", "", errors.New(`the API token must have the form "<user>@<realm>!<token name>:<secret>", as PBS shows it when the token is created`)
	}
	return id, secret, nil
}

// BaseURL returns the server's root address without a trailing slash.
func (c *Client) BaseURL() string { return c.baseURL }

// Node returns the node name used in /nodes/{node} paths.
func (c *Client) Node() string { return c.node }

// AuthID returns who the client acts as: the token ID, or the username.
func (c *Client) AuthID() string { return c.authID }

// UsesAPIToken reports whether the client authenticates with an API token
// rather than a password. Some calls are closed to API tokens.
func (c *Client) UsesAPIToken() bool { return c.tokenAuth }

// CloseIdleConnections closes the connections the client keeps open between
// calls, so that the next call opens a new one.
func (c *Client) CloseIdleConnections() { c.httpClient.CloseIdleConnections() }

// credentials returns the current API token and password.
func (c *Client) credentials() (apiToken, password string) {
	c.credMu.Lock()
	defer c.credMu.Unlock()
	return c.apiToken, c.password
}

// UseAPITokenSecret replaces the secret of the API token the client signs in
// with, after PBS regenerated it: the old one stopped working at once. It
// does nothing for a password session.
func (c *Client) UseAPITokenSecret(secret string) {
	if !c.tokenAuth {
		return
	}
	c.credMu.Lock()
	defer c.credMu.Unlock()
	c.apiToken = c.authID + ":" + secret
}

// Envelope is the wrapper of every /api2/json answer. Digest is the
// configuration file's digest where PBS sends one: next to data for most
// configuration objects, nowhere for lists of notification targets, and
// inside data for the node's DNS settings, which this field does not see.
type Envelope struct {
	Data   json.RawMessage `json:"data"`
	Digest string          `json:"digest,omitempty"`
}

// Get, Post, Put and Delete are Call with the method filled in.
func (c *Client) Get(ctx context.Context, path string, params url.Values, out any) (*Envelope, error) {
	return c.Call(ctx, http.MethodGet, path, params, out)
}

func (c *Client) Post(ctx context.Context, path string, params url.Values, out any) (*Envelope, error) {
	return c.Call(ctx, http.MethodPost, path, params, out)
}

func (c *Client) Put(ctx context.Context, path string, params url.Values, out any) (*Envelope, error) {
	return c.Call(ctx, http.MethodPut, path, params, out)
}

func (c *Client) Delete(ctx context.Context, path string, params url.Values, out any) (*Envelope, error) {
	return c.Call(ctx, http.MethodDelete, path, params, out)
}

// Call issues an API request and returns the envelope of the answer. path
// starts after /api2/json, e.g. "/config/remote"; build it with Path when it
// contains names. params go into the query string for GET and DELETE and
// into a form body for POST and PUT. When out is non-nil, data is decoded
// into it; a null data leaves out untouched.
//
// With a password session, a 401 means the ticket expired or the server lost
// it, before the handler ran, so the request is signed in again and retried
// once, whatever its method.
func (c *Client) Call(ctx context.Context, method, path string, params url.Values, out any) (*Envelope, error) {
	return c.call(ctx, method, path, params, out, true)
}

// call is Call, with the retry after a 401 optional: PUT /access/password
// answers 401 itself when the confirmation is wrong, and signing in again
// would only hide that.
//
// A request that fails because the server presented a certificate the client
// does not trust is tried once more when the client was changing the
// server's certificate meanwhile and has come to trust a new one since: the
// handshake failed before anything was sent, so nothing happened twice.
func (c *Client) call(ctx context.Context, method, path string, params url.Values, out any, retryUnauthorized bool) (*Envelope, error) {
	signedInAgain, triedNewCertificate := false, false
	// rejected is the generation of a ticket PBS rejected: a try after a
	// certificate change must not send it again.
	var rejected uint64
	for {
		// Read first: a sign-in, too, may meet a certificate the client
		// comes to trust only when a change ends.
		generation := c.trust.currentGeneration()
		var t *ticket
		if !c.tokenAuth {
			var err error
			if t, err = c.ticketNewerThan(ctx, rejected); err != nil {
				if !triedNewCertificate && c.awaitCertificateChange(ctx, err, generation) {
					triedNewCertificate = true
					continue
				}
				return nil, err
			}
		}

		resp, raw, err := c.send(ctx, method, path, params, t)
		if err != nil {
			if !triedNewCertificate && c.awaitCertificateChange(ctx, err, generation) {
				triedNewCertificate = true
				continue
			}
			return nil, err
		}

		if resp.StatusCode == http.StatusUnauthorized && t != nil && !signedInAgain && retryUnauthorized {
			signedInAgain = true
			rejected = t.gen
			tflog.Debug(ctx, "PBS rejected the ticket; signing in again", map[string]any{"method": method, "path": path})
			if _, err := c.ticketNewerThan(ctx, t.gen); err != nil {
				if !triedNewCertificate && c.awaitCertificateChange(ctx, err, generation) {
					triedNewCertificate = true
					continue
				}
				return nil, fmt.Errorf("%s %s: PBS rejected the ticket, and signing in again failed: %w", method, path, err)
			}
			continue
		}

		return c.decode(method, path, resp, raw, out)
	}
}

// send makes one attempt at an API request and returns the response, whose
// body has been read into raw and closed. t is the ticket to send, or nil for
// an API token.
func (c *Client) send(ctx context.Context, method, path string, params url.Values, t *ticket) (*http.Response, []byte, error) {
	target := c.baseURL + apiPrefix + path
	var body io.Reader
	isWrite := method == http.MethodPost || method == http.MethodPut
	if isWrite {
		body = strings.NewReader(params.Encode())
	} else if len(params) > 0 {
		target += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, fmt.Errorf("building request for %s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if isWrite {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if t != nil {
		// The cookie is set by hand rather than through a cookie jar, which
		// would also need the session's domain and path right.
		req.AddCookie(&http.Cookie{Name: ticketCookieName, Value: t.ticket})
		// PBS checks the CSRF token on every call but GET; sending it on
		// every call is harmless.
		req.Header.Set(csrfHeader, t.csrf)
	} else {
		apiToken, _ := c.credentials()
		req.Header.Set("Authorization", "PBSAPIToken="+apiToken)
	}

	resp, err := c.httpClientFor(ctx).Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading response body for %s %s: %w", method, path, err)
	}
	return resp, raw, nil
}

// decode turns a response into an *Error, or into its envelope.
func (c *Client) decode(method, path string, resp *http.Response, raw []byte, out any) (*Envelope, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := newError(method, path, resp.StatusCode, resp.Header, raw)
		// PBS does not echo credentials, but an error body is shown to the
		// user verbatim, so make sure.
		apiErr.Message = Redact(apiErr.Message, c.secrets()...)
		apiErr.Body = Redact(apiErr.Body, c.secrets()...)
		return nil, apiErr
	}

	// Every API answer is application/json. Anything else came from
	// somewhere other than the API — a reverse proxy's error page, say — and
	// would otherwise decode as nothing.
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("%s %s: expected a JSON response but got Content-Type %q; check that the endpoint is the PBS root address",
			method, path, resp.Header.Get("Content-Type"))
	}

	var env Envelope
	if err := json.Unmarshal(bytes.TrimSpace(raw), &env); err != nil {
		return nil, fmt.Errorf("decoding response body for %s %s: %w (body: %s)", method, path, err, truncate(string(raw), 512))
	}
	if out != nil && len(env.Data) > 0 && !bytes.Equal(env.Data, []byte("null")) {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return nil, fmt.Errorf("decoding the data of %s %s: %w (data: %s)", method, path, err, truncate(string(env.Data), 512))
		}
	}
	return &env, nil
}

// secrets returns the credentials the client holds, for Redact.
func (c *Client) secrets() []string {
	apiToken, password := c.credentials()
	if c.tokenAuth {
		_, secret, _ := SplitAPIToken(apiToken)
		return []string{secret}
	}
	return []string{password}
}

// Path joins path segments into an API path, escaping each one: names such as
// user IDs and UPIDs contain characters that must not split the path.
func Path(segments ...string) string {
	var b strings.Builder
	for _, s := range segments {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}

// NodePath is Path below /nodes/{node}.
func (c *Client) NodePath(segments ...string) string {
	return Path(append([]string{"nodes", c.node}, segments...)...)
}

// sleepContext waits for d, or until ctx is done.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
