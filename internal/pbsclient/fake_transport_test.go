package pbsclient

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakePBS emulates a PBS in process, through Options.Transport, so tests need
// no listening socket. It reproduces what the client depends on, as observed
// on PBS 4.0 and 4.2:
//
//   - POST /api2/json/access/ticket signs a user in with the form's username
//     and password and answers a ticket and a CSRF token; a wrong password is
//     401 "authentication failed - invalid credentials";
//   - every other call needs "Authorization: PBSAPIToken=<id>:<secret>", or
//     the PBSAuthCookie ticket, plus the CSRFPreventionToken header on every
//     method but GET; anything else is 401 "authentication failed - ...";
//   - routes are matched by "METHOD /path", the path after /api2/json and
//     without the query string; an unrouted path is 404 "Path '...' not
//     found.", as PBS answers for routes and methods it does not have;
//   - GET /version answers 4.2.8 until a test routes it differently.
//
// Successes are the {"data": ...} envelope. Errors are plain text, sent with
// Content-Type application/json, as PBS sends them.
//
// expireTickets invalidates every ticket issued so far, as a server restart
// does. Every request is recorded in order with its query and form.
type fakePBS struct {
	mu sync.Mutex

	// tokenID and tokenSecret make up the API token the fake accepts.
	tokenID     string
	tokenSecret string
	// username and password are the credentials a ticket sign-in accepts.
	username string
	password string
	// tfa makes the sign-in answer the half ticket of a user with a second
	// factor.
	tfa bool

	ticketGen int
	tickets   map[string]string // ticket -> CSRF token
	logins    int

	handlers map[string]http.HandlerFunc
	calls    []fakeCall
}

// fakeCall is one request the fake received.
type fakeCall struct {
	route  string
	query  url.Values
	form   url.Values
	header http.Header
}

const (
	fakeTokenID     = "tfacc@pbs!acc"
	fakeTokenSecret = "3f0c6c1e-8a0e-4bd2-9c7e-0c5f8b5a7f11"
	fakeAPIToken    = fakeTokenID + ":" + fakeTokenSecret
	fakeUsername    = "tfacc@pbs"
	fakePassword    = "correct-horse-battery"
	fakeVersionJSON = `{"data":{"release":"8","repoid":"0123456789abcdef","version":"4.2"}}`
)

func newFakePBS() *fakePBS {
	f := &fakePBS{
		tokenID:     fakeTokenID,
		tokenSecret: fakeTokenSecret,
		username:    fakeUsername,
		password:    fakePassword,
		tickets:     map[string]string{},
		handlers:    map[string]http.HandlerFunc{},
	}
	f.reply("GET /version", http.StatusOK, fakeVersionJSON)
	return f
}

// expireTickets makes every ticket issued so far invalid.
func (f *fakePBS) expireTickets() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tickets = map[string]string{}
}

func (f *fakePBS) handle(route string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[route] = h
}

// reply answers route with a fixed status and body: the body is the whole
// envelope for a 2xx and the plain error text otherwise.
func (f *fakePBS) reply(route string, status int, body string) {
	f.replies(route, status, body)
}

// replies answers successive requests to route with bodies in turn, repeating
// the last one once they run out.
func (f *fakePBS) replies(route string, status int, bodies ...string) {
	var mu sync.Mutex
	next := 0
	f.handle(route, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		body := bodies[next]
		if next < len(bodies)-1 {
			next++
		}
		mu.Unlock()
		writeFakeResponse(w, status, body)
	})
}

// writeFakeResponse writes body with the Content-Type PBS uses for both
// successes and errors of /api2/json.
func writeFakeResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (f *fakePBS) RoundTrip(req *http.Request) (*http.Response, error) {
	f.record(req)
	rec := httptest.NewRecorder()
	f.serve(rec, req)
	return rec.Result(), nil
}

// record adds req to the calls the fake received.
func (f *fakePBS) record(req *http.Request) {
	call := fakeCall{route: req.Method + " " + strings.TrimPrefix(req.URL.Path, apiPrefix), query: req.URL.Query(), header: req.Header.Clone()}
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		call.form, _ = url.ParseQuery(string(raw))
		req.Body = io.NopCloser(strings.NewReader(string(raw)))
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

// serveRecorded serves req as a server would, recording it as RoundTrip
// does: for tests that serve the fake over real TLS.
func (f *fakePBS) serveRecorded(w http.ResponseWriter, req *http.Request) {
	f.record(req)
	f.serve(w, req)
}

func (f *fakePBS) serve(w http.ResponseWriter, req *http.Request) {
	if !strings.HasPrefix(req.URL.Path, apiPrefix+"/") {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	path := strings.TrimPrefix(req.URL.Path, apiPrefix)

	if req.Method == http.MethodPost && path == "/access/ticket" {
		f.serveTicket(w, req)
		return
	}
	if message := f.authenticate(req); message != "" {
		writeFakeResponse(w, http.StatusUnauthorized, "authentication failed - "+message)
		return
	}

	f.mu.Lock()
	h := f.handlers[req.Method+" "+path]
	f.mu.Unlock()
	if h == nil {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	h(w, req)
}

// authenticate returns why the request is not authenticated, or "".
func (f *fakePBS) authenticate(req *http.Request) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if auth := req.Header.Get("Authorization"); auth != "" {
		if auth != "PBSAPIToken="+f.tokenID+":"+f.tokenSecret {
			return "invalid credentials"
		}
		return ""
	}
	cookie, err := req.Cookie(ticketCookieName)
	if err != nil {
		return "no authentication credentials provided."
	}
	csrf, ok := f.tickets[cookie.Value]
	if !ok {
		return "invalid PBS authentication cookie"
	}
	if req.Method != http.MethodGet && req.Header.Get(csrfHeader) != csrf {
		return "missing CSRF prevention token"
	}
	return ""
}

func (f *fakePBS) serveTicket(w http.ResponseWriter, req *http.Request) {
	_ = req.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins++
	if req.PostForm.Get("username") != f.username || req.PostForm.Get("password") != f.password {
		writeFakeResponse(w, http.StatusUnauthorized, "authentication failed - invalid credentials")
		return
	}
	f.ticketGen++
	if f.tfa {
		ticket := fmt.Sprintf("PBS:!tfa!%%7B%%22webauthn%%22%%3Atrue%%7D:%d", f.ticketGen)
		writeFakeResponse(w, http.StatusOK, fmt.Sprintf(`{"data":{"ticket":%q,"username":%q}}`, ticket, f.username))
		return
	}
	ticket := fmt.Sprintf("PBS:%s:6AE11CDF::ticket-%d", f.username, f.ticketGen)
	csrf := fmt.Sprintf("6AE11CDF:csrf-%d", f.ticketGen)
	f.tickets[ticket] = csrf
	writeFakeResponse(w, http.StatusOK, fmt.Sprintf(`{"data":{"CSRFPreventionToken":%q,"ticket":%q,"username":%q}}`, csrf, ticket, f.username))
}

// routes returns the calls made so far, in order.
func (f *fakePBS) routes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	routes := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		routes = append(routes, c.route)
	}
	return routes
}

// count returns how many requests were made to route.
func (f *fakePBS) count(route string) int {
	n := 0
	for _, r := range f.routes() {
		if r == route {
			n++
		}
	}
	return n
}

// lastCall returns the most recent request to route.
func (f *fakePBS) lastCall(t *testing.T, route string) fakeCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].route == route {
			return f.calls[i]
		}
	}
	t.Fatalf("no request was made to %s; calls: %v", route, f.calls)
	return fakeCall{}
}

// client returns a client that signs in with the fake's API token.
func (f *fakePBS) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(Options{Endpoint: "https://pbs.test:8007", APIToken: fakeAPIToken, Transport: f})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = noSleep
	return c
}

// passwordClient returns a client that signs in with the fake's password.
func (f *fakePBS) passwordClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Options{Endpoint: "https://pbs.test:8007", Username: fakeUsername, Password: fakePassword, Transport: f})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = noSleep
	return c
}
