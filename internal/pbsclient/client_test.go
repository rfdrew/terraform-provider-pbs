package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// noSleep replaces the client's sleep in tests, so that polls and retries
// run at once.
func noSleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

func TestNewValidatesOptions(t *testing.T) {
	tests := map[string]struct {
		opts    Options
		wantErr string
	}{
		"empty endpoint":     {Options{APIToken: fakeAPIToken}, "must not be empty"},
		"plain http":         {Options{Endpoint: "http://pbs.test:8007", APIToken: fakeAPIToken}, "https:// URL"},
		"no host":            {Options{Endpoint: "https://", APIToken: fakeAPIToken}, "https:// URL"},
		"credentials in URL": {Options{Endpoint: "https://root:secret@pbs.test", APIToken: fakeAPIToken}, "must not contain credentials"},
		"query":              {Options{Endpoint: "https://pbs.test?x=1", APIToken: fakeAPIToken}, "query or fragment"},
		"no credentials":     {Options{Endpoint: "https://pbs.test"}, "either an API token or both"},
		"username only":      {Options{Endpoint: "https://pbs.test", Username: "root@pam"}, "either an API token or both"},
		"token and password": {Options{Endpoint: "https://pbs.test", APIToken: fakeAPIToken, Username: "root@pam", Password: "x"}, "mutually exclusive"},
		"token without name": {Options{Endpoint: "https://pbs.test", APIToken: "root@pam:secret"}, "<user>@<realm>!<token name>:<secret>"},
		"PVE-style token":    {Options{Endpoint: "https://pbs.test", APIToken: "root@pam!t=secret"}, "<user>@<realm>!<token name>:<secret>"},
		"token without realm": {Options{Endpoint: "https://pbs.test", APIToken: "root!t:secret"},
			"<user>@<realm>!<token name>:<secret>"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("New() error = %v, want one containing %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "secret") && !strings.Contains(tc.wantErr, "secret") {
				t.Fatalf("New() error quotes the secret: %v", err)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	c, err := New(Options{Endpoint: "https://pbs.test:8007/", APIToken: fakeAPIToken})
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != "https://pbs.test:8007" || c.Node() != DefaultNode || c.taskTimeout != DefaultTaskTimeout ||
		c.httpClient.Timeout != DefaultTimeout || c.AuthID() != fakeTokenID || !c.UsesAPIToken() {
		t.Fatalf("client = %+v", c)
	}

	c, err = New(Options{Endpoint: "https://pbs.test", Username: "root@pam", Password: "x", Node: "pbs1"})
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthID() != "root@pam" || c.UsesAPIToken() || c.NodePath("tasks") != "/nodes/pbs1/tasks" {
		t.Fatalf("client = %+v", c)
	}
}

func TestTokenAuthentication(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)

	v, err := c.ServerVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.String() != "4.2.8" {
		t.Fatalf("version = %s", v)
	}
	call := fake.lastCall(t, "GET /version")
	if got := call.header.Get("Authorization"); got != "PBSAPIToken="+fakeAPIToken {
		t.Fatalf("Authorization = %q", got)
	}
	if call.header.Get(csrfHeader) != "" || fake.count("POST /access/ticket") != 0 {
		t.Fatalf("a token client sent a ticket or CSRF token: %v", fake.routes())
	}
}

// GET and DELETE carry parameters in the query string, POST and PUT in a form
// body; arrays are the key repeated.
func TestParametersTravelByMethod(t *testing.T) {
	fake := newFakePBS()
	for _, route := range []string{"GET /config/remote", "DELETE /config/remote/r1", "POST /config/remote", "PUT /config/remote/r1"} {
		fake.reply(route, http.StatusOK, `{"data":null}`)
	}
	c := fake.client(t)
	ctx := context.Background()
	params := func() url.Values {
		p := url.Values{"comment": {"a b&c"}}
		AddDelete(p, "port", "fingerprint")
		return p
	}

	if _, err := c.Get(ctx, "/config/remote", params(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Delete(ctx, "/config/remote/r1", params(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Post(ctx, "/config/remote", params(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(ctx, "/config/remote/r1", params(), nil); err != nil {
		t.Fatal(err)
	}

	want := url.Values{"comment": {"a b&c"}, "delete": {"fingerprint", "port"}}
	for _, route := range []string{"GET /config/remote", "DELETE /config/remote/r1"} {
		call := fake.lastCall(t, route)
		if !reflect.DeepEqual(call.query, want) || len(call.form) != 0 {
			t.Errorf("%s query = %v, form = %v", route, call.query, call.form)
		}
	}
	for _, route := range []string{"POST /config/remote", "PUT /config/remote/r1"} {
		call := fake.lastCall(t, route)
		if !reflect.DeepEqual(call.form, want) || len(call.query) != 0 {
			t.Errorf("%s form = %v, query = %v", route, call.form, call.query)
		}
		if ct := call.header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("%s Content-Type = %q", route, ct)
		}
	}
}

func TestEnvelopeCarriesDataAndDigest(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/remote/r1", http.StatusOK, `{"data":{"name":"r1","host":"pbs2"},"digest":"e3b0c442"}`)
	fake.reply("GET /config/datastore/null", http.StatusOK, `{"data":null}`)
	c := fake.client(t)

	var remote struct{ Name, Host string }
	env, err := c.Get(context.Background(), "/config/remote/r1", nil, &remote)
	if err != nil {
		t.Fatal(err)
	}
	if env.Digest != "e3b0c442" || remote.Name != "r1" || remote.Host != "pbs2" {
		t.Fatalf("envelope = %+v, remote = %+v", env, remote)
	}

	remote.Name = "untouched"
	env, err = c.Get(context.Background(), "/config/datastore/null", nil, &remote)
	if err != nil || env.Digest != "" || remote.Name != "untouched" {
		t.Fatalf("null data: envelope = %+v, remote = %+v, err = %v", env, remote, err)
	}
}

func TestNonJSONAnswerIsAnError(t *testing.T) {
	fake := newFakePBS()
	fake.handle("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>proxy login</html>"))
	})
	_, err := fake.client(t).ServerVersion(context.Background())
	if err == nil || !strings.Contains(err.Error(), "expected a JSON response") {
		t.Fatalf("error = %v", err)
	}
}

func TestBadDataIsAnError(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /version", http.StatusOK, `{"data":{"version":4}}`)
	_, err := fake.client(t).ServerVersion(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decoding the data of GET /version") {
		t.Fatalf("error = %v", err)
	}
}

func TestErrorsAreRedacted(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/remote/r1", http.StatusBadRequest, "bad value "+fakeTokenSecret)
	_, err := fake.client(t).Get(context.Background(), "/config/remote/r1", nil, nil)
	if err == nil || strings.Contains(err.Error(), fakeTokenSecret) || !strings.Contains(err.Error(), "<redacted>") {
		t.Fatalf("error = %v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	fake := newFakePBS()
	fake.handle("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://other.test/")
		w.WriteHeader(http.StatusFound)
	})
	_, err := fake.client(t).ServerVersion(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirected to https://other.test/") {
		t.Fatalf("error = %v", err)
	}
}

func TestPathEscapesSegments(t *testing.T) {
	got := Path("access", "users", "backup@pbs", "token", "pve 1")
	if got != "/access/users/backup@pbs/token/pve%201" {
		t.Fatalf("Path() = %q", got)
	}
	upid := "UPID:pbs-acc:0000000B:00001327:00000003:6AE11CDF:create-datastore:probe\\x2db:tfacc@pbs!acc:"
	if got := Path("nodes", "localhost", "tasks", upid, "status"); !strings.Contains(got, "probe%5Cx2db") || strings.Count(got, "/") != 5 {
		t.Fatalf("Path() = %q", got)
	}
}
