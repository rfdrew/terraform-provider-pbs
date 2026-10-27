package pbsclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// sampleTokenSecret is a token secret in the form PBS generates, for answers
// that carry one. It differs from the fake's own token secret, so the
// redaction the client applies to its own credentials cannot hide a leak these
// tests look for.
const sampleTokenSecret = "5e0f7c1a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"

// ListUsers asks for tokens only when told to, and decodes the tokens PBS
// nests in each user.
func TestListUsersIncludesTokensOnlyWhenAsked(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/users", http.StatusOK, `{"data":[`+
		`{"userid":"a@b.example@pbs","email":"a@b.example","firstname":"Ann","lastname":"Bee","comment":"ops","tokens":[`+
		`{"tokenid":"a@b.example@pbs!ci","comment":"pipeline","expire":1767225600},`+
		`{"tokenid":"a@b.example@pbs!old","enable":false}]},`+
		`{"userid":"root@pam","enable":true}]}`)
	c := fake.client(t)
	ctx := context.Background()

	if _, err := c.ListUsers(ctx, false); err != nil {
		t.Fatal(err)
	}
	if call := fake.lastCall(t, "GET /access/users"); len(call.query) != 0 {
		t.Fatalf("without tokens: query = %v, want none", call.query)
	}

	users, err := c.ListUsers(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if call := fake.lastCall(t, "GET /access/users"); !reflect.DeepEqual(call.query, url.Values{"include_tokens": {"1"}}) {
		t.Fatalf("with tokens: query = %v", call.query)
	}

	if len(users) != 2 {
		t.Fatalf("users = %+v", users)
	}
	a := users[0]
	if a.UserID != "a@b.example@pbs" || a.Email != "a@b.example" || a.Firstname != "Ann" || a.Lastname != "Bee" ||
		a.Comment != "ops" || !a.Enabled() || a.Expiry() != 0 || len(a.Tokens) != 2 {
		t.Fatalf("users[0] = %+v", a)
	}
	if ci := a.Tokens[0]; ci.TokenID != "a@b.example@pbs!ci" || ci.Comment != "pipeline" || !ci.Enabled() || ci.Expiry() != 1767225600 {
		t.Errorf("tokens[0] = %+v", ci)
	}
	if old := a.Tokens[1]; old.TokenID != "a@b.example@pbs!old" || old.Enabled() || old.Expiry() != 0 {
		t.Errorf("tokens[1] = %+v", old)
	}
	if root := users[1]; root.UserID != "root@pam" || !root.Enabled() || root.Tokens != nil {
		t.Errorf("users[1] = %+v", root)
	}
}

// PBS leaves "enable" and "expire" out at their defaults, so their absence
// must read as an account that is enabled and never expires.
func TestUserValidityDefaultsToEnabledAndNeverExpiring(t *testing.T) {
	tests := map[string]struct {
		json        string
		wantEnabled bool
		wantExpiry  int64
	}{
		"both absent":       {`{"userid":"alice@pbs"}`, true, 0},
		"enabled":           {`{"userid":"alice@pbs","enable":true}`, true, 0},
		"disabled, expires": {`{"userid":"alice@pbs","enable":false,"expire":1767225600}`, false, 1767225600},
		"expire reset to 0": {`{"userid":"alice@pbs","expire":0}`, true, 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var user User
			if err := json.Unmarshal([]byte(tc.json), &user); err != nil {
				t.Fatal(err)
			}
			if user.Enabled() != tc.wantEnabled || user.Expiry() != tc.wantExpiry {
				t.Fatalf("Enabled() = %v, Expiry() = %d, want %v, %d", user.Enabled(), user.Expiry(), tc.wantEnabled, tc.wantExpiry)
			}
		})
	}

	// The zero Validity, which a user built in code has, follows the same
	// defaults.
	if v := (Validity{}); !v.Enabled() || v.Expiry() != 0 {
		t.Fatal("the zero Validity is not an enabled, never expiring account")
	}
}

// A user ID reaches the path as one segment: "@" stays as it is, and "!",
// legal in a user name, is escaped, so the server sees the ID the client was
// given.
func TestGetUserEscapesThePath(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/users/a@b.example@pbs", http.StatusOK, `{"data":{"userid":"a@b.example@pbs","email":"a@b.example"}}`)
	var escaped string
	fake.handle("GET /access/users/x!y@pbs", func(w http.ResponseWriter, r *http.Request) {
		escaped = r.URL.EscapedPath()
		writeFakeResponse(w, http.StatusOK, `{"data":{"userid":"x!y@pbs"}}`)
	})
	c := fake.client(t)
	ctx := context.Background()

	user, err := c.GetUser(ctx, "a@b.example@pbs")
	if err != nil {
		t.Fatal(err)
	}
	if user.UserID != "a@b.example@pbs" || user.Email != "a@b.example" {
		t.Fatalf("user = %+v", user)
	}

	if user, err = c.GetUser(ctx, "x!y@pbs"); err != nil || user.UserID != "x!y@pbs" {
		t.Fatalf("user = %+v, err = %v", user, err)
	}
	if escaped != apiPrefix+"/access/users/x%21y@pbs" {
		t.Fatalf("escaped path = %q", escaped)
	}
}

// PBS may quote a rejected value in its error, and a new user's password is a
// secret the client does not otherwise hold, so CreateUser redacts it itself,
// in every form the error may quote it.
func TestCreateUserRedactsThePassword(t *testing.T) {
	const password = `n3w "pa55" w0rd`
	fake := newFakePBS()
	fake.reply("POST /access/users", http.StatusBadRequest,
		`parameter verification failed - 'password': value "n3w \"pa55\" w0rd" rejected: n3w "pa55" w0rd`)
	c := fake.client(t)

	params := url.Values{"userid": {"alice@pbs"}, "password": {password}, "comment": {"ops"}}
	err := c.CreateUser(context.Background(), params)
	apiErr, ok := asError(err)
	if !ok {
		t.Fatalf("error = %v, want an API error", err)
	}
	if strings.Contains(err.Error(), "pa55") || strings.Contains(apiErr.Body, "pa55") || !strings.Contains(err.Error(), redactedMarker) {
		t.Fatalf("error = %v, body = %q", err, apiErr.Body)
	}
	if call := fake.lastCall(t, "POST /access/users"); !reflect.DeepEqual(call.form, params) {
		t.Fatalf("form = %v, want %v", call.form, params)
	}
}

// Redaction keeps the *Error, so a user that is already there is still
// recognised as one.
func TestCreateUserReportsAnExistingUser(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	ctx := context.Background()
	params := url.Values{"userid": {"alice@pbs"}, "password": {"n3w-pa55-w0rd"}}

	fake.reply("POST /access/users", http.StatusOK, `{"data":null}`)
	if err := c.CreateUser(ctx, params); err != nil {
		t.Fatalf("CreateUser() = %v", err)
	}

	fake.reply("POST /access/users", http.StatusBadRequest, "user 'alice@pbs' already exists.")
	if err := c.CreateUser(ctx, params); !IsAlreadyExists(err) {
		t.Fatalf("CreateUser() = %v, want an already-exists error", err)
	}
}

// PBS closes PUT /access/password to API tokens, so a token client fails at
// once rather than send the new password only to have it refused.
func TestChangePasswordNeedsAPasswordSession(t *testing.T) {
	fake := newFakePBS()
	err := fake.client(t).ChangePassword(context.Background(), "alice@pbs", "n3w-pa55-w0rd")
	if !errors.Is(err, ErrPasswordChangeNeedsPassword) {
		t.Fatalf("ChangePassword() = %v, want ErrPasswordChangeNeedsPassword", err)
	}
	if fake.count("PUT /access/password") != 0 || len(fake.routes()) != 0 {
		t.Fatalf("a token client made requests: %v", fake.routes())
	}
}

// PBS wants the caller's own password as confirmation, so the client sends
// the one it signed in with.
func TestChangePasswordSendsTheConfirmation(t *testing.T) {
	fake := newFakePBS()
	fake.reply("PUT /access/password", http.StatusOK, `{"data":null}`)
	if err := fake.passwordClient(t).ChangePassword(context.Background(), "alice@pbs", "n3w-pa55-w0rd"); err != nil {
		t.Fatal(err)
	}
	want := url.Values{"userid": {"alice@pbs"}, "password": {"n3w-pa55-w0rd"}, "confirmation-password": {fakePassword}}
	if call := fake.lastCall(t, "PUT /access/password"); !reflect.DeepEqual(call.form, want) {
		t.Fatalf("form = %v, want %v", call.form, want)
	}
}

// The new password is redacted from PBS's error as the client's own is.
func TestChangePasswordRedactsTheNewPassword(t *testing.T) {
	const password = "n3w-pa55-w0rd"
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized} {
		fake := newFakePBS()
		fake.reply("PUT /access/password", status, "refused new password "+password+" for alice@pbs")
		err := fake.passwordClient(t).ChangePassword(context.Background(), "alice@pbs", password)
		apiErr, ok := asError(err)
		if !ok || apiErr.StatusCode != status {
			t.Fatalf("HTTP %d: error = %v, want the API error", status, err)
		}
		if strings.Contains(err.Error(), password) || strings.Contains(apiErr.Body, password) || !strings.Contains(err.Error(), redactedMarker) {
			t.Fatalf("HTTP %d: error = %v, body = %q", status, err, apiErr.Body)
		}
	}
}

// A wrong confirmation is a 401 from the handler, not an expired ticket: the
// client neither signs in again nor sends the new password a second time.
func TestChangePasswordDoesNotRetryAWrongConfirmation(t *testing.T) {
	fake := newFakePBS()
	fake.reply("PUT /access/password", http.StatusUnauthorized, "authentication failed - invalid credentials")
	err := fake.passwordClient(t).ChangePassword(context.Background(), "alice@pbs", "n3w-pa55-w0rd")
	if apiErr, ok := asError(err); !ok || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ChangePassword() = %v, want PBS's 401", err)
	}
	if fake.count("PUT /access/password") != 1 || fake.logins != 1 {
		t.Fatalf("PUT /access/password sent %d times after %d sign-ins, want once after one", fake.count("PUT /access/password"), fake.logins)
	}
}

// Once the client changed its own user's password, it confirms with the new
// one, and signs in with it too.
func TestChangePasswordOfTheClientsOwnUser(t *testing.T) {
	fake := newFakePBS()
	fake.reply("PUT /access/password", http.StatusOK, `{"data":null}`)
	c := fake.passwordClient(t)
	ctx := context.Background()
	if err := c.ChangePassword(ctx, fakeUsername, "r0tated-pa55"); err != nil {
		t.Fatal(err)
	}
	if err := c.ChangePassword(ctx, "alice@pbs", "n3w-pa55-w0rd"); err != nil {
		t.Fatal(err)
	}
	if got := fake.lastCall(t, "PUT /access/password").form.Get("confirmation-password"); got != "r0tated-pa55" {
		t.Errorf("confirmation-password = %q, want the client's new password", got)
	}

	fake.mu.Lock()
	fake.password = "r0tated-pa55"
	fake.mu.Unlock()
	fake.expireTickets()
	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatalf("signing in again with the new password: %v", err)
	}

	// Another user's password leaves the client's alone.
	if err := c.ChangePassword(ctx, "bob@pbs", "b0bs-pa55-w0rd"); err != nil {
		t.Fatal(err)
	}
	if got := fake.lastCall(t, "PUT /access/password").form.Get("confirmation-password"); got != "r0tated-pa55" {
		t.Errorf("confirmation-password = %q after changing another user's password", got)
	}
}

// After PBS regenerated the secret of the client's own token, the client
// signs in with the new secret and redacts it from errors.
func TestUseAPITokenSecret(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	const secret = "6d1c1f1e-0000-4000-8000-000000000042"
	c.UseAPITokenSecret(secret)
	fake.mu.Lock()
	fake.tokenSecret = secret
	fake.mu.Unlock()
	if _, err := c.ServerVersion(context.Background()); err != nil {
		t.Fatalf("signing in with the new secret: %v", err)
	}
	if got := fake.lastCall(t, "GET /version").header.Get("Authorization"); got != "PBSAPIToken="+fakeTokenID+":"+secret {
		t.Errorf("Authorization = %q", got)
	}
	if c.AuthID() != fakeTokenID || !c.UsesAPIToken() {
		t.Errorf("the token ID changed: %s", c.AuthID())
	}

	fake.reply("GET /version", http.StatusInternalServerError, "echo "+secret)
	if _, err := c.ServerVersion(context.Background()); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("error = %v, want the new secret redacted", err)
	}

	// A password client has no token secret to replace.
	p := fake.passwordClient(t)
	p.UseAPITokenSecret(secret)
	if p.UsesAPIToken() || p.AuthID() != fakeUsername {
		t.Errorf("a password client turned into a token client: %s", p.AuthID())
	}
}

func TestCreateAPITokenReturnsTheSecret(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /access/users/a@b.example@pbs/token/ci", http.StatusOK,
		`{"data":{"tokenid":"a@b.example@pbs!ci","value":"`+sampleTokenSecret+`"}}`)
	c := fake.client(t)

	params := url.Values{"comment": {"pipeline"}, "expire": {"1767225600"}}
	tokenID, secret, err := c.CreateAPIToken(context.Background(), "a@b.example@pbs", "ci", params)
	if err != nil {
		t.Fatal(err)
	}
	if tokenID != "a@b.example@pbs!ci" || secret != sampleTokenSecret {
		t.Fatalf("CreateAPIToken() = %q, %q", tokenID, secret)
	}
	if call := fake.lastCall(t, "POST /access/users/a@b.example@pbs/token/ci"); !reflect.DeepEqual(call.form, params) {
		t.Fatalf("form = %v, want %v", call.form, params)
	}
}

// Without a tokenid in the answer, the token's ID is the one it was created
// under.
func TestCreateAPITokenFallsBackToTheTokenID(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /access/users/alice@pbs/token/ci", http.StatusOK, `{"data":{"value":"`+sampleTokenSecret+`"}}`)
	tokenID, secret, err := fake.client(t).CreateAPIToken(context.Background(), "alice@pbs", "ci", nil)
	if err != nil || tokenID != "alice@pbs!ci" || secret != sampleTokenSecret {
		t.Fatalf("CreateAPIToken() = %q, %q, %v", tokenID, secret, err)
	}
}

// An answer without the secret is an error, and one that must not quote the
// answer: whatever PBS sent in place of "value" may well be the secret.
func TestCreateAPITokenWithoutSecretDoesNotQuoteTheData(t *testing.T) {
	answers := map[string]string{
		"secret under another key": `{"data":{"tokenid":"alice@pbs!ci","secret":"` + sampleTokenSecret + `"}}`,
		"empty value":              `{"data":{"tokenid":"alice@pbs!ci","value":"","comment":"` + sampleTokenSecret + `"}}`,
		"data not an object":       `{"data":"` + sampleTokenSecret + `"}`,
		"null data":                `{"data":null}`,
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("POST /access/users/alice@pbs/token/ci", http.StatusOK, answer)
			tokenID, secret, err := fake.client(t).CreateAPIToken(context.Background(), "alice@pbs", "ci", nil)
			if err == nil || tokenID != "" || secret != "" {
				t.Fatalf("CreateAPIToken() = %q, %q, %v", tokenID, secret, err)
			}
			if strings.Contains(err.Error(), sampleTokenSecret) || !strings.Contains(err.Error(), "alice@pbs!ci") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// A refusal comes back as PBS's own error, which the provider recognises.
func TestCreateAPITokenReportsAnExistingToken(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /access/users/alice@pbs/token/ci", http.StatusBadRequest, "token 'ci' for user 'alice@pbs' already exists.")
	_, _, err := fake.client(t).CreateAPIToken(context.Background(), "alice@pbs", "ci", nil)
	if !IsAlreadyExists(err) {
		t.Fatalf("CreateAPIToken() = %v, want an already-exists error", err)
	}
}

func TestUpdateAPITokenWithoutRegenerateSendsTheParams(t *testing.T) {
	fake := newFakePBS()
	fake.reply("PUT /access/users/alice@pbs/token/ci", http.StatusOK, `{"data":null}`)
	params := url.Values{"comment": {"pipeline"}, "delete": {"expire"}}
	secret, err := fake.client(t).UpdateAPIToken(context.Background(), "alice@pbs", "ci", params, false)
	if err != nil || secret != "" {
		t.Fatalf("UpdateAPIToken() = %q, %v", secret, err)
	}
	if call := fake.lastCall(t, "PUT /access/users/alice@pbs/token/ci"); !reflect.DeepEqual(call.form, params) {
		t.Fatalf("form = %v, want %v", call.form, params)
	}
}

func TestUpdateAPITokenRegeneratesTheSecret(t *testing.T) {
	const route = "PUT /access/users/alice@pbs/token/ci"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":{"secret":"`+sampleTokenSecret+`"}}`)
	c := fake.client(t)
	ctx := context.Background()

	params := url.Values{"comment": {"pipeline"}}
	secret, err := c.UpdateAPIToken(ctx, "alice@pbs", "ci", params, true)
	if err != nil || secret != sampleTokenSecret {
		t.Fatalf("UpdateAPIToken() = %q, %v", secret, err)
	}
	want := url.Values{"comment": {"pipeline"}, "regenerate": {"1"}}
	if call := fake.lastCall(t, route); !reflect.DeepEqual(call.form, want) {
		t.Fatalf("form = %v, want %v", call.form, want)
	}
	// The caller's params stay its own: a caller that reuses them, for a
	// retry say, must not regenerate the secret by accident.
	if !reflect.DeepEqual(params, url.Values{"comment": {"pipeline"}}) {
		t.Fatalf("params = %v, changed by the call", params)
	}

	// With nothing else to change, regenerate is the whole request.
	if _, err := c.UpdateAPIToken(ctx, "alice@pbs", "ci", nil, true); err != nil {
		t.Fatal(err)
	}
	if call := fake.lastCall(t, route); !reflect.DeepEqual(call.form, url.Values{"regenerate": {"1"}}) {
		t.Fatalf("form = %v, want only regenerate", call.form)
	}
}

// The old secret stops working once PBS regenerates it, so an answer without
// the new one is an error, which must not quote the answer either.
func TestUpdateAPITokenWithoutSecretIsAnError(t *testing.T) {
	answers := map[string]string{
		"null data":                `{"data":null}`,
		"secret under another key": `{"data":{"value":"` + sampleTokenSecret + `"}}`,
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("PUT /access/users/alice@pbs/token/ci", http.StatusOK, answer)
			secret, err := fake.client(t).UpdateAPIToken(context.Background(), "alice@pbs", "ci", nil, true)
			if err == nil || secret != "" {
				t.Fatalf("UpdateAPIToken() = %q, %v", secret, err)
			}
			if strings.Contains(err.Error(), sampleTokenSecret) || !strings.Contains(err.Error(), "alice@pbs!ci") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestListACLFiltersByPath(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/acl", http.StatusOK, `{"data":[`+
		`{"path":"/datastore/ds1","ugid":"alice@pbs!ci","ugid_type":"user","roleid":"DatastoreBackup","propagate":false},`+
		`{"path":"/datastore/ds1","ugid":"alice@pbs","ugid_type":"user","roleid":"DatastoreAudit"}`+
		`],"digest":"9f86d081884c7d65"}`)
	c := fake.client(t)
	ctx := context.Background()

	no := false
	wantEntries := []ACLEntry{
		{Path: "/datastore/ds1", UGID: "alice@pbs!ci", UGIDType: "user", RoleID: "DatastoreBackup", Propagate: &no},
		{Path: "/datastore/ds1", UGID: "alice@pbs", UGIDType: "user", RoleID: "DatastoreAudit"},
	}
	tests := []struct {
		path      string
		exact     bool
		wantQuery url.Values
	}{
		// exact means nothing without a path, so it is not sent.
		{"", false, url.Values{}},
		{"", true, url.Values{}},
		{"/datastore/ds1", false, url.Values{"path": {"/datastore/ds1"}}},
		{"/datastore/ds1", true, url.Values{"path": {"/datastore/ds1"}, "exact": {"1"}}},
	}
	for _, tc := range tests {
		entries, digest, err := c.ListACL(ctx, tc.path, tc.exact)
		if err != nil {
			t.Fatal(err)
		}
		if call := fake.lastCall(t, "GET /access/acl"); !reflect.DeepEqual(call.query, tc.wantQuery) {
			t.Errorf("ListACL(%q, %v) query = %v, want %v", tc.path, tc.exact, call.query, tc.wantQuery)
		}
		if digest != "9f86d081884c7d65" || !reflect.DeepEqual(entries, wantEntries) {
			t.Fatalf("ListACL(%q, %v) = %+v, %q", tc.path, tc.exact, entries, digest)
		}
	}

	fake.reply("GET /access/acl", http.StatusForbidden, "permission check failed")
	entries, digest, err := c.ListACL(ctx, "", false)
	if !IsForbidden(err) || entries != nil || digest != "" {
		t.Fatalf("ListACL() = %+v, %q, %v, want only the error", entries, digest, err)
	}
}

// PBS leaves propagate out at its default, true.
func TestACLEntryPropagatesByDefault(t *testing.T) {
	yes, no := true, false
	if !(ACLEntry{}).Propagates() || !(ACLEntry{Propagate: &yes}).Propagates() || (ACLEntry{Propagate: &no}).Propagates() {
		t.Fatal("Propagates() does not default to true or does not follow Propagate")
	}

	var entry ACLEntry
	if err := json.Unmarshal([]byte(`{"path":"/","ugid":"alice@pbs","ugid_type":"user","roleid":"Audit"}`), &entry); err != nil {
		t.Fatal(err)
	}
	if !entry.Propagates() {
		t.Fatalf("an entry without propagate does not propagate: %+v", entry)
	}
}

// UpdateACL always names the path, the user or token and the role, and
// sends the optional parameters only when they are set.
func TestUpdateACLSendsOnlyWhatIsSet(t *testing.T) {
	yes, no := true, false
	tests := map[string]struct {
		change ACLChange
		want   url.Values
	}{
		"grant": {
			ACLChange{Path: "/datastore/ds1", AuthID: "alice@pbs!ci", Role: "DatastoreBackup"},
			url.Values{"path": {"/datastore/ds1"}, "auth-id": {"alice@pbs!ci"}, "role": {"DatastoreBackup"}},
		},
		"propagate": {
			ACLChange{Path: "/", AuthID: "alice@pbs", Role: "Audit", Propagate: &yes},
			url.Values{"path": {"/"}, "auth-id": {"alice@pbs"}, "role": {"Audit"}, "propagate": {"true"}},
		},
		"no propagate": {
			ACLChange{Path: "/", AuthID: "alice@pbs", Role: "Audit", Propagate: &no},
			url.Values{"path": {"/"}, "auth-id": {"alice@pbs"}, "role": {"Audit"}, "propagate": {"false"}},
		},
		"remove with digest": {
			ACLChange{Path: "/datastore/ds1", AuthID: "alice@pbs!ci", Role: "DatastoreBackup", Delete: true, Digest: "9f86d081884c7d65"},
			url.Values{"path": {"/datastore/ds1"}, "auth-id": {"alice@pbs!ci"}, "role": {"DatastoreBackup"},
				"delete": {"1"}, "digest": {"9f86d081884c7d65"}},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("PUT /access/acl", http.StatusOK, `{"data":null}`)
			if err := fake.client(t).UpdateACL(context.Background(), tc.change); err != nil {
				t.Fatal(err)
			}
			if call := fake.lastCall(t, "PUT /access/acl"); !reflect.DeepEqual(call.form, tc.want) {
				t.Fatalf("form = %v, want %v", call.form, tc.want)
			}
		})
	}
}

func TestListRolesDecodesPrivileges(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/roles", http.StatusOK, `{"data":[`+
		`{"roleid":"Admin","privs":["Sys.Audit","Sys.Modify"]},`+
		`{"roleid":"NoAccess","comment":"Disable Access","privs":[]}]}`)
	roles, err := fake.client(t).ListRoles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Role{
		{RoleID: "Admin", Privileges: []string{"Sys.Audit", "Sys.Modify"}},
		{RoleID: "NoAccess", Comment: "Disable Access", Privileges: []string{}},
	}
	if !reflect.DeepEqual(roles, want) {
		t.Fatalf("ListRoles() = %+v, want %+v", roles, want)
	}
	if call := fake.lastCall(t, "GET /access/roles"); len(call.query) != 0 {
		t.Fatalf("query = %v, want none", call.query)
	}
}

// Without auth-id PBS answers for the caller, and without path for every path
// the caller has an entry on, so each is sent only when set.
func TestPermissionsSendsOnlyWhatIsSet(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/permissions", http.StatusOK,
		`{"data":{"/":{"Sys.Audit":false},"/datastore/ds1":{"Datastore.Audit":true,"Datastore.Backup":true}}}`)
	c := fake.client(t)
	ctx := context.Background()

	wantPermissions := map[string]map[string]bool{
		"/":              {"Sys.Audit": false},
		"/datastore/ds1": {"Datastore.Audit": true, "Datastore.Backup": true},
	}
	tests := []struct {
		authID, path string
		wantQuery    url.Values
	}{
		{"", "", url.Values{}},
		{"alice@pbs!ci", "", url.Values{"auth-id": {"alice@pbs!ci"}}},
		{"", "/datastore/ds1", url.Values{"path": {"/datastore/ds1"}}},
		{"alice@pbs!ci", "/datastore/ds1", url.Values{"auth-id": {"alice@pbs!ci"}, "path": {"/datastore/ds1"}}},
	}
	for _, tc := range tests {
		permissions, err := c.Permissions(ctx, tc.authID, tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if call := fake.lastCall(t, "GET /access/permissions"); !reflect.DeepEqual(call.query, tc.wantQuery) {
			t.Errorf("Permissions(%q, %q) query = %v, want %v", tc.authID, tc.path, call.query, tc.wantQuery)
		}
		if !reflect.DeepEqual(permissions, wantPermissions) {
			t.Fatalf("Permissions(%q, %q) = %v", tc.authID, tc.path, permissions)
		}
	}
}

// A user name may contain "!" and "@"; a realm and a token name contain
// neither, which is what makes a token ID splittable at all.
func TestSplitTokenID(t *testing.T) {
	valid := []struct {
		tokenID, userID, tokenName string
	}{
		{"alice@pbs!ci", "alice@pbs", "ci"},
		{"a@b.example@pbs!ci", "a@b.example@pbs", "ci"},
		{"x!y@pbs!ci", "x!y@pbs", "ci"},
		{"root@pam!pve-1.backup_2", "root@pam", "pve-1.backup_2"},
	}
	for _, tc := range valid {
		userID, tokenName, ok := SplitTokenID(tc.tokenID)
		if !ok || userID != tc.userID || tokenName != tc.tokenName {
			t.Errorf("SplitTokenID(%q) = %q, %q, %v, want %q, %q, true", tc.tokenID, userID, tokenName, ok, tc.userID, tc.tokenName)
		}
		if got := TokenID(tc.userID, tc.tokenName); got != tc.tokenID {
			t.Errorf("TokenID(%q, %q) = %q, want %q", tc.userID, tc.tokenName, got, tc.tokenID)
		}
	}

	for _, bad := range []string{
		"",
		"alice@pbs",
		"alice@pbs!",
		"!ci",
		"alice!ci",
		// A user ID whose name contains "!": the part before it has no realm.
		"x!y@pbs",
	} {
		if userID, tokenName, ok := SplitTokenID(bad); ok || userID != "" || tokenName != "" {
			t.Errorf("SplitTokenID(%q) = %q, %q, %v, want it refused", bad, userID, tokenName, ok)
		}
	}
}

// "a@b!c@pbs" is a user ID, name "a@b!c" and realm "pbs", not a token ID: what
// follows its last "!" contains "@", which a token name never does.
func TestSplitTokenIDRefusesAUserIDWithAtAndBangInTheName(t *testing.T) {
	if userID, tokenName, ok := SplitTokenID("a@b!c@pbs"); ok || userID != "" || tokenName != "" {
		t.Fatalf("SplitTokenID(%q) = %q, %q, %v, want it refused", "a@b!c@pbs", userID, tokenName, ok)
	}
}

// The realm is what follows the last "@", since a user name may contain "@"
// and a realm never does.
func TestRealm(t *testing.T) {
	tests := map[string]string{
		"alice@pbs":       "pbs",
		"root@pam":        "pam",
		"a@b.example@pbs": "pbs",
		"x!y@pbs":         "pbs",
		"alice":           "",
		"":                "",
	}
	for userID, want := range tests {
		if got := Realm(userID); got != want {
			t.Errorf("Realm(%q) = %q, want %q", userID, got, want)
		}
	}
}

// The texts PBS answers when asked to create a user or token that exists;
// only a 400 with one of them counts.
func TestIsAlreadyExists(t *testing.T) {
	for _, message := range []string{
		"user 'x' already exists.",
		"token 'a' for user 'b' already exists.",
	} {
		if !IsAlreadyExists(apiError(http.StatusBadRequest, message)) {
			t.Errorf("IsAlreadyExists(400 %q) = false, want true", message)
		}
	}

	others := []struct {
		status  int
		message string
	}{
		{400, "parameter verification failed - 'userid': value does not match the regex pattern"},
		{400, "no such user 'x'"},
		{400, "detected modified configuration - file changed by other user? Try again."},
		{404, "user 'x' already exists."},
		{404, "Path '/api2/json/access/users' not found."},
	}
	for _, tc := range others {
		if IsAlreadyExists(apiError(tc.status, tc.message)) {
			t.Errorf("IsAlreadyExists(%d %q) = true, want false", tc.status, tc.message)
		}
	}
	if IsAlreadyExists(errors.New("user 'x' already exists.")) || IsAlreadyExists(nil) {
		t.Error("IsAlreadyExists accepted an error that is not an API error")
	}
}

// The calls that only name a user or token go to its path and send nothing
// else, with a user name containing "!" reaching the server intact.
func TestAccessCallsHitTheirRoutes(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /access/users/x!y@pbs/token", http.StatusOK,
		`{"data":[{"tokenid":"x!y@pbs!ci","comment":"pipeline"},{"tokenid":"x!y@pbs!old","enable":false}]}`)
	fake.reply("GET /access/users/x!y@pbs/token/ci", http.StatusOK,
		`{"data":{"tokenid":"x!y@pbs!ci","comment":"pipeline","expire":1767225600}}`)
	fake.reply("DELETE /access/users/x!y@pbs/token/ci", http.StatusOK, `{"data":null}`)
	fake.reply("PUT /access/users/a@b.example@pbs", http.StatusOK, `{"data":null}`)
	fake.reply("DELETE /access/users/a@b.example@pbs", http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	tokens, err := c.ListAPITokens(ctx, "x!y@pbs")
	if err != nil || len(tokens) != 2 || tokens[0].TokenID != "x!y@pbs!ci" || tokens[0].Comment != "pipeline" ||
		!tokens[0].Enabled() || tokens[1].TokenID != "x!y@pbs!old" || tokens[1].Enabled() {
		t.Fatalf("ListAPITokens() = %+v, %v", tokens, err)
	}
	token, err := c.GetAPIToken(ctx, "x!y@pbs", "ci")
	if err != nil || token.TokenID != "x!y@pbs!ci" || token.Comment != "pipeline" || token.Expiry() != 1767225600 {
		t.Fatalf("GetAPIToken() = %+v, %v", token, err)
	}
	if err := c.DeleteAPIToken(ctx, "x!y@pbs", "ci"); err != nil {
		t.Fatalf("DeleteAPIToken() = %v", err)
	}
	params := url.Values{"comment": {"ops"}}
	if err := c.UpdateUser(ctx, "a@b.example@pbs", params); err != nil {
		t.Fatalf("UpdateUser() = %v", err)
	}
	if call := fake.lastCall(t, "PUT /access/users/a@b.example@pbs"); !reflect.DeepEqual(call.form, params) {
		t.Fatalf("UpdateUser form = %v, want %v", call.form, params)
	}
	if err := c.DeleteUser(ctx, "a@b.example@pbs"); err != nil {
		t.Fatalf("DeleteUser() = %v", err)
	}

	want := []string{
		"GET /access/users/x!y@pbs/token",
		"GET /access/users/x!y@pbs/token/ci",
		"DELETE /access/users/x!y@pbs/token/ci",
		"PUT /access/users/a@b.example@pbs",
		"DELETE /access/users/a@b.example@pbs",
	}
	if got := fake.routes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	for _, route := range []string{"GET /access/users/x!y@pbs/token", "GET /access/users/x!y@pbs/token/ci",
		"DELETE /access/users/x!y@pbs/token/ci", "DELETE /access/users/a@b.example@pbs"} {
		if call := fake.lastCall(t, route); len(call.query) != 0 || len(call.form) != 0 {
			t.Errorf("%s query = %v, form = %v, want neither", route, call.query, call.form)
		}
	}
}
