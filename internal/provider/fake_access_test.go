package provider

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeAccess keeps users, API tokens and ACL entries in memory and serves
// PBS's access API from them through a fakePBS, with the behaviour observed
// on PBS 4.0 and 4.2 (see internal/pbsclient/access.go):
//
//   - reads leave out properties at their defaults (enable, expire) and
//     answer the digest of user.cfg or acl.cfg next to the data;
//   - a write carrying a digest that is not the current one fails with 400
//     "detected modified configuration - ...";
//   - PUT /access/users/{userid} ignores a password, and delete accepts only
//     the names PBS accepts; a token's delete only "comment";
//   - only PUT /access/password changes a password: an API token gets 400,
//     and everyone but root@pam must confirm with their own password;
//   - deleting a user deletes its tokens and their ACL entries, but not the
//     user's own; deleting a token deletes its entries;
//   - granting a role to a user or token that does not exist is 400 "no such
//     user." or "no such API token."; granting and removing are idempotent;
//     NoAccess and the other roles of one user or token on one path exclude
//     each other;
//   - GET /access/permissions answers the caller's privileges on
//     /access/acl, and without Sys.Audit there (hideACL) GET /access/acl
//     shows only the entries of the caller's own user's tokens;
//   - missing objects answer the 400s PBS answers.
//
// Tests set up state with addUser, addToken and addACL, and look at it with
// user, token, aclEntries and password.
type fakeAccess struct {
	fake *fakePBS

	mu        sync.Mutex
	users     map[string]pbsclient.User
	passwords map[string]string
	tokens    map[string]pbsclient.APIToken
	secrets   map[string]string
	acl       []pbsclient.ACLEntry
	// userGen and aclGen count the writes to user.cfg and acl.cfg; the
	// digests are derived from them.
	userGen, aclGen int
	secretGen       int
	// hideACL takes Sys.Audit on /access/acl away from the fake's token: PBS
	// then shows it only the entries of its own user's tokens.
	hideACL bool
}

// fakeRoles is what GET /access/roles answers: a few of PBS's roles, enough
// for tests.
const fakeRoles = `{"data":[
	{"roleid":"Admin","comment":"Administrator","privs":["Datastore.Allocate","Datastore.Audit","Permissions.Modify","Sys.Audit"]},
	{"roleid":"NoAccess","comment":"Disable Access - overrides other roles.","privs":[]},
	{"roleid":"DatastoreBackup","comment":"Datastore Backup User (only backup and restore owned backups)","privs":["Datastore.Backup"]}]}`

// newFakeAccess serves the access API from fake.
func newFakeAccess(fake *fakePBS) *fakeAccess {
	a := &fakeAccess{
		fake:      fake,
		users:     map[string]pbsclient.User{},
		passwords: map[string]string{},
		tokens:    map[string]pbsclient.APIToken{},
		secrets:   map[string]string{},
	}
	fake.handle("GET /access/users", a.listUsers)
	fake.handle("POST /access/users", a.createUser)
	fake.handle("PUT /access/password", a.changePassword)
	fake.handle("GET /access/acl", a.readACL)
	fake.handle("PUT /access/acl", a.updateACL)
	fake.handle("GET /access/permissions", a.permissions)
	fake.reply("GET /access/roles", http.StatusOK, fakeRoles)
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /access/users/", a.serveUser)
	}
	return a
}

// --- test helpers -------------------------------------------------------------

func (a *fakeAccess) addUser(u pbsclient.User) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.users[u.UserID] = u
	a.userGen++
}

func (a *fakeAccess) addToken(t pbsclient.APIToken, secret string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[t.TokenID] = t
	a.secrets[t.TokenID] = secret
	a.userGen++
}

func (a *fakeAccess) addACL(e pbsclient.ACLEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.acl = append(a.acl, e)
	a.aclGen++
}

func (a *fakeAccess) user(userID string) (pbsclient.User, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := a.users[userID]
	return u, ok
}

func (a *fakeAccess) token(tokenID string) (pbsclient.APIToken, string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tokens[tokenID]
	return t, a.secrets[tokenID], ok
}

func (a *fakeAccess) password(userID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.passwords[userID]
}

// aclEntries returns the entries as "path|ugid|role|propagate", sorted.
func (a *fakeAccess) aclEntries() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.acl {
		out = append(out, aclID(e.Path, e.UGID, e.RoleID)+"|"+strconv.FormatBool(e.Propagates()))
	}
	sort.Strings(out)
	return out
}

// touchACL changes acl.cfg as another client would, so that a digest read
// before is stale.
func (a *fakeAccess) touchACL() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.aclGen++
}

// --- serving ------------------------------------------------------------------

func fakeDigest(file string, gen int) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(file+strconv.Itoa(gen))))
}

// writeData answers {"data": data, "digest": digest}.
func writeData(w http.ResponseWriter, data any, digest string) {
	envelope := map[string]any{"data": data}
	if digest != "" {
		envelope["digest"] = digest
	}
	body, _ := json.Marshal(envelope)
	writeFakeResponse(w, http.StatusOK, string(body))
}

func writeError(w http.ResponseWriter, format string, args ...any) {
	writeFakeResponse(w, http.StatusBadRequest, fmt.Sprintf(format, args...))
}

// form returns the request's parameters: the query for GET and DELETE, the
// form body otherwise.
func form(req *http.Request) url.Values {
	if req.Method == http.MethodGet || req.Method == http.MethodDelete {
		return req.URL.Query()
	}
	_ = req.ParseForm()
	return req.PostForm
}

// staleDigest reports whether params carry a digest other than current.
func staleDigest(params url.Values, current string) bool {
	d := params.Get(pbsclient.DigestParam)
	return d != "" && d != current
}

const fakeDigestConflict = "detected modified configuration - file changed by other user? Try again."

func fakeBool(s string) bool { return s == "1" || s == "true" || s == "yes" || s == "on" }

// applyValidity sets enable and expire from params as PBS stores them: an
// expire of 0 is no expiry, which reads as no property at all.
func applyValidity(v *pbsclient.Validity, params url.Values) {
	if s, ok := params["enable"]; ok {
		b := fakeBool(s[0])
		v.Enable = &b
	}
	if s, ok := params["expire"]; ok {
		n, _ := strconv.ParseInt(s[0], 10, 64)
		v.Expire = &n
		if n == 0 {
			v.Expire = nil
		}
	}
}

// checkDelete fails like PBS when delete names a property outside allowed.
func checkDelete(w http.ResponseWriter, params url.Values, allowed ...string) bool {
	for _, name := range params[pbsclient.DeleteParam] {
		if !slices.Contains(allowed, name) {
			writeError(w, "parameter verification failed - 'delete': value '%s' is not defined in the enumeration.", name)
			return false
		}
	}
	return true
}

func (a *fakeAccess) listUsers(w http.ResponseWriter, req *http.Request) {
	withTokens := fakeBool(req.URL.Query().Get("include_tokens"))
	a.mu.Lock()
	defer a.mu.Unlock()
	users := []pbsclient.User{}
	for _, u := range a.users {
		u.Tokens = nil
		if withTokens {
			for id, t := range a.tokens {
				if owner, _, _ := pbsclient.SplitTokenID(id); owner == u.UserID {
					u.Tokens = append(u.Tokens, t)
				}
			}
		}
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].UserID < users[j].UserID })
	writeData(w, users, fakeDigest("user.cfg", a.userGen))
}

func (a *fakeAccess) createUser(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	userID := params.Get("userid")
	if _, exists := a.users[userID]; exists {
		writeError(w, "user '%s' already exists.", userID)
		return
	}
	u := pbsclient.User{
		UserID:    userID,
		Comment:   params.Get("comment"),
		Email:     params.Get("email"),
		Firstname: params.Get("firstname"),
		Lastname:  params.Get("lastname"),
	}
	applyValidity(&u.Validity, params)
	a.users[userID] = u
	if password := params.Get("password"); password != "" {
		a.passwords[userID] = password
	}
	a.userGen++
	writeData(w, nil, "")
}

// serveUser serves /access/users/{userid}[/token[/{name}]].
func (a *fakeAccess) serveUser(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/access/users/")
	parts := strings.Split(rest, "/")
	switch {
	case len(parts) == 1:
		a.serveOneUser(w, req, parts[0])
	case len(parts) == 2 && parts[1] == "token" && req.Method == http.MethodGet:
		a.listTokens(w, parts[0])
	case len(parts) == 3 && parts[1] == "token":
		a.serveToken(w, req, parts[0], parts[2])
	default:
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
	}
}

func (a *fakeAccess) serveOneUser(w http.ResponseWriter, req *http.Request, userID string) {
	params := form(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	u, exists := a.users[userID]
	digest := fakeDigest("user.cfg", a.userGen)

	switch req.Method {
	case http.MethodGet:
		if !exists {
			writeError(w, "no such user '%s'", userID)
			return
		}
		writeData(w, u, digest)
	case http.MethodPut:
		if staleDigest(params, digest) {
			writeError(w, fakeDigestConflict)
			return
		}
		if !exists {
			writeError(w, "no such user '%s'", userID)
			return
		}
		if !checkDelete(w, params, userDeletable...) {
			return
		}
		for _, name := range params[pbsclient.DeleteParam] {
			setUserProperty(&u, name, "")
		}
		for _, name := range []string{"comment", "email", "firstname", "lastname"} {
			if _, ok := params[name]; ok {
				setUserProperty(&u, name, params.Get(name))
			}
		}
		applyValidity(&u.Validity, params)
		// PBS answers 200 to a password here and ignores it.
		a.users[userID] = u
		a.userGen++
		writeData(w, nil, "")
	case http.MethodDelete:
		if !exists {
			writeError(w, "user '%s' does not exist.", userID)
			return
		}
		delete(a.users, userID)
		delete(a.passwords, userID)
		for id := range a.tokens {
			if owner, _, _ := pbsclient.SplitTokenID(id); owner == userID {
				a.removeTokenLocked(id)
			}
		}
		a.userGen++
		writeData(w, nil, "")
	default:
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
	}
}

func setUserProperty(u *pbsclient.User, name, value string) {
	switch name {
	case "comment":
		u.Comment = strings.TrimSpace(value)
	case "email":
		u.Email = value
	case "firstname":
		u.Firstname = value
	case "lastname":
		u.Lastname = value
	}
}

// removeTokenLocked deletes a token and its ACL entries.
func (a *fakeAccess) removeTokenLocked(tokenID string) {
	delete(a.tokens, tokenID)
	delete(a.secrets, tokenID)
	kept := a.acl[:0]
	removed := false
	for _, e := range a.acl {
		if e.UGID == tokenID {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	a.acl = kept
	if removed {
		a.aclGen++
	}
}

func (a *fakeAccess) listTokens(w http.ResponseWriter, userID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.users[userID]; !exists {
		writeError(w, "no such user '%s'", userID)
		return
	}
	type listed struct {
		pbsclient.APIToken
		TokenName string `json:"token-name"`
	}
	tokens := []listed{}
	for id, t := range a.tokens {
		if owner, name, _ := pbsclient.SplitTokenID(id); owner == userID {
			tokens = append(tokens, listed{APIToken: t, TokenName: name})
		}
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].TokenID < tokens[j].TokenID })
	writeData(w, tokens, fakeDigest("user.cfg", a.userGen))
}

func (a *fakeAccess) serveToken(w http.ResponseWriter, req *http.Request, userID, name string) {
	params := form(req)
	tokenID := pbsclient.TokenID(userID, name)
	a.mu.Lock()
	defer a.mu.Unlock()
	t, exists := a.tokens[tokenID]
	digest := fakeDigest("user.cfg", a.userGen)

	switch req.Method {
	case http.MethodGet:
		if !exists {
			writeError(w, "no such token '%s'", tokenID)
			return
		}
		writeData(w, t, digest)
	case http.MethodPost:
		if _, ok := a.users[userID]; !ok {
			writeError(w, "no such user '%s'", userID)
			return
		}
		if exists {
			writeError(w, "token '%s' for user '%s' already exists.", name, userID)
			return
		}
		t = pbsclient.APIToken{TokenID: tokenID, Comment: params.Get("comment")}
		applyValidity(&t.Validity, params)
		a.tokens[tokenID] = t
		secret := a.newSecretLocked()
		a.secrets[tokenID] = secret
		a.userGen++
		writeData(w, map[string]string{"tokenid": tokenID, "value": secret}, "")
	case http.MethodPut:
		if staleDigest(params, digest) {
			writeError(w, fakeDigestConflict)
			return
		}
		if !exists {
			writeError(w, "no such token '%s'", tokenID)
			return
		}
		if !checkDelete(w, params, apiTokenDeletable...) {
			return
		}
		if len(params[pbsclient.DeleteParam]) > 0 {
			t.Comment = ""
		}
		if _, ok := params["comment"]; ok {
			t.Comment = strings.TrimSpace(params.Get("comment"))
		}
		applyValidity(&t.Validity, params)
		a.tokens[tokenID] = t
		a.userGen++
		if fakeBool(params.Get("regenerate")) {
			secret := a.newSecretLocked()
			a.secrets[tokenID] = secret
			// The token the fake accepts is revoked as PBS revokes it.
			if tokenID == a.fake.tokenID {
				a.fake.mu.Lock()
				a.fake.tokenSecret = secret
				a.fake.mu.Unlock()
			}
			writeData(w, map[string]string{"secret": secret}, "")
			return
		}
		writeData(w, map[string]any{}, "")
	case http.MethodDelete:
		if !exists {
			writeError(w, "token '%s' of user '%s' does not exist.", name, userID)
			return
		}
		a.removeTokenLocked(tokenID)
		a.userGen++
		writeData(w, nil, "")
	}
}

func (a *fakeAccess) newSecretLocked() string {
	a.secretGen++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", a.secretGen)
}

func (a *fakeAccess) changePassword(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if req.Header.Get("Authorization") != "" {
		writeError(w, "API tokens cannot access this API endpoint")
		return
	}
	// Only the fake's own user signs in with a ticket.
	caller := a.fake.username
	if caller != "root@pam" && params.Get("confirmation-password") != a.fake.password {
		writeFakeResponse(w, http.StatusUnauthorized, "authentication failed - invalid credentials")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	userID := params.Get("userid")
	if _, ok := a.users[userID]; !ok {
		writeError(w, "no such user '%s'", userID)
		return
	}
	a.passwords[userID] = params.Get("password")
	writeData(w, nil, "")
}

func (a *fakeAccess) readACL(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	path, exact := query.Get("path"), fakeBool(query.Get("exact"))
	a.mu.Lock()
	defer a.mu.Unlock()
	entries := []pbsclient.ACLEntry{}
	for _, e := range a.acl {
		if owner, _, isToken := pbsclient.SplitTokenID(e.UGID); a.hideACL && (!isToken || owner != fakeUsername) {
			continue
		}
		switch {
		case path == "":
		case e.Path == path:
		case !exact && (path == "/" || strings.HasPrefix(e.Path, path+"/")):
		default:
			continue
		}
		propagate := e.Propagates()
		e.Propagate = &propagate
		entries = append(entries, e)
	}
	writeData(w, entries, fakeDigest("acl.cfg", a.aclGen))
}

// permissions answers the caller's own privileges on a path: Admin's on
// /access/acl unless hideACL, nothing anywhere else.
func (a *fakeAccess) permissions(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Query().Get("path")
	a.mu.Lock()
	defer a.mu.Unlock()
	privileges := map[string]bool{"Permissions.Modify": true, "Sys.Audit": true}
	if a.hideACL {
		delete(privileges, "Sys.Audit")
	}
	if path != "/access/acl" {
		privileges = map[string]bool{}
	}
	writeData(w, map[string]map[string]bool{path: privileges}, "")
}

func (a *fakeAccess) updateACL(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	path, authID, role := params.Get("path"), params.Get("auth-id"), params.Get("role")
	a.mu.Lock()
	defer a.mu.Unlock()
	if staleDigest(params, fakeDigest("acl.cfg", a.aclGen)) {
		writeError(w, fakeDigestConflict)
		return
	}
	if !aclPathPattern.MatchString(path) || strings.HasPrefix(path, "/bogus") {
		writeError(w, "invalid acl path '%s'.", path)
		return
	}

	index := -1
	for i, e := range a.acl {
		if e.Path == path && e.UGID == authID && e.RoleID == role {
			index = i
		}
	}
	if fakeBool(params.Get("delete")) {
		if index >= 0 {
			a.acl = append(a.acl[:index], a.acl[index+1:]...)
			a.aclGen++
		}
		writeData(w, nil, "")
		return
	}

	if strings.Contains(authID, "!") {
		if _, ok := a.tokens[authID]; !ok {
			writeError(w, "no such API token.")
			return
		}
	} else if _, ok := a.users[authID]; !ok {
		writeError(w, "no such user.")
		return
	}
	propagate := true
	if s, ok := params["propagate"]; ok {
		propagate = fakeBool(s[0])
	}
	// NoAccess excludes every other role of the same user or token on the
	// path, both ways.
	kept := a.acl[:0]
	for _, e := range a.acl {
		if e.Path == path && e.UGID == authID && e.RoleID != role &&
			(role == pbsclient.NoAccessRole || e.RoleID == pbsclient.NoAccessRole) {
			continue
		}
		kept = append(kept, e)
	}
	a.acl = kept
	entry := pbsclient.ACLEntry{Path: path, UGID: authID, UGIDType: "user", RoleID: role, Propagate: &propagate}
	replaced := false
	for i, e := range a.acl {
		if e.Path == path && e.UGID == authID && e.RoleID == role {
			a.acl[i], replaced = entry, true
		}
	}
	if !replaced {
		a.acl = append(a.acl, entry)
	}
	a.aclGen++
	writeData(w, nil, "")
}
