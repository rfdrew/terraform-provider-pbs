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
//     user's own; deleting a token deletes its entries. A user of a realm
//     removeRealm took away is deleted, but the deletion answers 400
//     "unknown realm" and leaves its tokens, which can still be listed and
//     deleted, as the tokens of any user, existing or not;
//   - granting a role to a user or token that does not exist is 400 "no such
//     user." or "no such API token."; granting and removing are idempotent;
//     NoAccess and the other roles of one user or token on one path exclude
//     each other; root@pam's own entries are granted and removed without an
//     error but never stored, since PBS never saves them;
//   - GET /access/acl with path "/" and without exact names the entries below
//     the root "//datastore", "//datastore/store1" and so on, as PBS does;
//   - the fake's API token and its user, signed in with its password, have
//     the Admin role on /access and below unless hideACL takes it away. GET
//     /access/permissions of the caller answers Sys.Audit and
//     Permissions.Modify, two of Admin's privileges, on /access/acl, or no
//     path at all with hideACL, since PBS leaves out a path without
//     privileges. With hideACL, GET /access/acl shows the token no entry at
//     all and the user only the entries of its own API tokens; PUT
//     /access/acl lets only the user change the entries of its own tokens
//     and refuses everything else with PBS's 400s "Unprivileged ..."; and GET
//     /access/permissions about another user or token is 400 "not allowed to
//     list permissions of ...", except the user's about its own tokens. The
//     fake works out no privileges of other users and tokens and answers none
//     for them;
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
	// hideACL takes the Admin role on /access and below away from the
	// fake's token and its user. Without Sys.Audit on /access/acl, PBS shows
	// the token no ACL entry and the user only those of its own API tokens;
	// without Permissions.Modify there, which only Admin grants, it lets only
	// the user change its own tokens' entries; without Sys.Audit on /access,
	// it lets neither read another's privileges, but the user its tokens'
	// (src/api2/access/acl.rs, read_acl and update_acl, and
	// src/api2/access/mod.rs, list_permissions, proxmox-backup 7c86c5ad5,
	// after 4.2.11). Tests that set it hold mu.
	hideACL bool
	// goneRealms are realms deleted while users of them remain.
	goneRealms map[string]bool
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
		fake:       fake,
		users:      map[string]pbsclient.User{},
		passwords:  map[string]string{},
		tokens:     map[string]pbsclient.APIToken{},
		secrets:    map[string]string{},
		goneRealms: map[string]bool{},
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

// removeRealm deletes a realm, keeping the users of it, as PBS does.
func (a *fakeAccess) removeRealm(realm string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.goneRealms[realm] = true
}

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
		if realm := pbsclient.Realm(userID); a.goneRealms[realm] {
			a.userGen++
			writeError(w, "unknown realm '%s'", realm)
			return
		}
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

// listTokens lists the tokens of a user as PBS does, by owner, without
// looking the user up: the list of a user that does not exist is empty, or
// the tokens a deletion that answered "unknown realm" left
// (src/api2/access/user.rs, list_tokens).
func (a *fakeAccess) listTokens(w http.ResponseWriter, userID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
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

// caller returns who sent req: the fake's API token when the request
// carries the Authorization header, its user otherwise, since only that user
// signs in with a ticket.
func (a *fakeAccess) caller(req *http.Request) (authID string, byToken bool) {
	a.fake.mu.Lock()
	defer a.fake.mu.Unlock()
	if req.Header.Get("Authorization") != "" {
		return a.fake.tokenID, true
	}
	return a.fake.username, false
}

func (a *fakeAccess) changePassword(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	caller, byToken := a.caller(req)
	if byToken {
		writeError(w, "API tokens cannot access this API endpoint")
		return
	}
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

// readACL answers GET /access/acl as PBS's read_acl does: every entry
// without a path; with one, the entries on it and, unless exact, those below
// it, at the path asked for joined with the names below it by a slash, which
// for "/" makes "//datastore"; without a path but with exact, the root's
// entries only. With hideACL, the caller sees only what PBS shows a caller
// without Sys.Audit on /access/acl (src/api2/access/acl.rs, read_acl and
// extract_acl_node_data, proxmox-backup 7c86c5ad5, after 4.2.11).
func (a *fakeAccess) readACL(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	path, exact := query.Get("path"), fakeBool(query.Get("exact"))
	caller, byToken := a.caller(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	entries := []pbsclient.ACLEntry{}
	for _, e := range a.acl {
		if a.hideACL && !shownWithoutAudit(e, caller, byToken) {
			continue
		}
		switch {
		case path == "" && (!exact || e.Path == "/"):
		case e.Path == path:
		case !exact && path == "/":
			e.Path = "/" + e.Path
		case !exact && strings.HasPrefix(e.Path, path+"/"):
		default:
			continue
		}
		propagate := e.Propagates()
		e.Propagate = &propagate
		entries = append(entries, e)
	}
	writeData(w, entries, fakeDigest("acl.cfg", a.aclGen))
}

// shownWithoutAudit reports whether PBS shows the entry e to a caller
// without Sys.Audit on /access/acl: to an API token none, not even its own
// ("tokens can't have tokens"); to a user signed in with its password only
// those of its own API tokens, neither its own nor a group's
// (src/api2/access/acl.rs, extract_acl_node_data).
func shownWithoutAudit(e pbsclient.ACLEntry, caller string, byToken bool) bool {
	if byToken {
		return false
	}
	owner, _, isToken := pbsclient.SplitTokenID(e.UGID)
	return isToken && owner == caller
}

// permissions answers GET /access/permissions as PBS's list_permissions does,
// as far as the provider asks: about the caller itself on /access/acl, where
// it answers Sys.Audit and Permissions.Modify unless hideACL, and nothing
// with hideACL, since PBS leaves out a path without privileges. Any other
// question about the caller — without a path, PBS answers every path of
// acl.cfg and /, /access, /datastore, /remote and /system, which the fake
// does not work out — fails with 501, so that no test relies on an answer
// PBS would not give. About another user or token, it answers no
// privileges, which the fake does not work out either, or with hideACL
// PBS's 400, except to the user about its own tokens (src/api2/access/mod.rs,
// list_permissions, proxmox-backup 7c86c5ad5, after 4.2.11).
func (a *fakeAccess) permissions(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	path, authID := query.Get("path"), query.Get("auth-id")
	caller, byToken := a.caller(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	privileges := map[string]map[string]bool{}
	if authID != "" && authID != caller {
		owner, _, isToken := pbsclient.SplitTokenID(authID)
		if a.hideACL && (byToken || !isToken || owner != caller) {
			writeError(w, "not allowed to list permissions of %s", authID)
			return
		}
		writeData(w, privileges, "")
		return
	}
	if path != "/access/acl" {
		writeFakeResponse(w, http.StatusNotImplemented, "fake: GET /access/permissions about the caller is "+
			"modelled only for path=/access/acl, not "+strconv.Quote(path))
		return
	}
	if !a.hideACL {
		privileges["/access/acl"] = map[string]bool{"Permissions.Modify": true, "Sys.Audit": true}
	}
	writeData(w, privileges, "")
}

// unprivilegedACLChange returns PBS's refusal of an ACL change to a caller
// without Permissions.Modify on /access/acl, or "" when PBS lets the change
// through, as it does for a user signed in with its password and the entries
// of its own API tokens (src/api2/access/acl.rs, update_acl). PBS refuses
// before it looks at the digest, and removing an entry as well as granting
// one.
func unprivilegedACLChange(params url.Values, caller string, byToken bool) string {
	authID := params.Get("auth-id")
	owner, _, isToken := pbsclient.SplitTokenID(authID)
	switch {
	case params.Has("group"):
		return "Unprivileged users are not allowed to create group ACL item."
	case authID == "":
		return "Unprivileged user needs to provide auth_id to update ACL item."
	case byToken:
		return "Unprivileged API tokens can't set ACL items."
	case !isToken:
		return "Unprivileged users can only set ACL items for API tokens."
	case owner != caller:
		return "Unprivileged users can only set ACL items for their own API tokens."
	}
	return ""
}

func (a *fakeAccess) updateACL(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	path, authID, role := params.Get("path"), params.Get("auth-id"), params.Get("role")
	caller, byToken := a.caller(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hideACL {
		if refusal := unprivilegedACLChange(params, caller, byToken); refusal != "" {
			writeError(w, "%s", refusal)
			return
		}
	}
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

	// user.cfg always has root@pam, but acl.cfg never its entries: PBS
	// grants the role and leaves it out when it saves the file, since
	// root@pam always has every privilege (pbs-config/src/acl.rs,
	// write_node_config). acl.cfg, and so its digest, stays as it was.
	if authID == "root@pam" {
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
