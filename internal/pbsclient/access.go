package pbsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// The access layer: users, their API tokens, ACL entries, roles and
// privileges. Users and tokens live in user.cfg, ACL entries in acl.cfg; see
// locks.go for why writes to them are serialised.
//
// What PBS 4.0 and 4.2 do, as observed on real servers:
//
//   - A user or token read leaves out every property at its default: no
//     "enable" for an enabled account and no "expire" for one that never
//     expires. "expire" cannot be deleted; 0 resets it.
//   - POST /access/users takes the new user's password. PUT
//     /access/users/{userid} accepts a password too, answers 200 and ignores
//     it: only PUT /access/password changes a password, and that endpoint is
//     closed to API tokens.
//   - A token's secret is in the answer to its creation, {tokenid, value},
//     and to PUT regenerate=true, {secret}, and nowhere else. The old secret
//     stops working at once.
//   - Deleting a user deletes its tokens and their ACL entries, but not the
//     user's own entries, which apply again to a user created later under
//     the same ID. Deleting a token deletes its ACL entries.
//   - PUT /access/acl adds or, with delete=1, removes one role of one user or
//     token on one path. Both are idempotent, and removing works for a user
//     that no longer exists. An entry for a user or token that does not exist
//     is 400 "no such user." or "no such API token.". NoAccess excludes every
//     other role: granting it removes the user's or token's other roles on
//     the path, and granting another role removes NoAccess there.
//   - A missing user is 400 "no such user 'x'" on GET and "user 'x' does not
//     exist." on DELETE; a missing token is 400 "no such token 'x'" and
//     "token 'x' of user 'y' does not exist."; IsNotFound covers them all.

// Roles is the fixed set of roles PBS knows; it has no API to define others.
var Roles = []string{
	"Admin",
	"Audit",
	"NoAccess",
	"DatastoreAdmin",
	"DatastoreReader",
	"DatastoreBackup",
	"DatastorePowerUser",
	"DatastoreAudit",
	"RemoteAudit",
	"RemoteAdmin",
	"RemoteSyncOperator",
	"RemoteSyncPushOperator",
	"RemoteDatastorePowerUser",
	"RemoteDatastoreAdmin",
	"TapeAudit",
	"TapeAdmin",
	"TapeOperator",
	"TapeReader",
}

// NoAccessRole is the role that excludes every other: on one path, a user or
// token has either NoAccess or any other roles.
const NoAccessRole = "NoAccess"

// ErrPasswordChangeNeedsPassword means the client signs in with an API token,
// and PBS lets only a password session change passwords.
var ErrPasswordChangeNeedsPassword = errors.New("PBS changes passwords only through PUT /access/password, which API tokens cannot call (\"API tokens cannot access this API endpoint\"); sign in with a username and password instead")

// Validity is when a user or token may sign in. PBS leaves out both fields at
// their defaults, so use Enabled and Expiry rather than the fields.
type Validity struct {
	Enable *bool  `json:"enable,omitempty"`
	Expire *int64 `json:"expire,omitempty"`
}

// Enabled reports whether the account is enabled, which it is unless PBS
// says otherwise.
func (v Validity) Enabled() bool { return v.Enable == nil || *v.Enable }

// Expiry is when the account expires, in seconds since the epoch; 0 means
// never.
func (v Validity) Expiry() int64 {
	if v.Expire == nil {
		return 0
	}
	return *v.Expire
}

// User is a user as PBS reports it.
type User struct {
	UserID    string `json:"userid"`
	Comment   string `json:"comment,omitempty"`
	Email     string `json:"email,omitempty"`
	Firstname string `json:"firstname,omitempty"`
	Lastname  string `json:"lastname,omitempty"`
	Validity
	// Tokens is filled only by ListUsers with tokens.
	Tokens []APIToken `json:"tokens,omitempty"`
}

// APIToken is an API token's metadata. Its secret is never part of it.
type APIToken struct {
	// TokenID is "<user>@<realm>!<token name>".
	TokenID string `json:"tokenid"`
	Comment string `json:"comment,omitempty"`
	Validity
}

// ACLEntry is one role of one user or token on one path.
type ACLEntry struct {
	Path string `json:"path"`
	// UGID is the user ID or token ID the entry is for, and UGIDType is
	// "user" for both; PBS has no API for groups.
	UGID     string `json:"ugid"`
	UGIDType string `json:"ugid_type"`
	RoleID   string `json:"roleid"`
	// Propagate is whether the role applies below Path too; nil means true,
	// PBS's default.
	Propagate *bool `json:"propagate,omitempty"`
}

// Propagates reports whether the role applies to the paths below Path.
func (e ACLEntry) Propagates() bool { return e.Propagate == nil || *e.Propagate }

// Role is a role and the privileges it grants.
type Role struct {
	RoleID     string   `json:"roleid"`
	Comment    string   `json:"comment,omitempty"`
	Privileges []string `json:"privs"`
}

// TokenID joins a user ID and a token name into a token ID.
func TokenID(userID, tokenName string) string { return userID + "!" + tokenName }

// SplitTokenID splits a token ID, "<user>@<realm>!<token name>", into the
// user ID and the token name. A user name may contain "!" and "@", but
// neither a realm nor a token name does, so the split is at the last "!",
// which must come after the last "@": "a@b!c@pbs" is a user ID.
func SplitTokenID(tokenID string) (userID, tokenName string, ok bool) {
	i := strings.LastIndexByte(tokenID, '!')
	if i <= 0 || i == len(tokenID)-1 {
		return "", "", false
	}
	userID, tokenName = tokenID[:i], tokenID[i+1:]
	if !strings.Contains(userID, "@") || strings.Contains(tokenName, "@") {
		return "", "", false
	}
	return userID, tokenName, true
}

// Realm returns the realm of a user ID, the part after the last "@": a user
// name may itself contain "@", a realm never does.
func Realm(userID string) string {
	i := strings.LastIndexByte(userID, '@')
	if i < 0 {
		return ""
	}
	return userID[i+1:]
}

// redactAPIError removes secrets the client does not hold — a new password,
// say — from the text of an API error.
func redactAPIError(err error, secrets ...string) error {
	if apiErr, ok := asError(err); ok {
		apiErr.Message = Redact(apiErr.Message, secrets...)
		apiErr.Body = Redact(apiErr.Body, secrets...)
	}
	return err
}

// --- users ------------------------------------------------------------------

// ListUsers reads every user the caller may see: all of them with Sys.Audit
// on /access/users, only itself otherwise. With tokens, every user carries
// its API tokens.
func (c *Client) ListUsers(ctx context.Context, withTokens bool) ([]User, error) {
	var params url.Values
	if withTokens {
		params = url.Values{"include_tokens": {"1"}}
	}
	var users []User
	_, err := c.Get(ctx, "/access/users", params, &users)
	return users, err
}

// GetUser reads one user.
func (c *Client) GetUser(ctx context.Context, userID string) (User, error) {
	var user User
	_, err := c.Get(ctx, Path("access", "users", userID), nil, &user)
	return user, err
}

// CreateUser creates a user from params, which must hold "userid" and may
// hold "password". The password is kept out of any error.
func (c *Client) CreateUser(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/access/users", params, nil)
	return redactAPIError(err, params.Get("password"))
}

// UpdateUser changes the properties params carries, and deletes those named
// in its delete parameter. It cannot change the password; see
// ChangePassword.
func (c *Client) UpdateUser(ctx context.Context, userID string, params url.Values) error {
	_, err := c.Put(ctx, Path("access", "users", userID), params, nil)
	return err
}

// DeleteUser deletes a user and its API tokens, with the tokens' ACL entries
// but not the user's own.
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	_, err := c.Delete(ctx, Path("access", "users", userID), nil, nil)
	return err
}

// ChangePassword sets a user's password through PUT /access/password, which
// only a password session may call; with an API token it fails with
// ErrPasswordChangeNeedsPassword without a request. PBS wants the caller's
// own password as confirmation from everyone but root@pam, and accepts it
// from root@pam too, so it is always sent. The new password is kept out of
// any error.
//
// A wrong confirmation is a 401 from the handler, so the call is not signed
// in again and retried as other calls are after a 401. When the user is the
// one the client signs in as, the client uses the new password from then on,
// to confirm later changes and to sign in again.
func (c *Client) ChangePassword(ctx context.Context, userID, password string) error {
	if c.UsesAPIToken() {
		return ErrPasswordChangeNeedsPassword
	}
	c.passwordChange.Lock()
	defer c.passwordChange.Unlock()
	_, confirmation := c.credentials()
	params := url.Values{
		"userid":                {userID},
		"password":              {password},
		"confirmation-password": {confirmation},
	}
	if _, err := c.call(ctx, http.MethodPut, "/access/password", params, nil, false); err != nil {
		return redactAPIError(err, password)
	}
	if userID == c.username {
		c.credMu.Lock()
		c.password = password
		c.credMu.Unlock()
	}
	return nil
}

// --- API tokens ---------------------------------------------------------------

// ListAPITokens reads the API tokens of one user.
func (c *Client) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	var tokens []APIToken
	_, err := c.Get(ctx, Path("access", "users", userID, "token"), nil, &tokens)
	return tokens, err
}

// GetAPIToken reads the metadata of one API token.
func (c *Client) GetAPIToken(ctx context.Context, userID, tokenName string) (APIToken, error) {
	var token APIToken
	_, err := c.Get(ctx, Path("access", "users", userID, "token", tokenName), nil, &token)
	return token, err
}

// CreateAPIToken creates an API token with the properties in params and
// returns its ID and its secret, which PBS shows only now.
func (c *Client) CreateAPIToken(ctx context.Context, userID, tokenName string, params url.Values) (tokenID, secret string, err error) {
	// The answer is decoded here rather than by Call, whose decoding errors
	// quote the data, and the data holds the secret.
	env, err := c.Post(ctx, Path("access", "users", userID, "token", tokenName), params, nil)
	if err != nil {
		return "", "", err
	}
	var created struct {
		TokenID string `json:"tokenid"`
		Value   string `json:"value"`
	}
	if json.Unmarshal(env.Data, &created) != nil || created.Value == "" {
		return "", "", fmt.Errorf("PBS created API token %s but answered without its secret; delete the token and create it again", TokenID(userID, tokenName))
	}
	if created.TokenID == "" {
		created.TokenID = TokenID(userID, tokenName)
	}
	return created.TokenID, created.Value, nil
}

// UpdateAPIToken changes the properties params carries, and deletes those
// named in its delete parameter. With regenerate, PBS also replaces the
// token's secret and the new one is returned; the old one stops working at
// once.
func (c *Client) UpdateAPIToken(ctx context.Context, userID, tokenName string, params url.Values, regenerate bool) (secret string, err error) {
	if regenerate {
		params = cloneValues(params)
		params.Set("regenerate", "1")
	}
	env, err := c.Put(ctx, Path("access", "users", userID, "token", tokenName), params, nil)
	if err != nil || !regenerate {
		return "", err
	}
	var regenerated struct {
		Secret string `json:"secret"`
	}
	if json.Unmarshal(env.Data, &regenerated) != nil || regenerated.Secret == "" {
		return "", fmt.Errorf("PBS regenerated the secret of API token %s but answered without it; regenerate it again", TokenID(userID, tokenName))
	}
	return regenerated.Secret, nil
}

// DeleteAPIToken deletes an API token and its ACL entries.
func (c *Client) DeleteAPIToken(ctx context.Context, userID, tokenName string) error {
	_, err := c.Delete(ctx, Path("access", "users", userID, "token", tokenName), nil, nil)
	return err
}

// --- ACL ----------------------------------------------------------------------

// ListACL reads ACL entries and the digest of acl.cfg: every entry without a
// path; with one, the entries on it and, unless exact, those below it. A
// caller without Sys.Audit on /access/acl sees only the entries of its own
// API tokens.
func (c *Client) ListACL(ctx context.Context, path string, exact bool) ([]ACLEntry, string, error) {
	params := url.Values{}
	if path != "" {
		params.Set("path", path)
		if exact {
			params.Set("exact", "1")
		}
	}
	var entries []ACLEntry
	env, err := c.Get(ctx, "/access/acl", params, &entries)
	if err != nil {
		return nil, "", err
	}
	return entries, env.Digest, nil
}

// ACLChange is one call to PUT /access/acl.
type ACLChange struct {
	Path   string
	AuthID string
	Role   string
	// Propagate is sent when set; PBS defaults to true.
	Propagate *bool
	// Delete removes the role instead of granting it.
	Delete bool
	// Digest, when set, makes PBS refuse the change if acl.cfg changed since
	// it was read.
	Digest string
}

// UpdateACL grants or removes one role of one user or token on one path.
// Granting a role the entry already has sets its propagate flag; removing
// one it does not have is a no-op. Granting NoAccess removes the other roles
// of the same user or token on the path, and granting another role removes
// NoAccess; see NoAccessRole.
func (c *Client) UpdateACL(ctx context.Context, change ACLChange) error {
	params := url.Values{
		"path":    {change.Path},
		"auth-id": {change.AuthID},
		"role":    {change.Role},
	}
	if change.Propagate != nil {
		params.Set("propagate", FormatBool(*change.Propagate))
	}
	if change.Delete {
		params.Set("delete", "1")
	}
	if change.Digest != "" {
		params.Set(DigestParam, change.Digest)
	}
	_, err := c.Put(ctx, "/access/acl", params, nil)
	return err
}

// --- roles and privileges -----------------------------------------------------

// ListRoles reads the roles and the privileges each grants.
func (c *Client) ListRoles(ctx context.Context) ([]Role, error) {
	var roles []Role
	_, err := c.Get(ctx, "/access/roles", nil, &roles)
	return roles, err
}

// Permissions reads the privileges of a user or token — the caller itself
// when authID is empty — on every path it has an ACL entry for or, with path
// set, on that path. The result maps each path to its privileges, each to
// whether it propagates to the paths below. Asking about anyone else needs
// Sys.Audit on /access.
func (c *Client) Permissions(ctx context.Context, authID, path string) (map[string]map[string]bool, error) {
	params := url.Values{}
	if authID != "" {
		params.Set("auth-id", authID)
	}
	if path != "" {
		params.Set("path", path)
	}
	permissions := map[string]map[string]bool{}
	_, err := c.Get(ctx, "/access/permissions", params, &permissions)
	return permissions, err
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v)+1)
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
