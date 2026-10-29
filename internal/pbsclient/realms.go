package pbsclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Realms are where users sign in: the built-in pam and pbs, and the LDAP,
// Active Directory and OpenID Connect realms an administrator adds. They all
// live in domains.cfg, one section each, keyed by the realm's name; the API
// daemon adds the sections of pam, as the default, and pbs when they are
// missing. What PBS 4.2 does with OpenID Connect realms, read in its source
// (src/api2/config/access/openid.rs, src/config/mod.rs,
// pbs-config/src/domains.rs, pbs-api-types/src/openid.rs):
//
//   - Creating or changing a realm contacts nothing: PBS checks the
//     parameters against their schema and saves them. The issuer is first
//     asked for its configuration when someone signs in.
//   - The client key is returned by reads, like every other property. It is
//     optional: without one, PBS signs in as a public client.
//   - scopes, acr-values and audiences are single strings that PBS splits
//     at commas, semicolons and white space; it stores them as sent.
//     audiences needs PBS 4.2.1.
//   - username-claim can be set only when the realm is created.
//   - default = true takes the flag away from every other realm, of any
//     type. An update clears the realm's own flag unless it sends default =
//     true again, whatever else it changes.
//   - A duplicate name is 400 "parameter verification failed - 'realm':
//     realm 'x' already exists." — for a realm of any type. A missing realm is
//     400 "no such openid 'x'" on GET and PUT, and 404 "realm 'x' does not
//     exist." on DELETE; IsNotFound covers them. A realm of another type
//     answers GET and PUT with 400 "got unexpected type 'ldap' for openid
//     'x'", IsRealmOfOtherType, but DELETE removes it all the same.
//
// LDAP and Active Directory realms — directory realms here — differ, as read
// in src/api2/config/access/{ldap,ad}.rs, src/auth.rs, src/auth_helpers.rs,
// pbs-api-types/src/{ldap,ad}.rs and the proxmox-ldap crate:
//
//   - Every create and every update, whatever it changes, first connects to
//     the server as the realm would after the change: server1, then server2,
//     on port, or 389 — 636 with mode ldaps — binding as bind-dn when there
//     is one and searching base-dn. Any failure is a 400 with the reason, and
//     nothing is saved: "LDAP bind failed, bind_dn or password could be
//     incorrect: …", "Could not search LDAP realm, base_dn could be incorrect:
//     …", "Missing bind password for <bind-dn>", or the I/O or TLS error of the
//     connection, such as "I/O error: Connection refused (os error 111): …".
//     Connections time out after 5 seconds.
//   - The bind password goes in the parameter password, and PBS keeps it in
//     ldap_passwords.json, outside domains.cfg: reads never return it. An
//     update without one binds with the stored password; delete=password
//     removes it.
//   - An Active Directory realm has no user-attr: PBS looks users up by
//     sAMAccountName. Its base-dn is optional: without one, a create — or an
//     update of a realm that has none — asks the server's root DSE for
//     defaultNamingContext and stores that, or fails with "failed to
//     determine base_dn: …" or "server did not provide
//     `defaultNamingContext`".
//   - user-classes is a list that PBS splits at commas, semicolons and white
//     space; without it, PBS uses inetorgperson, posixaccount, person and
//     user. sync-attributes and sync-defaults-options are property strings;
//     the remove-vanished list inside the latter is separated by semicolons.
//   - capath, base-dn, user-attr and server1 cannot be deleted; delete
//     accepts server2, port, comment, default, verify, mode, bind-dn,
//     password, filter, sync-defaults-options, sync-attributes and
//     user-classes. An update accepts capath, but ignores it: a realm keeps
//     the capath it was created with.
//   - default, the duplicate name and the missing realm behave as for OpenID
//     realms, with "no such ldap 'x'" and "no such ad 'x'". DELETE removes
//     the stored bind password with the section.

// Realm types, as /access/domains reports them.
const (
	RealmTypePAM    = "pam"
	RealmTypePBS    = "pbs"
	RealmTypeOpenID = "openid"
	RealmTypeLDAP   = "ldap"
	RealmTypeAD     = "ad"
)

// RealmInfo is a realm of any type as /access/domains lists it.
type RealmInfo struct {
	Realm   string `json:"realm"`
	Type    string `json:"type"`
	Comment string `json:"comment,omitempty"`
	Default *bool  `json:"default,omitempty"`
}

// OpenIDRealm is an OpenID Connect realm as PBS reports it. The lists —
// Scopes, ACRValues and Audiences — are the strings PBS stores; SplitList
// splits them as PBS does.
type OpenIDRealm struct {
	Realm     string `json:"realm"`
	IssuerURL string `json:"issuer-url"`
	ClientID  string `json:"client-id"`
	ClientKey string `json:"client-key,omitempty"`
	// Scopes is nil for PBS's default, DefaultOpenIDScopes. PBS asks for no
	// scopes but openid when it keeps an empty list.
	Scopes        *string `json:"scopes,omitempty"`
	ACRValues     string  `json:"acr-values,omitempty"`
	Audiences     string  `json:"audiences,omitempty"`
	Prompt        string  `json:"prompt,omitempty"`
	Comment       string  `json:"comment,omitempty"`
	Default       *bool   `json:"default,omitempty"`
	Autocreate    *bool   `json:"autocreate,omitempty"`
	UsernameClaim string  `json:"username-claim,omitempty"`
}

// DefaultOpenIDScopes are the scopes PBS asks for when a realm sets none.
const DefaultOpenIDScopes = "email profile"

// DirectoryRealm is an LDAP or Active Directory realm as PBS reports it,
// without the bind password, which PBS never returns. UserAttr is empty for
// Active Directory, where PBS looks users up by sAMAccountName.
type DirectoryRealm struct {
	Realm    string `json:"realm"`
	Server1  string `json:"server1"`
	Server2  string `json:"server2,omitempty"`
	Port     *int64 `json:"port,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Verify   *bool  `json:"verify,omitempty"`
	CAPath   string `json:"capath,omitempty"`
	BaseDN   string `json:"base-dn,omitempty"`
	BindDN   string `json:"bind-dn,omitempty"`
	UserAttr string `json:"user-attr,omitempty"`
	Filter   string `json:"filter,omitempty"`
	// UserClasses is empty for PBS's default, DefaultUserClasses.
	UserClasses         string `json:"user-classes,omitempty"`
	SyncAttributes      string `json:"sync-attributes,omitempty"`
	SyncDefaultsOptions string `json:"sync-defaults-options,omitempty"`
	Comment             string `json:"comment,omitempty"`
	Default             *bool  `json:"default,omitempty"`
}

// DefaultUserClasses are the object classes a directory realm's sync
// considers users when it sets none.
const DefaultUserClasses = "inetorgperson,posixaccount,person,user"

// DefaultLDAPMode is how PBS connects to a directory realm's server when it
// sets no mode: plain LDAP.
const DefaultLDAPMode = "ldap"

// SplitList splits a list PBS keeps in one string, such as the scopes of an
// OpenID realm, as PBS does: at commas, semicolons and ASCII white space —
// Rust's is_ascii_whitespace, which leaves out the vertical tab — dropping
// empty items.
func SplitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return strings.ContainsRune(",; \t\n\f\r", r)
	})
}

// ListRealms lists every realm, of every type. PBS answers it to anyone, as
// the sign-in form needs it.
func (c *Client) ListRealms(ctx context.Context) ([]RealmInfo, error) {
	var realms []RealmInfo
	_, err := c.Get(ctx, "/access/domains", nil, &realms)
	return realms, err
}

// The calls below take the type of the realm — RealmTypeOpenID,
// RealmTypeLDAP or RealmTypeAD — which is the path PBS serves it under:
// /config/access/<type>[/<realm>].

// getRealm reads a realm of the given type into out, and returns the digest
// of domains.cfg with it.
func (c *Client) getRealm(ctx context.Context, realmType, realm string, out any) (string, error) {
	envelope, err := c.Get(ctx, Path("config", "access", realmType, realm), nil, out)
	if err != nil {
		return "", err
	}
	return envelope.Digest, nil
}

// createRealm creates a realm of the given type from params, keeping the
// value of the parameter secret, a client key or bind password, out of any
// error.
func (c *Client) createRealm(ctx context.Context, realmType string, params url.Values, secret string) error {
	_, err := c.Post(ctx, Path("config", "access", realmType), params, nil)
	return redactAPIError(err, params.Get(secret))
}

// updateRealm changes the properties params carries and deletes those named
// in its delete parameter, keeping the value of the parameter secret out of
// any error.
func (c *Client) updateRealm(ctx context.Context, realmType, realm string, params url.Values, secret string) error {
	_, err := c.Put(ctx, Path("config", "access", realmType, realm), params, nil)
	return redactAPIError(err, params.Get(secret))
}

// GetOpenIDRealm reads an OpenID Connect realm, and returns the digest of
// domains.cfg with it.
func (c *Client) GetOpenIDRealm(ctx context.Context, realm string) (OpenIDRealm, string, error) {
	var r OpenIDRealm
	digest, err := c.getRealm(ctx, RealmTypeOpenID, realm, &r)
	if err != nil {
		return OpenIDRealm{}, "", err
	}
	return r, digest, nil
}

// CreateOpenIDRealm creates an OpenID Connect realm from params, which must
// hold "realm", "issuer-url" and "client-id". The client key is kept out of
// any error.
func (c *Client) CreateOpenIDRealm(ctx context.Context, params url.Values) error {
	return c.createRealm(ctx, RealmTypeOpenID, params, "client-key")
}

// UpdateOpenIDRealm changes the properties params carries and deletes those
// named in its delete parameter. The client key is kept out of any error.
func (c *Client) UpdateOpenIDRealm(ctx context.Context, realm string, params url.Values) error {
	return c.updateRealm(ctx, RealmTypeOpenID, realm, params, "client-key")
}

// GetDirectoryRealm reads an LDAP or Active Directory realm — realmType is
// RealmTypeLDAP or RealmTypeAD — and returns the digest of domains.cfg with
// it.
func (c *Client) GetDirectoryRealm(ctx context.Context, realmType, realm string) (DirectoryRealm, string, error) {
	var r DirectoryRealm
	digest, err := c.getRealm(ctx, realmType, realm, &r)
	if err != nil {
		return DirectoryRealm{}, "", err
	}
	return r, digest, nil
}

// CreateDirectoryRealm creates an LDAP or Active Directory realm from params,
// which must hold "realm" and "server1", and for LDAP "base-dn" and
// "user-attr". PBS connects to the server before it saves anything. The bind
// password is kept out of any error.
func (c *Client) CreateDirectoryRealm(ctx context.Context, realmType string, params url.Values) error {
	return c.createRealm(ctx, realmType, params, "password")
}

// UpdateDirectoryRealm changes the properties of an LDAP or Active Directory
// realm that params carries and deletes those named in its delete
// parameter. PBS connects to the server as the realm would after the change
// before it saves anything. The bind password is kept out of any error.
func (c *Client) UpdateDirectoryRealm(ctx context.Context, realmType, realm string, params url.Values) error {
	return c.updateRealm(ctx, realmType, realm, params, "password")
}

// RealmDigest reads a realm of the given type only to learn the digest of
// domains.cfg: it fails, IsRealmOfOtherType, when the realm has another type.
func (c *Client) RealmDigest(ctx context.Context, realmType, realm string) (string, error) {
	return c.getRealm(ctx, realmType, realm, nil)
}

// DeleteRealm deletes a realm, provided domains.cfg still has the digest
// given, when one is. PBS does not check the realm's type — DELETE under
// /config/access/ldap removes an OpenID realm just as well — so read it
// first, and pass the digest of that read.
func (c *Client) DeleteRealm(ctx context.Context, realmType, realm, digest string) error {
	var params url.Values
	if digest != "" {
		params = url.Values{"digest": {digest}}
	}
	_, err := c.Delete(ctx, Path("config", "access", realmType, realm), params, nil)
	return err
}

// DirectoryCheckFailure is why PBS refused to save an LDAP or Active
// Directory realm: what went wrong when it connected to the server first.
type DirectoryCheckFailure int

const (
	// DirectoryCheckPassed: the error is not a failed connection check.
	DirectoryCheckPassed DirectoryCheckFailure = iota
	// DirectoryConnectFailed: PBS could not connect — the server did not
	// answer, refused the connection or failed TLS, or a capath was
	// unreadable.
	DirectoryConnectFailed
	// DirectoryMissingPassword: the realm has a bind-dn, but PBS has no bind
	// password for it.
	DirectoryMissingPassword
	// DirectoryBindFailed: the server refused the bind-dn with the password.
	DirectoryBindFailed
	// DirectoryBindNeedsTLS: the server refused to bind over a connection
	// that is not protected, with strongerAuthRequired (Active Directory
	// with LDAP signing required) or confidentialityRequired.
	DirectoryBindNeedsTLS
	// DirectoryBaseDNFailed: the search of base-dn failed — no such entry,
	// or none the bind may read.
	DirectoryBaseDNFailed
	// DirectoryNoNamingContext: an Active Directory realm without base-dn,
	// and the server did not name its defaultNamingContext.
	DirectoryNoNamingContext
)

// DirectoryCheckFailureOf tells, from the 400 PBS answered a create or
// update of an LDAP or Active Directory realm with, whether and how its
// check of the connection failed. Errors that have other causes — parameter
// verification, a duplicate name, a digest conflict, a missing realm or one
// of another type — are DirectoryCheckPassed; any other 400 of these calls
// comes from connecting, which fails with the I/O or TLS error as its text.
//
// The missing realm is told by its own text, "no such ldap 'x'" or "no such
// ad 'x'", not by IsNotFound: a capath missing on the PBS host fails the
// connection with "No such file or directory (os error 2)", which IsNotFound
// takes for a missing object. PBS asks an Active Directory server without
// base-dn for its naming context with a connection of its own, and puts
// "failed to determine base_dn: " before whatever fails there: a connection
// that fails there is DirectoryConnectFailed, and only a server that answers
// without a naming context DirectoryNoNamingContext.
func DirectoryCheckFailureOf(err error) DirectoryCheckFailure {
	apiErr, ok := asError(err)
	if !ok || apiErr.StatusCode != http.StatusBadRequest {
		return DirectoryCheckPassed
	}
	m := apiErr.Message
	if strings.HasPrefix(m, "parameter verification failed") || strings.HasPrefix(m, "no such "+RealmTypeLDAP+" ") ||
		strings.HasPrefix(m, "no such "+RealmTypeAD+" ") || IsAlreadyExists(err) || IsDigestConflict(err) ||
		IsRealmOfOtherType(err) {
		return DirectoryCheckPassed
	}
	switch {
	case strings.Contains(m, "Missing bind password for "):
		return DirectoryMissingPassword
	case strings.Contains(m, "LDAP bind failed") && (strings.Contains(m, "rc=8 (") || strings.Contains(m, "rc=13 (")):
		return DirectoryBindNeedsTLS
	case strings.Contains(m, "LDAP bind failed"):
		return DirectoryBindFailed
	case strings.Contains(m, "Could not search LDAP realm"):
		return DirectoryBaseDNFailed
	case strings.Contains(m, "defaultNamingContext") || strings.Contains(m, "root DSE") ||
		strings.HasPrefix(m, "failed to determine base_dn: LDAP operation result"):
		return DirectoryNoNamingContext
	}
	return DirectoryConnectFailed
}

// IsRealmOfOtherType reports whether PBS answered that the realm exists, but
// with another type than the call is for: an LDAP realm read as an OpenID
// one, say.
func IsRealmOfOtherType(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest &&
		strings.HasPrefix(apiErr.Message, "got unexpected type ")
}
