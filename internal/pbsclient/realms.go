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

// GetOpenIDRealm reads an OpenID Connect realm, and returns the digest of
// domains.cfg with it.
func (c *Client) GetOpenIDRealm(ctx context.Context, realm string) (OpenIDRealm, string, error) {
	var r OpenIDRealm
	envelope, err := c.Get(ctx, Path("config", "access", "openid", realm), nil, &r)
	if err != nil {
		return OpenIDRealm{}, "", err
	}
	return r, envelope.Digest, nil
}

// CreateOpenIDRealm creates an OpenID Connect realm from params, which must
// hold "realm", "issuer-url" and "client-id". The client key is kept out of
// any error.
func (c *Client) CreateOpenIDRealm(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/access/openid", params, nil)
	return redactAPIError(err, params.Get("client-key"))
}

// UpdateOpenIDRealm changes the properties params carries and deletes those
// named in its delete parameter. The client key is kept out of any error.
func (c *Client) UpdateOpenIDRealm(ctx context.Context, realm string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "access", "openid", realm), params, nil)
	return redactAPIError(err, params.Get("client-key"))
}

// DeleteOpenIDRealm deletes a realm, provided domains.cfg still has the
// digest given, when one is. PBS does not check the realm's type: read it
// first.
func (c *Client) DeleteOpenIDRealm(ctx context.Context, realm, digest string) error {
	var params url.Values
	if digest != "" {
		params = url.Values{"digest": {digest}}
	}
	_, err := c.Delete(ctx, Path("config", "access", "openid", realm), params, nil)
	return err
}

// IsRealmOfOtherType reports whether PBS answered that the realm exists, but
// with another type than the call is for: an LDAP realm read as an OpenID
// one, say.
func IsRealmOfOtherType(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest &&
		strings.HasPrefix(apiErr.Message, "got unexpected type ")
}
