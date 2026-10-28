package pbsclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// A read answers every property PBS stores, the client key too, and the
// digest of domains.cfg; the list has realms of every type.
func TestOpenIDRealmCallsHitTheirRoutes(t *testing.T) {
	const (
		listRoute   = "GET /access/domains"
		getRoute    = "GET /config/access/openid/authentik"
		createRoute = "POST /config/access/openid"
		updateRoute = "PUT /config/access/openid/authentik"
		deleteRoute = "DELETE /config/access/openid/authentik"
		digest      = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	)
	fake := newFakePBS()
	fake.reply(listRoute, http.StatusOK, `{"data":[{"realm":"pam","type":"pam","comment":"Linux PAM"},`+
		`{"realm":"authentik","type":"openid","default":true}],"digest":"`+digest+`"}`)
	fake.reply(getRoute, http.StatusOK, `{"data":{"realm":"authentik","issuer-url":"https://authentik.example.com/application/o/pbs/",`+
		`"client-id":"pbs","client-key":"s3cret","scopes":"email profile groups","acr-values":"gold","audiences":"pbs-extra",`+
		`"prompt":"login","comment":"SSO","default":true,"autocreate":false,"username-claim":"preferred_username"},"digest":"`+digest+`"}`)
	fake.reply(createRoute, http.StatusOK, `{"data":null}`)
	fake.reply(updateRoute, http.StatusOK, `{"data":null}`)
	fake.reply(deleteRoute, http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	realms, err := c.ListRealms(ctx)
	if err != nil {
		t.Fatal(err)
	}
	yes, no := true, false
	wantRealms := []RealmInfo{{Realm: "pam", Type: RealmTypePAM, Comment: "Linux PAM"}, {Realm: "authentik", Type: RealmTypeOpenID, Default: &yes}}
	if !reflect.DeepEqual(realms, wantRealms) {
		t.Errorf("ListRealms() = %+v, want %+v", realms, wantRealms)
	}

	realm, gotDigest, err := c.GetOpenIDRealm(ctx, "authentik")
	if err != nil {
		t.Fatal(err)
	}
	scopes := "email profile groups"
	want := OpenIDRealm{Realm: "authentik", IssuerURL: "https://authentik.example.com/application/o/pbs/", ClientID: "pbs",
		ClientKey: "s3cret", Scopes: &scopes, ACRValues: "gold", Audiences: "pbs-extra", Prompt: "login",
		Comment: "SSO", Default: &yes, Autocreate: &no, UsernameClaim: "preferred_username"}
	if !reflect.DeepEqual(realm, want) || gotDigest != digest {
		t.Errorf("GetOpenIDRealm() = %+v, %q", realm, gotDigest)
	}

	if err := c.CreateOpenIDRealm(ctx, url.Values{"realm": {"authentik"}, "client-id": {"pbs"}}); err != nil {
		t.Fatal(err)
	}
	if got := fake.lastCall(t, createRoute).form.Get("client-id"); got != "pbs" {
		t.Errorf("POST client-id = %q", got)
	}
	if err := c.UpdateOpenIDRealm(ctx, "authentik", url.Values{"comment": {"SSO"}}); err != nil {
		t.Fatal(err)
	}
	if got := fake.lastCall(t, updateRoute).form.Get("comment"); got != "SSO" {
		t.Errorf("PUT comment = %q", got)
	}

	// The delete sends the digest when it has one, and nothing otherwise.
	if err := c.DeleteOpenIDRealm(ctx, "authentik", digest); err != nil {
		t.Fatal(err)
	}
	if got := fake.lastCall(t, deleteRoute).query.Get(DigestParam); got != digest {
		t.Errorf("DELETE digest = %q", got)
	}
	if err := c.DeleteOpenIDRealm(ctx, "authentik", ""); err != nil {
		t.Fatal(err)
	}
	if got := fake.lastCall(t, deleteRoute).query; len(got) != 0 {
		t.Errorf("DELETE query = %v, want none", got)
	}
}

// A failed write does not repeat the client key it carried, and a failed
// read is an error.
func TestOpenIDRealmErrors(t *testing.T) {
	const key = "client-secret-value"
	fake := newFakePBS()
	fake.reply("POST /config/access/openid", http.StatusBadRequest,
		"parameter verification failed - 'client-key': value '"+key+"' is invalid")
	fake.reply("PUT /config/access/openid/authentik", http.StatusBadRequest,
		"parameter verification failed - 'client-key': value '"+key+"' is invalid")
	fake.reply("GET /config/access/openid/ldap1", http.StatusBadRequest, "got unexpected type 'ldap' for openid 'ldap1'")
	fake.reply("GET /config/access/openid/missing", http.StatusBadRequest, "no such openid 'missing'")
	fake.reply("DELETE /config/access/openid/missing", http.StatusNotFound, "realm 'missing' does not exist.")
	c := fake.client(t)
	ctx := context.Background()

	for name, err := range map[string]error{
		"create": c.CreateOpenIDRealm(ctx, url.Values{"realm": {"authentik"}, "client-key": {key}}),
		"update": c.UpdateOpenIDRealm(ctx, "authentik", url.Values{"client-key": {key}}),
	} {
		var apiErr *Error
		if !errors.As(err, &apiErr) || strings.Contains(err.Error(), key) || strings.Contains(apiErr.Body, key) {
			t.Errorf("%s error = %v, body %q", name, err, apiErr.Body)
		}
	}

	_, _, err := c.GetOpenIDRealm(ctx, "ldap1")
	if !IsRealmOfOtherType(err) || IsNotFound(err) {
		t.Errorf("GET of an LDAP realm: %v", err)
	}
	_, _, err = c.GetOpenIDRealm(ctx, "missing")
	if !IsNotFound(err) || IsRealmOfOtherType(err) {
		t.Errorf("GET of a missing realm: %v", err)
	}
	if err := c.DeleteOpenIDRealm(ctx, "missing", ""); !IsNotFound(err) {
		t.Errorf("DELETE of a missing realm: %v", err)
	}
	if IsRealmOfOtherType(errors.New("got unexpected type 'ldap'")) {
		t.Error("IsRealmOfOtherType took an error that is not from PBS")
	}
}

// Lists split as PBS splits them, at commas, semicolons and ASCII white
// space, without empty items.
func TestSplitList(t *testing.T) {
	for in, want := range map[string][]string{
		"":                           nil,
		"email profile":              {"email", "profile"},
		" email,profile;;groups\t\n": {"email", "profile", "groups"},
		"a\fb\rc":                    {"a", "b", "c"},
		"a\vb":                       {"a\vb"},
	} {
		if got := SplitList(in); !reflect.DeepEqual(got, want) && (len(got) != 0 || len(want) != 0) {
			t.Errorf("SplitList(%q) = %q, want %q", in, got, want)
		}
	}
}
