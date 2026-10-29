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
	if err := c.DeleteRealm(ctx, RealmTypeOpenID, "authentik", digest); err != nil {
		t.Fatal(err)
	}
	if got := fake.lastCall(t, deleteRoute).query.Get(DigestParam); got != digest {
		t.Errorf("DELETE digest = %q", got)
	}
	if err := c.DeleteRealm(ctx, RealmTypeOpenID, "authentik", ""); err != nil {
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
	if err := c.DeleteRealm(ctx, RealmTypeOpenID, "missing", ""); !IsNotFound(err) {
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

// A directory realm is read and written under the path of its type; a read
// has no bind password, and the digest of domains.cfg.
func TestDirectoryRealmCallsHitTheirRoutes(t *testing.T) {
	const digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	for _, realmType := range []string{RealmTypeLDAP, RealmTypeAD} {
		t.Run(realmType, func(t *testing.T) {
			getRoute := "GET /config/access/" + realmType + "/corp"
			createRoute := "POST /config/access/" + realmType
			updateRoute := "PUT /config/access/" + realmType + "/corp"
			deleteRoute := "DELETE /config/access/" + realmType + "/corp"
			fake := newFakePBS()
			fake.reply(getRoute, http.StatusOK, `{"data":{"realm":"corp","server1":"ldap.example.com",`+
				`"server2":"[fd00::389]","port":636,"mode":"ldaps","verify":true,"capath":"/etc/ssl/certs/corp.pem",`+
				`"base-dn":"dc=example,dc=com","bind-dn":"uid=pbs,dc=example,dc=com","user-attr":"uid",`+
				`"filter":"(objectClass=person)","user-classes":"person,user","sync-attributes":"email=mail",`+
				`"sync-defaults-options":"enable-new=false,remove-vanished=acl;entry","comment":"Directory",`+
				`"default":true},"digest":"`+digest+`"}`)
			fake.reply(createRoute, http.StatusOK, `{"data":null}`)
			fake.reply(updateRoute, http.StatusOK, `{"data":null}`)
			fake.reply(deleteRoute, http.StatusOK, `{"data":null}`)
			c := fake.client(t)
			ctx := context.Background()

			realm, gotDigest, err := c.GetDirectoryRealm(ctx, realmType, "corp")
			if err != nil {
				t.Fatal(err)
			}
			yes, port := true, int64(636)
			want := DirectoryRealm{Realm: "corp", Server1: "ldap.example.com", Server2: "[fd00::389]", Port: &port,
				Mode: "ldaps", Verify: &yes, CAPath: "/etc/ssl/certs/corp.pem", BaseDN: "dc=example,dc=com",
				BindDN: "uid=pbs,dc=example,dc=com", UserAttr: "uid", Filter: "(objectClass=person)",
				UserClasses: "person,user", SyncAttributes: "email=mail",
				SyncDefaultsOptions: "enable-new=false,remove-vanished=acl;entry", Comment: "Directory", Default: &yes}
			if !reflect.DeepEqual(realm, want) || gotDigest != digest {
				t.Errorf("GetDirectoryRealm() = %+v, %q", realm, gotDigest)
			}
			if gotDigest, err := c.RealmDigest(ctx, realmType, "corp"); err != nil || gotDigest != digest {
				t.Errorf("RealmDigest() = %q, %v", gotDigest, err)
			}

			params := url.Values{"realm": {"corp"}, "server1": {"ldap.example.com"}, "password": {"bind-secret"}}
			if err := c.CreateDirectoryRealm(ctx, realmType, params); err != nil {
				t.Fatal(err)
			}
			if got := fake.lastCall(t, createRoute).form; !reflect.DeepEqual(got, params) {
				t.Errorf("POST form = %v", got)
			}
			params = url.Values{"comment": {"Directory"}, "delete": {"filter", "port"}}
			if err := c.UpdateDirectoryRealm(ctx, realmType, "corp", params); err != nil {
				t.Fatal(err)
			}
			if got := fake.lastCall(t, updateRoute).form; !reflect.DeepEqual(got, params) {
				t.Errorf("PUT form = %v", got)
			}

			if err := c.DeleteRealm(ctx, realmType, "corp", digest); err != nil {
				t.Fatal(err)
			}
			if got := fake.lastCall(t, deleteRoute).query.Get(DigestParam); got != digest {
				t.Errorf("DELETE digest = %q", got)
			}
			if err := c.DeleteRealm(ctx, realmType, "corp", ""); err != nil {
				t.Fatal(err)
			}
			if got := fake.lastCall(t, deleteRoute).query; len(got) != 0 {
				t.Errorf("DELETE query = %v, want none", got)
			}
		})
	}
}

// A failed write does not repeat the bind password it carried; reads of a
// realm of another type, or of none, fail as such.
func TestDirectoryRealmErrors(t *testing.T) {
	const password = "bind-secret-value"
	fake := newFakePBS()
	fake.reply("POST /config/access/ldap", http.StatusBadRequest,
		"parameter verification failed - 'password': value '"+password+"' is invalid")
	fake.reply("PUT /config/access/ad/corp", http.StatusBadRequest, "LDAP bind failed for "+password)
	fake.reply("GET /config/access/ldap/sso", http.StatusBadRequest, "got unexpected type 'openid' for ldap 'sso'")
	fake.reply("GET /config/access/ad/missing", http.StatusBadRequest, "no such ad 'missing'")
	c := fake.client(t)
	ctx := context.Background()

	for name, err := range map[string]error{
		"create": c.CreateDirectoryRealm(ctx, RealmTypeLDAP, url.Values{"realm": {"corp"}, "password": {password}}),
		"update": c.UpdateDirectoryRealm(ctx, RealmTypeAD, "corp", url.Values{"password": {password}}),
	} {
		var apiErr *Error
		if !errors.As(err, &apiErr) || strings.Contains(err.Error(), password) || strings.Contains(apiErr.Body, password) {
			t.Errorf("%s error = %v, body %q", name, err, apiErr.Body)
		}
	}
	// Redacted, the failed bind is still one.
	err := c.UpdateDirectoryRealm(ctx, RealmTypeAD, "corp", url.Values{"password": {password}})
	if DirectoryCheckFailureOf(err) != DirectoryBindFailed {
		t.Errorf("DirectoryCheckFailureOf(%v) = %v", err, DirectoryCheckFailureOf(err))
	}

	if _, _, err := c.GetDirectoryRealm(ctx, RealmTypeLDAP, "sso"); !IsRealmOfOtherType(err) || IsNotFound(err) {
		t.Errorf("GET of an OpenID realm: %v", err)
	}
	if _, err := c.RealmDigest(ctx, RealmTypeLDAP, "sso"); !IsRealmOfOtherType(err) {
		t.Errorf("RealmDigest of an OpenID realm: %v", err)
	}
	if _, _, err := c.GetDirectoryRealm(ctx, RealmTypeAD, "missing"); !IsNotFound(err) || IsRealmOfOtherType(err) {
		t.Errorf("GET of a missing realm: %v", err)
	}
}

// DirectoryCheckFailureOf tells PBS's failed checks of the connection apart,
// by the texts PBS 4.2 answers them with, from errors with other causes.
func TestDirectoryCheckFailureOf(t *testing.T) {
	const refused = "I/O error: Connection refused (os error 111): Connection refused (os error 111)"
	for message, want := range map[string]DirectoryCheckFailure{
		refused:                                  DirectoryConnectFailed,
		"I/O error: connection timed out":        DirectoryConnectFailed,
		"No such file or directory (os error 2)": DirectoryConnectFailed,
		"native TLS error: error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify " +
			"failed:../ssl/statem/statem_clnt.c:2091: (unable to get local issuer certificate)": DirectoryConnectFailed,
		"failed to determine base_dn: I/O error: Connection refused (os error 111)": DirectoryConnectFailed,
		"failed to determine base_dn: No such file or directory (os error 2)":       DirectoryConnectFailed,
		"Missing bind password for uid=pbs,ou=services,dc=example,dc=com":           DirectoryMissingPassword,
		`LDAP bind failed, bind_dn or password could be incorrect: LDAP operation result: rc=49 (invalidCredentials), ` +
			`dn: "", text: "": rc=49 (invalidCredentials), dn: "", text: ""`: DirectoryBindFailed,
		`LDAP bind failed, bind_dn or password could be incorrect: LDAP operation result: rc=8 (strongerAuthRequired), ` +
			`dn: "", text: "": rc=8 (strongerAuthRequired), dn: "", text: ""`: DirectoryBindNeedsTLS,
		`LDAP bind failed, bind_dn or password could be incorrect: LDAP operation result: rc=13 (confidentialityRequired), ` +
			`dn: "", text: "": rc=13 (confidentialityRequired), dn: "", text: ""`: DirectoryBindNeedsTLS,
		`Could not search LDAP realm, base_dn could be incorrect: LDAP operation result: rc=32 (noSuchObject), ` +
			`dn: "dc=example,dc=com", text: "": rc=32 (noSuchObject), dn: "dc=example,dc=com", text: ""`: DirectoryBaseDNFailed,
		"server did not provide `defaultNamingContext`":                                                          DirectoryNoNamingContext,
		"failed to determine base_dn: failed to retrieve root DSE attribute 'defaultNamingContext'":              DirectoryNoNamingContext,
		"failed to determine base_dn: found multiple root DSEs with attribute 'defaultNamingContext'":            DirectoryNoNamingContext,
		`failed to determine base_dn: LDAP operation result: rc=50 (insufficientAccessRights), dn: "", text: ""`: DirectoryNoNamingContext,
		"parameter verification failed - 'realm': realm 'corp' already exists.":                                  DirectoryCheckPassed,
		"parameter verification failed - 'delete': value 'capath' is not defined in the enumeration.":            DirectoryCheckPassed,
		"detected modified configuration - file changed by other user? Try again.":                               DirectoryCheckPassed,
		"no such ldap 'corp'":                          DirectoryCheckPassed,
		"no such ad 'corp'":                            DirectoryCheckPassed,
		"got unexpected type 'openid' for ldap 'corp'": DirectoryCheckPassed,
	} {
		err := &Error{Method: http.MethodPost, Path: "/config/access/ldap", StatusCode: http.StatusBadRequest, Message: message}
		if got := DirectoryCheckFailureOf(err); got != want {
			t.Errorf("DirectoryCheckFailureOf(%q) = %v, want %v", message, got, want)
		}
	}
	for _, err := range []error{
		nil,
		errors.New(refused),
		&Error{StatusCode: http.StatusForbidden, Message: "permission check failed"},
		&Error{StatusCode: http.StatusInternalServerError, Message: refused},
		&Error{StatusCode: http.StatusNotFound, Message: "realm 'corp' does not exist."},
	} {
		if got := DirectoryCheckFailureOf(err); got != DirectoryCheckPassed {
			t.Errorf("DirectoryCheckFailureOf(%v) = %v, want DirectoryCheckPassed", err, got)
		}
	}
}
