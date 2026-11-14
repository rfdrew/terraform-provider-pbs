package provider

import (
	"net/http"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestRealmListResources(t *testing.T) {
	h, fake, realms := newDirectoryRealmHarness(t)
	h.create(t, "pbs_realm_ldap", ldapKind.config(t, h, map[string]any{
		"bind_dn": testLDAPBindDN, "password_wo": testBindPassword, "password_wo_version": 1, "comment": "Directory",
	}))
	h.create(t, "pbs_realm_ldap", ldapKind.config(t, h, map[string]any{"realm": "anon", "filter": "(objectClass=person)", "port": 389}))
	h.create(t, "pbs_realm_ad", adKind.config(t, h, map[string]any{
		"realm": "ad", "bind_dn": testADBindDN, "password_wo": testBindPassword, "password_wo_version": 1, "default": true,
	}))
	h.create(t, "pbs_realm_openid", openIDRealmConfig(t, h, map[string]any{"client_key": "first-secret", "comment": "Authentik"}))
	h.create(t, "pbs_realm_openid", openIDRealmConfig(t, h, map[string]any{
		"realm": "keycloak", "client_key_wo": "second-secret", "client_key_wo_version": 1, "scopes": []any{"openid"},
		"autocreate": true,
	}))

	// Without resources, each list names the realms of its type, from one
	// call; pam and pbs, built in, are no list's.
	for typeName, want := range map[string][]string{
		"pbs_realm_ldap":   {"anon", "corp"},
		"pbs_realm_ad":     {"ad"},
		"pbs_realm_openid": {"authentik", "keycloak"},
	} {
		before := fake.count("GET /access/domains")
		results := h.listedObjects(t, typeName, listRequest{})
		if got := listedIdentities(t, results, "realm"); !slices.Equal(got, want) {
			t.Fatalf("%s listed %q, want %q", typeName, got, want)
		}
		if fake.count("GET /access/domains") != before+1 || !results[0].resource.IsNull() {
			t.Fatalf("%s: a list without resources made %d calls", typeName, fake.count("GET /access/domains")-before)
		}
	}
	requireListedDisplayNames(t, h.listedObjects(t, "pbs_realm_ldap", listRequest{}), "anon", "corp — Directory")
	requireListedDisplayNames(t, h.listedObjects(t, "pbs_realm_openid", listRequest{}), "authentik — Authentik", "keycloak")

	// With resources, each result is what importing the realm gives, and
	// its generated configuration plans no change: the bind password and
	// the client key, which an import does not read, stay as PBS has them.
	ldap := h.listedObjects(t, "pbs_realm_ldap", listRequest{includeResource: true})
	for _, result := range ldap {
		h.requireListedLikeImport(t, "pbs_realm_ldap", result)
	}
	if stringAt(t, ldap[1].resource, "bind_dn") != testLDAPBindDN || !isNullAt(t, ldap[1].resource, "password_wo_version") ||
		int64At(t, ldap[0].resource, "port") != 389 {
		t.Fatalf("listed %s, %s", ldap[0].resource, ldap[1].resource)
	}
	ad := h.listedObjects(t, "pbs_realm_ad", listRequest{includeResource: true})
	h.requireListedLikeImport(t, "pbs_realm_ad", ad[0])
	if !boolAt(t, ad[0].resource, "default") || stringAt(t, ad[0].resource, "base_dn") != testADBaseDN {
		t.Fatalf("listed %s", ad[0].resource)
	}
	openID := h.listedObjects(t, "pbs_realm_openid", listRequest{includeResource: true})
	for _, result := range openID {
		h.requireListedLikeImport(t, "pbs_realm_openid", result)
		if !isNullAt(t, result.resource, "client_key") || !isNullAt(t, result.resource, "client_key_wo_version") {
			t.Fatalf("listed the client key: %s", result.resource)
		}
	}
	if props, _ := realms.realm("authentik"); props["client-key"] != "first-secret" {
		t.Fatalf("PBS has the client key %v", props["client-key"])
	}

	// A realm with a bind_dn needs its password only to be created again:
	// a new capath, which replaces it, fails in the plan without one.
	generated := h.generateConfig(t, "pbs_realm_ldap", ldap[1].resource)
	replaced := filledIn(t, generated, map[string]tftypes.Value{"capath": tftypes.NewValue(tftypes.String, testCAPath)})
	plan := h.plan(t, "pbs_realm_ldap", h.importListed(t, "pbs_realm_ldap", ldap[1]), replaced)
	requireProtocolErrorContaining(t, plan.Diagnostics, "Missing bind password")
}

// Naming realms needs no privilege, reading them Sys.Audit: a realm the
// provider may not read is left out with a warning that says so.
func TestRealmListResourceUnreadableRealm(t *testing.T) {
	h, fake, realms := newDirectoryRealmHarness(t)
	realms.addRealm("corp", "ldap", ldapKind.props(fakeProperties{"comment": "Directory"}))
	realms.addRealm("people", "ldap", ldapKind.props(nil))
	fake.reply("GET /config/access/ldap/corp", http.StatusForbidden, "permission check failed")
	var listed []string
	warned := false
	for _, result := range h.listResources(t, "pbs_realm_ldap", listRequest{includeResource: true}) {
		requireNoProtocolErrors(t, result.diagnostics)
		if result.identity.IsNull() {
			requireProtocolWarningContaining(t, result.diagnostics, "Left out corp — Directory")
			requireProtocolWarningContaining(t, result.diagnostics, realmReadPrivilege)
			warned = true
			continue
		}
		listed = append(listed, stringAt(t, result.identity, "realm"))
	}
	if !warned || !slices.Equal(listed, []string{"people"}) {
		t.Fatalf("listed %q, warned %v", listed, warned)
	}
}

// A failed listing fails the list block.
func TestRealmListResourcesListFails(t *testing.T) {
	h, fake, _ := newRealmHarness(t)
	fake.reply("GET /access/domains", http.StatusInternalServerError, "unable to parse domains.cfg")
	for typeName, summary := range map[string]string{
		"pbs_realm_ldap":   "Unable to list PBS LDAP realms",
		"pbs_realm_ad":     "Unable to list PBS Active Directory realms",
		"pbs_realm_openid": "Unable to list PBS OpenID realms",
	} {
		results := h.listResources(t, typeName, listRequest{})
		if len(results) != 1 {
			t.Fatalf("%s: got %d results", typeName, len(results))
		}
		requireProtocolErrorContaining(t, results[0].diagnostics, summary)
	}
}
