package provider

import (
	"context"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestDirectoryRealmSchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, NewLDAPRealmResource())
	requireValidResourceSchema(t, NewADRealmResource())
}

// What the fake PBS host reaches: an OpenLDAP server and an Active Directory
// domain controller, each letting PBS's service account bind, and a CA file
// a capath can name.
const (
	testLDAPServer   = "ldap.example.com"
	testLDAPBaseDN   = "ou=people,dc=example,dc=com"
	testLDAPBindDN   = "uid=pbs,ou=services,dc=example,dc=com"
	testADServer     = "dc1.example.com"
	testADBaseDN     = "DC=example,DC=com"
	testADBindDN     = "pbs@example.com"
	testBindPassword = "first-bind-secret"
	testCAPath       = "/etc/proxmox-backup/ldap-ca.pem"
)

// newDirectoryRealmHarness is newRealmHarness with the directory servers and
// the CA file above.
func newDirectoryRealmHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeRealms) {
	t.Helper()
	h, fake, realms := newRealmHarness(t)
	realms.addServer(testLDAPServer, fakeDirectory{
		entries: []string{"dc=example,dc=com", testLDAPBaseDN, "ou=services,dc=example,dc=com"},
		binds:   map[string]string{testLDAPBindDN: testBindPassword},
	})
	realms.addServer(testADServer, fakeDirectory{
		entries:       []string{testADBaseDN, "OU=Staff,DC=example,DC=com"},
		binds:         map[string]string{testADBindDN: testBindPassword},
		namingContext: testADBaseDN,
	})
	realms.addCAFile(testCAPath)
	return h, fake, realms
}

// directoryKind is one of the two resources, with what a realm "corp" of it
// needs to reach its server.
type directoryKind struct {
	typeName  string
	realmType string
	// name is how messages call the kind.
	name                   string
	server, baseDN, bindDN string
	// required are the attributes the realm needs, and requiredForm what a
	// create sends for them: the Active Directory realm leaves base_dn to
	// PBS.
	required     map[string]any
	requiredForm map[string]string
}

var (
	ldapKind = directoryKind{
		typeName: "pbs_realm_ldap", realmType: pbsclient.RealmTypeLDAP, name: "LDAP",
		server: testLDAPServer, baseDN: testLDAPBaseDN, bindDN: testLDAPBindDN,
		required:     map[string]any{"realm": "corp", "server1": testLDAPServer, "base_dn": testLDAPBaseDN, "user_attr": "uid"},
		requiredForm: map[string]string{"realm": "corp", "server1": testLDAPServer, "base-dn": testLDAPBaseDN, "user-attr": "uid"},
	}
	adKind = directoryKind{
		typeName: "pbs_realm_ad", realmType: pbsclient.RealmTypeAD, name: "Active Directory",
		server: testADServer, baseDN: testADBaseDN, bindDN: testADBindDN,
		required:     map[string]any{"realm": "corp", "server1": testADServer},
		requiredForm: map[string]string{"realm": "corp", "server1": testADServer},
	}
	directoryKinds = []directoryKind{ldapKind, adKind}
)

// config is the configuration of the realm, with attrs on top of what it
// needs.
func (k directoryKind) config(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := maps.Clone(k.required)
	maps.Copy(config, attrs)
	return h.resourceValue(t, k.typeName, config)
}

// props are the properties PBS keeps of such a realm, with extra on top.
func (k directoryKind) props(extra fakeProperties) fakeProperties {
	props := fakeProperties{"server1": k.server, "base-dn": k.baseDN}
	if k.realmType == pbsclient.RealmTypeLDAP {
		props["user-attr"] = "uid"
	}
	maps.Copy(props, extra)
	return props
}

// route is the route of a call for the kind: POST creates, the other
// methods name realm.
func (k directoryKind) route(method, realm string) string {
	if method == http.MethodPost {
		return "POST /config/access/" + k.realmType
	}
	return method + " /config/access/" + k.realmType + "/" + realm
}

// requireForm fails the test unless form is exactly want; the values of a
// repeated parameter — delete — are joined by commas.
func requireForm(t *testing.T, what string, form url.Values, want map[string]string) {
	t.Helper()
	got := make(map[string]string, len(form))
	for name, values := range form {
		got[name] = strings.Join(values, ",")
	}
	if !maps.Equal(got, want) {
		t.Errorf("%s form = %v, want %v", what, got, want)
	}
}

// requireNoSecretIn fails the test when a diagnostic repeats one of the
// secrets.
func requireNoSecretIn(t *testing.T, diags []*tfprotov6.Diagnostic, secrets ...string) {
	t.Helper()
	for _, d := range diags {
		for _, secret := range secrets {
			if strings.Contains(d.Summary, secret) || strings.Contains(d.Detail, secret) {
				t.Errorf("diagnostic repeats %q: %s: %s", secret, d.Summary, d.Detail)
			}
		}
	}
}

// directoryCreateResponse plans config for a new realm, failing the test on
// an error in the plan, and returns the apply's answer, errors and all.
func directoryCreateResponse(t *testing.T, h *protocolHarness, typeName string, config tftypes.Value) *tfprotov6.ApplyResourceChangeResponse {
	t.Helper()
	planned := h.plan(t, typeName, nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	return h.apply(t, typeName, nil, config, planned)
}

// directoryUpdateResponse is directoryCreateResponse for an update of inst.
func directoryUpdateResponse(t *testing.T, h *protocolHarness, inst *resourceInstance, config tftypes.Value) *tfprotov6.ApplyResourceChangeResponse {
	t.Helper()
	planned := h.plan(t, inst.typeName, inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	return h.apply(t, inst.typeName, inst, config, planned)
}

var (
	passwordWOPath = tftypes.NewAttributePath().WithAttributeName("password_wo")
	realmPath      = tftypes.NewAttributePath().WithAttributeName("realm")
	capathPath     = tftypes.NewAttributePath().WithAttributeName("capath")
)

// The life of a realm of either kind: created with what differs from PBS's
// defaults and the bind password; updated with only what changed, the
// password only with a new version, and default = true every time; reset by
// deleting; destroyed with its password.
func TestDirectoryRealmResourceLifecycle(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, realms := newDirectoryRealmHarness(t)
			put := k.route(http.MethodPut, "corp")

			attrs := map[string]any{"bind_dn": k.bindDN, "password_wo": testBindPassword, "password_wo_version": 1,
				"comment": "Directory"}
			config := k.config(t, h, attrs)
			inst := h.create(t, k.typeName, config)
			want := maps.Clone(k.requiredForm)
			maps.Copy(want, map[string]string{"bind-dn": k.bindDN, "password": testBindPassword, "comment": "Directory"})
			requireForm(t, "POST", fake.lastCall(t, k.route(http.MethodPost, "")).form, want)
			if stringAt(t, inst.state, "id") != "corp" || stringAt(t, inst.state, "base_dn") != k.baseDN ||
				stringAt(t, inst.state, "mode") != "ldap" || boolAt(t, inst.state, "verify") ||
				boolAt(t, inst.state, "default") || !isNullAt(t, inst.state, "port") ||
				!isNullAt(t, inst.state, "server2") || !isNullAt(t, inst.state, "capath") ||
				!isNullAt(t, inst.state, "filter") || !isNullAt(t, inst.state, "sync_attributes") ||
				!isNullAt(t, inst.state, "sync_defaults") || !isNullAt(t, inst.state, "password_wo") ||
				int64At(t, inst.state, "password_wo_version") != 1 ||
				!slices.Equal(setStringsAt(t, inst.state, "user_classes"), []string{"inetorgperson", "person", "posixaccount", "user"}) {
				t.Errorf("state = %s", inst.state)
			}
			if got := stringAt(t, h.identityValue(t, k.typeName, inst.identity), "realm"); got != "corp" {
				t.Errorf("identity realm = %q", got)
			}
			if got, _ := realms.bindPassword("corp"); got != testBindPassword {
				t.Errorf("bind password = %q", got)
			}
			requireNoPlannedChange(t, h, inst, config)

			// Changes made outside Terraform show, and the next apply undoes
			// them.
			realms.mu.Lock()
			realms.realms["corp"]["comment"] = "changed outside"
			realms.realms["corp"]["filter"] = "(objectClass=person)"
			realms.mu.Unlock()
			inst = h.refresh(t, inst)
			if stringAt(t, inst.state, "comment") != "changed outside" || stringAt(t, inst.state, "filter") != "(objectClass=person)" {
				t.Errorf("state after changes outside = %s", inst.state)
			}
			inst = h.update(t, inst, config)
			requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"comment": "Directory", "delete": "filter"})

			// Only what changed is sent: user classes separated by commas,
			// sorted, and the property strings with their keys sorted, the
			// remove-vanished list separated by semicolons.
			attrs["server2"] = "ldap-2.example.com"
			attrs["port"] = 389
			attrs["mode"] = "ldap+starttls"
			attrs["verify"] = true
			attrs["filter"] = "(memberOf=cn=pbs,ou=groups,dc=example,dc=com)"
			attrs["user_classes"] = []string{"user", "person"}
			attrs["sync_attributes"] = map[string]any{"firstname": "givenName", "email": "mail"}
			attrs["sync_defaults"] = map[string]any{"enable_new": true, "remove_vanished": []string{"entry", "acl"}}
			config = k.config(t, h, attrs)
			inst = h.update(t, inst, config)
			requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"server2": "ldap-2.example.com",
				"port": "389", "mode": "ldap+starttls", "verify": "true",
				"filter": "(memberOf=cn=pbs,ou=groups,dc=example,dc=com)", "user-classes": "person,user",
				"sync-attributes":       "email=mail,firstname=givenName",
				"sync-defaults-options": "enable-new=true,remove-vanished=acl;entry"})
			if got, _ := realms.realm("corp"); got["sync-defaults-options"] != "enable-new=true,remove-vanished=acl;entry" {
				t.Errorf("stored sync-defaults-options = %v", got["sync-defaults-options"])
			}
			requireNoPlannedChange(t, h, inst, config)
			attrs["sync_defaults"] = map[string]any{"enable_new": true, "remove_vanished": []string{"acl", "entry"}}
			requireNoPlannedChange(t, h, inst, k.config(t, h, attrs))

			// A bind password changed in the directory fails every update,
			// which changes nothing, until PBS has it too ...
			realms.setServerPassword(k.server, k.bindDN, "second-bind-secret")
			attrs["comment"] = "Directory realm"
			resp := directoryUpdateResponse(t, h, inst, k.config(t, h, attrs))
			requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to update PBS "+k.name+" realm")
			requireProtocolErrorContaining(t, resp.Diagnostics, "The server refused bind_dn with the password PBS bound with")
			if got, _ := realms.realm("corp"); got["comment"] != "Directory" {
				t.Errorf("comment = %v after a failed update", got["comment"])
			}

			// ... and a new version sends it, alone.
			attrs["comment"] = "Directory"
			attrs["password_wo"] = "second-bind-secret"
			attrs["password_wo_version"] = 2
			config = k.config(t, h, attrs)
			inst = h.update(t, inst, config)
			requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"password": "second-bind-secret"})
			if got, _ := realms.bindPassword("corp"); got != "second-bind-secret" {
				t.Errorf("bind password = %q after a new version", got)
			}
			if !isNullAt(t, inst.state, "password_wo") || int64At(t, inst.state, "password_wo_version") != 2 {
				t.Errorf("state = %s", inst.state)
			}
			requireNoPlannedChange(t, h, inst, config)

			// A new password without a new version is not sent.
			puts := fake.count(put)
			attrs["password_wo"] = "unsent-bind-secret"
			inst = h.update(t, inst, k.config(t, h, attrs))
			if fake.count(put) != puts {
				t.Error("a new password_wo without a new version was sent")
			}

			// Removing password_wo and its version sends nothing, and leaves
			// PBS its password, also for the next plan.
			delete(attrs, "password_wo")
			delete(attrs, "password_wo_version")
			config = k.config(t, h, attrs)
			inst = h.update(t, inst, config)
			if fake.count(put) != puts {
				t.Error("removing password_wo sent an update")
			}
			if got, ok := realms.bindPassword("corp"); !ok || got != "second-bind-secret" {
				t.Errorf("bind password = %q, %v after removing password_wo", got, ok)
			}
			if !isNullAt(t, inst.state, "password_wo_version") {
				t.Errorf("state = %s", inst.state)
			}
			inst = h.refresh(t, inst)
			requireNoPlannedChange(t, h, inst, config)

			// default = true takes the flag from pam, and goes with every
			// update that sends anything: PBS clears it otherwise.
			if realms.defaultRealm() != "pam" {
				t.Fatalf("default realm = %q before, want pam", realms.defaultRealm())
			}
			attrs["default"] = true
			inst = h.update(t, inst, k.config(t, h, attrs))
			requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"default": "true"})
			attrs["comment"] = "Directory realm"
			config = k.config(t, h, attrs)
			inst = h.update(t, inst, config)
			requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"comment": "Directory realm", "default": "true"})
			if realms.defaultRealm() != "corp" || !boolAt(t, inst.state, "default") {
				t.Errorf("default realm = %q, state = %s", realms.defaultRealm(), inst.state)
			}
			requireNoPlannedChange(t, h, inst, config)

			// Back to the defaults: deleted, not written, and the flag goes
			// with them.
			config = k.config(t, h, map[string]any{"bind_dn": k.bindDN})
			inst = h.update(t, inst, config)
			requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{
				"delete": "comment,default,filter,mode,port,server2,sync-attributes,sync-defaults-options,user-classes,verify"})
			stored, _ := realms.realm("corp")
			wantKeys := []string{"base-dn", "bind-dn", "realm", "server1"}
			if k.realmType == pbsclient.RealmTypeLDAP {
				wantKeys = []string{"base-dn", "bind-dn", "realm", "server1", "user-attr"}
			}
			if got := slices.Sorted(maps.Keys(stored)); !slices.Equal(got, wantKeys) || realms.defaultRealm() != "" {
				t.Errorf("stored realm = %v, default realm %q", stored, realms.defaultRealm())
			}
			requireNoPlannedChange(t, h, inst, config)

			// Destroying the realm deletes it, with the digest of its read,
			// and PBS forgets its password.
			h.destroy(t, inst)
			if _, exists := realms.realm("corp"); exists {
				t.Error("destroy left the realm")
			}
			if _, ok := realms.bindPassword("corp"); ok {
				t.Error("destroy left the bind password")
			}
			if fake.lastCall(t, k.route(http.MethodDelete, "corp")).query.Get(pbsclient.DigestParam) == "" {
				t.Error("DELETE sent no digest")
			}
		})
	}
}

// A realm created with every attribute sends them all; default = true takes
// the flag from pam, and destroying the realm leaves no realm the default.
func TestDirectoryRealmResourceCreatesWithEverything(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, realms := newDirectoryRealmHarness(t)
			realms.mu.Lock()
			realms.servers[k.server].ca = testCAPath
			realms.mu.Unlock()

			config := k.config(t, h, map[string]any{"server2": "[fd00::389]", "port": 636, "mode": "ldaps",
				"verify": true, "capath": testCAPath, "base_dn": k.baseDN, "bind_dn": k.bindDN,
				"password_wo": testBindPassword, "password_wo_version": 7, "filter": "(objectClass=person)",
				"user_classes":    []string{"person", "user", "inetOrgPerson"},
				"sync_attributes": map[string]any{"email": "mail", "firstname": "givenName", "lastname": "sn"},
				"sync_defaults":   map[string]any{"enable_new": false, "remove_vanished": []string{"properties", "entry", "acl"}},
				"default":         true, "comment": "Corporate directory"})
			inst := h.create(t, k.typeName, config)
			want := maps.Clone(k.requiredForm)
			maps.Copy(want, map[string]string{"server2": "[fd00::389]", "port": "636", "mode": "ldaps", "verify": "true",
				"capath": testCAPath, "base-dn": k.baseDN, "bind-dn": k.bindDN, "password": testBindPassword,
				"filter": "(objectClass=person)", "user-classes": "inetOrgPerson,person,user",
				"sync-attributes":       "email=mail,firstname=givenName,lastname=sn",
				"sync-defaults-options": "enable-new=false,remove-vanished=acl;entry;properties",
				"default":               "true", "comment": "Corporate directory"})
			requireForm(t, "POST", fake.lastCall(t, k.route(http.MethodPost, "")).form, want)
			if int64At(t, inst.state, "port") != 636 || stringAt(t, inst.state, "capath") != testCAPath ||
				stringAt(t, inst.state, "server2") != "[fd00::389]" || boolAt(t, inst.state, "sync_defaults", "enable_new") ||
				!slices.Equal(setStringsAt(t, inst.state, "sync_defaults", "remove_vanished"), []string{"acl", "entry", "properties"}) ||
				stringAt(t, inst.state, "sync_attributes", "lastname") != "sn" ||
				!slices.Equal(setStringsAt(t, inst.state, "user_classes"), []string{"inetOrgPerson", "person", "user"}) ||
				!boolAt(t, inst.state, "default") || int64At(t, inst.state, "password_wo_version") != 7 {
				t.Errorf("state = %s", inst.state)
			}
			if realms.defaultRealm() != "corp" {
				t.Errorf("default realm = %q", realms.defaultRealm())
			}
			requireNoPlannedChange(t, h, inst, config)

			h.destroy(t, inst)
			if realms.defaultRealm() != "" {
				t.Errorf("default realm = %q after the destroy", realms.defaultRealm())
			}
		})
	}
}

// PBS's update ignores capath, so changing or removing it replaces the
// realm; the replacement creates the realm, which needs the bind password.
func TestDirectoryRealmResourceCAPathReplaces(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, realms := newDirectoryRealmHarness(t)
			realms.addCAFile("/etc/ssl/certs")
			withCA := map[string]any{"mode": "ldaps", "verify": true, "capath": testCAPath, "bind_dn": k.bindDN,
				"password_wo": testBindPassword, "password_wo_version": 1}
			inst := h.create(t, k.typeName, k.config(t, h, withCA))

			for name, capath := range map[string]any{"changed": "/etc/ssl/certs", "removed": nil} {
				attrs := maps.Clone(withCA)
				attrs["capath"] = capath
				planned := h.plan(t, k.typeName, inst, k.config(t, h, attrs))
				requireNoProtocolErrors(t, planned.Diagnostics)
				if len(planned.RequiresReplace) != 1 || !planned.RequiresReplace[0].Equal(capathPath) {
					t.Errorf("capath %s: RequiresReplace = %v", name, planned.RequiresReplace)
				}

				delete(attrs, "password_wo")
				delete(attrs, "password_wo_version")
				planned = h.plan(t, k.typeName, inst, k.config(t, h, attrs))
				requireProtocolErrorOn(t, planned.Diagnostics, passwordWOPath)
				requireProtocolErrorContaining(t, planned.Diagnostics, `The plan replaces `+k.name+` realm "corp"`)
			}

			// Other changes leave the realm, and capath, alone.
			attrs := maps.Clone(withCA)
			attrs["comment"] = "TLS"
			planned := h.plan(t, k.typeName, inst, k.config(t, h, attrs))
			requireNoProtocolErrors(t, planned.Diagnostics)
			if len(planned.RequiresReplace) != 0 {
				t.Errorf("RequiresReplace = %v", planned.RequiresReplace)
			}
			inst = h.update(t, inst, k.config(t, h, attrs))
			requireForm(t, "PUT", fake.lastCall(t, k.route(http.MethodPut, "corp")).form, map[string]string{"comment": "TLS"})

			// Terraform replaces the realm by destroying it and creating it
			// anew, with the new capath.
			h.destroy(t, inst)
			attrs["capath"] = "/etc/ssl/certs"
			inst = h.create(t, k.typeName, k.config(t, h, attrs))
			if got := fake.lastCall(t, k.route(http.MethodPost, "")).form.Get("capath"); got != "/etc/ssl/certs" {
				t.Errorf("POST capath = %q", got)
			}
			if stringAt(t, inst.state, "capath") != "/etc/ssl/certs" {
				t.Errorf("state = %s", inst.state)
			}
		})
	}
}

// PBS binds as bind_dn before it creates a realm, and has no password for a
// new one: a plan that creates one with bind_dn but without password_wo
// fails, a replacement included, while an update binds with the password PBS
// has.
func TestDirectoryRealmResourceNeedsBindPasswordToCreate(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, realms := newDirectoryRealmHarness(t)
			for _, bindDN := range []any{k.bindDN, tfUnknown} {
				planned := h.plan(t, k.typeName, nil, k.config(t, h, map[string]any{"bind_dn": bindDN}))
				requireProtocolErrorOn(t, planned.Diagnostics, passwordWOPath)
				requireProtocolErrorContaining(t, planned.Diagnostics, `The plan creates `+k.name+` realm "corp"`)
			}
			for _, attrs := range []map[string]any{
				nil,
				{"bind_dn": k.bindDN, "password_wo": testBindPassword, "password_wo_version": 1},
				{"bind_dn": k.bindDN, "password_wo": testBindPassword, "password_wo_version": tfUnknown},
			} {
				planned := h.plan(t, k.typeName, nil, k.config(t, h, attrs))
				requireNoProtocolErrors(t, planned.Diagnostics)
			}
			requireProtocolErrorContaining(t, h.validateResource(t, k.typeName,
				k.config(t, h, map[string]any{"password_wo": testBindPassword, "password_wo_version": 1})),
				`"bind_dn" must be specified`)

			// A realm PBS has a password for, imported, updates without one.
			realms.addRealm("legacy", k.realmType, k.props(fakeProperties{"bind-dn": k.bindDN}))
			realms.setBindPassword("legacy", testBindPassword)
			inst := h.importByID(t, k.typeName, "legacy")
			attrs := map[string]any{"realm": "legacy", "bind_dn": k.bindDN, "comment": "Imported"}
			inst = h.update(t, inst, k.config(t, h, attrs))
			requireForm(t, "PUT", fake.lastCall(t, k.route(http.MethodPut, "legacy")).form, map[string]string{"comment": "Imported"})

			// A new name replaces it, and needs the password.
			attrs["realm"] = "renamed"
			planned := h.plan(t, k.typeName, inst, k.config(t, h, attrs))
			requireProtocolErrorOn(t, planned.Diagnostics, passwordWOPath)
			requireProtocolErrorContaining(t, planned.Diagnostics, `The plan replaces `+k.name+` realm "renamed"`)
			attrs["password_wo"] = testBindPassword
			attrs["password_wo_version"] = 1
			planned = h.plan(t, k.typeName, inst, k.config(t, h, attrs))
			requireNoProtocolErrors(t, planned.Diagnostics)
			if len(planned.RequiresReplace) != 1 || !planned.RequiresReplace[0].Equal(realmPath) {
				t.Errorf("RequiresReplace = %v", planned.RequiresReplace)
			}
		})
	}
}

// Without base_dn, PBS asks the domain controller for its naming context when
// it creates the realm; base_dn is unknown until then, and keeps what PBS
// found when the configuration leaves it out.
func TestADRealmResourceBaseDN(t *testing.T) {
	h, fake, realms := newDirectoryRealmHarness(t)
	post, put := adKind.route(http.MethodPost, ""), adKind.route(http.MethodPut, "corp")

	config := adKind.config(t, h, nil)
	planned := h.plan(t, "pbs_realm_ad", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if !isUnknownAt(t, h.decodeResource(t, "pbs_realm_ad", planned.PlannedState), "base_dn") {
		t.Errorf("planned base_dn is known: %s", h.decodeResource(t, "pbs_realm_ad", planned.PlannedState))
	}
	inst := h.create(t, "pbs_realm_ad", config)
	if fake.lastCall(t, post).form.Has("base-dn") {
		t.Error("POST sent a base-dn")
	}
	if stored, _ := realms.realm("corp"); stringAt(t, inst.state, "base_dn") != testADBaseDN || stored["base-dn"] != testADBaseDN {
		t.Errorf("state = %s, stored realm = %v", inst.state, stored)
	}
	requireNoPlannedChange(t, h, inst, config)
	requireNoPlannedChange(t, h, inst, adKind.config(t, h, map[string]any{"base_dn": testADBaseDN}))

	// Another base_dn is sent; removing it from the configuration keeps it,
	// and other updates leave it alone.
	inst = h.update(t, inst, adKind.config(t, h, map[string]any{"base_dn": "OU=Staff,DC=example,DC=com"}))
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"base-dn": "OU=Staff,DC=example,DC=com"})
	requireNoPlannedChange(t, h, inst, config)
	inst = h.update(t, inst, adKind.config(t, h, map[string]any{"comment": "AD"}))
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"comment": "AD"})
	if got := stringAt(t, inst.state, "base_dn"); got != "OU=Staff,DC=example,DC=com" {
		t.Errorf("base_dn = %q after an update without it", got)
	}

	// A base_dn in the configuration of a new realm is sent.
	h.create(t, "pbs_realm_ad", adKind.config(t, h, map[string]any{"realm": "corp2", "base_dn": testADBaseDN}))
	if got := fake.lastCall(t, post).form.Get("base-dn"); got != testADBaseDN {
		t.Errorf("POST base-dn = %q", got)
	}

	// A realm without base-dn, from a domains.cfg edited by hand, gets the
	// naming context from its next update.
	realms.addRealm("legacy", pbsclient.RealmTypeAD, fakeProperties{"server1": testADServer})
	inst = h.importByID(t, "pbs_realm_ad", "legacy")
	if !isNullAt(t, inst.state, "base_dn") {
		t.Fatalf("state = %s", inst.state)
	}
	config = adKind.config(t, h, map[string]any{"realm": "legacy", "comment": "Legacy"})
	planned = h.plan(t, "pbs_realm_ad", inst, config)
	if !isUnknownAt(t, h.decodeResource(t, "pbs_realm_ad", planned.PlannedState), "base_dn") {
		t.Errorf("planned base_dn is known: %s", h.decodeResource(t, "pbs_realm_ad", planned.PlannedState))
	}
	// When reading it back fails, state gets a null base_dn, not the unknown
	// of the plan, which state cannot hold.
	get := adKind.route(http.MethodGet, "legacy")
	fake.reply(get, http.StatusInternalServerError, "unable to parse domains.cfg")
	resp := directoryUpdateResponse(t, h, inst, adKind.config(t, h, map[string]any{"realm": "legacy", "comment": "Old"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "the change was recorded in state")
	if failed := h.decodeResource(t, "pbs_realm_ad", resp.NewState); !failed.IsFullyKnown() || !isNullAt(t, failed, "base_dn") {
		t.Errorf("state after a failed read-back = %s", failed)
	}
	fake.handle(get, nil)
	inst = h.update(t, inst, config)
	requireForm(t, "PUT", fake.lastCall(t, adKind.route(http.MethodPut, "legacy")).form, map[string]string{"comment": "Legacy"})
	if got := stringAt(t, inst.state, "base_dn"); got != testADBaseDN {
		t.Errorf("base_dn = %q", got)
	}
	requireNoPlannedChange(t, h, inst, config)
}

// An LDAP realm's user_attr and base_dn change in place.
func TestLDAPRealmResourceChangesUserAttrInPlace(t *testing.T) {
	h, fake, _ := newDirectoryRealmHarness(t)
	inst := h.create(t, "pbs_realm_ldap", ldapKind.config(t, h, nil))

	config := ldapKind.config(t, h, map[string]any{"user_attr": "cn", "base_dn": "dc=example,dc=com"})
	planned := h.plan(t, "pbs_realm_ldap", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 0 {
		t.Errorf("RequiresReplace = %v", planned.RequiresReplace)
	}
	inst = h.update(t, inst, config)
	requireForm(t, "PUT", fake.lastCall(t, ldapKind.route(http.MethodPut, "corp")).form,
		map[string]string{"user-attr": "cn", "base-dn": "dc=example,dc=com"})
	if stringAt(t, inst.state, "user_attr") != "cn" {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)
}

// PBS splits user-classes and remove-vanished at commas, semicolons and white
// space, and keeps the property strings in any order: they read as sets and
// objects, which a configuration in any order matches.
func TestDirectoryRealmResourceReadsListsAsPBSSplitsThem(t *testing.T) {
	h, fake, realms := newDirectoryRealmHarness(t)
	put := ldapKind.route(http.MethodPut, "corp")
	realms.addRealm("corp", pbsclient.RealmTypeLDAP, ldapKind.props(fakeProperties{
		"user-classes":          "person; user\torganizationalPerson,person",
		"sync-attributes":       "lastname=sn,email=mail",
		"sync-defaults-options": `remove-vanished="entry,acl",enable-new=0`,
	}))
	inst := h.importByID(t, "pbs_realm_ldap", "corp")
	if !slices.Equal(setStringsAt(t, inst.state, "user_classes"), []string{"organizationalPerson", "person", "user"}) ||
		stringAt(t, inst.state, "sync_attributes", "email") != "mail" ||
		!isNullAt(t, inst.state, "sync_attributes", "firstname") ||
		stringAt(t, inst.state, "sync_attributes", "lastname") != "sn" ||
		boolAt(t, inst.state, "sync_defaults", "enable_new") ||
		!slices.Equal(setStringsAt(t, inst.state, "sync_defaults", "remove_vanished"), []string{"acl", "entry"}) {
		t.Errorf("state = %s", inst.state)
	}
	attrs := map[string]any{"user_classes": []string{"user", "organizationalPerson", "person"},
		"sync_attributes": map[string]any{"lastname": "sn", "email": "mail"}}
	for _, order := range [][]string{{"acl", "entry"}, {"entry", "acl"}} {
		attrs["sync_defaults"] = map[string]any{"enable_new": false, "remove_vanished": order}
		requireNoPlannedChange(t, h, inst, ldapKind.config(t, h, attrs))
	}

	// A change writes the whole string anew, as the provider writes it.
	attrs["sync_defaults"] = map[string]any{"enable_new": false, "remove_vanished": []string{"properties", "entry", "acl"}}
	inst = h.update(t, inst, ldapKind.config(t, h, attrs))
	const options = "enable-new=false,remove-vanished=acl;entry;properties"
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"sync-defaults-options": options})
	if stored, _ := realms.realm("corp"); stored["sync-defaults-options"] != options {
		t.Errorf("stored realm = %v", stored)
	}

	// PBS's default classes, in the configuration, delete the property
	// rather than write them; stored all the same, they read as the default.
	attrs["user_classes"] = []string{"user", "person", "posixaccount", "inetorgperson"}
	config := ldapKind.config(t, h, attrs)
	inst = h.update(t, inst, config)
	requireForm(t, "PUT", fake.lastCall(t, put).form, map[string]string{"delete": "user-classes"})
	delete(attrs, "user_classes")
	requireNoPlannedChange(t, h, inst, ldapKind.config(t, h, attrs))
	realms.mu.Lock()
	realms.realms["corp"]["user-classes"] = pbsclient.DefaultUserClasses
	realms.mu.Unlock()
	inst = h.refresh(t, inst)
	requireNoPlannedChange(t, h, inst, config)
	requireNoPlannedChange(t, h, inst, ldapKind.config(t, h, attrs))
}

// PBS checks the connection before it saves a realm: a check that fails
// saves nothing, and the error advises on what failed, without the bind
// password.
func TestDirectoryRealmResourceConnectionCheckFailures(t *testing.T) {
	const (
		connect = "PBS connects to the server before it saves the realm"
		refused = "Connection refused (os error 111)"
	)
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, realms := newDirectoryRealmHarness(t)
			realms.mu.Lock()
			realms.servers[k.server].ca = testCAPath
			realms.mu.Unlock()

			for name, tc := range map[string]struct {
				attrs        map[string]any
				advice, text string
			}{
				"unreachable server":    {map[string]any{"server1": "ldap-down.example.com"}, connect, refused},
				"unreachable fallback":  {map[string]any{"server1": "ldap-down.example.com", "server2": "ldap-gone.example.com"}, connect, refused},
				"closed port":           {map[string]any{"port": 1389}, connect, refused},
				"ldaps to plain LDAP":   {map[string]any{"mode": "ldaps", "port": 389}, connect, "wrong version number"},
				"plain LDAP to ldaps":   {map[string]any{"port": 636}, connect, "Connection reset by peer"},
				"untrusted certificate": {map[string]any{"mode": "ldap+starttls", "verify": true}, connect, "certificate verify failed"},
				"missing capath": {map[string]any{"capath": "/etc/proxmox-backup/missing.pem"},
					"capath, when set, must exist on the PBS host", "No such file or directory (os error 2)"},
				"wrong password": {map[string]any{"bind_dn": k.bindDN, "password_wo": "wrong-bind-secret", "password_wo_version": 1},
					"The server refused bind_dn", "rc=49 (invalidCredentials)"},
				"unknown bind DN": {map[string]any{"bind_dn": "uid=nobody,dc=example,dc=com", "password_wo": testBindPassword,
					"password_wo_version": 1}, "The server refused bind_dn", "LDAP bind failed"},
				"missing base DN": {map[string]any{"base_dn": "ou=missing,dc=example,dc=com"},
					"PBS connected, but could not read base_dn", "Could not search LDAP realm"},
			} {
				t.Run(name, func(t *testing.T) {
					resp := directoryCreateResponse(t, h, k.typeName, k.config(t, h, tc.attrs))
					requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to create PBS "+k.name+" realm")
					requireProtocolErrorContaining(t, resp.Diagnostics, tc.advice)
					requireProtocolErrorContaining(t, resp.Diagnostics, tc.text)
					requireNoSecretIn(t, resp.Diagnostics, "wrong-bind-secret", testBindPassword)
					if _, exists := realms.realm("corp"); exists {
						t.Error("PBS saved a realm whose check failed")
					}
				})
			}

			// server2 answers when server1 does not, an IPv6 address in
			// brackets as well as a name; a server is reached on its port.
			realms.addServer("[fd00::389]", fakeDirectory{entries: []string{k.baseDN}, namingContext: k.baseDN})
			realms.addServer("ldap-1389.example.com", fakeDirectory{ports: map[int64]string{1389: "ldap"},
				entries: []string{k.baseDN}, namingContext: k.baseDN})
			for _, attrs := range []map[string]any{
				{"server1": "ldap-down.example.com", "server2": "[fd00::389]"},
				{"server1": "ldap-1389.example.com", "port": 1389},
			} {
				h.destroy(t, h.create(t, k.typeName, k.config(t, h, attrs)))
			}

			// An update checks the connection the realm has after it: a
			// bind_dn PBS has no password for fails, and changes nothing ...
			inst := h.create(t, k.typeName, k.config(t, h, nil))
			resp := directoryUpdateResponse(t, h, inst, k.config(t, h, map[string]any{"bind_dn": k.bindDN}))
			requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to update PBS "+k.name+" realm")
			requireProtocolErrorContaining(t, resp.Diagnostics, "PBS has no password for bind_dn")
			requireProtocolErrorContaining(t, resp.Diagnostics, "Missing bind password for "+k.bindDN)
			if stored, _ := realms.realm("corp"); stored["bind-dn"] != nil {
				t.Errorf("stored realm = %v after a failed update", stored)
			}

			// ... and goes through with one.
			bind := map[string]any{"bind_dn": k.bindDN, "password_wo": testBindPassword, "password_wo_version": 1}
			inst = h.update(t, inst, k.config(t, h, bind))
			requireForm(t, "PUT", fake.lastCall(t, k.route(http.MethodPut, "corp")).form,
				map[string]string{"bind-dn": k.bindDN, "password": testBindPassword})

			// A server out of reach fails the update.
			bind["server1"] = "ldap-down.example.com"
			resp = directoryUpdateResponse(t, h, inst, k.config(t, h, bind))
			requireProtocolErrorContaining(t, resp.Diagnostics, connect)
			requireNoSecretIn(t, resp.Diagnostics, testBindPassword)
			if stored, _ := realms.realm("corp"); stored["server1"] != k.server {
				t.Errorf("stored realm = %v after a failed update", stored)
			}
		})
	}
}

// An Active Directory realm without base_dn first asks the server for its
// naming context, over a connection of its own: a server that names none
// fails with advice to set base_dn, one PBS cannot reach with the advice on
// connecting.
func TestADRealmResourceNamingContextFailures(t *testing.T) {
	h, _, realms := newDirectoryRealmHarness(t)
	realms.addServer("openldap.example.com", fakeDirectory{entries: []string{"dc=example,dc=com"}})

	resp := directoryCreateResponse(t, h, "pbs_realm_ad", adKind.config(t, h, map[string]any{"server1": "openldap.example.com"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "the server named none")
	requireProtocolErrorContaining(t, resp.Diagnostics, "failed to retrieve root DSE attribute 'defaultNamingContext'")

	resp = directoryCreateResponse(t, h, "pbs_realm_ad", adKind.config(t, h, map[string]any{"server1": "dc-down.example.com"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS connects to the server before it saves the realm")
	requireProtocolErrorContaining(t, resp.Diagnostics, "failed to determine base_dn: I/O error: Connection refused")

	// With base_dn, PBS asks for nothing: any directory server will do.
	h.create(t, "pbs_realm_ad", adKind.config(t, h, map[string]any{"server1": "openldap.example.com", "base_dn": "dc=example,dc=com"}))
}

// The bind password never appears in a diagnostic, not even where PBS's
// error repeats it.
func TestDirectoryRealmResourceKeepsThePasswordOutOfErrors(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, realms := newDirectoryRealmHarness(t)
			post, put := k.route(http.MethodPost, ""), k.route(http.MethodPut, "corp")
			const leaky = "leaky-bind-secret"

			fake.reply(post, http.StatusBadRequest, "parameter verification failed - 'password': value '"+leaky+"' is invalid")
			resp := directoryCreateResponse(t, h, k.typeName, k.config(t, h, map[string]any{"bind_dn": k.bindDN,
				"password_wo": leaky, "password_wo_version": 1}))
			requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to create PBS "+k.name+" realm")
			requireNoSecretIn(t, resp.Diagnostics, leaky)

			fake.handle(post, realms.createDirectoryRealm(k.realmType))
			inst := h.create(t, k.typeName, k.config(t, h, map[string]any{"bind_dn": k.bindDN,
				"password_wo": testBindPassword, "password_wo_version": 1}))
			fake.reply(put, http.StatusBadRequest, "LDAP bind failed for "+leaky)
			resp = directoryUpdateResponse(t, h, inst, k.config(t, h, map[string]any{"bind_dn": k.bindDN,
				"password_wo": leaky, "password_wo_version": 2}))
			requireProtocolErrorContaining(t, resp.Diagnostics, "The server refused bind_dn")
			requireNoSecretIn(t, resp.Diagnostics, leaky)
		})
	}
}

// Realms of every type share one namespace: a name PBS has, for a realm of
// any type, fails the create with advice to import it. pam and pbs fail
// validation already, and PBS refuses them all the same.
func TestDirectoryRealmResourceNameTaken(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, _, realms := newDirectoryRealmHarness(t)
			realms.addRealm("corp", pbsclient.RealmTypeOpenID, fakeProperties{"issuer-url": testIssuerURL, "client-id": "pbs"})
			resp := directoryCreateResponse(t, h, k.typeName, k.config(t, h, nil))
			requireProtocolErrorOn(t, resp.Diagnostics, realmPath)
			requireProtocolErrorContaining(t, resp.Diagnostics, "If it is an "+k.name+" realm, import it")

			config := k.config(t, h, map[string]any{"realm": "pam"})
			requireProtocolErrorContaining(t, h.validateResource(t, k.typeName, config), "value must be none of")
			resp = directoryCreateResponse(t, h, k.typeName, config)
			requireProtocolErrorContaining(t, resp.Diagnostics, `PBS already has a realm "pam"`)
			if stored, _ := realms.realm("pam"); len(stored) != 2 || realms.defaultRealm() != "pam" {
				t.Errorf("pam = %v", stored)
			}
		})
	}
}

// A realm replaced outside Terraform by one of another type, the other
// directory type included, leaves state with a warning, and destroying the
// resource leaves that realm alone.
func TestDirectoryRealmResourceReplacedByAnotherType(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, _, realms := newDirectoryRealmHarness(t)
			inst := h.create(t, k.typeName, k.config(t, h, nil))

			other := pbsclient.RealmTypeAD
			if k.realmType == pbsclient.RealmTypeAD {
				other = pbsclient.RealmTypeLDAP
			}
			realms.addRealm("corp", other, fakeProperties{"server1": "other.example.com", "base-dn": "dc=other"})
			resp := h.read(t, inst)
			requireProtocolWarningContaining(t, resp.Diagnostics, "PBS realm is no "+k.name+" realm")
			requireProtocolWarningContaining(t, resp.Diagnostics, "not of type "+k.realmType)
			if state := h.decodeResource(t, k.typeName, resp.NewState); !state.IsNull() {
				t.Errorf("refresh kept the realm: %s", state)
			}

			destroyed := syncDestroyResponse(t, h, inst)
			requireProtocolWarningContaining(t, destroyed.Diagnostics, "so it was not deleted")
			realms.mu.Lock()
			defer realms.mu.Unlock()
			if realms.types["corp"] != other {
				t.Errorf("destroy deleted the %s realm", other)
			}
		})
	}
}

// The delete sends the digest of its read, and reads again when another
// writer changed domains.cfg in between; a realm already gone is no error.
func TestDirectoryRealmResourceDeleteRetriesOnDigestConflict(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, realms := newDirectoryRealmHarness(t)
			inst := h.create(t, k.typeName, k.config(t, h, map[string]any{"bind_dn": k.bindDN,
				"password_wo": testBindPassword, "password_wo_version": 1}))

			route := k.route(http.MethodDelete, "corp")
			bumped := false
			fake.handle(route, func(w http.ResponseWriter, req *http.Request) {
				if !bumped {
					bumped = true
					realms.addRealm("other", pbsclient.RealmTypeOpenID, fakeProperties{"issuer-url": testIssuerURL, "client-id": "x"})
				}
				realms.serveDirectoryRealm(k.realmType)(w, req)
			})
			h.destroy(t, inst)
			if _, exists := realms.realm("corp"); exists {
				t.Error("destroy left the realm")
			}
			if _, ok := realms.bindPassword("corp"); ok {
				t.Error("destroy left the bind password")
			}
			if got := fake.count(route); got != 2 {
				t.Errorf("DELETE was sent %d times, want 2", got)
			}
			if got := fake.lastCall(t, route).query.Get(pbsclient.DigestParam); got == "" {
				t.Error("DELETE sent no digest")
			}
			h.destroy(t, inst)
		})
	}
}

// A realm is imported by name, every property but the bind password, which
// PBS keeps and binds with.
func TestDirectoryRealmResourceImport(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, realms := newDirectoryRealmHarness(t)
			realms.addRealm("corp", k.realmType, k.props(fakeProperties{"server2": "[fd00::389]", "port": int64(389),
				"mode": "ldap+starttls", "verify": true, "capath": testCAPath, "bind-dn": k.bindDN,
				"filter": "(objectClass=person)", "user-classes": "person,user", "sync-attributes": "email=mail",
				"sync-defaults-options": "enable-new=false", "comment": "Imported", "default": true}))
			realms.setBindPassword("corp", testBindPassword)

			for name, inst := range map[string]*resourceInstance{
				"id":       h.importByID(t, k.typeName, "corp"),
				"identity": h.importByIdentity(t, k.typeName, map[string]any{"realm": "corp"}),
			} {
				if stringAt(t, inst.state, "id") != "corp" || stringAt(t, inst.state, "server1") != k.server ||
					stringAt(t, inst.state, "server2") != "[fd00::389]" || int64At(t, inst.state, "port") != 389 ||
					stringAt(t, inst.state, "mode") != "ldap+starttls" || !boolAt(t, inst.state, "verify") ||
					stringAt(t, inst.state, "capath") != testCAPath || stringAt(t, inst.state, "base_dn") != k.baseDN ||
					stringAt(t, inst.state, "bind_dn") != k.bindDN || stringAt(t, inst.state, "filter") != "(objectClass=person)" ||
					!slices.Equal(setStringsAt(t, inst.state, "user_classes"), []string{"person", "user"}) ||
					stringAt(t, inst.state, "sync_attributes", "email") != "mail" ||
					boolAt(t, inst.state, "sync_defaults", "enable_new") ||
					!isNullAt(t, inst.state, "sync_defaults", "remove_vanished") ||
					stringAt(t, inst.state, "comment") != "Imported" || !boolAt(t, inst.state, "default") ||
					!isNullAt(t, inst.state, "password_wo") || !isNullAt(t, inst.state, "password_wo_version") {
					t.Errorf("import by %s = %s", name, inst.state)
				}
				if got := stringAt(t, h.identityValue(t, k.typeName, inst.identity), "realm"); got != "corp" {
					t.Errorf("import by %s: identity realm = %q", name, got)
				}
			}

			// A configuration without the password matches, and an update
			// binds with the one PBS has.
			attrs := map[string]any{"server2": "[fd00::389]", "port": 389, "mode": "ldap+starttls", "verify": true,
				"capath": testCAPath, "base_dn": k.baseDN, "bind_dn": k.bindDN, "filter": "(objectClass=person)",
				"user_classes": []string{"user", "person"}, "sync_attributes": map[string]any{"email": "mail"},
				"sync_defaults": map[string]any{"enable_new": false}, "comment": "Imported", "default": true}
			inst := h.importByID(t, k.typeName, "corp")
			requireNoPlannedChange(t, h, inst, k.config(t, h, attrs))
			attrs["comment"] = "Imported realm"
			h.update(t, inst, k.config(t, h, attrs))
			requireForm(t, "PUT", fake.lastCall(t, k.route(http.MethodPut, "corp")).form,
				map[string]string{"comment": "Imported realm", "default": "true"})

			resp := h.importResource(t, k.typeName, "corp/x", nil)
			requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS "+k.name+" realm by its realm")
			if got := h.importByID(t, k.typeName, "absent"); !got.state.IsNull() {
				t.Errorf("import of a missing realm = %s", got.state)
			}
		})
	}
}

func TestDirectoryRealmResourceValidation(t *testing.T) {
	h, _, _ := newDirectoryRealmHarness(t)
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			cases := map[string]struct {
				attrs map[string]any
				want  string
			}{
				"built-in pam":            {map[string]any{"realm": "pam"}, "value must be none of"},
				"built-in pbs":            {map[string]any{"realm": "pbs"}, "value must be none of"},
				"short name":              {map[string]any{"realm": "c"}, "string length must be between 2 and 32"},
				"name with a slash":       {map[string]any{"realm": "corp/x"}, "must start with a letter"},
				"IPv6 without brackets":   {map[string]any{"server1": "fd00::1"}, "must be a host name or IPv4 address"},
				"server with a port":      {map[string]any{"server1": "ldap.example.com:389"}, "must be a host name or IPv4 address"},
				"server as a URL":         {map[string]any{"server2": "ldap://ldap.example.com"}, "must be a host name or IPv4 address"},
				"server with a space":     {map[string]any{"server2": "ldap example.com"}, "must be a host name or IPv4 address"},
				"port zero":               {map[string]any{"port": 0}, "value must be between 1 and 65535"},
				"port too high":           {map[string]any{"port": 65536}, "value must be between 1 and 65535"},
				"mode":                    {map[string]any{"mode": "starttls"}, "value must be one of"},
				"relative capath":         {map[string]any{"capath": "certs/ca.pem"}, "must be an absolute path"},
				"padded capath":           {map[string]any{"capath": "/etc/ca.pem "}, "must be an absolute path"},
				"empty base DN":           {map[string]any{"base_dn": ""}, "string length must be at least 1"},
				"padded bind DN":          {map[string]any{"bind_dn": " uid=pbs,dc=example,dc=com"}, "must not begin or end with white space"},
				"password without DN":     {map[string]any{"password_wo": "x", "password_wo_version": 1}, `"bind_dn" must be specified`},
				"empty password":          {map[string]any{"bind_dn": k.bindDN, "password_wo": "", "password_wo_version": 1}, "string length must be at least 1"},
				"version alone":           {map[string]any{"password_wo_version": 1}, "password_wo"},
				"filter without parens":   {map[string]any{"filter": "uid=*"}, "must be an LDAP search filter in parentheses"},
				"filter on two lines":     {map[string]any{"filter": "(uid=a)\n(uid=b)"}, "must be an LDAP search filter in parentheses"},
				"no user classes":         {map[string]any{"user_classes": []string{}}, "set must contain at least 1 elements"},
				"user class with space":   {map[string]any{"user_classes": []string{"inet orgperson"}}, "must be an LDAP attribute name"},
				"null user class":         {map[string]any{"user_classes": []any{"person", nil}}, "null"},
				"empty sync attributes":   {map[string]any{"sync_attributes": map[string]any{}}, "must set at least one attribute"},
				"bad sync attribute":      {map[string]any{"sync_attributes": map[string]any{"email": "e-mail address"}}, "must be an LDAP attribute name"},
				"empty sync defaults":     {map[string]any{"sync_defaults": map[string]any{}}, "must set at least one attribute"},
				"unknown remove_vanish":   {map[string]any{"sync_defaults": map[string]any{"remove_vanished": []string{"users"}}}, "value must be one of"},
				"empty remove_vanished":   {map[string]any{"sync_defaults": map[string]any{"remove_vanished": []string{}}}, "set must contain at least 1 elements"},
				"comment on two lines":    {map[string]any{"comment": "a\nb"}, "must be a single line"},
				"comment longer than 128": {map[string]any{"comment": strings.Repeat("a", 129)}, "string length must be between 1 and 128"},
			}
			if k.realmType == pbsclient.RealmTypeLDAP {
				cases["user_attr starting with a digit"] = struct {
					attrs map[string]any
					want  string
				}{map[string]any{"user_attr": "1uid"}, "must be an LDAP attribute name"}
				cases["user_attr with a colon"] = struct {
					attrs map[string]any
					want  string
				}{map[string]any{"user_attr": "uid:"}, "must be an LDAP attribute name"}
			}
			for name, tc := range cases {
				t.Run(name, func(t *testing.T) {
					requireProtocolErrorContaining(t, h.validateResource(t, k.typeName, k.config(t, h, tc.attrs)), tc.want)
				})
			}

			for _, attrs := range []map[string]any{
				{"server1": "[fd00::1]", "server2": "[2001:db8::10]"},
				{"server1": "192.0.2.10", "server2": "ldap-2.example.com."},
				{"capath": "/etc/ssl/certs", "filter": "(&(objectClass=person)(memberOf=cn=pbs,dc=example,dc=com))"},
				{"user_classes": []string{"inetOrgPerson", "2.5.6.6"},
					"sync_attributes": map[string]any{"email": "mail", "lastname": "sn"},
					"sync_defaults":   map[string]any{"remove_vanished": []string{"acl", "entry", "properties"}}},
			} {
				requireNoProtocolErrors(t, h.validateResource(t, k.typeName, k.config(t, h, attrs)))
			}
		})
	}
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_realm_ldap", ldapKind.config(t, h, map[string]any{"user_attr": "2.5.4.3"})))
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_realm_ldap", ldapKind.config(t, h, map[string]any{"user_attr": "sAMAccountName"})))
}

// Failed calls are errors that name the privilege they need. A realm whose
// read-back fails is still recorded — tainted after a create, and without a
// base_dn PBS was to find — and a password Terraform has not resolved is
// never sent as an empty one.
func TestDirectoryRealmResourceAPIErrors(t *testing.T) {
	for _, k := range directoryKinds {
		t.Run(k.typeName, func(t *testing.T) {
			h, fake, _ := newDirectoryRealmHarness(t)
			get, put := k.route(http.MethodGet, "corp"), k.route(http.MethodPut, "corp")
			config := k.config(t, h, nil)

			fake.reply(get, http.StatusForbidden, "permission check failed")
			resp := directoryCreateResponse(t, h, k.typeName, config)
			requireProtocolErrorContaining(t, resp.Diagnostics, "marked tainted")
			requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /access/domains")
			state := h.decodeResource(t, k.typeName, resp.NewState)
			if stringAt(t, state, "id") != "corp" || (k.realmType == pbsclient.RealmTypeAD && !isNullAt(t, state, "base_dn")) {
				t.Errorf("state after a failed read-back = %s", state)
			}
			fake.handle(get, nil)
			inst := h.refresh(t, &resourceInstance{typeName: k.typeName, state: state, identity: resp.NewIdentity})
			if stringAt(t, inst.state, "base_dn") != k.baseDN {
				t.Errorf("state after a refresh = %s", inst.state)
			}

			fake.reply(get, http.StatusInternalServerError, "unable to parse domains.cfg")
			requireProtocolErrorContaining(t, h.read(t, inst).Diagnostics, "Unable to read PBS "+k.name+" realm")
			resp = directoryUpdateResponse(t, h, inst, k.config(t, h, map[string]any{"comment": "Directory"}))
			requireProtocolErrorContaining(t, resp.Diagnostics, "the change was recorded in state")
			fake.handle(get, nil)

			fake.reply(put, http.StatusForbidden, "permission check failed")
			resp = directoryUpdateResponse(t, h, inst, k.config(t, h, map[string]any{"comment": "Other"}))
			requireProtocolErrorContaining(t, resp.Diagnostics, "Realm.Allocate on /access/domains")
			if strings.Contains(resp.Diagnostics[0].Detail, "PBS connects") {
				t.Errorf("a refused update got advice on connecting: %s", resp.Diagnostics[0].Detail)
			}
			fake.handle(put, nil)

			fake.reply(k.route(http.MethodDelete, "corp"), http.StatusForbidden, "permission check failed")
			requireProtocolErrorContaining(t, syncDestroyResponse(t, h, inst).Diagnostics, "Unable to delete PBS "+k.name+" realm")

			unresolved := map[string]any{"bind_dn": k.bindDN, "password_wo": tfUnknown, "password_wo_version": 2}
			resp = directoryUpdateResponse(t, h, inst, k.config(t, h, unresolved))
			requireProtocolErrorContaining(t, resp.Diagnostics, "password_wo_version changed, but password_wo is not known")
			unresolved["realm"] = "other"
			resp = directoryCreateResponse(t, h, k.typeName, k.config(t, h, unresolved))
			requireProtocolErrorContaining(t, resp.Diagnostics, "password_wo_version is set, but password_wo is not known")
			if fake.count(k.route(http.MethodPost, "")) != 1 || fake.count(put) != 2 {
				t.Errorf("calls = %v", fake.routes())
			}
		})
	}
}

// The fake refuses what PBS refuses, and saves nothing when a check fails.
func TestFakeDirectoryRealms(t *testing.T) {
	fake := newFakePBS()
	realms := newFakeRealms(fake)
	realms.addServer(testLDAPServer, fakeDirectory{entries: []string{testLDAPBaseDN},
		binds: map[string]string{testLDAPBindDN: testBindPassword}})
	client := fake.configured(t).client
	ctx := context.Background()
	ldap := url.Values{"realm": {"corp"}, "server1": {testLDAPServer}, "base-dn": {testLDAPBaseDN}, "user-attr": {"uid"}}
	with := func(params url.Values, extra ...string) url.Values {
		out := url.Values{}
		for name, values := range params {
			out[name] = slices.Clone(values)
		}
		for i := 0; i+1 < len(extra); i += 2 {
			out.Add(extra[i], extra[i+1])
		}
		return out
	}

	for name, tc := range map[string]struct {
		realmType string
		params    url.Values
		want      string
	}{
		"AD with user-attr":    {pbsclient.RealmTypeAD, ldap, "'user-attr': schema does not allow additional properties"},
		"LDAP without base-dn": {pbsclient.RealmTypeLDAP, url.Values{"realm": {"corp"}, "server1": {testLDAPServer}, "user-attr": {"uid"}}, "'base-dn': parameter is missing"},
		"unknown mode":         {pbsclient.RealmTypeLDAP, with(ldap, "mode", "tls"), "'mode': value 'tls'"},
		"empty user classes":   {pbsclient.RealmTypeLDAP, with(ldap, "user-classes", " ;"), "'user-classes'"},
		"unknown sync key":     {pbsclient.RealmTypeLDAP, with(ldap, "sync-attributes", "mail=mail"), "'sync-attributes'"},
		"unknown vanished":     {pbsclient.RealmTypeLDAP, with(ldap, "sync-defaults-options", "remove-vanished=users"), "value 'users'"},
		"bad enable-new":       {pbsclient.RealmTypeLDAP, with(ldap, "sync-defaults-options", "enable-new=maybe"), "'enable-new'"},
		"failed check":         {pbsclient.RealmTypeLDAP, with(ldap, "default", "true", "bind-dn", testLDAPBindDN), "Missing bind password"},
	} {
		err := client.CreateDirectoryRealm(ctx, tc.realmType, tc.params)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
	if _, exists := realms.realm("corp"); exists || realms.defaultRealm() != "pam" {
		t.Fatalf("a refused create changed the realms: default realm %q", realms.defaultRealm())
	}

	if err := client.CreateDirectoryRealm(ctx, pbsclient.RealmTypeLDAP, with(ldap, "bind-dn", testLDAPBindDN, "password", testBindPassword)); err != nil {
		t.Fatal(err)
	}
	// An update ignores capath; delete=password removes the password before
	// the check, for good.
	realms.addCAFile(testCAPath)
	if err := client.UpdateDirectoryRealm(ctx, pbsclient.RealmTypeLDAP, "corp", url.Values{"capath": {testCAPath}}); err != nil {
		t.Fatal(err)
	}
	if stored, _ := realms.realm("corp"); stored["capath"] != nil {
		t.Errorf("stored realm = %v after an update of capath", stored)
	}
	err := client.UpdateDirectoryRealm(ctx, pbsclient.RealmTypeLDAP, "corp", url.Values{"delete": {"password"}})
	if pbsclient.DirectoryCheckFailureOf(err) != pbsclient.DirectoryMissingPassword {
		t.Errorf("update deleting the password: %v", err)
	}
	if _, ok := realms.bindPassword("corp"); ok {
		t.Error("the password survived delete=password")
	}
	err = client.UpdateDirectoryRealm(ctx, pbsclient.RealmTypeLDAP, "corp", url.Values{"digest": {strings.Repeat("0", 64)}})
	if !pbsclient.IsDigestConflict(err) {
		t.Errorf("update with a stale digest: %v", err)
	}
	if _, _, err := client.GetDirectoryRealm(ctx, pbsclient.RealmTypeAD, "corp"); !pbsclient.IsRealmOfOtherType(err) {
		t.Errorf("GET of an LDAP realm as AD: %v", err)
	}
	// The ad route deletes an LDAP realm just as well.
	if err := client.DeleteRealm(ctx, pbsclient.RealmTypeAD, "corp", ""); err != nil {
		t.Fatal(err)
	}
	if _, exists := realms.realm("corp"); exists {
		t.Error("DELETE under /config/access/ad left the LDAP realm")
	}
}

// The advice a failed check of the connection gets depends on what failed,
// and, for base_dn, on whether the realm binds or searches anonymously.
func TestDirectoryRealmErrorAdvice(t *testing.T) {
	bindFailed := func(rc string) error {
		return &pbsclient.Error{StatusCode: http.StatusBadRequest, Message: "LDAP bind failed, bind_dn or password " +
			"could be incorrect: LDAP operation result: " + rc + `, dn: "", text: ""`}
	}
	baseFailed := &pbsclient.Error{StatusCode: http.StatusBadRequest, Message: "Could not search LDAP realm, base_dn " +
		`could be incorrect: LDAP operation result: rc=32 (noSuchObject), dn: "", text: ""`}
	for name, tc := range map[string]struct {
		kind      realmKind
		err       error
		hasBindDN bool
		want      string
	}{
		"wrong password":           {ldapRealmKind, bindFailed("rc=49 (invalidCredentials)"), true, "The server refused bind_dn with the password PBS bound with"},
		"signing required":         {adRealmKind, bindFailed("rc=8 (strongerAuthRequired)"), true, `use mode = "ldaps" or "ldap+starttls"`},
		"confidentiality required": {ldapRealmKind, bindFailed("rc=13 (confidentialityRequired)"), true, `use mode = "ldaps" or "ldap+starttls"`},
		"base_dn with a bind":      {ldapRealmKind, baseFailed, true, "and that bind_dn may read it"},
		"base_dn, LDAP, anonymous": {ldapRealmKind, baseFailed, false, "which many directories refuse: set bind_dn"},
		"base_dn, AD, anonymous":   {adRealmKind, baseFailed, false, "which Active Directory refuses by default: set bind_dn"},
		"other errors get none":    {ldapRealmKind, &pbsclient.Error{StatusCode: http.StatusBadRequest, Message: "parameter verification failed - 'port': x"}, true, "parameter verification failed"},
		"missing capath, any mode": {ldapRealmKind, &pbsclient.Error{StatusCode: http.StatusBadRequest, Message: "No such file or directory (os error 2)"}, false, "capath, when set, must exist on the PBS host whatever the mode"},
	} {
		t.Run(name, func(t *testing.T) {
			r := &directoryRealmResource{kind: tc.kind, data: &providerData{}}
			got := r.directoryRealmErrorDetail(tc.err, tc.hasBindDN)
			if !strings.Contains(got, tc.want) {
				t.Errorf("advice = %q, want it to contain %q", got, tc.want)
			}
			if name == "other errors get none" && got != tc.err.Error() {
				t.Errorf("advice = %q, want the error alone", got)
			}
		})
	}
}
