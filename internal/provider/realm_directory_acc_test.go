package provider

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_realm_ldap and pbs_realm_ad, against the OpenLDAP
// server scripts/bootstrap-test-pbs.sh starts in the PBS container's network
// namespace. PBS connects to the server on every create and update, so every
// step that changes a realm also tests that PBS reaches the server with the
// realm's settings; the tests sign in through the realms as the directory's
// user, which PBS looks up by uid in an LDAP realm and by sAMAccountName in an
// Active Directory realm. The server lets nobody read the directory without
// binding, and answers anonymous clients only with its root DSE, which names
// the directory's root as defaultNamingContext, as a domain controller does.

// The facts scripts/bootstrap-test-pbs.sh exports about its LDAP server.
const (
	// envAccLDAPServer is the server as PBS reaches it, 127.0.0.1, with
	// plain LDAP and StartTLS on port 389 and LDAPS on 636.
	envAccLDAPServer = "PBS_ACC_LDAP_SERVER"
	// envAccLDAPBaseDN is the root of the directory, which the root DSE
	// names as defaultNamingContext.
	envAccLDAPBaseDN = "PBS_ACC_LDAP_BASE_DN"
	// envAccLDAPBindDN and envAccLDAPBindPassword are an account that may
	// read the directory.
	envAccLDAPBindDN       = "PBS_ACC_LDAP_BIND_DN"
	envAccLDAPBindPassword = "PBS_ACC_LDAP_BIND_PASSWORD"
	// envAccLDAPUser and envAccLDAPUserPassword are a user of the
	// directory, by its uid, which is also its sAMAccountName, and its
	// password. Its entry is uid=<user>,ou=people,<base DN>.
	envAccLDAPUser         = "PBS_ACC_LDAP_USER"
	envAccLDAPUserPassword = "PBS_ACC_LDAP_USER_PASSWORD"
	// envAccLDAPCAFile is the certificate of the CA that signed the
	// server's, a path on the PBS host. It is alone in its directory, so
	// that the directory works as a capath too. PBS does not trust the CA
	// otherwise.
	envAccLDAPCAFile = "PBS_ACC_LDAP_CA_FILE"
)

// testAccRefusingServer is an address on the PBS host that refuses LDAP
// connections at once: Linux routes all of 127.0.0.0/8 to the loopback
// interface, and the stand's server listens on 127.0.0.1 only.
const testAccRefusingServer = "127.0.0.2"

// testAccDirectory is the stand's LDAP server; see the envAccLDAP*
// constants.
type testAccDirectory struct {
	server, baseDN, bindDN, bindPassword, user, userPassword, caFile string
}

// caDir is the directory of the CA certificate. As capath, it replaces the
// system's certificate authorities.
func (d testAccDirectory) caDir() string { return path.Dir(d.caFile) }

// testAccLDAP returns the stand's LDAP server, or skips the test when the
// stand runs none.
func testAccLDAP(t *testing.T) testAccDirectory {
	t.Helper()
	d := testAccDirectory{
		server:       os.Getenv(envAccLDAPServer),
		baseDN:       os.Getenv(envAccLDAPBaseDN),
		bindDN:       os.Getenv(envAccLDAPBindDN),
		bindPassword: os.Getenv(envAccLDAPBindPassword),
		user:         os.Getenv(envAccLDAPUser),
		userPassword: os.Getenv(envAccLDAPUserPassword),
		caFile:       os.Getenv(envAccLDAPCAFile),
	}
	if os.Getenv("TF_ACC") == "" {
		return d
	}
	for _, name := range []string{envAccLDAPServer, envAccLDAPBaseDN, envAccLDAPBindDN, envAccLDAPBindPassword,
		envAccLDAPUser, envAccLDAPUserPassword, envAccLDAPCAFile} {
		if os.Getenv(name) == "" {
			t.Skipf("%s is not set: the stand runs no LDAP server", name)
		}
	}
	return d
}

// testAccCheckDirectoryRealmsDestroyed checks that the realms, of the type
// given, are gone.
func testAccCheckDirectoryRealmsDestroyed(realmType string, names ...string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		for _, name := range names {
			if _, _, err := client.GetDirectoryRealm(context.Background(), realmType, name); err == nil {
				return fmt.Errorf("%s realm %s still exists", realmType, name)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		return nil
	}
}

// testAccCheckDirectoryRealm checks a realm as PBS reports it.
func testAccCheckDirectoryRealm(realmType, name string, check func(pbsclient.DirectoryRealm) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		realm, _, err := client.GetDirectoryRealm(context.Background(), realmType, name)
		if err != nil {
			return err
		}
		if err := check(realm); err != nil {
			return fmt.Errorf("%s realm %s: %w", realmType, name, err)
		}
		return nil
	}
}

// testAccSortedList splits a list PBS keeps in one string and sorts it.
func testAccSortedList(s string) []string {
	list := pbsclient.SplitList(s)
	slices.Sort(list)
	return list
}

// testAccPasswordWO is the write-only bind password of a realm's
// configuration.
func testAccPasswordWO(password string, version int) string {
	return fmt.Sprintf("password_wo         = %q\n  password_wo_version = %d", password, version)
}

// An LDAP realm through its life: created with every sync setting, which
// PBS stores as sent, and which an update then deletes; switched to LDAPS
// and then StartTLS, verifying the certificate against capath — a file,
// trusted besides the system's CAs, then a directory, trusted instead of
// them —, each new capath replacing the realm; back to plain LDAP with a
// server1 that refuses, so that PBS falls back to server2; the default
// flag, which the provider sends again with every update; import; a wrong
// bind password, which PBS refuses without saving it, so that the realm
// keeps working with the right one; capath removed, which replaces the
// realm; and password_wo removed, which keeps the password PBS has. The
// directory's user signs in through the realm all along.
func TestAccRealmLDAP(t *testing.T) {
	d := testAccLDAP(t)
	name := testAccRealmName()
	userID := d.user + "@" + name
	const resourceName = "pbs_realm_ldap.test"
	config := func(body string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_realm_ldap" "test" {
  realm     = %q
  base_dn   = %q
  user_attr = "uid"
  bind_dn   = %q
%s
}

resource "pbs_user" "user" {
  userid  = "%s@${pbs_realm_ldap.test.realm}"
  comment = "terraform-provider-pbs acceptance tests"
}

data "pbs_realms" "all" {
  depends_on = [pbs_realm_ldap.test]
}
`, name, d.baseDN, d.bindDN, body, d.user)
	}
	realm := func(check func(pbsclient.DirectoryRealm) error) acc.TestCheckFunc {
		return testAccCheckDirectoryRealm(pbsclient.RealmTypeLDAP, name, check)
	}
	isDefault := func(want bool) acc.TestCheckFunc {
		return realm(func(r pbsclient.DirectoryRealm) error {
			if got := r.Default != nil && *r.Default; got != want {
				return fmt.Errorf("default = %t, want %t", got, want)
			}
			return nil
		})
	}
	// fallback is the realm on plain LDAP, with a server1 that refuses.
	fallback := func(password, extra string) string {
		return config(fmt.Sprintf(`
  server1 = %q
  server2 = %q
  port    = 389
  capath  = %q
  %s
  %s`, testAccRefusingServer, d.server, d.caDir(), password, extra))
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); testAccRestoreDefaultRealm(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckDirectoryRealmsDestroyed(pbsclient.RealmTypeLDAP, name),
			testAccCheckAccessDestroyed(userID),
		),
		Steps: []acc.TestStep{
			{
				Config: config(fmt.Sprintf(`
  server1         = %q
  %s
  filter          = "(objectClass=inetOrgPerson)"
  user_classes    = ["person", "inetorgperson"]
  sync_attributes = { email = "mail", firstname = "givenName", lastname = "sn" }
  sync_defaults   = { enable_new = false, remove_vanished = ["entry", "acl"] }
  comment         = "terraform-provider-pbs acceptance tests"`, d.server, testAccPasswordWO(d.bindPassword, 1))),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", name),
					acc.TestCheckResourceAttr(resourceName, "mode", "ldap"),
					acc.TestCheckResourceAttr(resourceName, "verify", "false"),
					acc.TestCheckResourceAttr(resourceName, "default", "false"),
					acc.TestCheckNoResourceAttr(resourceName, "port"),
					acc.TestCheckNoResourceAttr(resourceName, "server2"),
					acc.TestCheckNoResourceAttr(resourceName, "capath"),
					acc.TestCheckNoResourceAttr(resourceName, "password_wo"),
					acc.TestCheckResourceAttr(resourceName, "password_wo_version", "1"),
					acc.TestCheckResourceAttr(resourceName, "user_classes.#", "2"),
					acc.TestCheckResourceAttr(resourceName, "sync_attributes.firstname", "givenName"),
					acc.TestCheckResourceAttr(resourceName, "sync_defaults.enable_new", "false"),
					acc.TestCheckResourceAttr(resourceName, "sync_defaults.remove_vanished.#", "2"),
					realm(func(r pbsclient.DirectoryRealm) error {
						// mode and verify keep PBS's defaults, which the
						// provider does not send.
						if r.Server1 != d.server || r.BaseDN != d.baseDN || r.BindDN != d.bindDN || r.UserAttr != "uid" ||
							r.Filter != "(objectClass=inetOrgPerson)" || r.Mode != "" || r.Verify != nil || r.Port != nil ||
							r.Comment != "terraform-provider-pbs acceptance tests" {
							return fmt.Errorf("realm = %+v", r)
						}
						if got := testAccSortedList(r.UserClasses); !slices.Equal(got, []string{"inetorgperson", "person"}) {
							return fmt.Errorf("user-classes = %q", r.UserClasses)
						}
						attributes, err := pbsclient.ParsePropertyString(r.SyncAttributes, "")
						if err != nil {
							return err
						}
						if !maps.Equal(attributes, pbsclient.PropertyString{"email": "mail", "firstname": "givenName", "lastname": "sn"}) {
							return fmt.Errorf("sync-attributes = %q", r.SyncAttributes)
						}
						defaults, err := pbsclient.ParsePropertyString(r.SyncDefaultsOptions, "")
						if err != nil {
							return err
						}
						if len(defaults) != 2 || defaults["enable-new"] != "false" ||
							!slices.Equal(testAccSortedList(defaults["remove-vanished"]), []string{"acl", "entry"}) {
							return fmt.Errorf("sync-defaults-options = %q", r.SyncDefaultsOptions)
						}
						return nil
					}),
					testAccCheckListed("data.pbs_realms.all", "realms", "realm", name, "pam", "pbs"),
					testAccCheckSignIn(userID, d.userPassword, true),
					testAccCheckSignIn(userID, "wrong-"+d.userPassword, false),
				),
			},
			{
				// The sync settings and the comment removed, which an update
				// deletes in PBS; PBS checks it by binding with the password
				// it has.
				Config: config(fmt.Sprintf(`
  server1 = %q
  %s`, d.server, testAccPasswordWO(d.bindPassword, 1))),
				ConfigPlanChecks: acc.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "user_classes.#", "4"),
					acc.TestCheckNoResourceAttr(resourceName, "filter"),
					acc.TestCheckNoResourceAttr(resourceName, "sync_attributes"),
					acc.TestCheckNoResourceAttr(resourceName, "sync_defaults"),
					acc.TestCheckNoResourceAttr(resourceName, "comment"),
					realm(func(r pbsclient.DirectoryRealm) error {
						if r.Filter != "" || r.UserClasses != "" || r.SyncAttributes != "" || r.SyncDefaultsOptions != "" ||
							r.Comment != "" {
							return fmt.Errorf("realm = %+v", r)
						}
						return nil
					}),
					testAccCheckSignIn(userID, d.userPassword, true),
				),
			},
			{
				// LDAPS, with the certificate verified against capath, a file.
				// PBS ignores capath in an update, so setting it replaces the
				// realm, which works as the configuration has the password.
				Config: config(fmt.Sprintf(`
  server1 = %q
  mode    = "ldaps"
  verify  = true
  capath  = %q
  %s`, d.server, d.caFile, testAccPasswordWO(d.bindPassword, 1))),
				ConfigPlanChecks: acc.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "mode", "ldaps"),
					acc.TestCheckResourceAttr(resourceName, "verify", "true"),
					acc.TestCheckResourceAttr(resourceName, "capath", d.caFile),
					realm(func(r pbsclient.DirectoryRealm) error {
						if r.Mode != "ldaps" || r.Verify == nil || !*r.Verify || r.CAPath != d.caFile {
							return fmt.Errorf("realm = %+v", r)
						}
						return nil
					}),
					testAccCheckSignIn(userID, d.userPassword, true),
				),
			},
			{
				// StartTLS, with capath the CA's directory, which replaces the
				// system's certificate authorities; a new capath replaces the
				// realm again.
				Config: config(fmt.Sprintf(`
  server1 = %q
  mode    = "ldap+starttls"
  verify  = true
  capath  = %q
  %s`, d.server, d.caDir(), testAccPasswordWO(d.bindPassword, 1))),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "mode", "ldap+starttls"),
					realm(func(r pbsclient.DirectoryRealm) error {
						if r.Mode != "ldap+starttls" || r.CAPath != d.caDir() {
							return fmt.Errorf("realm = %+v", r)
						}
						return nil
					}),
					testAccCheckSignIn(userID, d.userPassword, true),
				),
			},
			{
				// Plain LDAP again: mode and verify reset delete them. PBS
				// finds server1 refusing and falls back to server2, when it
				// checks the realm and when the user signs in.
				Config: fallback(testAccPasswordWO(d.bindPassword, 1), ""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "mode", "ldap"),
					acc.TestCheckResourceAttr(resourceName, "verify", "false"),
					acc.TestCheckResourceAttr(resourceName, "server2", d.server),
					acc.TestCheckResourceAttr(resourceName, "port", "389"),
					realm(func(r pbsclient.DirectoryRealm) error {
						if r.Mode != "" || r.Verify != nil || r.Server1 != testAccRefusingServer || r.Server2 != d.server ||
							r.Port == nil || *r.Port != 389 {
							return fmt.Errorf("realm = %+v", r)
						}
						return nil
					}),
					testAccCheckSignIn(userID, d.userPassword, true),
				),
			},
			{
				Config: fallback(testAccPasswordWO(d.bindPassword, 1), `default = true`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "default", "true"),
					isDefault(true),
				),
			},
			{
				// PBS clears the flag on an update that leaves it out; the
				// provider sends it again.
				Config: fallback(testAccPasswordWO(d.bindPassword, 1), "default = true\n  comment = \"changed\""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "comment", "changed"),
					isDefault(true),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password_wo", "password_wo_version"},
			},
			{
				// PBS binds with a new password before it saves it, and
				// refuses a wrong one.
				Config:      fallback(testAccPasswordWO("wrong-"+d.bindPassword, 2), "default = true\n  comment = \"changed\""),
				ExpectError: regexp.MustCompile(`The\s+server\s+refused\s+bind_dn`),
			},
			{
				// It kept the right one: signing in, which binds with the
				// password PBS has, still works before the update sends the
				// right one again.
				PreConfig: func() {
					if err := testAccCheckSignIn(userID, d.userPassword, true)(nil); err != nil {
						t.Fatalf("after the refused password: %v", err)
					}
				},
				Config: fallback(testAccPasswordWO(d.bindPassword, 3), "default = true\n  comment = \"changed\""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "password_wo_version", "3"),
					isDefault(true),
					testAccCheckSignIn(userID, d.userPassword, true),
				),
			},
			{
				// PBS cannot delete capath: removing it replaces the realm,
				// which takes the bind password again.
				Config: config(fmt.Sprintf(`
  server1 = %q
  server2 = %q
  port    = 389
  %s
  default = true
  comment = "changed"`, testAccRefusingServer, d.server, testAccPasswordWO(d.bindPassword, 3))),
				ConfigPlanChecks: acc.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "capath"),
					realm(func(r pbsclient.DirectoryRealm) error {
						if r.CAPath != "" || r.Server2 != d.server || r.Comment != "changed" {
							return fmt.Errorf("realm = %+v", r)
						}
						return nil
					}),
					isDefault(true),
					testAccCheckSignIn(userID, d.userPassword, true),
				),
			},
			{
				// Without password_wo, PBS keeps the password it has, and the
				// update binds with it.
				Config: config(fmt.Sprintf(`
  server1 = %q
  server2 = %q
  port    = 389
  comment = "kept"`, testAccRefusingServer, d.server)),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "password_wo_version"),
					acc.TestCheckResourceAttr(resourceName, "default", "false"),
					realm(func(r pbsclient.DirectoryRealm) error {
						if r.BindDN != d.bindDN || r.Comment != "kept" {
							return fmt.Errorf("realm = %+v", r)
						}
						return nil
					}),
					isDefault(false),
					testAccCheckSignIn(userID, d.userPassword, true),
				),
			},
		},
	})
}

// An Active Directory realm without base_dn, against the stand's OpenLDAP:
// PBS takes the base DN from the root DSE's defaultNamingContext, and looks
// the user up by sAMAccountName. A base_dn set later is kept when it is
// removed again, as PBS cannot delete it.
func TestAccRealmAD(t *testing.T) {
	d := testAccLDAP(t)
	name := testAccRealmName()
	userID := d.user + "@" + name
	people := "ou=people," + d.baseDN
	const resourceName = "pbs_realm_ad.test"
	config := func(body string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_realm_ad" "test" {
  realm   = %q
  server1 = %q
  bind_dn = %q
  %s
  comment = "terraform-provider-pbs acceptance tests"
%s
}

resource "pbs_user" "user" {
  userid  = "%s@${pbs_realm_ad.test.realm}"
  comment = "terraform-provider-pbs acceptance tests"
}
`, name, d.server, d.bindDN, testAccPasswordWO(d.bindPassword, 1), body, d.user)
	}
	baseDN := func(want string) acc.TestCheckFunc {
		return acc.ComposeAggregateTestCheckFunc(
			acc.TestCheckResourceAttr(resourceName, "base_dn", want),
			testAccCheckDirectoryRealm(pbsclient.RealmTypeAD, name, func(r pbsclient.DirectoryRealm) error {
				if r.BaseDN != want || r.UserAttr != "" || r.BindDN != d.bindDN {
					return fmt.Errorf("realm = %+v", r)
				}
				return nil
			}),
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckDirectoryRealmsDestroyed(pbsclient.RealmTypeAD, name),
			testAccCheckAccessDestroyed(userID),
		),
		Steps: []acc.TestStep{
			{
				Config: config(""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", name),
					acc.TestCheckNoResourceAttr(resourceName, "password_wo"),
					baseDN(d.baseDN),
					testAccCheckSignIn(userID, d.userPassword, true),
				),
			},
			{
				Config: config(fmt.Sprintf(`  base_dn = %q`, people)),
				Check: acc.ComposeAggregateTestCheckFunc(
					baseDN(people),
					testAccCheckSignIn(userID, d.userPassword, true),
				),
			},
			{
				// Removing base_dn keeps the one PBS has, without an update.
				Config: config(""),
				ConfigPlanChecks: acc.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionNoop),
					},
				},
				Check: baseDN(people),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password_wo", "password_wo_version"},
			},
		},
	})
}

// PBS saves no realm it cannot connect with, and the provider says why: a
// server that refuses the connection; a server that answers, but lets no
// anonymous client read base_dn, as the stand's does; and an Active
// Directory realm without base_dn, which PBS asks the server's root DSE for
// first. No realm is left behind.
func TestAccRealmDirectoryCheckFails(t *testing.T) {
	d := testAccLDAP(t)
	refused, anonymous, adRefused := testAccRealmName(), testAccRealmName(), testAccRealmName()
	ldap := func(name, server string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_realm_ldap" "test" {
  realm     = %q
  server1   = %q
  base_dn   = %q
  user_attr = "uid"
}
`, name, server, d.baseDN)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckDirectoryRealmsDestroyed(pbsclient.RealmTypeLDAP, refused, anonymous),
			testAccCheckDirectoryRealmsDestroyed(pbsclient.RealmTypeAD, adRefused),
		),
		Steps: []acc.TestStep{
			{
				Config:      ldap(refused, testAccRefusingServer),
				ExpectError: regexp.MustCompile(`and\s+could\s+not\.\s+Check\s+server1`),
			},
			{
				Config:      ldap(anonymous, d.server),
				ExpectError: regexp.MustCompile(`could\s+not\s+read\s+base_dn`),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_realm_ad" "test" {
  realm   = %q
  server1 = %q
}
`, adRefused, testAccRefusingServer),
				ExpectError: regexp.MustCompile(`failed\s+to\s+determine\s+base_dn`),
			},
		},
	})
}

// From Terraform 1.12, the realm imports by identity too. An import reads no
// bind password, so the import plans to set password_wo_version, and with
// it to send the password again: an update, never a replacement.
func TestAccRealmLDAPImportByIdentity(t *testing.T) {
	d := testAccLDAP(t)
	name := testAccRealmName()
	const resourceName = "pbs_realm_ldap.test"
	config := providerConfig + fmt.Sprintf(`
resource "pbs_realm_ldap" "test" {
  realm     = %q
  server1   = %q
  base_dn   = %q
  user_attr = "uid"
  bind_dn   = %q
  %s
}
`, name, d.server, d.baseDN, d.bindDN, testAccPasswordWO(d.bindPassword, 1))
	update := acc.ImportPlanChecks{
		PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate)},
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckDirectoryRealmsDestroyed(pbsclient.RealmTypeLDAP, name),
		Steps: []acc.TestStep{
			{Config: config},
			{
				Config: config, ResourceName: resourceName, ImportState: true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity, ExpectNonEmptyPlan: true, ImportPlanChecks: update,
			},
			{
				Config: config, ResourceName: resourceName, ImportState: true,
				ImportStateKind: acc.ImportBlockWithID, ExpectNonEmptyPlan: true, ImportPlanChecks: update,
			},
		},
	})
}
