package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of the access layer: pbs_user, pbs_api_token, pbs_acl and
// their data sources, against the server scripts/bootstrap-test-pbs.sh boots.
// Every test works on users of its own, named tfacc-<random>@pbs, so that the
// tests can run in parallel and leave the stand's own users alone.

// testAccRandom returns n random lower-case hexadecimal digits. It is not
// terraform-plugin-testing's acctest, which would make the module depend on
// golang.org/x/crypto/ssh and its test dependencies.
func testAccRandom(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// testAccUserID returns a fresh user ID in the pbs realm.
func testAccUserID() string {
	return "tfacc-" + testAccRandom(8) + "@pbs"
}

// testAccPassword returns a fresh password PBS accepts.
func testAccPassword() string {
	return "pw-" + testAccRandom(20)
}

// writeOnlyVersions skips a test on Terraform before 1.11, which has no
// write-only attributes.
var writeOnlyVersions = []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)}

// testAccDatastore is the stand's datastore, to grant roles on.
func testAccDatastore(t *testing.T) string {
	t.Helper()
	if store := os.Getenv(envAccDatastore); store != "" {
		return store
	}
	return "tfacc"
}

// testAccCheckSignIn signs in as userID with password, and fails unless that
// works exactly when it should.
func testAccCheckSignIn(userID, password string, works bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		return testAccSignIn(func(o *pbsclient.Options) { o.Username, o.Password = userID, password }, userID, works)
	}
}

// testAccCheckTokenSignIn signs in with the token ID and secret a
// pbs_api_token resource holds in state.
func testAccCheckTokenSignIn(name string, works bool) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s not found in state", name)
		}
		tokenID, secret := rs.Primary.Attributes["tokenid"], rs.Primary.Attributes["value"]
		if secret == "" {
			return fmt.Errorf("%s has no value in state", name)
		}
		return testAccSignIn(func(o *pbsclient.Options) { o.APIToken = tokenID + ":" + secret }, tokenID, works)
	}
}

// testAccCheckTokenSecret signs in with a token ID and a secret captured by
// an earlier step.
func testAccCheckTokenSecret(tokenID string, secret *string, works bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		return testAccSignIn(func(o *pbsclient.Options) { o.APIToken = tokenID + ":" + *secret }, tokenID, works)
	}
}

func testAccSignIn(credentials func(*pbsclient.Options), who string, works bool) error {
	client, err := testAccClientAs(credentials)
	if err != nil {
		return err
	}
	_, err = client.ServerVersion(context.Background())
	switch {
	case works && err != nil:
		return fmt.Errorf("signing in as %s failed: %w", who, err)
	case !works && err == nil:
		return fmt.Errorf("signing in as %s worked, but should not", who)
	case !works && !pbsclient.IsUnauthorized(err):
		return fmt.Errorf("signing in as %s failed, but not for its credentials: %w", who, err)
	}
	return nil
}

// testAccWaitForACLCache waits until PBS applies ACL changes. Before 4.2.6,
// PBS caches privileges for up to 5 seconds and does not drop them when
// acl.cfg changes (proxmox-backup commit 0b24f4da), so privileges read right
// after a grant may not include it yet. A stand whose version is unknown is
// waited for too.
func testAccWaitForACLCache() {
	var major, minor, release int
	if n, _ := fmt.Sscanf(os.Getenv(envAccVersion), "%d.%d.%d", &major, &minor, &release); n == 3 &&
		(pbsclient.Version{Version: fmt.Sprintf("%d.%d", major, minor), Release: strconv.Itoa(release)}).AtLeast(4, 2, 6) {
		return
	}
	time.Sleep(6 * time.Second)
}

// testAccMustGrant grants a role outside Terraform.
func testAccMustGrant(t *testing.T, path, authID, role string) {
	t.Helper()
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateACL(context.Background(), pbsclient.ACLChange{Path: path, AuthID: authID, Role: role}); err != nil {
		t.Fatal(err)
	}
}

// testAccCheckAccessDestroyed checks that the users are gone, and every ACL
// entry of the users and of their tokens with them.
func testAccCheckAccessDestroyed(userIDs ...string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		ctx := context.Background()
		for _, userID := range userIDs {
			if _, err := client.GetUser(ctx, userID); err == nil {
				return fmt.Errorf("user %s still exists", userID)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		entries, _, err := client.ListACL(ctx, "", false)
		if err != nil {
			return err
		}
		for _, e := range entries {
			owner := e.UGID
			if user, _, ok := pbsclient.SplitTokenID(e.UGID); ok {
				owner = user
			}
			for _, userID := range userIDs {
				if owner == userID {
					return fmt.Errorf("ACL entry %s for %s on %s is left over", e.RoleID, e.UGID, e.Path)
				}
			}
		}
		return nil
	}
}

// captureAttr stores an attribute's value for comparison in a later step.
func captureAttr(resourceName, attribute string, into *string) acc.TestCheckFunc {
	return func(state *terraform.State) error {
		rs, ok := state.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		*into = rs.Primary.Attributes[attribute]
		return nil
	}
}

func TestAccUserResource(t *testing.T) {
	userID, password := testAccUserID(), testAccPassword()
	const name = "pbs_user.test"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckAccessDestroyed(userID),
		Steps: []acc.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_user" "test" {
  userid              = %q
  comment             = "terraform-provider-pbs acceptance tests"
  firstname           = "Terraform"
  email               = "tfacc@example.com"
  password_wo         = %q
  password_wo_version = 1
}
`, userID, password),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(name, "id", userID),
					acc.TestCheckResourceAttr(name, "firstname", "Terraform"),
					acc.TestCheckResourceAttr(name, "enable", "true"),
					acc.TestCheckResourceAttr(name, "expire", "0"),
					acc.TestCheckNoResourceAttr(name, "password_wo"),
					acc.TestCheckResourceAttr(name, "password_wo_version", "1"),
					// PBS takes the password at creation, from an API token too.
					testAccCheckSignIn(userID, password, true),
				),
			},
			{
				// An entry granted outside Terraform: destroying the user must
				// remove it, or it would apply again to a user created later
				// under the same ID.
				PreConfig: func() { testAccMustGrant(t, "/", userID, "Audit") },
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_user" "test" {
  userid              = %q
  comment             = "changed"
  enable              = false
  expire              = 4102444800
  password_wo         = %q
  password_wo_version = 1
}
`, userID, password),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(name, "comment", "changed"),
					acc.TestCheckNoResourceAttr(name, "firstname"),
					acc.TestCheckNoResourceAttr(name, "email"),
					acc.TestCheckResourceAttr(name, "enable", "false"),
					acc.TestCheckResourceAttr(name, "expire", "4102444800"),
					testAccCheckSignIn(userID, password, false),
				),
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password_wo", "password_wo_version"},
			},
		},
	})
}

// Changing a password needs a provider that signs in with a password: the
// stand's non-root Admin, which confirms with its own password, and the
// stand's admin, root@pam or admin@pbs.
func TestAccUserResourcePasswordChange(t *testing.T) {
	for _, signIn := range []struct{ name, usernameEnv, passwordEnv string }{
		{"admin", envAccAdminUsername, envAccAdminPassword},
		{"non-root admin", envAccUsername, envAccPassword},
	} {
		t.Run(signIn.name, func(t *testing.T) {
			username, providerPassword := os.Getenv(signIn.usernameEnv), os.Getenv(signIn.passwordEnv)
			if os.Getenv("TF_ACC") != "" && (username == "" || providerPassword == "") {
				t.Skipf("%s and %s are not set", signIn.usernameEnv, signIn.passwordEnv)
			}
			userID, first, second := testAccUserID(), testAccPassword(), testAccPassword()
			config := func(password string, version int) string {
				return fmt.Sprintf(`
provider "pbs" {
  username = %q
  password = %q
}

resource "pbs_user" "test" {
  userid              = %q
  password_wo         = %q
  password_wo_version = %d
}
`, username, providerPassword, userID, password, version)
			}

			acc.Test(t, acc.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				TerraformVersionChecks:   writeOnlyVersions,
				CheckDestroy:             testAccCheckAccessDestroyed(userID),
				Steps: []acc.TestStep{
					{
						Config: config(first, 1),
						Check:  testAccCheckSignIn(userID, first, true),
					},
					{
						Config: config(second, 2),
						Check: acc.ComposeAggregateTestCheckFunc(
							acc.TestCheckResourceAttr("pbs_user.test", "password_wo_version", "2"),
							testAccCheckSignIn(userID, second, true),
							testAccCheckSignIn(userID, first, false),
						),
					},
				},
			})
		})
	}
}

// With an API token, PBS refuses to change a password, so the plan does.
func TestAccUserResourcePasswordChangeWithToken(t *testing.T) {
	userID := testAccUserID()
	config := func(version int) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_user" "test" {
  userid              = %q
  password_wo         = "password-%d"
  password_wo_version = %d
}
`, userID, version, version)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckAccessDestroyed(userID),
		Steps: []acc.TestStep{
			{Config: config(1)},
			{
				Config:      config(2),
				ExpectError: regexp.MustCompile(`Cannot change the password with an API token`),
			},
		},
	})
}

func TestAccAPITokenResource(t *testing.T) {
	userID := testAccUserID()
	tokenID := userID + "!ci"
	const name = "pbs_api_token.test"
	config := func(token string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_user" "test" {
  userid = %q
}

resource "pbs_api_token" "test" {
  userid     = pbs_user.test.userid
  token_name = "ci"
%s}
`, userID, token)
	}
	var first string

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckAccessDestroyed(userID),
		Steps: []acc.TestStep{
			{
				Config: config(`  comment    = "terraform-provider-pbs acceptance tests"` + "\n"),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(name, "id", tokenID),
					acc.TestCheckResourceAttr(name, "tokenid", tokenID),
					acc.TestCheckResourceAttrSet(name, "value"),
					acc.TestCheckResourceAttr(name, "enable", "true"),
					captureAttr(name, "value", &first),
					testAccCheckTokenSignIn(name, true),
				),
			},
			{
				// A new secret; the old one stops working at once.
				Config: config(`  comment    = "terraform-provider-pbs acceptance tests"` + "\n" + `  regenerate = "1"` + "\n"),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttrWith(name, "value", func(value string) error {
						if value == first {
							return fmt.Errorf("value did not change")
						}
						return nil
					}),
					testAccCheckTokenSignIn(name, true),
					testAccCheckTokenSecret(tokenID, &first, false),
				),
			},
			{
				Config: config(`  enable     = false` + "\n" + `  regenerate = "1"` + "\n"),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(name, "comment"),
					acc.TestCheckResourceAttr(name, "enable", "false"),
					testAccCheckTokenSignIn(name, false),
				),
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"value", "regenerate"},
			},
		},
	})
}

// The main scenario: a user and an API token for a Proxmox VE cluster, with
// the role to back up to a datastore, and what PBS makes of it.
func TestAccACLResource(t *testing.T) {
	userID := testAccUserID()
	tokenID := userID + "!cluster1"
	store := testAccDatastore(t)
	path := "/datastore/" + store
	config := func(propagate string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_user" "pve" {
  userid  = %q
  comment = "PVE cluster"
}

resource "pbs_api_token" "pve" {
  userid     = pbs_user.pve.userid
  token_name = "cluster1"
}

resource "pbs_acl" "user" {
  path    = %q
  auth_id = pbs_user.pve.userid
  role    = "DatastoreBackup"
}

resource "pbs_acl" "token" {
  path      = %q
  auth_id   = pbs_api_token.pve.tokenid
  role      = "DatastoreBackup"
  propagate = %s
}

data "pbs_permissions" "token" {
  auth_id    = pbs_api_token.pve.tokenid
  path       = %q
  depends_on = [pbs_acl.user, pbs_acl.token]
}
`, userID, path, path, propagate, path)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckAccessDestroyed(userID),
		Steps: []acc.TestStep{
			{
				Config: config("true"),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_acl.token", "id", path+"|"+tokenID+"|DatastoreBackup"),
					acc.TestCheckResourceAttr("pbs_acl.token", "propagate", "true"),
				),
			},
			{
				// The same configuration again, which reads the data source
				// anew once PBS applies the new entries.
				PreConfig: testAccWaitForACLCache,
				Config:    config("true"),
				Check:     acc.TestCheckResourceAttrSet("data.pbs_permissions.token", "permissions."+path+".Datastore.Backup"),
			},
			{
				Config: config("false"),
				Check:  acc.TestCheckResourceAttr("pbs_acl.token", "propagate", "false"),
			},
			{
				ResourceName:      "pbs_acl.token",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAccessDataSources(t *testing.T) {
	userID := testAccUserID()
	tokenID := userID + "!reader"
	path := "/datastore/" + testAccDatastore(t)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckAccessDestroyed(userID),
		Steps: []acc.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_user" "test" {
  userid    = %q
  comment   = "terraform-provider-pbs acceptance tests"
  lastname  = "Reader"
}

resource "pbs_api_token" "test" {
  userid     = pbs_user.test.userid
  token_name = "reader"
}

resource "pbs_acl" "test" {
  path    = %q
  auth_id = pbs_api_token.test.tokenid
  role    = "DatastoreReader"
}

data "pbs_user" "test" {
  userid = pbs_user.test.userid
}

data "pbs_users" "pbs" {
  realm      = "pbs"
  depends_on = [pbs_user.test]
}

data "pbs_api_tokens" "test" {
  userid     = pbs_user.test.userid
  depends_on = [pbs_api_token.test]
}

data "pbs_acl" "test" {
  path       = pbs_acl.test.path
  exact      = true
  auth_id    = pbs_api_token.test.tokenid
  depends_on = [pbs_acl.test]
}

data "pbs_roles" "all" {}
`, userID, path),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("data.pbs_user.test", "comment", "terraform-provider-pbs acceptance tests"),
					acc.TestCheckResourceAttr("data.pbs_user.test", "lastname", "Reader"),
					acc.TestCheckResourceAttr("data.pbs_user.test", "enable", "true"),
					acc.TestCheckTypeSetElemNestedAttrs("data.pbs_users.pbs", "users.*", map[string]string{"userid": userID}),
					acc.TestCheckResourceAttr("data.pbs_api_tokens.test", "tokens.#", "1"),
					acc.TestCheckResourceAttr("data.pbs_api_tokens.test", "tokens.0.tokenid", tokenID),
					acc.TestCheckResourceAttr("data.pbs_api_tokens.test", "tokens.0.token_name", "reader"),
					acc.TestCheckResourceAttr("data.pbs_acl.test", "entries.#", "1"),
					acc.TestCheckResourceAttr("data.pbs_acl.test", "entries.0.role", "DatastoreReader"),
					acc.TestCheckResourceAttr("data.pbs_acl.test", "entries.0.propagate", "true"),
					acc.TestCheckTypeSetElemNestedAttrs("data.pbs_roles.all", "roles.*", map[string]string{"roleid": "DatastoreBackup"}),
					acc.TestCheckTypeSetElemAttr("data.pbs_roles.all", "roles.*.privileges.*", "Datastore.Backup"),
				),
			},
		},
	})
}

// From Terraform 1.12, every access resource imports by its identity too.
func TestAccAccessResourcesImportByIdentity(t *testing.T) {
	userID := testAccUserID()
	path := "/datastore/" + testAccDatastore(t)
	config := providerConfig + fmt.Sprintf(`
resource "pbs_user" "test" {
  userid = %q
}

resource "pbs_api_token" "test" {
  userid     = pbs_user.test.userid
  token_name = "identity"
}

resource "pbs_acl" "test" {
  path    = %q
  auth_id = pbs_api_token.test.tokenid
  role    = "DatastoreAudit"
}
`, userID, path)

	steps := []acc.TestStep{{Config: config}}
	for _, name := range []string{"pbs_user.test", "pbs_api_token.test", "pbs_acl.test"} {
		steps = append(steps,
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			// Resource identity, and import blocks that use one, arrived in
			// Terraform 1.12.
			tfversion.SkipBelow(tfversion.Version1_12_0),
		},
		CheckDestroy: testAccCheckAccessDestroyed(userID),
		Steps:        steps,
	})
}
