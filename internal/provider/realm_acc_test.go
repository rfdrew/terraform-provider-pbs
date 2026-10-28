package provider

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_realm_openid and pbs_realms. PBS contacts nothing
// when it saves an OpenID realm, so the issuer is on a host that does not
// exist: that it is accepted is part of what is tested. Nobody signs in
// through the realms.

// testAccIssuerURL is an issuer in the form Authentik gives one, on a host
// that does not exist.
const testAccIssuerURL = "https://authentik.invalid/application/o/pbs/"

// testAccRealmName returns a fresh realm name.
func testAccRealmName() string {
	return "tfacc-" + testAccRandom(8)
}

// testAccCheckOpenIDRealmsDestroyed checks that the realms are gone.
func testAccCheckOpenIDRealmsDestroyed(names ...string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		for _, name := range names {
			if _, _, err := client.GetOpenIDRealm(context.Background(), name); err == nil {
				return fmt.Errorf("realm %s still exists", name)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		return nil
	}
}

// testAccCheckOpenIDRealm checks a realm as PBS reports it, client key
// included.
func testAccCheckOpenIDRealm(name string, check func(pbsclient.OpenIDRealm) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		realm, _, err := client.GetOpenIDRealm(context.Background(), name)
		if err != nil {
			return err
		}
		return check(realm)
	}
}

// testAccRestoreDefaultRealm gives the default flag back, when the test is
// done, to the realm that has it now, as setting default on a realm takes
// it away.
func testAccRestoreDefaultRealm(t *testing.T) {
	t.Helper()
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	realms, err := client.ListRealms(context.Background())
	if err != nil {
		t.Fatalf("listing the stand's realms: %v", err)
	}
	for _, r := range realms {
		if r.Default == nil || !*r.Default {
			continue
		}
		p := pbsclient.Path("config", "access", r.Type)
		if r.Type != pbsclient.RealmTypePAM && r.Type != pbsclient.RealmTypePBS {
			p = pbsclient.Path("config", "access", r.Type, r.Realm)
		}
		t.Cleanup(func() {
			if _, err := client.Put(context.Background(), p, url.Values{"default": {"1"}}, nil); err != nil {
				t.Errorf("restoring the default realm %s: %v", r.Realm, err)
			}
		})
	}
}

// The realm with a client key in state, then a write-only one, then
// neither and a key in state again. The issuer does not exist; PBS saves
// the realm all the same. audiences, of PBS 4.2.1, only where the stand has
// it.
func TestAccRealmOpenID(t *testing.T) {
	name := testAccRealmName()
	const resourceName = "pbs_realm_openid.test"
	audiences := ""
	if testAccVersionAtLeast(4, 2, 1) {
		audiences = `audiences = ["pbs-extra"]`
	}
	config := func(body string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_realm_openid" "test" {
  realm          = %q
  issuer_url     = %q
  client_id      = "pbs"
  username_claim = "preferred_username"
%s
}

data "pbs_realms" "all" {
  depends_on = [pbs_realm_openid.test]
}
`, name, testAccIssuerURL, body)
	}
	key := func(want string) acc.TestCheckFunc {
		return testAccCheckOpenIDRealm(name, func(r pbsclient.OpenIDRealm) error {
			if r.ClientKey != want {
				return fmt.Errorf("client key = %q, want %q", r.ClientKey, want)
			}
			return nil
		})
	}
	isDefault := func(want bool) acc.TestCheckFunc {
		return testAccCheckOpenIDRealm(name, func(r pbsclient.OpenIDRealm) error {
			if got := r.Default != nil && *r.Default; got != want {
				return fmt.Errorf("default = %t, want %t", got, want)
			}
			return nil
		})
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); testAccRestoreDefaultRealm(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckOpenIDRealmsDestroyed(name),
		Steps: []acc.TestStep{
			{
				Config: config(`
  client_key = "first-secret"
  scopes     = ["openid", "email", "profile"]
  acr_values = ["urn:example:loa:2", "urn:example:loa:1"]
  prompt     = "login"
  autocreate = true
  comment    = "terraform-provider-pbs acceptance tests"
  ` + audiences),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", name),
					acc.TestCheckResourceAttr(resourceName, "client_key", "first-secret"),
					acc.TestCheckResourceAttr(resourceName, "scopes.#", "3"),
					acc.TestCheckResourceAttr(resourceName, "acr_values.0", "urn:example:loa:2"),
					acc.TestCheckResourceAttr(resourceName, "default", "false"),
					key("first-secret"),
					testAccCheckOpenIDRealm(name, func(r pbsclient.OpenIDRealm) error {
						var scopes []string
						if r.Scopes != nil {
							scopes = pbsclient.SplitList(*r.Scopes)
						}
						slices.Sort(scopes)
						if !slices.Equal(scopes, []string{"email", "openid", "profile"}) || r.UsernameClaim != "preferred_username" ||
							r.ACRValues != "urn:example:loa:2 urn:example:loa:1" || r.Autocreate == nil || !*r.Autocreate {
							return fmt.Errorf("realm = %+v", r)
						}
						if audiences != "" && r.Audiences != "pbs-extra" {
							return fmt.Errorf("audiences = %q", r.Audiences)
						}
						return nil
					}),
					testAccCheckListed("data.pbs_realms.all", "realms", "realm", name, "pam", "pbs"),
				),
			},
			{
				// A write-only key, which stays out of state, and the default
				// flag.
				Config: config(`
  client_key_wo         = "second-secret"
  client_key_wo_version = 1
  default               = true
  comment               = "terraform-provider-pbs acceptance tests"`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "client_key"),
					acc.TestCheckNoResourceAttr(resourceName, "client_key_wo"),
					acc.TestCheckResourceAttr(resourceName, "client_key_wo_version", "1"),
					acc.TestCheckResourceAttr(resourceName, "scopes.#", "2"),
					acc.TestCheckNoResourceAttr(resourceName, "acr_values"),
					acc.TestCheckResourceAttr(resourceName, "default", "true"),
					key("second-secret"),
					isDefault(true),
				),
			},
			{
				// PBS clears the flag on an update that leaves it out; the
				// provider sends it again.
				Config: config(`
  client_key_wo         = "second-secret"
  client_key_wo_version = 1
  default               = true
  comment               = "changed"`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "comment", "changed"),
					isDefault(true),
					key("second-secret"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"client_key", "client_key_wo", "client_key_wo_version"},
			},
			{
				// Without client_key_wo, PBS keeps the key.
				Config: config(""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "client_key_wo_version"),
					acc.TestCheckResourceAttr(resourceName, "default", "false"),
					key("second-secret"),
					isDefault(false),
				),
			},
			{
				Config: config(`  client_key = "third-secret"`),
				Check:  key("third-secret"),
			},
			{
				// Removing client_key deletes the key from PBS.
				Config: config(""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "client_key"),
					key(""),
				),
			},
		},
	})
}

// From Terraform 1.12, the realm imports by identity too. An import block
// plans no change only when the configuration matches what an import
// reads, and an import reads no client key, so the realm has none: a public
// client.
func TestAccRealmOpenIDImportByIdentity(t *testing.T) {
	name := testAccRealmName()
	config := providerConfig + fmt.Sprintf(`
resource "pbs_realm_openid" "test" {
  realm      = %q
  issuer_url = %q
  client_id  = "pbs-public"
  scopes     = ["openid", "email"]
}
`, name, testAccIssuerURL)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckOpenIDRealmsDestroyed(name),
		Steps: []acc.TestStep{
			{Config: config},
			{Config: config, ResourceName: "pbs_realm_openid.test", ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			{Config: config, ResourceName: "pbs_realm_openid.test", ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		},
	})
}
