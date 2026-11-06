package provider

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_acme_directories, pbs_acme_challenge_schema and
// pbs_acme_accounts. The directories are built into PBS and the challenge
// schema comes with its acme.sh plugins, so those two need no CA; the
// accounts are registered at Pebble, as in acme_acc_test.go.

// testAccCheckNotListed checks that no element of a list attribute has the
// value given as its key attribute.
func testAccCheckNotListed(resourceName, list, key, value string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("%s is not in state", resourceName)
		}
		attributes := rs.Primary.Attributes
		n, _ := strconv.Atoi(attributes[list+".#"])
		for i := range n {
			if attributes[fmt.Sprintf("%s.%d.%s", list, i, key)] == value {
				return fmt.Errorf("%s lists %s %q", resourceName, key, value)
			}
		}
		return nil
	}
}

// PBS knows Let's Encrypt's two directories, production first.
func TestAccACMEDirectories(t *testing.T) {
	const dataName = "data.pbs_acme_directories.all"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{{
			Config: providerConfig + `data "pbs_acme_directories" "all" {}` + "\n",
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttr(dataName, "directories.#", "2"),
				acc.TestCheckResourceAttr(dataName, "directories.0.name", "Let's Encrypt V2"),
				acc.TestCheckResourceAttr(dataName, "directories.0.url", pbsclient.DefaultACMEDirectory),
				acc.TestCheckResourceAttr(dataName, "directories.1.name", "Let's Encrypt V2 Staging"),
				acc.TestCheckResourceAttr(dataName, "directories.1.url", pbsclient.ACMEStagingDirectory),
			),
		}},
	})
}

// testAccACMEAPITypePattern matches the type attribute of an API of
// pbs_acme_challenge_schema, capturing the API's name.
var testAccACMEAPITypePattern = regexp.MustCompile(`^apis\.([^.]+)\.type$`)

// testAccDecimalPattern matches a number as JSON writes an integer.
var testAccDecimalPattern = regexp.MustCompile(`^[0-9]+$`)

// The challenge schema the stand's plugins package ships: Cloudflare with
// its documented fields, every API a DNS one with a name, and no standalone
// plugin, which is no DNS API. HETZNER_TTL of Hetzner Cloud, where the
// package has the API, has a JSON number as its default, which reads as
// text, and is marked optional with 1, which reads as true.
func TestAccACMEChallengeSchema(t *testing.T) {
	const dataName = "data.pbs_acme_challenge_schema.all"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{{
			Config: providerConfig + `data "pbs_acme_challenge_schema" "all" {}` + "\n",
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttr(dataName, "apis.cf.name", "Cloudflare Managed DNS"),
				acc.TestCheckResourceAttr(dataName, "apis.cf.type", "dns"),
				acc.TestCheckResourceAttr(dataName, "apis.cf.fields.CF_Token.type", "string"),
				acc.TestCheckResourceAttrSet(dataName, "apis.cf.fields.CF_Token.description"),
				// Cloudflare takes a token or a global key, but the schema
				// marks every field required.
				acc.TestCheckResourceAttr(dataName, "apis.cf.fields.CF_Token.optional", "false"),
				acc.TestCheckNoResourceAttr(dataName, "apis.standalone.type"),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources[dataName]
					if !ok {
						return fmt.Errorf("%s is not in state", dataName)
					}
					attributes := rs.Primary.Attributes
					apis := 0
					for key, value := range attributes {
						m := testAccACMEAPITypePattern.FindStringSubmatch(key)
						if m == nil {
							continue
						}
						apis++
						if value != "dns" || attributes["apis."+m[1]+".name"] == "" {
							return fmt.Errorf("API %s has the type %q and the name %q", m[1], value, attributes["apis."+m[1]+".name"])
						}
					}
					if apis < 2 {
						return fmt.Errorf("%s lists %d APIs", dataName, apis)
					}
					const ttl = "apis.hetznercloud.fields.HETZNER_TTL."
					if typ, ok := attributes[ttl+"type"]; ok &&
						(typ != "integer" || !testAccDecimalPattern.MatchString(attributes[ttl+"default"]) || attributes[ttl+"optional"] != "true") {
						return fmt.Errorf("HETZNER_TTL has the type %q, the default %q and optional %q",
							typ, attributes[ttl+"default"], attributes[ttl+"optional"])
					}
					return nil
				},
			),
		}},
	})
}

// Two accounts registered at Pebble are listed, sorted by name, as PBS
// recorded them; the one deactivated, by removing its resource, is listed no
// more once the data source reads again.
func TestAccACMEAccounts(t *testing.T) {
	directory := testAccACMEDirectory(t)
	first, second := testAccACMEName(), testAccACMEName()
	const dataName = "data.pbs_acme_accounts.all"
	account := func(resource, name string) string {
		return fmt.Sprintf(`
resource "pbs_acme_account" %q {
  name      = %q
  contact   = "tfacc@pbs.test"
  directory = %q
  tos_url   = %q
}
`, resource, name, directory, pebbleToS)
	}
	both := providerConfig + account("first", first) + account("second", second) + `
data "pbs_acme_accounts" "all" {
  depends_on = [pbs_acme_account.first, pbs_acme_account.second]
}
`
	firstOnly := providerConfig + account("first", first) + `
data "pbs_acme_accounts" "all" {
  depends_on = [pbs_acme_account.first]
}
`
	// listed checks the account's element against the resource, whose
	// location the CA chose.
	listed := func(resource, name string) acc.TestCheckFunc {
		return func(s *terraform.State) error {
			rs, ok := s.RootModule().Resources["pbs_acme_account."+resource]
			if !ok {
				return fmt.Errorf("pbs_acme_account.%s is not in state", resource)
			}
			location := rs.Primary.Attributes["location"]
			if location == "" {
				return fmt.Errorf("pbs_acme_account.%s has no location", resource)
			}
			return testAccCheckListElement(dataName, "accounts", "name", name, map[string]string{
				"directory": directory,
				"location":  location,
				"status":    "valid",
				"contact":   "tfacc@pbs.test",
				"tos_url":   pebbleToS,
			})(s)
		}
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckACMEDestroyed([]string{first, second}, nil),
		Steps: []acc.TestStep{
			{
				Config: both,
				Check: acc.ComposeAggregateTestCheckFunc(
					listed("first", first),
					listed("second", second),
					testAccCheckSortedBy(dataName, "accounts", "name"),
				),
			},
			{
				// The data source reads while Terraform plans, before the
				// second account is deactivated.
				Config: firstOnly,
				Check:  listed("first", first),
			},
			{
				RefreshState: true,
				Check: acc.ComposeAggregateTestCheckFunc(
					listed("first", first),
					testAccCheckNotListed(dataName, "accounts", "name", second),
				),
			},
		},
	})
}
