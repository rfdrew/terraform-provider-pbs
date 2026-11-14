package provider

import (
	"fmt"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// An account at Pebble, which returns its contacts: the generated
// configuration of the account plans no change.
func TestAccACMEAccountListResource(t *testing.T) {
	directory := testAccACMEDirectory(t)
	name := testAccACMEName()
	identity := map[string]knownvalue.Check{"name": knownvalue.StringExact(name)}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_acme_account" "test" {
  name      = %q
  contact   = "tfacc@pbs.test"
  directory = %q
  tos_url   = %q
}
`, name, directory, pebbleToS)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy:             testAccCheckACMEDestroyed([]string{name}, nil),
		Steps: []acc.TestStep{
			{Config: config},
			{
				Query: true,
				Config: `
list "pbs_acme_account" "all" {
  provider         = pbs
  include_resource = true
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("pbs_acme_account.all", identity),
					querycheck.ExpectResourceDisplayName("pbs_acme_account.all", queryfilter.ByResourceIdentity(identity), knownvalue.StringExact(name)),
					querycheck.ExpectResourceKnownValues("pbs_acme_account.all", queryfilter.ByResourceIdentity(identity), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("contact"), KnownValue: knownvalue.StringExact("tfacc@pbs.test")},
						{Path: tfjsonpath.New("directory"), KnownValue: knownvalue.StringExact(directory)},
						{Path: tfjsonpath.New("tos_url"), KnownValue: knownvalue.StringExact(pebbleToS)},
						{Path: tfjsonpath.New("status"), KnownValue: knownvalue.StringExact("valid")},
					}),
				},
			},
			{
				Config:          config,
				ResourceName:    "pbs_acme_account.test",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}

// A DNS plugin, whose settings the results leave out, and the built-in
// standalone plugin, which every PBS has and whose generated configuration
// plans no change. Creating a plugin needs no CA.
func TestAccACMEPluginListResource(t *testing.T) {
	id := testAccACMEName()
	identity := map[string]knownvalue.Check{"id": knownvalue.StringExact(id)}
	standalone := map[string]knownvalue.Check{"id": knownvalue.StringExact(pbsclient.StandaloneACMEPlugin)}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_acme_plugin" "cloudflare" {
  id   = %q
  api  = "cf"
  data = { CF_Token = "not-a-real-token" }
}

import {
  to = pbs_acme_plugin.standalone
  id = "standalone"
}

resource "pbs_acme_plugin" "standalone" {
  id = "standalone"
}
`, id)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy:             testAccCheckACMEDestroyed(nil, []string{id}),
		Steps: []acc.TestStep{
			{Config: config},
			{
				Query: true,
				Config: `
list "pbs_acme_plugin" "all" {
  provider         = pbs
  include_resource = true
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("pbs_acme_plugin.all", identity),
					querycheck.ExpectIdentity("pbs_acme_plugin.all", standalone),
					querycheck.ExpectResourceDisplayName("pbs_acme_plugin.all", queryfilter.ByResourceIdentity(identity),
						knownvalue.StringExact(id+" — DNS plugin, API cf")),
					querycheck.ExpectResourceDisplayName("pbs_acme_plugin.all", queryfilter.ByResourceIdentity(standalone),
						knownvalue.StringExact("standalone — built-in HTTP-01 plugin")),
					querycheck.ExpectResourceKnownValues("pbs_acme_plugin.all", queryfilter.ByResourceIdentity(identity), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("type"), KnownValue: knownvalue.StringExact(pbsclient.DNSACMEPluginType)},
						{Path: tfjsonpath.New("api"), KnownValue: knownvalue.StringExact("cf")},
						// Sensitive, so null in the results.
						{Path: tfjsonpath.New("data"), KnownValue: knownvalue.Null()},
					}),
				},
			},
			{
				Config:          config,
				ResourceName:    "pbs_acme_plugin.standalone",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}
