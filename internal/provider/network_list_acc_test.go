package provider

import (
	"fmt"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// The stand's veth NICs, one of them taken over with a comment, which PBS
// lists from the pending configuration; the takeover is never applied, and
// the NICs are reset when the test ends.
func TestAccNetworkInterfaceListResource(t *testing.T) {
	nics := testAccNetworkNICs(t)
	client := testAccNetworkAdmin(t)
	testAccRestoreNetwork(t, client, nil, nics)
	node := client.Node()
	identity := map[string]knownvalue.Check{"node": knownvalue.StringExact(node), "name": knownvalue.StringExact(nics[0])}
	other := map[string]knownvalue.Check{"node": knownvalue.StringExact(node), "name": knownvalue.StringExact(nics[1])}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_network_interface" "nic" {
  name     = %q
  type     = "eth"
  comments = "Listed by terraform query"
}
`, nics[0])

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		Steps: []acc.TestStep{
			{Config: config},
			{
				Query: true,
				Config: `
list "pbs_network_interface" "eth" {
  provider         = pbs
  include_resource = true

  config {
    type = "eth"
  }
}

list "pbs_network_interface" "bridges" {
  provider = pbs

  config {
    type = "bridge"
  }
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("pbs_network_interface.eth", identity),
					querycheck.ExpectIdentity("pbs_network_interface.eth", other),
					querycheck.ExpectNoIdentity("pbs_network_interface.bridges", identity),
					querycheck.ExpectResourceDisplayName("pbs_network_interface.eth", queryfilter.ByResourceIdentity(identity),
						knownvalue.StringExact(nics[0]+" (eth) — Listed by terraform query")),
					querycheck.ExpectResourceDisplayName("pbs_network_interface.eth", queryfilter.ByResourceIdentity(other),
						knownvalue.StringExact(nics[1]+" (eth)")),
					querycheck.ExpectResourceKnownValues("pbs_network_interface.eth", queryfilter.ByResourceIdentity(identity), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("type"), KnownValue: knownvalue.StringExact("eth")},
						{Path: tfjsonpath.New("comments"), KnownValue: knownvalue.StringExact("Listed by terraform query")},
						{Path: tfjsonpath.New("autostart"), KnownValue: knownvalue.Bool(true)},
						{Path: tfjsonpath.New("method"), KnownValue: knownvalue.StringExact("manual")},
					}),
					querycheck.ExpectResourceKnownValues("pbs_network_interface.eth", queryfilter.ByResourceIdentity(other), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("autostart"), KnownValue: knownvalue.Bool(false)},
						{Path: tfjsonpath.New("comments"), KnownValue: knownvalue.Null()},
					}),
				},
			},
			{
				Config:          config,
				ResourceName:    "pbs_network_interface.nic",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}
