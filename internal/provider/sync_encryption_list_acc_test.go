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

func TestAccSyncEncryptionKeyListResource(t *testing.T) {
	testAccSkipWithoutSyncEncryptionKeys(t)
	active, archived := "tfacc-list-"+testAccRandom(6), "tfacc-list-"+testAccRandom(6)
	activeIdentity := map[string]knownvalue.Check{"id": knownvalue.StringExact(active)}
	archivedIdentity := map[string]knownvalue.Check{"id": knownvalue.StringExact(archived)}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_sync_encryption_key" "active" {
  id = %q
}

resource "pbs_sync_encryption_key" "archived" {
  id       = %q
  archived = true
}
`, active, archived)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy:             testAccCheckEncryptionKeysDestroyed(active, archived),
		Steps: []acc.TestStep{
			{Config: config},
			{
				Query: true,
				Config: `
list "pbs_sync_encryption_key" "all" {
  provider         = pbs
  include_resource = true
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("pbs_sync_encryption_key.all", activeIdentity),
					querycheck.ExpectIdentity("pbs_sync_encryption_key.all", archivedIdentity),
					querycheck.ExpectResourceDisplayName("pbs_sync_encryption_key.all", queryfilter.ByResourceIdentity(archivedIdentity),
						knownvalue.StringExact(archived+" — archived")),
					querycheck.ExpectResourceDisplayName("pbs_sync_encryption_key.all", queryfilter.ByResourceIdentity(activeIdentity),
						knownvalue.StringExact(active)),
					querycheck.ExpectResourceKnownValues("pbs_sync_encryption_key.all", queryfilter.ByResourceIdentity(archivedIdentity), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("archived"), KnownValue: knownvalue.Bool(true)},
						{Path: tfjsonpath.New("key_wo_version"), KnownValue: knownvalue.Null()},
						{Path: tfjsonpath.New("fingerprint"), KnownValue: knownvalue.NotNull()},
					}),
				},
			},
			// A key's generated configuration has no key_wo and keeps the
			// key PBS has.
			{
				Config:          config,
				ResourceName:    "pbs_sync_encryption_key.archived",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}
