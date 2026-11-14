package provider

import (
	"fmt"
	"regexp"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The entries and standard repositories every stand has: Debian's sources
// and the enterprise repository, which the configuration keeps enabled —
// as every stand has it — to import it with a generated configuration.
func TestAccAPTListResources(t *testing.T) {
	path, index := testAccAPTEntryOf(t, pbsclient.APTHandleEnterprise)
	node := knownvalue.StringExact("localhost")
	entry := map[string]knownvalue.Check{"node": node, "file_path": knownvalue.StringExact(path), "index": knownvalue.Int64Exact(index)}
	enterprise := map[string]knownvalue.Check{"node": node, "handle": knownvalue.StringExact(pbsclient.APTHandleEnterprise)}
	test := map[string]knownvalue.Check{"node": node, "handle": knownvalue.StringExact(pbsclient.APTHandleTest)}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_apt_repository" "enterprise" {
  file_path = %q
  index     = %d
  enabled   = true
}
`, path, index)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); testAccRestoreAPTSources(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		Steps: []acc.TestStep{
			{Config: config},
			{
				Query: true,
				Config: `
list "pbs_apt_repository" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_apt_standard_repository" "all" {
  provider         = pbs
  include_resource = true
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					// debian.sources has an entry or two, besides.
					querycheck.ExpectLengthAtLeast("pbs_apt_repository.all", 2),
					querycheck.ExpectIdentity("pbs_apt_repository.all", entry),
					querycheck.ExpectResourceDisplayName("pbs_apt_repository.all", queryfilter.ByResourceIdentity(entry),
						knownvalue.StringRegexp(regexp.MustCompile("^"+regexp.QuoteMeta(fmt.Sprintf("%s:%d — deb https://enterprise.proxmox.com/debian/pbs", path, index))+`/? trixie pbs-enterprise$`))),
					querycheck.ExpectResourceKnownValues("pbs_apt_repository.all", queryfilter.ByResourceIdentity(entry), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("enabled"), KnownValue: knownvalue.Bool(true)},
						{Path: tfjsonpath.New("components"), KnownValue: knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("pbs-enterprise")})},
					}),
					querycheck.ExpectIdentity("pbs_apt_standard_repository.all", enterprise),
					querycheck.ExpectNoIdentity("pbs_apt_standard_repository.all", test),
					querycheck.ExpectResourceDisplayName("pbs_apt_standard_repository.all", queryfilter.ByResourceIdentity(enterprise),
						knownvalue.StringExact("enterprise — Enterprise, enabled")),
					querycheck.ExpectResourceKnownValues("pbs_apt_standard_repository.all", queryfilter.ByResourceIdentity(enterprise), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("file_path"), KnownValue: knownvalue.StringExact(path)},
						{Path: tfjsonpath.New("index"), KnownValue: knownvalue.Int64Exact(index)},
					}),
				},
			},
			// The identity's index is a number, and imports as one.
			{
				Config:          config,
				ResourceName:    "pbs_apt_repository.enterprise",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}
