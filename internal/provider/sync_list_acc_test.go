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

// The list resources of remotes and sync jobs, against a remote that points
// the stand at itself, as in sync_acc_test.go, and a push and a pull job
// between the stand's datastore and itself, which nothing runs. Other tests
// add remotes and jobs meanwhile, so the checks look for the test's own.
func TestAccRemoteAndSyncJobListResources(t *testing.T) {
	remote := "tfacc-" + testAccRandom(8)
	store := testAccDatastore(t)
	pushID, pullID := "tfacc-push-"+testAccRandom(6), "tfacc-pull-"+testAccRandom(6)
	self := map[string]knownvalue.Check{"name": knownvalue.StringExact(remote)}
	push := map[string]knownvalue.Check{"id": knownvalue.StringExact(pushID)}
	pull := map[string]knownvalue.Check{"id": knownvalue.StringExact(pullID)}
	config := providerConfig + testAccSelfRemote(t, remote, "") + fmt.Sprintf(`
resource "pbs_sync_job" "push" {
  id             = %[1]q
  sync_direction = "push"
  store          = %[3]q
  remote         = pbs_remote.self.name
  remote_store   = %[3]q
  remote_ns      = "pushed"
  rate_out       = "1.5 GB"
  comment        = "listed by terraform query"
}

resource "pbs_sync_job" "pull" {
  id           = %[2]q
  store        = %[3]q
  ns           = "pulled"
  remote       = pbs_remote.self.name
  remote_store = %[3]q
  group_filter = ["type:vm"]
}
`, pushID, pullID, store)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy:             testAccCheckSyncDestroyed([]string{remote}, []string{pushID, pullID}),
		Steps: []acc.TestStep{
			{Config: config},
			{
				// The step keeps the configuration of the step before, with
				// its provider block, next to this query file.
				Query: true,
				Config: fmt.Sprintf(`
list "pbs_remote" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_sync_job" "push" {
  provider         = pbs
  include_resource = true

  config {
    store          = %[1]q
    sync_direction = "push"
  }
}

list "pbs_sync_job" "pull" {
  provider = pbs

  config {
    sync_direction = "pull"
  }
}
`, store),
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("pbs_remote.all", self),
					querycheck.ExpectResourceDisplayName("pbs_remote.all", queryfilter.ByResourceIdentity(self),
						knownvalue.StringExact(remote+" — terraform-provider-pbs acceptance tests")),
					// The password is never read.
					querycheck.ExpectResourceKnownValues("pbs_remote.all", queryfilter.ByResourceIdentity(self), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("host"), KnownValue: knownvalue.StringExact("127.0.0.1")},
						{Path: tfjsonpath.New("password_wo"), KnownValue: knownvalue.Null()},
						{Path: tfjsonpath.New("password_wo_version"), KnownValue: knownvalue.Null()},
					}),
					querycheck.ExpectIdentity("pbs_sync_job.push", push),
					querycheck.ExpectNoIdentity("pbs_sync_job.push", pull),
					querycheck.ExpectResourceDisplayName("pbs_sync_job.push", queryfilter.ByResourceIdentity(push),
						knownvalue.StringExact(pushID+" — listed by terraform query")),
					querycheck.ExpectResourceKnownValues("pbs_sync_job.push", queryfilter.ByResourceIdentity(push), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("remote"), KnownValue: knownvalue.StringExact(remote)},
						{Path: tfjsonpath.New("remote_ns"), KnownValue: knownvalue.StringExact("pushed")},
						{Path: tfjsonpath.New("rate_out"), KnownValue: knownvalue.NotNull()},
					}),
					querycheck.ExpectIdentity("pbs_sync_job.pull", pull),
					querycheck.ExpectNoIdentity("pbs_sync_job.pull", push),
				},
			},
			// What -generate-config-out writes for an object is the
			// configuration Terraform generates from its imported state:
			// it must plan no change — for the remote without its password,
			// which the imported remote keeps.
			{
				Config:          config,
				ResourceName:    "pbs_remote.self",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
			{
				Config:          config,
				ResourceName:    "pbs_sync_job.pull",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}
