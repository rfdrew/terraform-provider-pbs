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

// The list resources of datastores, their namespaces and their prune and
// verify jobs, against a datastore of the test's own. The stand has a
// datastore of its own, and other tests add theirs meanwhile — removable
// ones that are not mounted among them, whose namespaces are left out with
// a warning — so the lists over every datastore are checked for the test's
// objects only.
func TestAccDatastoreListResources(t *testing.T) {
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	pruneID, verifyID := "tfacc-prune-"+testAccRandom(6), "tfacc-verify-"+testAccRandom(6)
	datastore := map[string]knownvalue.Check{"name": knownvalue.StringExact(name)}
	namespace := func(ns string) map[string]knownvalue.Check {
		return map[string]knownvalue.Check{"store": knownvalue.StringExact(name), "namespace": knownvalue.StringExact(ns)}
	}
	prune := map[string]knownvalue.Check{"id": knownvalue.StringExact(pruneID)}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %[1]q
  path         = %[2]q
  comment      = "listed by terraform query"
  gc_schedule  = "daily"
  destroy_data = true
}

resource "pbs_namespace" "parent" {
  store     = pbs_datastore.test.name
  namespace = "dept1"
}

resource "pbs_namespace" "child" {
  store     = pbs_datastore.test.name
  namespace = "${pbs_namespace.parent.namespace}/hosts"
}

resource "pbs_prune_job" "test" {
  id       = %[3]q
  store    = pbs_datastore.test.name
  ns       = pbs_namespace.parent.namespace
  schedule = "daily"
  keep     = { last = 3 }
}

resource "pbs_verify_job" "test" {
  id      = %[4]q
  store   = pbs_datastore.test.name
  comment = "listed by terraform query"
}
`, name, dir, pruneID, verifyID)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, []string{pruneID}, []string{verifyID}),
		Steps: []acc.TestStep{
			{Config: config},
			{
				// The step keeps the configuration of the step before, with
				// its provider block, next to this query file.
				Query: true,
				Config: fmt.Sprintf(`
list "pbs_datastore" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_namespace" "test" {
  provider         = pbs
  include_resource = true

  config {
    store = %[1]q
  }
}

list "pbs_namespace" "all" {
  provider = pbs
}

list "pbs_prune_job" "test" {
  provider         = pbs
  include_resource = true

  config {
    store = %[1]q
  }
}

list "pbs_verify_job" "test" {
  provider = pbs

  config {
    store = %[1]q
  }
}
`, name),
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("pbs_datastore.all", datastore),
					querycheck.ExpectResourceDisplayName("pbs_datastore.all", queryfilter.ByResourceIdentity(datastore),
						knownvalue.StringExact(name+" — listed by terraform query")),
					// The attributes that exist only in Terraform come out
					// at their defaults, as after an import.
					querycheck.ExpectResourceKnownValues("pbs_datastore.all", queryfilter.ByResourceIdentity(datastore), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("path"), KnownValue: knownvalue.StringExact(dir)},
						{Path: tfjsonpath.New("gc_schedule"), KnownValue: knownvalue.StringExact("daily")},
						{Path: tfjsonpath.New("destroy_data"), KnownValue: knownvalue.Bool(false)},
					}),
					querycheck.ExpectLength("pbs_namespace.test", 2),
					querycheck.ExpectIdentity("pbs_namespace.test", namespace("dept1")),
					querycheck.ExpectIdentity("pbs_namespace.test", namespace("dept1/hosts")),
					querycheck.ExpectResourceDisplayName("pbs_namespace.test", queryfilter.ByResourceIdentity(namespace("dept1/hosts")),
						knownvalue.StringExact(name+":dept1/hosts")),
					querycheck.ExpectResourceKnownValues("pbs_namespace.test", queryfilter.ByResourceIdentity(namespace("dept1")), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("delete_groups"), KnownValue: knownvalue.Bool(false)},
						{Path: tfjsonpath.New("error_on_protected"), KnownValue: knownvalue.Bool(true)},
					}),
					querycheck.ExpectIdentity("pbs_namespace.all", namespace("dept1/hosts")),
					querycheck.ExpectLength("pbs_prune_job.test", 1),
					querycheck.ExpectResourceKnownValues("pbs_prune_job.test", queryfilter.ByResourceIdentity(prune), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("ns"), KnownValue: knownvalue.StringExact("dept1")},
						{Path: tfjsonpath.New("keep").AtMapKey("last"), KnownValue: knownvalue.Int64Exact(3)},
					}),
					querycheck.ExpectLength("pbs_verify_job.test", 1),
					querycheck.ExpectIdentity("pbs_verify_job.test", map[string]knownvalue.Check{"id": knownvalue.StringExact(verifyID)}),
					querycheck.ExpectResourceDisplayName("pbs_verify_job.test", queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"id": knownvalue.StringExact(verifyID)}),
						knownvalue.StringExact(verifyID+" — listed by terraform query")),
				},
			},
			// What -generate-config-out writes for an object is the
			// configuration Terraform generates from its imported state:
			// it must plan no change.
			{
				Config:          config,
				ResourceName:    "pbs_datastore.test",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
			{
				Config:          config,
				ResourceName:    "pbs_namespace.child",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}
