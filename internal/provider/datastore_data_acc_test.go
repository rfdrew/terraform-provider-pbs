package provider

import (
	"fmt"
	"regexp"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Acceptance tests of pbs_datastore, pbs_datastores, pbs_datastore_status and
// pbs_gc_status, on a datastore of their own.

func TestAccDatastoreDataSources(t *testing.T) {
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	config := providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  comment      = "terraform-provider-pbs acceptance tests"
  gc_schedule  = "daily"
  destroy_data = true

  tuning = {
    chunk_order = "none"
  }
}

data "pbs_datastore" "test" {
  name = pbs_datastore.test.name
}

data "pbs_datastores" "all" {
  depends_on = [pbs_datastore.test]
}

data "pbs_datastore_status" "test" {
  store = pbs_datastore.test.name
}

data "pbs_gc_status" "test" {
  store = pbs_datastore.test.name
}
`, name, dir)
	number := regexp.MustCompile(`^[1-9][0-9]*$`)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			{
				Config: config,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("data.pbs_datastore.test", "path", dir),
					acc.TestCheckResourceAttr("data.pbs_datastore.test", "comment", "terraform-provider-pbs acceptance tests"),
					acc.TestCheckResourceAttr("data.pbs_datastore.test", "gc_schedule", "daily"),
					acc.TestCheckResourceAttr("data.pbs_datastore.test", "tuning.chunk_order", "none"),
					acc.TestCheckResourceAttr("data.pbs_datastore.test", "notification_mode", "notification-system"),
					acc.TestCheckResourceAttr("data.pbs_datastore.test", "mount_status", "nonremovable"),
					acc.TestCheckResourceAttr("data.pbs_datastore.test", "backend_type", "filesystem"),
					acc.TestCheckNoResourceAttr("data.pbs_datastore.test", "backing_device"),
					acc.TestCheckTypeSetElemNestedAttrs("data.pbs_datastores.all", "datastores.*", map[string]string{
						"name": name, "path": dir, "mount_status": "nonremovable",
					}),
					acc.TestCheckResourceAttr("data.pbs_datastore_status.test", "mount_status", "nonremovable"),
					acc.TestMatchResourceAttr("data.pbs_datastore_status.test", "total", number),
					acc.TestMatchResourceAttr("data.pbs_datastore_status.test", "avail", number),
					acc.TestCheckResourceAttrSet("data.pbs_datastore_status.test", "used"),
					acc.TestCheckNoResourceAttr("data.pbs_datastore_status.test", "error"),
					acc.TestCheckResourceAttr("data.pbs_gc_status.test", "schedule", "daily"),
					acc.TestMatchResourceAttr("data.pbs_gc_status.test", "next_run", number),
					acc.TestCheckNoResourceAttr("data.pbs_gc_status.test", "last_run_state"),
					acc.TestCheckResourceAttr("data.pbs_gc_status.test", "removed_chunks", "0"),
				),
			},
			{
				// After a garbage collection, its outcome.
				PreConfig: func() { testAccDatastoreTask(t, name, "gc") },
				Config:    config,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("data.pbs_gc_status.test", "last_run_state", "OK"),
					acc.TestMatchResourceAttr("data.pbs_gc_status.test", "upid", regexp.MustCompile(`^UPID:.*:garbage_collection:`)),
					acc.TestMatchResourceAttr("data.pbs_gc_status.test", "last_run_endtime", number),
					acc.TestCheckResourceAttrSet("data.pbs_gc_status.test", "duration"),
				),
			},
		},
	})
}

// A datastore that does not exist is an error, not an empty result.
func TestAccDatastoreDataSourceMissing(t *testing.T) {
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				Config:      providerConfig + `data "pbs_datastore" "missing" { name = "tfacc-missing" }`,
				ExpectError: regexp.MustCompile(`PBS has no datastore "tfacc-missing"`),
			},
			{
				Config:      providerConfig + `data "pbs_gc_status" "missing" { store = "tfacc-missing" }`,
				ExpectError: regexp.MustCompile(`PBS has no datastore "tfacc-missing"`),
			},
			{
				Config:      providerConfig + `data "pbs_datastore_status" "missing" { store = "tfacc-missing" }`,
				ExpectError: regexp.MustCompile(`PBS lists no datastore "tfacc-missing"`),
			},
		},
	})
}
