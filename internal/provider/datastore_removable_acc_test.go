package provider

import (
	"fmt"
	"os"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Acceptance tests of removable datastores. The packages stand has a file
// system on a loop device for them, whose UUID scripts/bootstrap-test-pbs.sh
// exports; the image stand has none, and the tests skip there.

// envAccRemovableUUID is the UUID of the file system the stand provides for
// removable datastores.
const envAccRemovableUUID = "PBS_ACC_REMOVABLE_UUID"

// testAccRemovableDevice returns the UUID of the stand's removable file
// system, skipping the test when there is none.
func testAccRemovableDevice(t *testing.T) string {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		return testDeviceUUID
	}
	uuid := os.Getenv(envAccRemovableUUID)
	if uuid == "" {
		t.Skipf("the stand provides no file system for removable datastores (%s is not set)", envAccRemovableUUID)
	}
	return uuid
}

// A removable datastore is created on the stand's device and mounted;
// unmounted outside Terraform, it reads as such, keeps its namespace in
// state, and takes changes; mounted again, it is destroyed with its data.
func TestAccDatastoreResourceRemovable(t *testing.T) {
	device := testAccRemovableDevice(t)
	name := testAccDatastoreName()
	const resourceName = "pbs_datastore.test"
	config := func(extra string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name           = %q
  path           = %q
  backing_device = %q
  gc_schedule    = "daily"
  destroy_data   = true
  %s
}

resource "pbs_namespace" "test" {
  store     = pbs_datastore.test.name
  namespace = "offsite"
}
`, name, name, device, extra)
	}
	// gc_on_unmount needs PBS 4.2.
	changed := `comment = "terraform-provider-pbs acceptance tests"`
	if testAccVersionAtLeast(4, 2, 0) {
		changed += "\n  gc_on_unmount = true"
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			{
				Config: config(""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "path", name),
					acc.TestCheckResourceAttr(resourceName, "backing_device", device),
					acc.TestCheckResourceAttr(resourceName, "mount_status", "mounted"),
					acc.TestCheckResourceAttr(resourceName, "gc_on_unmount", "false"),
					testAccCheckNamespace(name, "offsite", true),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"destroy_data"},
			},
			{
				// Unmounted, it reads as such, and the namespace stays in
				// state.
				PreConfig: func() { testAccDatastoreTask(t, name, "unmount") },
				Config:    config(""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "mount_status", "notmounted"),
					acc.TestCheckResourceAttr("pbs_namespace.test", "namespace", "offsite"),
				),
			},
			{
				// Its settings change while it is not mounted.
				Config: config(changed),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "comment", "terraform-provider-pbs acceptance tests"),
					acc.TestCheckResourceAttr(resourceName, "mount_status", "notmounted"),
				),
			},
			{
				// Mounted again, its namespace is still there; destroying
				// it with its data then works.
				PreConfig: func() { testAccDatastoreTask(t, name, "mount") },
				Config:    config(changed),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "mount_status", "mounted"),
					testAccCheckNamespace(name, "offsite", true),
				),
			},
		},
	})
}
