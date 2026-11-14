package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of the actions on removable datastores and on S3. They
// need the stand's removable file system, or its S3 server, and skip
// without.

// A removable datastore is unmounted and mounted again by the actions, each
// of which leaves a datastore that is in that state already as it is; PBS
// clears the maintenance mode an unmount sets.
func TestAccDatastoreMountActions(t *testing.T) {
	device := testAccRemovableDevice(t)
	name := testAccDatastoreName()
	config := providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name           = %q
  path           = %q
  backing_device = %q
  destroy_data   = true
}

action "pbs_datastore_unmount" "test" {
  config {
    store   = pbs_datastore.test.name
    timeout = "5m"
  }
}

action "pbs_datastore_mount" "test" {
  config {
    store = pbs_datastore.test.name
  }
}
`, name, name, device)
	unmount := func(input string) string {
		return config + testAccActionTrigger("action.pbs_datastore_unmount.test", input)
	}
	mount := func(input string) string {
		return config + testAccActionTrigger("action.pbs_datastore_mount.test", input)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		// A removable datastore is destroyed with its data only while it is
		// mounted, as the last step leaves it.
		CheckDestroy: testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			{Config: config, Check: testAccCheckMountStatus(name, pbsclient.MountStatusMounted)},
			{Config: unmount("1"), Check: testAccCheckMountStatus(name, pbsclient.MountStatusNotMounted)},
			{Config: unmount("2"), Check: testAccCheckMountStatus(name, pbsclient.MountStatusNotMounted)},
			{Config: mount("3"), Check: testAccCheckMountStatus(name, pbsclient.MountStatusMounted)},
			{Config: mount("4"), Check: testAccCheckMountStatus(name, pbsclient.MountStatusMounted)},
		},
	})
}

// testAccCheckMountStatus checks the mount status of datastore name as PBS
// lists it, and that it is in no maintenance mode.
func testAccCheckMountStatus(name, want string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		states, err := client.ListDatastoreStates(context.Background())
		if err != nil {
			return err
		}
		for _, state := range states {
			if state.Store != name {
				continue
			}
			if state.MountStatus != want || state.Maintenance != "" {
				return fmt.Errorf("PBS lists datastore %s with mount status %q and maintenance mode %q, want %q and none",
					name, state.MountStatus, state.Maintenance, want)
			}
			return nil
		}
		return fmt.Errorf("PBS does not list datastore %s", name)
	}
}

// The S3 actions on a datastore on the stand's S3 server: the check passes
// for the datastore's bucket and prefix, deleting its test object, and
// fails for a bucket that does not exist; the refresh reads namespaces that
// only the bucket holds into the datastore, and clears the maintenance mode
// it sets. One namespace holds a group, which every release reads; the other
// is empty, which releases before 4.1.5 skip (proxmox-backup 3ff962875,
// "datastore: don't skip empty namespaces on s3 refresh").
func TestAccS3Actions(t *testing.T) {
	testAccSkipWithoutS3Objects(t)
	endpointID := "tfacc-" + testAccRandom(8)
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	bucket := testAccS3Bucket()
	testAccS3CleanUp(t, bucket, name)
	const namespace, groupNamespace = "refreshed", "grouped"
	emptyNamespaceRefreshed := testAccVersionAtLeast(4, 1, 5)

	base := providerConfig + testAccS3StandEndpoint("test", endpointID, testAccS3StandFingerprint()) + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  destroy_data = true

  backend = {
    type   = "s3"
    client = pbs_s3_endpoint.test.id
    bucket = %q
  }
}

action "pbs_datastore_s3_refresh" "test" {
  config {
    store = pbs_datastore.test.name
  }
}
`, name, dir, bucket)
	check := func(bucket, input string) string {
		return base + fmt.Sprintf(`
action "pbs_s3_endpoint_check" "test" {
  config {
    s3_endpoint  = pbs_s3_endpoint.test.id
    bucket       = %q
    store_prefix = pbs_datastore.test.name
  }
}
`, bucket) + testAccActionTrigger("action.pbs_s3_endpoint_check.test", input)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		// The endpoint's secret key is write-only, for Terraform 1.11 and
		// later; actions need 1.14.1 anyway.
		TerraformVersionChecks: actionVersionChecks,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
			testAccCheckS3EndpointsDestroyed(endpointID),
			testAccCheckS3Datastore(bucket, name, false),
		),
		Steps: []acc.TestStep{
			{
				Config: check(bucket, "1"),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckS3Object(bucket, name+"/"+pbsclient.S3CheckObject, false),
					testAccCheckNamespace(name, namespace, false),
					testAccCheckNamespace(name, groupNamespace, false),
				),
			},
			{
				Config:      check("tfacc-missing-"+testAccRandom(8), "2"),
				ExpectError: regexp.MustCompile(`head\s+object\s+failed`),
			},
			{
				// Namespaces that another PBS created in the bucket, which
				// this one learns of only from a refresh: an empty one, as
				// its marker object, and one with a group, as the group's
				// owner file.
				PreConfig: func() {
					testAccS3Put(t, bucket, name+"/.cnt/ns/"+namespace+"/.namespace", "")
					testAccS3Put(t, bucket, name+"/.cnt/ns/"+groupNamespace+"/host/tfacc/owner", "root@pam\n")
				},
				Config: base + testAccActionTrigger("action.pbs_datastore_s3_refresh.test", "3"),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckNamespace(name, namespace, emptyNamespaceRefreshed),
					testAccCheckNamespace(name, groupNamespace, true),
					testAccCheckDatastoreConfig(name, func(ds pbsclient.Datastore) error {
						if ds.MaintenanceMode != "" {
							return fmt.Errorf("datastore %s is in maintenance mode %q after the refresh", name, ds.MaintenanceMode)
						}
						return nil
					}),
				),
			},
		},
	})
}
