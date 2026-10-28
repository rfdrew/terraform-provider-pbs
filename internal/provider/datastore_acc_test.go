package provider

import (
	"context"
	"fmt"
	"os"
	"path"
	"regexp"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_datastore, pbs_prune_job and pbs_verify_job. Every
// test creates datastores of its own, named tfacc-<random>, in the directory
// that holds the stand's datastore — /datastore on both stands — and destroys
// them with their data.

// testAccDatastoreName returns a fresh datastore name.
func testAccDatastoreName() string {
	return "tfacc-" + testAccRandom(8)
}

// testAccDatastoreDir returns the directory for a datastore of the given
// name: next to the stand's own datastore, where the backup user may write.
func testAccDatastoreDir(t *testing.T, name string) string {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		return "/datastore/" + name
	}
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	ds, err := client.GetDatastore(context.Background(), testAccDatastore(t))
	if err != nil {
		t.Fatalf("reading the stand's datastore: %v", err)
	}
	return path.Join(path.Dir(ds.Path), name)
}

// testAccVersionAtLeast reports whether the stand runs PBS major.minor.release
// or newer; false when the stand does not say.
func testAccVersionAtLeast(major, minor, release int) bool {
	var gotMajor, gotMinor, gotRelease int
	if n, _ := fmt.Sscanf(os.Getenv(envAccVersion), "%d.%d.%d", &gotMajor, &gotMinor, &gotRelease); n != 3 {
		return false
	}
	return pbsclient.Version{Version: fmt.Sprintf("%d.%d", gotMajor, gotMinor), Release: fmt.Sprint(gotRelease)}.AtLeast(major, minor, release)
}

// testAccCheckDatastoresDestroyed checks that the datastores and jobs are
// gone.
func testAccCheckDatastoresDestroyed(names []string, pruneJobs, verifyJobs []string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		ctx := context.Background()
		for _, name := range names {
			if _, err := client.GetDatastore(ctx, name); err == nil {
				return fmt.Errorf("datastore %s still exists", name)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		for _, id := range pruneJobs {
			if _, err := client.GetPruneJob(ctx, id); err == nil {
				return fmt.Errorf("prune job %s still exists", id)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		for _, id := range verifyJobs {
			if _, err := client.GetVerifyJob(ctx, id); err == nil {
				return fmt.Errorf("verify job %s still exists", id)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		return nil
	}
}

// testAccDeleteDatastore deletes a datastore outside Terraform, with its data
// and, as PBS does without keep-job-configs, its jobs.
func testAccDeleteDatastore(t *testing.T, name string) {
	t.Helper()
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteDatastore(context.Background(), name, pbsclient.DatastoreDeletion{DestroyData: true}); err != nil {
		t.Fatal(err)
	}
}

func TestAccDatastoreResource(t *testing.T) {
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	const resourceName = "pbs_datastore.test"
	notifyUser := os.Getenv(envAccUsername)
	if notifyUser == "" {
		notifyUser = "tfacc@pbs"
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  comment      = "terraform-provider-pbs acceptance tests"
  gc_schedule  = "daily"
  destroy_data = true

  tuning = {
    sync_level  = "file"
    chunk_order = "none"
  }
}
`, name, dir),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", name),
					acc.TestCheckResourceAttr(resourceName, "path", dir),
					acc.TestCheckResourceAttr(resourceName, "notification_mode", "notification-system"),
					acc.TestCheckResourceAttr(resourceName, "verify_new", "false"),
					acc.TestCheckResourceAttr(resourceName, "tuning.sync_level", "file"),
					acc.TestCheckNoResourceAttr(resourceName, "tuning.gc_cache_capacity"),
					acc.TestCheckNoResourceAttr(resourceName, "maintenance_mode"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name              = %q
  path              = %q
  gc_schedule       = "sat 05:00"
  verify_new        = true
  notification_mode = "legacy-sendmail"
  notify_user       = %q
  destroy_data      = true

  notify = {
    gc     = "error"
    verify = "never"
  }

  tuning = {
    gc_atime_cutoff       = 1500
    gc_atime_safety_check = false
  }

  maintenance_mode = {
    type    = "read-only"
    message = "terraform acceptance tests \"moving\" disks"
  }
}
`, name, dir, notifyUser),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "comment"),
					acc.TestCheckResourceAttr(resourceName, "gc_schedule", "sat 05:00"),
					acc.TestCheckResourceAttr(resourceName, "notify.gc", "error"),
					acc.TestCheckNoResourceAttr(resourceName, "notify.prune"),
					acc.TestCheckNoResourceAttr(resourceName, "tuning.sync_level"),
					acc.TestCheckResourceAttr(resourceName, "tuning.gc_atime_safety_check", "false"),
					acc.TestCheckResourceAttr(resourceName, "maintenance_mode.type", "read-only"),
					acc.TestCheckResourceAttr(resourceName, "maintenance_mode.message", `terraform acceptance tests "moving" disks`),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"destroy_data"},
			},
			{
				// Back to the defaults; the maintenance mode ends.
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  destroy_data = true
}
`, name, dir),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "notification_mode", "notification-system"),
					acc.TestCheckNoResourceAttr(resourceName, "gc_schedule"),
					acc.TestCheckNoResourceAttr(resourceName, "notify"),
					acc.TestCheckNoResourceAttr(resourceName, "tuning"),
					acc.TestCheckNoResourceAttr(resourceName, "maintenance_mode"),
					testAccCheckDatastoreConfig(name, func(ds pbsclient.Datastore) error {
						if ds.NotificationMode != "" || ds.MaintenanceMode != "" || ds.VerifyNew != nil {
							return fmt.Errorf("PBS kept properties reset to their defaults: %+v", ds)
						}
						return nil
					}),
				),
			},
		},
	})
}

// testAccCheckDatastoreConfig checks a datastore as PBS reports it.
func testAccCheckDatastoreConfig(name string, check func(pbsclient.Datastore) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		ds, err := client.GetDatastore(context.Background(), name)
		if err != nil {
			return err
		}
		return check(ds)
	}
}

// The verification defaults in tuning need PBS 4.1.
func TestAccDatastoreResourceVerificationTuning(t *testing.T) {
	if os.Getenv("TF_ACC") != "" && !testAccVersionAtLeast(4, 1, 0) {
		t.Skipf("the stand runs PBS %q; the verification defaults need 4.1", os.Getenv(envAccVersion))
	}
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{{
			Config: providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  destroy_data = true

  tuning = {
    default_verification_readers = 2
    default_verification_workers = 6
  }
}
`, name, dir),
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttr("pbs_datastore.test", "tuning.default_verification_readers", "2"),
				acc.TestCheckResourceAttr("pbs_datastore.test", "tuning.default_verification_workers", "6"),
			),
		}},
	})
}

// PBS creates a datastore only in an empty directory, or with
// reuse_datastore on the chunk store a datastore left behind.
func TestAccDatastoreResourceReuse(t *testing.T) {
	first, second := testAccDatastoreName(), testAccDatastoreName()
	dir := testAccDatastoreDir(t, first)
	config := func(name string, reuse bool) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name            = %q
  path            = %q
  reuse_datastore = %t
  destroy_data    = %t
}
`, name, dir, reuse, reuse)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{first, second}, nil, nil),
		Steps: []acc.TestStep{
			{Config: config(first, false)},
			// Destroyed without destroy_data, it leaves its chunk store.
			{Config: providerConfig},
			{Config: config(second, false), ExpectError: regexp.MustCompile(`already holds a chunk store`)},
			{
				Config: config(second, true),
				Check:  acc.TestCheckResourceAttr("pbs_datastore.test", "reuse_datastore", "true"),
			},
		},
	})
}

// A datastore with its prune and verify jobs; deleting the datastore outside
// Terraform deletes the jobs too, and the next apply creates all three again.
func TestAccDatastoreJobs(t *testing.T) {
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	pruneID, verifyID := "tfacc-prune-"+testAccRandom(6), "tfacc-verify-"+testAccRandom(6)
	threads := ""
	if testAccVersionAtLeast(4, 1, 0) {
		threads = "read_threads = 2\n  verify_threads = 3"
	}
	config := func(jobs string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  gc_schedule  = "daily"
  destroy_data = true
}
`, name, dir) + jobs
	}
	initial := config(fmt.Sprintf(`
resource "pbs_prune_job" "test" {
  id       = %q
  store    = pbs_datastore.test.name
  schedule = "daily"

  keep = {
    daily  = 7
    weekly = 4
  }
}

resource "pbs_verify_job" "test" {
  id    = %q
  store = pbs_datastore.test.name
}
`, pruneID, verifyID))

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, []string{pruneID}, []string{verifyID}),
		Steps: []acc.TestStep{
			{
				Config: initial,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_prune_job.test", "keep.daily", "7"),
					acc.TestCheckNoResourceAttr("pbs_prune_job.test", "keep.last"),
					acc.TestCheckResourceAttr("pbs_prune_job.test", "disable", "false"),
					acc.TestCheckResourceAttr("pbs_verify_job.test", "max_depth", "7"),
					acc.TestCheckResourceAttr("pbs_verify_job.test", "ignore_verified", "true"),
					acc.TestCheckNoResourceAttr("pbs_verify_job.test", "schedule"),
				),
			},
			{
				Config: config(fmt.Sprintf(`
resource "pbs_prune_job" "test" {
  id        = %q
  store     = pbs_datastore.test.name
  schedule  = "sun 02:00"
  max_depth = 0
  disable   = true
  comment   = "terraform-provider-pbs acceptance tests"

  keep = {
    last    = 3
    monthly = 6
  }
}

resource "pbs_verify_job" "test" {
  id              = %q
  store           = pbs_datastore.test.name
  schedule        = "sat 03:00"
  max_depth       = 2
  ignore_verified = false
  outdated_after  = 30
  %s
}
`, pruneID, verifyID, threads)),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_prune_job.test", "keep.last", "3"),
					acc.TestCheckNoResourceAttr("pbs_prune_job.test", "keep.daily"),
					acc.TestCheckResourceAttr("pbs_prune_job.test", "max_depth", "0"),
					acc.TestCheckResourceAttr("pbs_prune_job.test", "disable", "true"),
					acc.TestCheckResourceAttr("pbs_verify_job.test", "outdated_after", "30"),
					acc.TestCheckResourceAttr("pbs_verify_job.test", "ignore_verified", "false"),
				),
			},
			{ResourceName: "pbs_prune_job.test", ImportState: true, ImportStateVerify: true},
			{ResourceName: "pbs_verify_job.test", ImportState: true, ImportStateVerify: true},
			{
				// Back to PBS's defaults: the verify job reads as {id, store}
				// again.
				Config: initial,
				Check: testAccCheckVerifyJob(verifyID, func(job pbsclient.VerifyJob) error {
					if job.MaxDepth != nil || job.IgnoreVerified != nil || job.Schedule != "" || job.OutdatedAfter != nil ||
						job.ReadThreads != nil || job.VerifyThreads != nil {
						return fmt.Errorf("PBS kept properties reset to their defaults: %+v", job)
					}
					return nil
				}),
			},
			{
				PreConfig:          func() { testAccDeleteDatastore(t, name) },
				Config:             initial,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: initial,
				Check:  acc.TestCheckResourceAttr("pbs_prune_job.test", "keep.weekly", "4"),
			},
		},
	})
}

// PBS cannot rename a datastore: a new name in the same directory needs
// reuse_datastore, which the plan says before anything is destroyed. With
// it, Terraform replaces the datastore on its own chunk store — the old one
// is destroyed with destroy_data = false from state, the new one gets true
// for the cleanup — and the jobs, which PBS deletes with the old datastore,
// follow the new name in the same apply.
func TestAccDatastoreRename(t *testing.T) {
	first, second := testAccDatastoreName(), testAccDatastoreName()
	dir := testAccDatastoreDir(t, first)
	pruneID, verifyID := "tfacc-prune-"+testAccRandom(6), "tfacc-verify-"+testAccRandom(6)
	config := func(name string, reuse bool) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name            = %q
  path            = %q
  reuse_datastore = %t
  destroy_data    = %t
}

resource "pbs_prune_job" "test" {
  id       = %q
  store    = pbs_datastore.test.name
  schedule = "daily"
  keep     = { daily = 7 }
}

resource "pbs_verify_job" "test" {
  id       = %q
  store    = pbs_datastore.test.name
  schedule = "sat 03:00"
}
`, name, dir, reuse, reuse, pruneID, verifyID)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{first, second}, []string{pruneID}, []string{verifyID}),
		Steps: []acc.TestStep{
			{Config: config(first, false)},
			{Config: config(second, false), ExpectError: regexp.MustCompile(`Renaming the datastore needs reuse_datastore`)},
			{
				Config: config(second, true),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_datastore.test", "name", second),
					acc.TestCheckResourceAttr("pbs_prune_job.test", "store", second),
					acc.TestCheckResourceAttr("pbs_verify_job.test", "store", second),
					testAccCheckVerifyJob(verifyID, func(job pbsclient.VerifyJob) error {
						if job.Store != second || job.Schedule != "sat 03:00" {
							return fmt.Errorf("verify job = %+v, want it on %s", job, second)
						}
						return nil
					}),
				),
			},
		},
	})
}

// testAccCheckVerifyJob checks a verify job as PBS reports it.
func testAccCheckVerifyJob(id string, check func(pbsclient.VerifyJob) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		job, err := client.GetVerifyJob(context.Background(), id)
		if err != nil {
			return err
		}
		return check(job)
	}
}

// From Terraform 1.12, the datastore and its jobs import by identity too.
// An import block plans no change only when the configuration matches what
// an import reads, and destroy_data exists only in Terraform, so this
// datastore leaves its directory behind on the throwaway stand.
func TestAccDatastoreResourcesImportByIdentity(t *testing.T) {
	name := testAccDatastoreName()
	pruneID, verifyID := "tfacc-prune-"+testAccRandom(6), "tfacc-verify-"+testAccRandom(6)
	config := providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name = %q
  path = %q
}

resource "pbs_prune_job" "test" {
  id       = %q
  store    = pbs_datastore.test.name
  schedule = "daily"
  keep     = { last = 1 }
}

resource "pbs_verify_job" "test" {
  id    = %q
  store = pbs_datastore.test.name
}
`, name, testAccDatastoreDir(t, name), pruneID, verifyID)

	steps := []acc.TestStep{{Config: config}}
	for _, resourceName := range []string{"pbs_datastore.test", "pbs_prune_job.test", "pbs_verify_job.test"} {
		steps = append(steps,
			acc.TestStep{Config: config, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			acc.TestStep{Config: config, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, []string{pruneID}, []string{verifyID}),
		Steps:                    steps,
	})
}
