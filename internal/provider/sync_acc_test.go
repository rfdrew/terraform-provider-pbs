package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_remote, pbs_sync_job and their data sources. There
// is one PBS in CI, so it is its own remote: a pbs_remote points at
// 127.0.0.1:8007 inside its container, pinned to the fingerprint of its own
// certificate, and signs in with the API token the tests use, which has the
// Admin role on /. The sync jobs copy between the stand's datastore and one
// the test creates next to it. Nothing runs them: what is tested is their
// configuration, and the scans, which do make PBS sign in to the remote.

// testAccSelfRemote returns the configuration of a remote, named name, that
// points the stand at itself, with extra on top of what it needs. It reads
// the stand's fingerprint with pbs_fingerprint, as a configuration for
// another PBS would.
func testAccSelfRemote(t *testing.T, name, extra string) string {
	t.Helper()
	tokenID, secret := "tfacc@pbs!acc", "unused"
	if token := os.Getenv(envAPIToken); token != "" {
		var err error
		if tokenID, secret, err = pbsclient.SplitAPIToken(token); err != nil {
			t.Fatal(err)
		}
	}
	return fmt.Sprintf(`
data "pbs_fingerprint" "self" {}

resource "pbs_remote" "self" {
  name        = %q
  host        = "127.0.0.1"
  auth_id     = %q
  fingerprint = data.pbs_fingerprint.self.fingerprint
  comment     = "terraform-provider-pbs acceptance tests"

  password_wo         = %q
  password_wo_version = 1
  %s
}
`, name, tokenID, secret, extra)
}

// testAccCheckSyncDestroyed checks that the remotes and sync jobs are gone.
func testAccCheckSyncDestroyed(remotes, syncJobs []string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		ctx := context.Background()
		for _, name := range remotes {
			if _, err := client.GetRemote(ctx, name); err == nil {
				return fmt.Errorf("remote %s still exists", name)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		for _, id := range syncJobs {
			if _, err := client.GetSyncJob(ctx, id); err == nil {
				return fmt.Errorf("sync job %s still exists", id)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		return nil
	}
}

// testAccCheckSyncJob checks a sync job as PBS reports it.
func testAccCheckSyncJob(id string, check func(pbsclient.SyncJob) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		job, err := client.GetSyncJob(context.Background(), id)
		if err != nil {
			return err
		}
		return check(job)
	}
}

// testAccCheckListed checks that a list attribute of a data source has an
// element whose key attribute is each of want.
func testAccCheckListed(resourceName, list, key string, want ...string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("%s is not in state", resourceName)
		}
		found := map[string]bool{}
		for k, v := range rs.Primary.Attributes {
			if strings.HasPrefix(k, list+".") && strings.HasSuffix(k, "."+key) {
				found[v] = true
			}
		}
		for _, w := range want {
			if !found[w] {
				return fmt.Errorf("%s has no %s with %s = %q; attributes: %v", resourceName, list, key, w, rs.Primary.Attributes)
			}
		}
		return nil
	}
}

// A remote and sync jobs of every kind: a pull from the remote, a push to it
// and a local pull. The scans sign in to the remote; deleting the target
// datastore outside Terraform deletes the jobs whose store it is, and the
// next apply creates them again.
func TestAccRemoteAndSyncJobs(t *testing.T) {
	remote := "tfacc-" + testAccRandom(8)
	target := testAccDatastoreName()
	dir := testAccDatastoreDir(t, target)
	source := testAccDatastore(t)
	pullID, pushID, localID := "tfacc-pull-"+testAccRandom(6), "tfacc-push-"+testAccRandom(6), "tfacc-local-"+testAccRandom(6)
	verifyID, pruneID := "tfacc-verify-"+testAccRandom(6), "tfacc-prune-"+testAccRandom(6)

	newer := ""
	remoteNewer := ""
	if testAccVersionAtLeast(4, 2, 0) {
		newer = "worker_threads = 2\n  run_on_mount = true\n  unmount_on_done = true"
		remoteNewer = "use_node_proxy = true"
	}
	config := func(remoteExtra, pullExtra string) string {
		return providerConfig + testAccSelfRemote(t, remote, remoteExtra) + fmt.Sprintf(`
resource "pbs_datastore" "target" {
  name         = %[1]q
  path         = %[2]q
  destroy_data = true
}

resource "pbs_sync_job" "pull" {
  id           = %[3]q
  store        = pbs_datastore.target.name
  remote       = pbs_remote.self.name
  remote_store = %[4]q
  schedule     = "daily"
  rate_in      = "10MiB"
  %[7]s
}

resource "pbs_sync_job" "push" {
  id              = %[5]q
  sync_direction  = "push"
  store           = %[4]q
  remote          = pbs_remote.self.name
  remote_store    = pbs_datastore.target.name
  remote_ns       = "pushed"
  remove_vanished = true
  rate_out        = "1.5 GB"
}

resource "pbs_sync_job" "local" {
  id           = %[6]q
  store        = pbs_datastore.target.name
  remote_store = %[4]q
  group_filter = ["type:vm", "exclude:group:vm/100"]
}

resource "pbs_verify_job" "target" {
  id    = %[8]q
  store = pbs_datastore.target.name
}

resource "pbs_prune_job" "target" {
  id       = %[9]q
  store    = pbs_datastore.target.name
  schedule = "daily"
  keep     = { last = 3 }
}

data "pbs_remote_datastores" "self" {
  remote = pbs_remote.self.name

  depends_on = [pbs_datastore.target]
}

data "pbs_remote_namespaces" "source" {
  remote = pbs_remote.self.name
  store  = %[4]q
}

data "pbs_remote" "self" {
  name = pbs_remote.self.name
}

data "pbs_sync_jobs" "target" {
  store = pbs_datastore.target.name

  depends_on = [pbs_sync_job.pull, pbs_sync_job.local]
}

data "pbs_sync_job" "push" {
  id = pbs_sync_job.push.id
}

data "pbs_verify_jobs" "target" {
  store = pbs_datastore.target.name

  depends_on = [pbs_verify_job.target]
}

data "pbs_prune_job" "target" {
  id = pbs_prune_job.target.id
}
`, target, dir, pullID, source, pushID, localID, pullExtra, verifyID, pruneID)
	}
	initial := config("", "")

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckSyncDestroyed([]string{remote}, []string{pullID, pushID, localID}),
			testAccCheckDatastoresDestroyed([]string{target}, []string{pruneID}, []string{verifyID}),
		),
		Steps: []acc.TestStep{
			{
				Config: initial,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_remote.self", "id", remote),
					acc.TestCheckResourceAttr("pbs_remote.self", "use_node_proxy", "false"),
					acc.TestCheckNoResourceAttr("pbs_remote.self", "port"),
					acc.TestCheckResourceAttrPair("pbs_remote.self", "fingerprint", "data.pbs_fingerprint.self", "fingerprint"),
					acc.TestCheckResourceAttr("pbs_sync_job.pull", "sync_direction", "pull"),
					acc.TestCheckResourceAttr("pbs_sync_job.pull", "rate_in", "10MiB"),
					acc.TestCheckResourceAttr("pbs_sync_job.pull", "remove_vanished", "false"),
					acc.TestCheckResourceAttr("pbs_sync_job.push", "sync_direction", "push"),
					acc.TestCheckResourceAttr("pbs_sync_job.push", "rate_out", "1.5 GB"),
					acc.TestCheckNoResourceAttr("pbs_sync_job.local", "remote"),
					acc.TestCheckResourceAttr("pbs_sync_job.local", "group_filter.#", "2"),
					testAccCheckSyncJob(pullID, func(job pbsclient.SyncJob) error {
						if job.RateIn != "10 MiB" || job.SyncDirection != "" || job.Remote != remote {
							return fmt.Errorf("pull job = %+v, want rate-in in PBS's spelling and no direction", job)
						}
						return nil
					}),
					testAccCheckListed("data.pbs_remote_datastores.self", "datastores", "store", source, target),
					testAccCheckListed("data.pbs_remote_namespaces.source", "namespaces", "ns", ""),
					acc.TestCheckResourceAttr("data.pbs_remote.self", "host", "127.0.0.1"),
					acc.TestCheckResourceAttrPair("data.pbs_remote.self", "fingerprint", "pbs_remote.self", "fingerprint"),
					testAccCheckListed("data.pbs_sync_jobs.target", "jobs", "id", pullID, localID),
					acc.TestCheckResourceAttr("data.pbs_sync_jobs.target", "jobs.#", "2"),
					acc.TestCheckResourceAttr("data.pbs_sync_job.push", "sync_direction", "push"),
					acc.TestCheckResourceAttr("data.pbs_sync_job.push", "remove_vanished", "true"),
					acc.TestCheckResourceAttr("data.pbs_sync_job.push", "remote_ns", "pushed"),
					testAccCheckListed("data.pbs_verify_jobs.target", "jobs", "id", verifyID),
					acc.TestCheckResourceAttr("data.pbs_prune_job.target", "keep.last", "3"),
				),
			},
			{
				Config: config(remoteNewer+"\n  port = 8007", `
  ns              = "pulled"
  max_depth       = 0
  owner           = "tfacc@pbs"
  remove_vanished = true
  transfer_last   = 3
  encrypted_only  = true
  verified_only   = true
  resync_corrupt  = true
  burst_in        = "20 MiB"
  comment         = "terraform-provider-pbs acceptance tests"
  `+newer),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_remote.self", "port", "8007"),
					acc.TestCheckResourceAttr("pbs_sync_job.pull", "ns", "pulled"),
					acc.TestCheckResourceAttr("pbs_sync_job.pull", "max_depth", "0"),
					acc.TestCheckResourceAttr("pbs_sync_job.pull", "resync_corrupt", "true"),
					// A scan still works on the remote as changed.
					testAccCheckListed("data.pbs_remote_datastores.self", "datastores", "store", source),
				),
			},
			{
				ResourceName:            "pbs_remote.self",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password_wo", "password_wo_version"},
			},
			{
				ResourceName:      "pbs_sync_job.pull",
				ImportState:       true,
				ImportStateVerify: true,
				// PBS writes sizes back its own way: "10 MiB".
				ImportStateVerifyIgnore: []string{"rate_in"},
			},
			{ResourceName: "pbs_sync_job.push", ImportState: true, ImportStateVerify: true},
			{ResourceName: "pbs_sync_job.local", ImportState: true, ImportStateVerify: true},
			{
				// Back to PBS's defaults; resync-corrupt, which PBS cannot
				// delete, is false.
				Config: initial,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr("pbs_sync_job.pull", "ns"),
					acc.TestCheckResourceAttr("pbs_sync_job.pull", "resync_corrupt", "false"),
					testAccCheckSyncJob(pullID, func(job pbsclient.SyncJob) error {
						if job.NS != "" || job.MaxDepth != nil || job.Owner != "" || job.RemoveVanished != nil ||
							job.TransferLast != nil || job.EncryptedOnly != nil || job.WorkerThreads != nil || job.BurstIn != "" {
							return fmt.Errorf("PBS kept properties reset to their defaults: %+v", job)
						}
						if job.ResyncCorrupt != nil && *job.ResyncCorrupt {
							return fmt.Errorf("resync-corrupt is still true: %+v", job)
						}
						return nil
					}),
				),
			},
			{
				// Deleting the target datastore deletes the pull and local
				// jobs, whose store it is, but not the push job, which only
				// pushes to it.
				PreConfig: func() {
					testAccDeleteDatastore(t, target)
					client, err := testAccClient()
					if err != nil {
						t.Fatal(err)
					}
					ctx := context.Background()
					if _, err := client.GetSyncJob(ctx, pullID); !pbsclient.IsNotFound(err) {
						t.Errorf("the pull job survived its datastore: %v", err)
					}
					if _, err := client.GetSyncJob(ctx, pushID); err != nil {
						t.Errorf("the push job did not survive: %v", err)
					}
				},
				Config:             initial,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: initial,
				Check:  acc.TestCheckResourceAttr("pbs_sync_job.local", "group_filter.#", "2"),
			},
		},
	})
}

// From Terraform 1.12, the remote and a sync job import by identity too. An
// import block plans no change only when the configuration matches what an
// import reads, and the password exists only in Terraform, so the remote is
// configured without one after it was created.
func TestAccRemoteAndSyncJobImportByIdentity(t *testing.T) {
	remote := "tfacc-" + testAccRandom(8)
	pushID := "tfacc-push-" + testAccRandom(6)
	jobs := fmt.Sprintf(`
resource "pbs_sync_job" "push" {
  id             = %q
  sync_direction = "push"
  store          = %q
  remote         = pbs_remote.self.name
  remote_store   = %q
}
`, pushID, testAccDatastore(t), testAccDatastore(t))
	created := providerConfig + testAccSelfRemote(t, remote, "") + jobs
	// The remote as an import reads it: without the password.
	imported := providerConfig + strings.NewReplacer("password_wo ", "# password_wo ", "password_wo_version", "# password_wo_version").
		Replace(testAccSelfRemote(t, remote, "")) + jobs

	steps := []acc.TestStep{{Config: created}, {Config: imported}}
	for _, resourceName := range []string{"pbs_remote.self", "pbs_sync_job.push"} {
		steps = append(steps,
			acc.TestStep{Config: imported, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			acc.TestStep{Config: imported, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckSyncDestroyed([]string{remote}, []string{pushID}),
		Steps:                    steps,
	})
}
