package provider

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_sync_job_run, pbs_verify_job_run and
// pbs_prune_job_run. The test makes two datastores of its own and the jobs:
// a local sync job pulling one into the other, and a verify job and a
// disabled prune job on the target. Where proxmox-backup-client can write a
// backup into the source, the sync has something to copy, and the verify
// and prune jobs something to check and keep.

func TestAccJobRunActions(t *testing.T) {
	source, target := testAccDatastoreName(), testAccDatastoreName()
	sourceDir, targetDir := testAccDatastoreDir(t, source), testAccDatastoreDir(t, target)
	syncID, verifyID, pruneID := "tfacc-sync-"+testAccRandom(6), "tfacc-verify-"+testAccRandom(6), "tfacc-prune-"+testAccRandom(6)
	backup := testAccCanWriteBackup()

	jobs := providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "source" {
  name         = %[1]q
  path         = %[2]q
  destroy_data = true
}

resource "pbs_datastore" "target" {
  name         = %[3]q
  path         = %[4]q
  destroy_data = true
}

resource "pbs_sync_job" "test" {
  id           = %[5]q
  store        = pbs_datastore.target.name
  remote_store = pbs_datastore.source.name
}

resource "pbs_verify_job" "test" {
  id    = %[6]q
  store = pbs_datastore.target.name
}

# Disabled: only its schedule stops, a run by hand goes ahead.
resource "pbs_prune_job" "test" {
  id       = %[7]q
  store    = pbs_datastore.target.name
  schedule = "daily"
  disable  = true
  keep     = { last = 1 }
}
`, source, sourceDir, target, targetDir, syncID, verifyID, pruneID)
	actions := `
action "pbs_sync_job_run" "test" {
  config {
    id = pbs_sync_job.test.id
  }
}

action "pbs_verify_job_run" "test" {
  config {
    id      = pbs_verify_job.test.id
    timeout = "10m"
  }
}

action "pbs_prune_job_run" "test" {
  config {
    id = pbs_prune_job.test.id
  }
}
`
	// One trigger runs the three in turn: the sync fills the target before
	// the verification and the prune look at it.
	trigger := testAccActionTrigger("action.pbs_sync_job_run.test, action.pbs_verify_job_run.test, action.pbs_prune_job_run.test", "1")

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckDatastoresDestroyed([]string{source, target}, []string{pruneID}, []string{verifyID}),
			testAccCheckSyncDestroyed(nil, []string{syncID}),
		),
		Steps: []acc.TestStep{
			// The jobs first, which have no schedule or a disabled one:
			// whatever runs them afterwards is the actions.
			{
				Config: jobs,
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckJobRun(pbsclient.JobKindSync, syncID, "", ""),
					testAccCheckJobRun(pbsclient.JobKindVerify, verifyID, "", ""),
					testAccCheckJobRun(pbsclient.JobKindPrune, pruneID, "", ""),
				),
			},
			{
				PreConfig: func() {
					if backup {
						testAccWriteBackup(t, source, "")
					}
				},
				Config: jobs + actions + trigger,
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckJobRun(pbsclient.JobKindSync, syncID, "syncjob", "OK"),
					testAccCheckJobRun(pbsclient.JobKindVerify, verifyID, "verificationjob", "OK"),
					testAccCheckJobRun(pbsclient.JobKindPrune, pruneID, "prunejob", "OK"),
					testAccCheckSnapshots(target, backup),
				),
			},
		},
	})
}

// testAccCanWriteBackup reports whether testAccWriteBackup can write a
// backup on the stand; testAccSkipWithoutBackupClient skips a test that
// cannot do without.
func testAccCanWriteBackup() bool {
	if os.Getenv("TF_ACC") == "" || os.Getenv(envAccContainer) == "" || os.Getenv(envAccVariant) != "packages" {
		return false
	}
	_, err := exec.LookPath("docker")
	return err == nil
}

// testAccCheckJobRun checks, in PBS's job list of its kind, how a job last
// ran: by a task of workerType that ended with state, or, with workerType
// "", never.
func testAccCheckJobRun(kind, id, workerType, state string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		jobs, err := client.ListJobRunStatuses(context.Background(), kind)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			if job.ID != id {
				continue
			}
			switch {
			case workerType == "" && job.LastRunUPID != "":
				return fmt.Errorf("%s job %s ran already: %s", kind, id, job.LastRunUPID)
			case workerType == "":
				return nil
			case !strings.Contains(job.LastRunUPID, ":"+workerType+":"):
				return fmt.Errorf("%s job %s did not run: last run %q", kind, id, job.LastRunUPID)
			case job.LastRunState != state:
				return fmt.Errorf("%s job %s: last run %s ended with %q, want %q", kind, id, job.LastRunUPID, job.LastRunState, state)
			}
			return nil
		}
		return fmt.Errorf("PBS lists no %s job %s", kind, id)
	}
}

// testAccCheckSnapshots checks that datastore store holds the backup
// testAccWriteBackup writes, or, when none was written, nothing.
func testAccCheckSnapshots(store string, want bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		var snapshots []struct {
			Type string `json:"backup-type"`
			ID   string `json:"backup-id"`
		}
		if _, err := client.Get(context.Background(), pbsclient.Path("admin", "datastore", store, "snapshots"), nil, &snapshots); err != nil {
			return err
		}
		found := false
		for _, s := range snapshots {
			found = found || (s.Type == "host" && s.ID == "tfacc")
		}
		if found != want || (!want && len(snapshots) > 0) {
			return fmt.Errorf("datastore %s holds %+v; want the synced backup: %v", store, snapshots, want)
		}
		return nil
	}
}
