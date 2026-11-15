package provider

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_datastore_verify and pbs_datastore_prune. The
// test makes a datastore of its own with a namespace. Where
// proxmox-backup-client can write backups — the packages stand — it writes
// two of one host into the namespace, which the actions verify, the older
// again on its own as a snapshot, dry-run prune, verify again as a group
// and prune to one; elsewhere both actions run on the empty namespace,
// which ends their tasks OK all the same.

func TestAccDatastoreVerifyPruneActions(t *testing.T) {
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	backup := testAccCanWriteBackup()
	// The thread counts need PBS 4.1; the 4.0 stand runs without them.
	threads := ""
	if testAccVersionAtLeast(4, 1, 0) {
		threads = "read_threads = 2"
	}
	var firstRun, secondRun time.Time
	// The older backup is an hour back, so that the other, written now, is
	// newer, as PBS requires of a group's next backup.
	firstBackup := time.Now().Add(-time.Hour).Truncate(time.Second)

	config := providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  destroy_data = true
}

resource "pbs_namespace" "test" {
  store         = pbs_datastore.test.name
  namespace     = "tfacc"
  delete_groups = true
}
`, name, dir)
	// The first run verifies the namespace, then, with backups written, the
	// older on its own, by its name in UTC, which the action verifies again
	// although the namespace's verification just did, and previews the
	// prune; the second verifies the group again, every backup, and prunes.
	actions := func(second bool) string {
		verify := "ignore_verified = false"
		if second && backup {
			verify += "\n    group           = \"host/tfacc\""
		}
		if !second {
			verify = threads
		}
		snapshot := ""
		if !second && backup {
			snapshot = fmt.Sprintf(`
action "pbs_datastore_verify" "snapshot" {
  config {
    store    = pbs_datastore.test.name
    ns       = pbs_namespace.test.namespace
    snapshot = %q
  }
}
`, "host/tfacc/"+firstBackup.UTC().Format(time.RFC3339))
		}
		return snapshot + fmt.Sprintf(`
action "pbs_datastore_verify" "test" {
  config {
    store = pbs_datastore.test.name
    ns    = pbs_namespace.test.namespace
    %s
  }
}

action "pbs_datastore_prune" "test" {
  config {
    store   = pbs_datastore.test.name
    ns      = pbs_namespace.test.namespace
    keep    = { last = 1 }
    dry_run = %t
  }
}
`, verify, !second)
	}
	// Terraform runs the actions of a trigger in their order.
	trigger := func(input string, snapshot bool) string {
		verify := "action.pbs_datastore_verify.test"
		if snapshot {
			verify += ", action.pbs_datastore_verify.snapshot"
		}
		return testAccActionTrigger(verify+", action.pbs_datastore_prune.test", input)
	}
	verifyType := "verify"
	if backup {
		verifyType = "verify_group"
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			{Config: config},
			{
				PreConfig: func() {
					firstRun = time.Now()
					if backup {
						testAccWriteBackup(t, name, "tfacc", "--backup-time", strconv.FormatInt(firstBackup.Unix(), 10))
						testAccWriteBackup(t, name, "tfacc")
					}
				},
				Config: config + actions(false) + trigger("1", backup),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckDatastoreTaskEnded("verify", name, &firstRun),
					testAccCheckDatastoreTaskEnded("prune", name, &firstRun),
					// The dry run removed nothing.
					testAccCheckVerifiedSnapshots(name, "tfacc", backup, 2),
					testAccCheckSnapshotVerifiedBy(name, "tfacc", backup, firstBackup, "verify_snapshot"),
				),
			},
			{
				PreConfig: func() { secondRun = time.Now() },
				Config:    config + actions(true) + trigger("2", false),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckDatastoreTaskEnded(verifyType, name, &secondRun),
					testAccCheckDatastoreTaskEnded("prune", name, &secondRun),
					testAccCheckVerifiedSnapshots(name, "tfacc", backup, 1),
				),
			},
		},
	})
}

// testAccCheckDatastoreTaskEnded checks that the latest task of a worker
// type on datastore store, started since a time, ended OK. The task list
// gives worker IDs unescaped: "<store>", or "<store>:" and more.
func testAccCheckDatastoreTaskEnded(workerType, store string, since *time.Time) acc.TestCheckFunc {
	return func(*terraform.State) error {
		tasks, err := testAccTasksOfType(workerType, *since)
		if err != nil {
			return err
		}
		for _, task := range tasks {
			if task.WorkerID != store && !strings.HasPrefix(task.WorkerID, store+":") {
				continue
			}
			if task.Status != "OK" {
				return fmt.Errorf("task %s ended with %q", task.UPID, task.Status)
			}
			return nil
		}
		return fmt.Errorf("PBS ran no %s task on datastore %s since %s", workerType, store, since.Format(time.RFC3339))
	}
}

// testAccCheckVerifiedSnapshots checks the backups of namespace ns of
// datastore store: with backups written, that there are want of them, all
// verified OK; without, that there are none.
func testAccCheckVerifiedSnapshots(store, ns string, backup bool, want int) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		var snapshots []struct {
			Type         string `json:"backup-type"`
			ID           string `json:"backup-id"`
			Time         int64  `json:"backup-time"`
			Verification *struct {
				State string `json:"state"`
			} `json:"verification"`
		}
		params := url.Values{"ns": {ns}}
		if _, err := client.Get(context.Background(), pbsclient.Path("admin", "datastore", store, "snapshots"), params, &snapshots); err != nil {
			return err
		}
		if !backup {
			want = 0
		}
		if len(snapshots) != want {
			return fmt.Errorf("namespace %s of datastore %s holds %d backups, want %d: %+v", ns, store, len(snapshots), want, snapshots)
		}
		for _, s := range snapshots {
			if s.Verification == nil || s.Verification.State != "ok" {
				return fmt.Errorf("backup %s/%s/%d of datastore %s is not verified: %+v", s.Type, s.ID, s.Time, store, s.Verification)
			}
		}
		return nil
	}
}

// testAccCheckSnapshotVerifiedBy checks, with backups written, that the
// backup of host/tfacc at backupTime in namespace ns of datastore store was
// last verified OK by a task of workerType that ended OK. A verification
// that missed the backup, or skipped it as verified before, leaves the
// verification of an earlier task.
func testAccCheckSnapshotVerifiedBy(store, ns string, backup bool, backupTime time.Time, workerType string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		if !backup {
			return nil
		}
		client, err := testAccClient()
		if err != nil {
			return err
		}
		var snapshots []struct {
			Type         string `json:"backup-type"`
			ID           string `json:"backup-id"`
			Time         int64  `json:"backup-time"`
			Verification *struct {
				State string `json:"state"`
				UPID  string `json:"upid"`
			} `json:"verification"`
		}
		params := url.Values{"ns": {ns}}
		if _, err := client.Get(context.Background(), pbsclient.Path("admin", "datastore", store, "snapshots"), params, &snapshots); err != nil {
			return err
		}
		for _, s := range snapshots {
			if s.Type != "host" || s.ID != "tfacc" || s.Time != backupTime.Unix() {
				continue
			}
			if s.Verification == nil || s.Verification.State != "ok" {
				return fmt.Errorf("backup host/tfacc/%d of datastore %s is not verified: %+v", s.Time, store, s.Verification)
			}
			upid, err := pbsclient.ParseUPID(s.Verification.UPID)
			if err != nil {
				return err
			}
			if upid.WorkerType != workerType {
				return fmt.Errorf("backup host/tfacc/%d of datastore %s was last verified by %s, want a %s task",
					s.Time, store, upid.Raw, workerType)
			}
			status, err := client.TaskStatus(context.Background(), upid)
			if err != nil {
				return err
			}
			if status.ExitStatus != "OK" {
				return fmt.Errorf("task %s ended with %q", upid.Raw, status.ExitStatus)
			}
			return nil
		}
		return fmt.Errorf("namespace %s of datastore %s holds no backup host/tfacc/%d: %+v", ns, store, backupTime.Unix(), snapshots)
	}
}
