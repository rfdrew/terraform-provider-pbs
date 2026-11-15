package provider

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance test of the provider waiting for PBS's lock of its datastore
// configuration. PBS takes /etc/proxmox-backup/.datastore.lck to change the
// settings of any datastore and to open any datastore, waits 10 s for it,
// and then refuses the call (pbsclient.IsDatastoreConfigLocked); from PBS
// 4.0.20 an S3 refresh holds it for as long as it reads its bucket. The test
// holds the lock itself, in the stand's container, as such a task would:
// that needs no S3 and takes the same time on every stand.
//
// The suite runs its tests one after another — none calls t.Parallel —, so
// no other test meets the lock while this one holds it.

const (
	// datastoreLockHold is how long the test holds the lock: long enough
	// that the first call of a step to meet it, which comes a few seconds
	// into the step, reaches PBS more than 10 s before the release, so that
	// PBS refuses it at least once and the provider has to try it again.
	datastoreLockHold = 40 * time.Second
	// datastoreLockSlack is how much sooner than datastoreLockHold after the
	// test saw the lock taken the holder may release it: the holder took it
	// a moment before the test saw it.
	datastoreLockSlack = 5 * time.Second
	// datastoreLockPIDFile is where the holder in the container writes its
	// process ID, for the cleanup: stopping `docker exec` does not stop the
	// process it runs.
	datastoreLockPIDFile = "/tmp/tfacc-datastore-lock.pid"
	// datastoreLockHolder takes the lock and keeps it: perl, which every
	// Debian has, with flock(2), as PBS does (proxmox-sys' lock_file). It
	// opens the file read-only, without O_CREAT, so that it never creates it
	// as root with mode 0644, which PBS's daemons, running as backup, could
	// not open; flock(2) does not need write access.
	datastoreLockHolder = `open my $p, ">", $ARGV[1] or die "$ARGV[1]: $!"; print $p $$; close $p; ` +
		`open my $f, "<", $ARGV[0] or die "$ARGV[0]: $!"; flock $f, LOCK_EX or die "flock: $!"; sleep $ARGV[2];`
	// datastoreLockProbe exits 1 while someone holds the lock, 0 when it is
	// free, and 2 when the file cannot be opened.
	datastoreLockProbe = `open my $f, "<", $ARGV[0] or exit 2; exit(flock($f, LOCK_EX | LOCK_NB) ? 0 : 1);`
)

// testAccSkipWithoutStandContainer skips a test that runs commands in the
// stand's container, without TF_ACC, without the container, or without
// docker or perl to run them; it returns the container.
func testAccSkipWithoutStandContainer(t *testing.T) string {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance tests run only with TF_ACC set")
	}
	container := os.Getenv(envAccContainer)
	if container == "" {
		t.Skipf("the test runs commands in the stand's container, which %s names; it is not set", envAccContainer)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("the test runs commands in the stand's container with docker:", err)
	}
	if out, err := exec.Command("docker", "exec", container, "perl", "-MFcntl=:flock", "-e", "1").CombinedOutput(); err != nil {
		t.Skipf("the test takes PBS's lock with perl, which the stand's container %s cannot run: %v\n%s", container, err, out)
	}
	return container
}

// testAccHoldDatastoreConfigLock takes PBS's lock of its datastore
// configuration in the stand's container, and keeps it for
// datastoreLockHold; it returns once the lock is held, with the time it saw
// it held, a moment after the holder took it. The test's cleanup ends the
// holder, should it still run.
func testAccHoldDatastoreConfigLock(t *testing.T, container string) time.Time {
	t.Helper()
	lockFile := pbsclient.DatastoreConfigLockFile
	// PBS creates the file when it first writes datastore.cfg, as the
	// datastore of the step before did.
	if out, err := exec.Command("docker", "exec", container, "test", "-e", lockFile).CombinedOutput(); err != nil {
		t.Fatalf("%s does not exist in the stand: %v\n%s", lockFile, err, out)
	}
	holder := exec.Command("docker", "exec", container, "perl", "-MFcntl=:flock", "-e", datastoreLockHolder,
		lockFile, datastoreLockPIDFile, strconv.Itoa(int(datastoreLockHold/time.Second)))
	if err := holder.Start(); err != nil {
		t.Fatalf("starting the holder of PBS's lock: %v", err)
	}
	t.Cleanup(func() {
		kill := exec.Command("docker", "exec", container, "sh", "-c", `kill "$(cat "$1")" 2>/dev/null; rm -f "$1"`,
			"sh", datastoreLockPIDFile)
		if out, err := kill.CombinedOutput(); err != nil {
			t.Errorf("ending the holder of PBS's lock: %v\n%s", err, out)
		}
		_ = holder.Wait()
	})

	deadline := time.Now().Add(20 * time.Second)
	for {
		err := exec.Command("docker", "exec", container, "perl", "-MFcntl=:flock", "-e", datastoreLockProbe, lockFile).Run()
		var exit *exec.ExitError
		switch {
		case errors.As(err, &exit) && exit.ExitCode() == 1:
			return time.Now()
		case err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 0):
			t.Fatalf("checking PBS's lock in the stand: %v", err)
		case time.Now().After(deadline):
			t.Fatalf("the holder did not take PBS's lock within 20 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// testAccDatastoreLockConfig is a datastore with a comment, and the given
// resources after it.
func testAccDatastoreLockConfig(name, dir, comment, rest string) string {
	return providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  comment      = %q
  destroy_data = true
}
`, name, dir, comment) + rest
}

// testAccCheckWaitedForDatastoreConfigLock checks that a step ended only once
// the holder taken at *lockedAt had released PBS's lock: the step succeeded,
// so its call that met the lock, refused by PBS at least once, waited for it.
func testAccCheckWaitedForDatastoreConfigLock(lockedAt *time.Time) acc.TestCheckFunc {
	return func(*terraform.State) error {
		if elapsed := time.Since(*lockedAt); elapsed < datastoreLockHold-datastoreLockSlack {
			return fmt.Errorf("the step ended %s after the lock was taken, before the holder released it after %s: "+
				"no call of the step waited for the lock", elapsed.Round(time.Second), datastoreLockHold)
		}
		return nil
	}
}

// While a task holds the lock of PBS's datastore configuration, changing a
// datastore and creating a namespace — which opens its datastore — wait for
// it rather than fail after PBS's 10 s. Each step meets the lock with one
// call: refreshing a datastore that is not removable reads datastore.cfg
// without the lock, and the steps start a new provider each, so no cool-off
// carries over.
func TestAccDatastoreConfigLockRetry(t *testing.T) {
	container := testAccSkipWithoutStandContainer(t)
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	var lockedAt time.Time
	const namespace = `
resource "pbs_namespace" "test" {
  store     = pbs_datastore.test.name
  namespace = "dept1"
}
`
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			{
				Config: testAccDatastoreLockConfig(name, dir, "Before the lock", ""),
			},
			// Under the lock, the datastore's comment changes: the update,
			// PUT /config/datastore/{name}, which takes the lock first, is
			// the step's one call to meet it.
			{
				PreConfig: func() { lockedAt = testAccHoldDatastoreConfigLock(t, container) },
				Config:    testAccDatastoreLockConfig(name, dir, "Under the lock", ""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_datastore.test", "comment", "Under the lock"),
					testAccCheckDatastoreConfig(name, func(ds pbsclient.Datastore) error {
						if ds.Comment != "Under the lock" {
							return fmt.Errorf("PBS has comment %q", ds.Comment)
						}
						return nil
					}),
					testAccCheckWaitedForDatastoreConfigLock(&lockedAt),
				),
			},
			// Under the lock again, the datastore stays as it is and a
			// namespace is created: its create, which lists the namespaces
			// and creates one, opening the datastore for each, is the step's
			// one call to meet the lock.
			{
				PreConfig: func() { lockedAt = testAccHoldDatastoreConfigLock(t, container) },
				Config:    testAccDatastoreLockConfig(name, dir, "Under the lock", namespace),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckNamespace(name, "dept1", true),
					testAccCheckWaitedForDatastoreConfigLock(&lockedAt),
				),
			},
		},
	})
}
