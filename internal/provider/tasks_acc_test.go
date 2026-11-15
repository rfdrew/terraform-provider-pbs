package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_tasks and pbs_task, on tasks the test makes: a
// garbage collection of a datastore of its own, which ends OK, and the
// creation of a datastore in the directory that holds the stand's
// datastores, which fails inside its task — PBS checks there that the path
// holds no other datastore (do_create_datastore, src/api2/config/
// datastore.rs, since 4.0.11) — before anything is written. A user with an
// API token, both with a role on the test's datastore only, sees the
// garbage collection through the job's privilege, and neither lists nor
// may read the failed creation. Data sources need no Terraform feature
// beyond 1.11, so the tests run on every stand, Terraform and OpenTofu.

// testAccFailingTask has PBS start a task that fails: creating datastore
// name in the directory that holds the stand's datastore, which PBS refuses
// in the task, "nested datastores not allowed". Should PBS ever create it,
// the test fails, and the datastore's configuration is removed without its
// data: the directory is the stand's. It returns the task's UPID.
func testAccFailingTask(t *testing.T, name string) string {
	t.Helper()
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ds, err := client.GetDatastore(ctx, testAccDatastore(t))
	if err != nil {
		t.Fatalf("reading the stand's datastore: %v", err)
	}
	parent := path.Dir(ds.Path)
	upid, err := client.StartTask(ctx, http.MethodPost, "/config/datastore", url.Values{"name": {name}, "path": {parent}})
	if err != nil {
		t.Fatalf("starting the creation of datastore %s in %s: %v", name, parent, err)
	}
	_, err = client.WaitTask(ctx, upid)
	var taskErr *pbsclient.TaskError
	switch {
	case errors.As(err, &taskErr):
		return upid.Raw
	case err == nil:
		if err := client.DeleteDatastore(ctx, name, pbsclient.DatastoreDeletion{}); err != nil {
			t.Errorf("removing the configuration of datastore %s: %v", name, err)
		}
		t.Fatalf("PBS created datastore %s in %s, which holds the stand's datastores, instead of refusing a nested "+
			"datastore; its configuration was removed and the directory left as it is", name, parent)
	default:
		t.Fatalf("creating datastore %s in %s: %v", name, parent, err)
	}
	return ""
}

// testAccLogTaskListings logs, without failing, how PBS lists the task upid
// right now: with the filters of the test's data source of failed tasks, and
// with fewer of them, and the first tasks of the unfiltered list in PBS's
// order with how they ended. On the packages stands, CI once saw that data
// source find the task in one step and lose it seconds later; these lines
// say which filter drops it.
func testAccLogTaskListings(t *testing.T, upid, tokenID string) {
	t.Helper()
	client, err := testAccClient()
	if err != nil {
		t.Logf("task listings: %v", err)
		return
	}
	ctx := context.Background()
	since := time.Now().Add(-time.Hour).Unix()
	variants := []struct {
		name string
		f    pbsclient.TaskListFilter
	}{
		{"as the data source", pbsclient.TaskListFilter{TypeFilter: "create-datastore", UserFilter: tokenID,
			Statuses: []string{"error"}, Since: &since}},
		{"without since", pbsclient.TaskListFilter{TypeFilter: "create-datastore", UserFilter: tokenID,
			Statuses: []string{"error"}}},
		{"without status", pbsclient.TaskListFilter{TypeFilter: "create-datastore", UserFilter: tokenID, Since: &since}},
		{"since only", pbsclient.TaskListFilter{Since: &since}},
		{"no filter", pbsclient.TaskListFilter{}},
	}
	for _, v := range variants {
		tasks, err := client.ListTasks(ctx, client.Node(), v.f)
		if err != nil {
			t.Logf("task listings, %s: %v", v.name, err)
			continue
		}
		found := "missing"
		for i, task := range tasks {
			if task.UPID == upid {
				found = fmt.Sprintf("at %d, status %s", i, testAccTaskStatusText(task))
			}
		}
		t.Logf("task listings, %s: %d tasks, the failed creation %s", v.name, len(tasks), found)
		if v.name == "no filter" {
			for i, task := range tasks[:min(len(tasks), 40)] {
				end := "running"
				if task.EndTime != nil {
					end = time.Unix(*task.EndTime, 0).UTC().Format(time.RFC3339)
				}
				t.Logf("  %2d %s start %s end %s status %s", i, task.UPID,
					time.Unix(task.StartTime, 0).UTC().Format(time.RFC3339), end, testAccTaskStatusText(task))
			}
		}
	}
}

// testAccTaskStatusText is a listed task's status, or "running".
func testAccTaskStatusText(task pbsclient.TaskListItem) string {
	if task.Status == nil {
		return "running"
	}
	return *task.Status
}

// testAccTaskUser creates a user with an API token, neither with a role
// yet, and deletes the user with its token and their ACL entries when the
// test ends. It returns the user ID, the token ID and the token's secret.
func testAccTaskUser(t *testing.T) (userID, tokenID, secret string) {
	t.Helper()
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	userID = testAccUserID()
	if err := client.CreateUser(ctx, url.Values{"userid": {userID}, "comment": {"terraform-provider-pbs acceptance tests"}}); err != nil {
		t.Fatalf("creating user %s: %v", userID, err)
	}
	t.Cleanup(func() {
		if err := client.DeleteUser(context.Background(), userID); err != nil && !pbsclient.IsNotFound(err) {
			t.Errorf("deleting user %s: %v", userID, err)
		}
	})
	tokenID, secret, err = client.CreateAPIToken(ctx, userID, "tasks", url.Values{})
	if err != nil {
		t.Fatalf("creating an API token of %s: %v", userID, err)
	}
	return userID, tokenID, secret
}

// testAccCheckEveryListed checks that every element of a list attribute has
// the value given as its key attribute.
func testAccCheckEveryListed(resourceName, list, key, value string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("%s is not in state", resourceName)
		}
		attributes := rs.Primary.Attributes
		n, _ := strconv.Atoi(attributes[list+".#"])
		for i := range n {
			if got := attributes[fmt.Sprintf("%s.%d.%s", list, i, key)]; got != value {
				return fmt.Errorf("%s lists %s %q, want only %q", resourceName, key, got, value)
			}
		}
		return nil
	}
}

// testAccCheckListedMatches checks that the element of a list attribute
// whose key attribute has the value given has an attribute matching
// pattern.
func testAccCheckListedMatches(resourceName, list, key, value, attribute string, pattern *regexp.Regexp) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("%s is not in state", resourceName)
		}
		attributes := rs.Primary.Attributes
		n, _ := strconv.Atoi(attributes[list+".#"])
		for i := range n {
			if attributes[fmt.Sprintf("%s.%d.%s", list, i, key)] != value {
				continue
			}
			if got := attributes[fmt.Sprintf("%s.%d.%s", list, i, attribute)]; !pattern.MatchString(got) {
				return fmt.Errorf("%s lists %s %q with %s %q, which does not match %s", resourceName, key, value, attribute, got, pattern)
			}
			return nil
		}
		return fmt.Errorf("%s lists no %s %q", resourceName, key, value)
	}
}

// testAccUTCTime is a time as the data sources report it.
var testAccUTCTime = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)

func TestAccTasksDataSources(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	testAccPreCheck(t)
	tokenID, _, err := pbsclient.SplitAPIToken(os.Getenv(envAPIToken))
	if err != nil {
		t.Fatal(err)
	}
	name, failName := testAccDatastoreName(), testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	userID, limitedTokenID, limitedSecret := testAccTaskUser(t)

	const (
		gc      = "data.pbs_tasks.gc"
		failed  = "data.pbs_tasks.failed"
		store   = "data.pbs_tasks.store"
		running = "data.pbs_tasks.running"
		task    = "data.pbs_task.gc"
		limited = "data.pbs_tasks.limited"
	)
	datastore := providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  comment      = "terraform-provider-pbs acceptance tests"
  destroy_data = true
}
`, name, dir)
	reads := datastore + fmt.Sprintf(`
data "pbs_tasks" "gc" {
  store       = pbs_datastore.test.name
  worker_type = "garbage_collection"
  limit       = 1
}

# Other tests fail to create datastores as this token too: limit = 0 lists
# every failure of the last hour, this test's among them.
data "pbs_tasks" "failed" {
  worker_type = "create-datastore"
  status      = ["error"]
  auth_id     = %q
  since       = timeadd(plantimestamp(), "-1h")
  limit       = 0
}

data "pbs_tasks" "store" {
  store = pbs_datastore.test.name
  limit = 0
}

data "pbs_tasks" "running" {
  running = true
}

data "pbs_task" "gc" {
  upid      = data.pbs_tasks.gc.tasks[0].upid
  log_lines = 3
}
`, tokenID)
	limitedReads := reads + fmt.Sprintf(`
provider "pbs" {
  alias     = "limited"
  api_token = %q
}

data "pbs_tasks" "limited" {
  provider = pbs.limited
  since    = timeadd(plantimestamp(), "-1h")
  limit    = 0
}
`, limitedTokenID+":"+limitedSecret)
	// The failed creation is named by its UPID, not looked up in
	// data.pbs_tasks.failed: that data source found it in step 2 but, on the
	// packages stands, lost it seconds later (see testAccLogTaskListings).
	// Step 2 writes the UPID to a file, which the configuration reads when
	// it is planned: it is built before the task exists.
	var failUPID string
	upidFile := filepath.Join(t.TempDir(), "failed-task-upid")
	denied := limitedReads + fmt.Sprintf(`
data "pbs_task" "denied" {
  provider = pbs.limited
  upid     = trimspace(file(%q))
}
`, upidFile)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name, failName}, nil, nil),
		Steps: []acc.TestStep{
			{Config: datastore},
			{
				PreConfig: func() {
					testAccDatastoreTask(t, name, "gc")
					failUPID = testAccFailingTask(t, failName)
					if err := os.WriteFile(upidFile, []byte(failUPID), 0o600); err != nil {
						t.Fatal(err)
					}
				},
				Config: reads,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttrSet(gc, "node"),
					acc.TestCheckResourceAttr(gc, "sees_all_tasks", "true"),
					acc.TestCheckResourceAttr(gc, "tasks.#", "1"),
					acc.TestCheckResourceAttr(gc, "tasks.0.worker_type", "garbage_collection"),
					acc.TestCheckResourceAttr(gc, "tasks.0.worker_id", name),
					acc.TestCheckResourceAttr(gc, "tasks.0.auth_id", tokenID),
					acc.TestCheckResourceAttr(gc, "tasks.0.status", "ok"),
					acc.TestCheckResourceAttr(gc, "tasks.0.exit_status", "OK"),
					acc.TestMatchResourceAttr(gc, "tasks.0.upid", regexp.MustCompile(`^UPID:.*:garbage_collection:`)),
					acc.TestMatchResourceAttr(gc, "tasks.0.start_time", testAccUTCTime),
					acc.TestMatchResourceAttr(gc, "tasks.0.end_time", testAccUTCTime),
					acc.TestMatchResourceAttr(gc, "tasks.0.duration", regexp.MustCompile(`^[0-9]+$`)),

					acc.TestCheckTypeSetElemNestedAttrs(failed, "tasks.*", map[string]string{
						"worker_type": "create-datastore", "worker_id": failName, "auth_id": tokenID, "status": "error",
					}),
					testAccCheckListedMatches(failed, "tasks", "worker_id", failName, "exit_status",
						regexp.MustCompile(`nested datastores not allowed`)),
					testAccCheckEveryListed(failed, "tasks", "status", "error"),

					// The creation of a datastore is not among its tasks.
					acc.TestCheckTypeSetElemNestedAttrs(store, "tasks.*", map[string]string{
						"worker_type": "garbage_collection", "worker_id": name,
					}),
					testAccCheckNotListed(store, "tasks", "worker_type", "create-datastore"),

					acc.TestCheckResourceAttrSet(running, "tasks.#"),
					testAccCheckEveryListed(running, "tasks", "status", "running"),

					// The end PBS lists, which pbs_task works out from the
					// log before PBS 4.2.1.
					acc.TestCheckResourceAttrPair(task, "upid", gc, "tasks.0.upid"),
					acc.TestCheckResourceAttrPair(task, "start_time", gc, "tasks.0.start_time"),
					acc.TestCheckResourceAttrPair(task, "end_time", gc, "tasks.0.end_time"),
					acc.TestCheckResourceAttrPair(task, "duration", gc, "tasks.0.duration"),
					acc.TestCheckResourceAttr(task, "worker_type", "garbage_collection"),
					acc.TestCheckResourceAttr(task, "worker_id", name),
					acc.TestCheckResourceAttr(task, "auth_id", tokenID),
					acc.TestCheckResourceAttr(task, "status", "ok"),
					acc.TestCheckResourceAttr(task, "exit_status", "OK"),
					acc.TestCheckResourceAttr(task, "log.#", "3"),
					acc.TestMatchResourceAttr(task, "log.2", regexp.MustCompile(`^\S+: TASK OK$`)),
				),
			},
			{
				// The role on the datastore holds Datastore.Modify, which
				// shows its garbage collections, and not Sys.Audit; the
				// creation of a datastore is no job's, and the token's user
				// did not start it.
				PreConfig: func() {
					testAccLogTaskListings(t, failUPID, tokenID)
					testAccMustGrant(t, "/datastore/"+name, userID, "DatastoreAdmin")
					testAccMustGrant(t, "/datastore/"+name, limitedTokenID, "DatastoreAdmin")
					testAccWaitForACLCache()
					testAccLogTaskListings(t, failUPID, tokenID)
				},
				Config:      denied,
				ExpectError: regexp.MustCompile(`may\s+not\s+read\s+task|task\s+access\s+not\s+allowed`),
			},
			// Last, so that the destroy, which reads the data sources
			// first, does not meet the failing one.
			{
				PreConfig: func() { testAccLogTaskListings(t, failUPID, tokenID) },
				Config:    limitedReads,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(limited, "sees_all_tasks", "false"),
					acc.TestCheckTypeSetElemNestedAttrs(limited, "tasks.*", map[string]string{
						"worker_type": "garbage_collection", "worker_id": name, "auth_id": tokenID,
					}),
					testAccCheckNotListed(limited, "tasks", "worker_id", failName),
				),
			},
		},
	})
}
