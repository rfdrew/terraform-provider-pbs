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

// testAccTask is a task as GET /nodes/{node}/tasks lists it.
type testAccTask struct {
	UPID       string `json:"upid"`
	WorkerType string `json:"worker_type"`
	WorkerID   string `json:"worker_id"`
	Status     string `json:"status"`
}

// testAccTasksOfType lists the tasks of a worker type the stand started
// since a time, which ended or not, newest first. PBS's typefilter matches
// a part of the type, so the type is compared again.
func testAccTasksOfType(workerType string, since time.Time) ([]testAccTask, error) {
	client, err := testAccClient()
	if err != nil {
		return nil, err
	}
	var tasks []testAccTask
	params := url.Values{
		"typefilter": {workerType},
		// A second earlier: PBS keeps start times in whole seconds.
		"since": {strconv.FormatInt(since.Unix()-1, 10)},
		"limit": {"0"},
	}
	if _, err := client.Get(context.Background(), pbsclient.Path("nodes", client.Node(), "tasks"), params, &tasks); err != nil {
		return nil, err
	}
	matching := tasks[:0]
	for _, task := range tasks {
		if task.WorkerType == workerType {
			matching = append(matching, task)
		}
	}
	return matching, nil
}

// testAccCheckTaskEnded checks that a task of a worker type started since
// a time ended without an error: OK, or with warnings when warningsAllowed.
func testAccCheckTaskEnded(workerType string, since *time.Time, warningsAllowed bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		tasks, err := testAccTasksOfType(workerType, *since)
		if err != nil {
			return err
		}
		if len(tasks) == 0 {
			return fmt.Errorf("PBS ran no %s task since %s", workerType, since.Format(time.RFC3339))
		}
		status := tasks[0].Status
		switch {
		case status == "OK":
		case warningsAllowed && strings.HasPrefix(status, "WARNINGS"):
		default:
			return fmt.Errorf("task %s ended with %q", tasks[0].UPID, status)
		}
		return nil
	}
}

// The APT update refreshes the stand's package lists. The stand may have
// the enterprise repository without a subscription, which apt fails to
// fetch, and PBS then ends the task with warnings, which the action reports
// as such: both outcomes pass, and PBS lists the updates afterwards.
func TestAccAPTUpdateAction(t *testing.T) {
	var start time.Time
	config := providerConfig + `
action "pbs_apt_update" "test" {
  config {
    timeout = "10m"
  }
}
` + testAccActionTrigger("action.pbs_apt_update.test", "1")

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		Steps: []acc.TestStep{
			{
				PreConfig: func() { start = time.Now() },
				Config:    config,
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckTaskEnded("aptupdate", &start, true),
					func(*terraform.State) error {
						client, err := testAccClient()
						if err != nil {
							return err
						}
						_, err = client.APTUpdates(context.Background(), client.Node())
						return err
					},
				),
			},
		},
	})
}
