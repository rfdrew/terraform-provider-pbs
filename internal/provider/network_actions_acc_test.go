package provider

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// The action applies a change made outside Terraform, and when nothing is
// pending it reloads nothing. The test changes one of the stand's veth NICs
// only, and testAccRestoreNetwork puts it back.
func TestAccNetworkReloadAction(t *testing.T) {
	nics := testAccNetworkNICs(t)
	if !testAccNetworkReload() {
		t.Skipf("%s is not set: PBS cannot apply network changes on this stand", envAccNetworkReload)
	}
	client := testAccNetworkAdmin(t)
	testAccRestoreNetwork(t, client, nil, nics)
	const comment = "applied by pbs_network_reload"
	start := time.Now()
	// reloads are the network reloads PBS ran before the last step.
	var reloads []string
	reloadsSince := func() ([]string, error) {
		tasks, err := testAccTasksOfType("srvreload", start)
		if err != nil {
			return nil, err
		}
		var upids []string
		for _, task := range tasks {
			if task.WorkerID == "networking" {
				upids = append(upids, task.UPID)
			}
		}
		return upids, nil
	}
	config := func(input string) string {
		return providerConfig + `
action "pbs_network_reload" "test" {
  config {
    timeout = "5m"
  }
}
` + testAccActionTrigger("action.pbs_network_reload.test", input)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		Steps: []acc.TestStep{
			{
				PreConfig: func() {
					params := map[string][]string{"comments": {comment}}
					if err := client.UpdateNetworkInterface(context.Background(), client.Node(), nics[0], params); err != nil {
						t.Fatalf("changing %s outside Terraform: %v", nics[0], err)
					}
				},
				Config: config("pending"),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckNetworkPending(false),
					testAccCheckTaskEnded("srvreload", &start, false),
					func(*terraform.State) error {
						// With nothing pending, PBS lists the running file.
						iface, err := client.NetworkInterface(context.Background(), client.Node(), nics[0])
						if err != nil {
							return err
						}
						if iface.Comments != comment {
							return fmt.Errorf("%s runs with comments %q", nics[0], iface.Comments)
						}
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					var err error
					if reloads, err = reloadsSince(); err != nil {
						t.Fatal(err)
					}
				},
				Config: config("nothing pending"),
				Check: func(*terraform.State) error {
					now, err := reloadsSince()
					if err != nil {
						return err
					}
					for _, upid := range now {
						if !slices.Contains(reloads, upid) {
							return fmt.Errorf("PBS reloaded the network with nothing pending: %s", upid)
						}
					}
					return nil
				},
			},
		},
	})
}
