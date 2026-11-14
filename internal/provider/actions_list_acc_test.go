package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-version"
	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

// Acceptance tests of actions and list resources run on Terraform 1.14 and
// later only. Terraform 1.14.0 ran after_create and after_update actions
// before the resource had finished (hashicorp/terraform#37930), so actions
// are tested from 1.14.1. OpenTofu has neither, whatever version it reports:
// its 1.14 would pass the version check and then fail on `action` blocks.
var (
	actionVersionChecks = []tfversion.TerraformVersionCheck{
		skipOpenTofu{}, tfversion.SkipBelow(version.Must(version.NewVersion("1.14.1"))),
	}
	queryVersionChecks = []tfversion.TerraformVersionCheck{skipOpenTofu{}, tfversion.SkipBelow(tfversion.Version1_14_0)}
)

// skipOpenTofu skips a test when it runs on OpenTofu, which CI says with
// TF_ACC_PROVIDER_HOST and TF_ACC_TERRAFORM_PATH.
type skipOpenTofu struct{}

func (skipOpenTofu) CheckTerraformVersion(_ context.Context, _ tfversion.CheckTerraformVersionRequest, resp *tfversion.CheckTerraformVersionResponse) {
	if os.Getenv("TF_ACC_PROVIDER_HOST") == "registry.opentofu.org" ||
		strings.HasPrefix(filepath.Base(os.Getenv("TF_ACC_TERRAFORM_PATH")), "tofu") {
		resp.Skip = "OpenTofu supports neither actions nor list resources"
	}
}

// testAccActionTrigger returns a terraform_data resource that invokes the
// action at address whenever it is created or its input changes: how a test
// invokes an action, since terraform-plugin-testing cannot run
// `terraform apply -invoke`.
func testAccActionTrigger(address, input string) string {
	return fmt.Sprintf(`
resource "terraform_data" "trigger" {
  input = %q

  lifecycle {
    action_trigger {
      events  = [after_create, after_update]
      actions = [%s]
    }
  }
}
`, input, address)
}

func TestAccDatastoreGCAction(t *testing.T) {
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	datastore := providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  destroy_data = true
}
`, name, dir)
	action := `
action "pbs_datastore_gc" "test" {
  config {
    store = pbs_datastore.test.name
  }
}
`

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			// The datastore first: a new datastore has never been garbage
			// collected, so a garbage collection afterwards is the action's.
			{Config: datastore, Check: testAccCheckGCRuns(name, 0)},
			{Config: datastore + action + testAccActionTrigger("action.pbs_datastore_gc.test", "1"), Check: testAccCheckGCRuns(name, 1)},
		},
	})
}

// testAccCheckGCRuns checks whether datastore name has been garbage
// collected: never (0), or once at least.
func testAccCheckGCRuns(name string, atLeast int) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		status, ok, err := client.GCJobStatus(context.Background(), name)
		switch {
		case err != nil:
			return err
		case !ok:
			return fmt.Errorf("PBS shows no garbage collection status of datastore %s", name)
		case atLeast == 0 && status.UPID != "":
			return fmt.Errorf("datastore %s was garbage collected already: %s", name, status.UPID)
		case atLeast > 0 && !strings.Contains(status.UPID, ":garbage_collection:"):
			return fmt.Errorf("datastore %s was not garbage collected: %+v", name, status)
		}
		return nil
	}
}

func TestAccUserListResource(t *testing.T) {
	userID := "tfacc-list-" + testAccRandom(6) + "@pbs"
	identity := map[string]knownvalue.Check{"userid": knownvalue.StringExact(userID)}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_user" "test" {
  userid    = %q
  comment   = "listed by terraform query"
  firstname = "List"
}
`, userID)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		Steps: []acc.TestStep{
			{Config: config},
			{
				// The step keeps the configuration of the step before, with
				// its provider block, next to this query file.
				Query: true,
				Config: `
list "pbs_user" "pbs" {
  provider         = pbs
  include_resource = true

  config {
    realm = "pbs"
  }
}

list "pbs_user" "pam" {
  provider = pbs

  config {
    realm = "pam"
  }
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("pbs_user.pbs", identity),
					querycheck.ExpectNoIdentity("pbs_user.pam", identity),
					querycheck.ExpectIdentity("pbs_user.pam", map[string]knownvalue.Check{"userid": knownvalue.StringExact("root@pam")}),
					querycheck.ExpectResourceDisplayName("pbs_user.pbs", queryfilter.ByResourceIdentity(identity),
						knownvalue.StringExact(userID+" — listed by terraform query")),
					querycheck.ExpectResourceKnownValues("pbs_user.pbs", queryfilter.ByResourceIdentity(identity), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("firstname"), KnownValue: knownvalue.StringExact("List")},
						{Path: tfjsonpath.New("enable"), KnownValue: knownvalue.Bool(true)},
					}),
				},
			},
			// What -generate-config-out writes for an object is the
			// configuration Terraform generates from its imported state:
			// it must plan no change.
			{
				Config:          config,
				ResourceName:    "pbs_user.test",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}
