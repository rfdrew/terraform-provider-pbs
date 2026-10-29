package provider

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_traffic_control_rule and its data sources. A rule
// limits the connections clients open to PBS, the tests' own among them, so
// the rules here match networks no client of the stand comes from: the
// documentation ranges of IPv4 and IPv6, and every IPv6 address, while the
// tests reach PBS over IPv4.

// testAccCheckTrafficControlRule checks a rule as PBS reports it.
func testAccCheckTrafficControlRule(name string, check func(pbsclient.TrafficControlRule) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		rule, err := client.GetTrafficControlRule(context.Background(), name)
		if err != nil {
			return err
		}
		return check(rule)
	}
}

// testAccCheckTrafficControlRulesDestroyed checks that the rules are gone.
func testAccCheckTrafficControlRulesDestroyed(names ...string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		for _, name := range names {
			if _, err := client.GetTrafficControlRule(context.Background(), name); err == nil {
				return fmt.Errorf("traffic control rule %s still exists", name)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		return nil
	}
}

// A rule with everything set — users from PBS 4.1 — then changed to other
// networks without time frames, users, comment and burst, imported, and read
// by the data sources. PBS writes 10MiB back as "10 MiB", which plans no
// change, and keeps a network with host bits as written.
func TestAccTrafficControlRule(t *testing.T) {
	name := "tfacc-" + testAccRandom(8)
	const resourceName = "pbs_traffic_control_rule.test"
	user := os.Getenv(envAccUsername)
	if user == "" {
		user = "tfacc@pbs"
	}
	withUsers := testAccVersionAtLeast(4, 1, 0)
	users := ""
	if withUsers {
		users = fmt.Sprintf("users     = [%q]", user)
	}
	lookups := `
data "pbs_traffic_control_rule" "test" {
  name = pbs_traffic_control_rule.test.name
}

data "pbs_traffic_control_rules" "all" {
  depends_on = [pbs_traffic_control_rule.test]
}
`
	initial := providerConfig + fmt.Sprintf(`
resource "pbs_traffic_control_rule" "test" {
  name      = %q
  network   = ["192.0.2.1/24", "::/0"]
  rate_in   = "10MiB"
  burst_in  = "20 MiB"
  rate_out  = "1.5 GB"
  timeframe = ["mon..fri 8:00-18:00", "sat,sun 10-14"]
  comment   = "terraform-provider-pbs acceptance tests"
  %s
}
`, name, users) + lookups
	changed := providerConfig + fmt.Sprintf(`
resource "pbs_traffic_control_rule" "test" {
  name     = %q
  network  = ["198.51.100.0/24", "2001:db8::/32"]
  rate_in  = "10MiB"
  rate_out = "1.5 GB"
}
`, name) + lookups

	initialChecks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr(resourceName, "id", name),
		acc.TestCheckResourceAttr(resourceName, "network.#", "2"),
		acc.TestCheckTypeSetElemAttr(resourceName, "network.*", "192.0.2.1/24"),
		acc.TestCheckTypeSetElemAttr(resourceName, "network.*", "::/0"),
		acc.TestCheckResourceAttr(resourceName, "rate_in", "10MiB"),
		acc.TestCheckResourceAttr(resourceName, "burst_in", "20 MiB"),
		acc.TestCheckNoResourceAttr(resourceName, "burst_out"),
		acc.TestCheckResourceAttr(resourceName, "timeframe.#", "2"),
		acc.TestCheckTypeSetElemAttr(resourceName, "timeframe.*", "sat,sun 10-14"),
		testAccCheckTrafficControlRule(name, func(rule pbsclient.TrafficControlRule) error {
			if rule.RateIn != "10 MiB" || rule.BurstIn != "20 MiB" || rule.RateOut != "1.5 GB" || rule.BurstOut != "" ||
				!slices.Contains(rule.Network, "192.0.2.1/24") || len(rule.Network) != 2 || len(rule.Timeframe) != 2 ||
				rule.Comment != "terraform-provider-pbs acceptance tests" {
				return fmt.Errorf("PBS has the rule as %+v", rule)
			}
			if withUsers && !slices.Equal(rule.Users, []string{user}) {
				return fmt.Errorf("PBS has the users %v, want %s", rule.Users, user)
			}
			return nil
		}),
		acc.TestCheckResourceAttr("data.pbs_traffic_control_rule.test", "rate_in", "10 MiB"),
		acc.TestCheckResourceAttr("data.pbs_traffic_control_rule.test", "network.#", "2"),
		acc.TestCheckTypeSetElemAttr("data.pbs_traffic_control_rule.test", "network.*", "192.0.2.1/24"),
		acc.TestCheckResourceAttr("data.pbs_traffic_control_rule.test", "timeframe.#", "2"),
		acc.TestCheckResourceAttr("data.pbs_traffic_control_rule.test", "comment", "terraform-provider-pbs acceptance tests"),
		testAccCheckListed("data.pbs_traffic_control_rules.all", "rules", "name", name),
		acc.TestCheckTypeSetElemNestedAttrs("data.pbs_traffic_control_rules.all", "rules.*", map[string]string{
			"name": name, "rate_out": "1.5 GB",
		}),
	}
	if withUsers {
		initialChecks = append(initialChecks,
			acc.TestCheckResourceAttr(resourceName, "users.#", "1"),
			acc.TestCheckTypeSetElemAttr(resourceName, "users.*", user),
			acc.TestCheckTypeSetElemAttr("data.pbs_traffic_control_rule.test", "users.*", user),
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckTrafficControlRulesDestroyed(name),
		Steps: []acc.TestStep{
			{
				Config: initial,
				Check:  acc.ComposeAggregateTestCheckFunc(initialChecks...),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// PBS writes sizes back its own way: "10 MiB".
				ImportStateVerifyIgnore: []string{"rate_in"},
			},
			{
				Config: changed,
				ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
				}},
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "network.#", "2"),
					acc.TestCheckTypeSetElemAttr(resourceName, "network.*", "198.51.100.0/24"),
					acc.TestCheckTypeSetElemAttr(resourceName, "network.*", "2001:db8::/32"),
					acc.TestCheckResourceAttr(resourceName, "rate_in", "10MiB"),
					acc.TestCheckNoResourceAttr(resourceName, "burst_in"),
					acc.TestCheckNoResourceAttr(resourceName, "timeframe"),
					acc.TestCheckNoResourceAttr(resourceName, "users"),
					acc.TestCheckNoResourceAttr(resourceName, "comment"),
					testAccCheckTrafficControlRule(name, func(rule pbsclient.TrafficControlRule) error {
						if !slices.Equal(rule.Network, []string{"198.51.100.0/24", "2001:db8::/32"}) &&
							!slices.Equal(rule.Network, []string{"2001:db8::/32", "198.51.100.0/24"}) {
							return fmt.Errorf("PBS has the networks %v", rule.Network)
						}
						if rule.RateIn != "10 MiB" || rule.RateOut != "1.5 GB" || rule.BurstIn != "" ||
							rule.Timeframe != nil || rule.Users != nil || rule.Comment != "" {
							return fmt.Errorf("PBS kept properties removed from the rule: %+v", rule)
						}
						return nil
					}),
					acc.TestCheckNoResourceAttr("data.pbs_traffic_control_rule.test", "timeframe"),
					acc.TestCheckNoResourceAttr("data.pbs_traffic_control_rule.test", "comment"),
					acc.TestCheckTypeSetElemAttr("data.pbs_traffic_control_rule.test", "network.*", "2001:db8::/32"),
				),
			},
		},
	})
}

// From Terraform 1.12, a rule imports by identity too. Its sizes are in
// PBS's spelling, which an import reads, so that the import block plans no
// change.
func TestAccTrafficControlRuleImportByIdentity(t *testing.T) {
	name := "tfacc-" + testAccRandom(8)
	config := providerConfig + fmt.Sprintf(`
resource "pbs_traffic_control_rule" "test" {
  name      = %q
  network   = ["192.0.2.0/24"]
  rate_in   = "10 MiB"
  timeframe = ["8-17"]
}
`, name)
	const resourceName = "pbs_traffic_control_rule.test"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckTrafficControlRulesDestroyed(name),
		Steps: []acc.TestStep{
			{Config: config},
			{Config: config, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			{Config: config, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		},
	})
}
