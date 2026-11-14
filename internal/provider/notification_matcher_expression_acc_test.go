package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Acceptance tests of pbs_notification_matcher's expression, from PBS
// 4.2.10.

// testAccSkipWithoutMatcherExpressions skips a test of matcher expressions on
// a stand older than PBS 4.2.10, which does not know them.
func testAccSkipWithoutMatcherExpressions(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") != "" && !testAccVersionAtLeast(4, 2, 10) {
		t.Skipf("the stand runs PBS %q; matcher expressions need 4.2.10", os.Getenv(envAccVersion))
	}
}

// testAccMatcherExpressionConfig is an SMTP endpoint and a matcher sending to
// it, with body.
func testAccMatcherExpressionConfig(endpoint, matcher, body string) string {
	return providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_smtp" "test" {
  name         = %q
  server       = "smtp.example.com"
  from_address = "pbs@example.com"
  mailto       = ["ops@example.com"]
}

resource "pbs_notification_matcher" "test" {
  name   = %q
  target = [pbs_notification_endpoint_smtp.test.name]
%s
}
`, endpoint, matcher, body)
}

// The rules of the example in PBS's documentation, as the configuration
// writes them, and other rules.
const (
	testAccMatcherExpressionBody = `
  expression = jsonencode({
    "all-of" = [
      { "any-of" = [
        { match = { type = "calendar", schedule = "mon..fri 09:00-17:00" } },
        { match = { type = "severity", severities = ["warning", "error"] } },
      ] },
      { match = { type = "field", field = "type", values = ["gc"] } },
    ]
  })
`
	testAccMatcherOtherExpressionBody = `
  expression = jsonencode({
    not = { match = { type = "field", field = "job-id", regex = "^daily-" } }
  })
`
)

// testAccCheckMatcherExpression checks that PBS holds the matcher with
// expression, the same rules written in any way, and without match-*
// rules, mode or invert-match; with an empty expression, that it holds
// none.
func testAccCheckMatcherExpression(name, expression string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		matcher, err := client.GetNotificationMatcher(context.Background(), name)
		if err != nil {
			return err
		}
		switch {
		case expression == "" && matcher.Expression != "":
			return fmt.Errorf("matcher %s kept its expression: %+v", name, matcher)
		case expression != "" && !sameJSONDocument(matcher.Expression, expression):
			return fmt.Errorf("matcher %s has the expression %s, want %s", name, matcher.Expression, expression)
		case expression != "" && (matcher.MatchSeverity != nil || matcher.MatchField != nil || matcher.MatchCalendar != nil ||
			matcher.Mode != "" || matcher.InvertMatch != nil):
			return fmt.Errorf("matcher %s has rules next to its expression: %+v", name, matcher)
		}
		return nil
	}
}

// A matcher with an expression, imported with a configuration that writes
// it another way than PBS stores it, and switched to match_* rules and back,
// each in one update.
func TestAccNotificationMatcherExpression(t *testing.T) {
	testAccSkipWithoutMatcherExpressions(t)
	endpoint, matcher := testAccNotificationName(), testAccNotificationName()
	const resourceName = "pbs_notification_matcher.test"
	withExpression := testAccMatcherExpressionConfig(endpoint, matcher, testAccMatcherExpressionBody)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNotificationsDestroyed([]string{endpoint}, []string{matcher}),
		Steps: []acc.TestStep{
			{
				Config: withExpression,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "expression", testMatcherExpressionEncoded),
					acc.TestCheckResourceAttr(resourceName, "mode", "all"),
					acc.TestCheckResourceAttr(resourceName, "invert_match", "false"),
					testAccCheckMatcherExpression(matcher, testMatcherExpressionStored),
				),
			},
			// The imported expression is PBS's own text; the configuration's
			// plans no change.
			{Config: withExpression, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
			{
				Config: testAccMatcherExpressionConfig(endpoint, matcher, `
  match_severity = ["error"]
  mode           = "any"
  invert_match   = true
`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "expression"),
					acc.TestCheckResourceAttr(resourceName, "mode", "any"),
					testAccCheckMatcherExpression(matcher, ""),
				),
			},
			{
				Config: testAccMatcherExpressionConfig(endpoint, matcher, testAccMatcherOtherExpressionBody),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "match_severity"),
					acc.TestCheckResourceAttr(resourceName, "mode", "all"),
					acc.TestCheckResourceAttr(resourceName, "invert_match", "false"),
					testAccCheckMatcherExpression(matcher, `{"not":{"match":{"type":"field","field":"job-id","regex":"^daily-"}}}`),
				),
			},
		},
	})
}

// terraform query lists a matcher with its expression, and the
// configuration -generate-config-out writes for it — the expression as
// jsonencode(…), next to mode "all" and invert_match false — is valid and
// plans no change.
func TestAccNotificationMatcherExpressionList(t *testing.T) {
	testAccSkipWithoutMatcherExpressions(t)
	endpoint, matcher := testAccNotificationName(), testAccNotificationName()
	config := testAccMatcherExpressionConfig(endpoint, matcher, testAccMatcherExpressionBody)
	identity := map[string]knownvalue.Check{"name": knownvalue.StringExact(matcher)}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy:             testAccCheckNotificationsDestroyed([]string{endpoint}, []string{matcher}),
		Steps: []acc.TestStep{
			{Config: config},
			{
				// The step keeps the configuration of the step before, with
				// its provider block, next to this query file.
				Query: true,
				Config: `
list "pbs_notification_matcher" "all" {
  provider         = pbs
  include_resource = true
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("pbs_notification_matcher.all", identity),
					querycheck.ExpectResourceKnownValues("pbs_notification_matcher.all", queryfilter.ByResourceIdentity(identity),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("expression"), KnownValue: knownvalue.StringFunc(func(v string) error {
								if !sameJSONDocument(v, testMatcherExpressionStored) {
									return fmt.Errorf("listed expression %s, want %s", v, testMatcherExpressionStored)
								}
								return nil
							})},
							{Path: tfjsonpath.New("mode"), KnownValue: knownvalue.StringExact("all")},
							{Path: tfjsonpath.New("match_severity"), KnownValue: knownvalue.Null()},
						}),
				},
			},
			{
				Config:          config,
				ResourceName:    "pbs_notification_matcher.test",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}
