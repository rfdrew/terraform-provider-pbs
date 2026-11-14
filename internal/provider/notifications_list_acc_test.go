package provider

import (
	"fmt"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// The list resources of the notification endpoints, one per type, and of
// the matchers. PBS saves Gotify and webhook endpoints without contacting
// their servers, so they point at hosts that do not exist; the SMTP
// endpoint's server is never contacted either, as nothing is sent.
func TestAccNotificationListResources(t *testing.T) {
	sendmail, smtp, gotify, webhook, matcher := testAccNotificationName(), testAccNotificationName(),
		testAccNotificationName(), testAccNotificationName(), testAccNotificationName()
	identity := func(name string) map[string]knownvalue.Check {
		return map[string]knownvalue.Check{"name": knownvalue.StringExact(name)}
	}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_sendmail" "test" {
  name    = %q
  mailto  = ["ops@example.com"]
  comment = "listed by terraform query"
}

resource "pbs_notification_endpoint_smtp" "test" {
  name         = %q
  server       = "smtp.invalid"
  mode         = "starttls"
  from_address = "pbs@example.com"
  mailto       = ["ops@example.com"]
}

resource "pbs_notification_endpoint_gotify" "test" {
  name             = %q
  server           = "https://gotify.invalid"
  token_wo         = "tfacc-token"
  token_wo_version = 1
}

resource "pbs_notification_endpoint_webhook" "test" {
  name = %q
  url  = "https://hooks.invalid/{{ secrets.channel }}"

  secret = [{ name = "channel", value_wo = "alerts", value_wo_version = 1 }]
}

resource "pbs_notification_matcher" "test" {
  name           = %q
  target         = [pbs_notification_endpoint_sendmail.test.name, pbs_notification_endpoint_smtp.test.name]
  match_severity = ["error"]
  comment        = "listed by terraform query"
}
`, sendmail, smtp, gotify, webhook, matcher)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckEndpointsDestroyed(map[string][]string{"sendmail": {sendmail}, "gotify": {gotify}, "webhook": {webhook}}),
			testAccCheckNotificationsDestroyed([]string{smtp}, []string{matcher}),
		),
		Steps: []acc.TestStep{
			{Config: config},
			{
				// The step keeps the configuration of the step before, with
				// its provider block, next to this query file.
				Query: true,
				Config: `
list "pbs_notification_endpoint_sendmail" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_notification_endpoint_smtp" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_notification_endpoint_gotify" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_notification_endpoint_webhook" "all" {
  provider = pbs
}

list "pbs_notification_matcher" "all" {
  provider         = pbs
  include_resource = true
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					// Each list has the endpoints of its type, and only those;
					// the built-in entries are listed too.
					querycheck.ExpectIdentity("pbs_notification_endpoint_sendmail.all", identity(sendmail)),
					querycheck.ExpectIdentity("pbs_notification_endpoint_sendmail.all", identity(mailToRoot)),
					querycheck.ExpectNoIdentity("pbs_notification_endpoint_sendmail.all", identity(smtp)),
					querycheck.ExpectIdentity("pbs_notification_endpoint_smtp.all", identity(smtp)),
					querycheck.ExpectNoIdentity("pbs_notification_endpoint_smtp.all", identity(sendmail)),
					querycheck.ExpectIdentity("pbs_notification_endpoint_gotify.all", identity(gotify)),
					querycheck.ExpectIdentity("pbs_notification_endpoint_webhook.all", identity(webhook)),
					querycheck.ExpectNoIdentity("pbs_notification_endpoint_webhook.all", identity(gotify)),
					querycheck.ExpectIdentity("pbs_notification_matcher.all", identity(matcher)),
					querycheck.ExpectIdentity("pbs_notification_matcher.all", identity(defaultMatcher)),
					querycheck.ExpectNoIdentity("pbs_notification_matcher.all", identity(sendmail)),
					querycheck.ExpectResourceDisplayName("pbs_notification_endpoint_sendmail.all", queryfilter.ByResourceIdentity(identity(sendmail)),
						knownvalue.StringExact(sendmail+" — listed by terraform query")),
					querycheck.ExpectResourceDisplayName("pbs_notification_endpoint_smtp.all", queryfilter.ByResourceIdentity(identity(smtp)),
						knownvalue.StringExact(smtp)),
					querycheck.ExpectResourceKnownValues("pbs_notification_endpoint_smtp.all", queryfilter.ByResourceIdentity(identity(smtp)),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("mode"), KnownValue: knownvalue.StringExact("starttls")},
							{Path: tfjsonpath.New("send_test_on_apply"), KnownValue: knownvalue.Bool(false)},
						}),
					// The token is write-only: the result knows neither it nor
					// its version.
					querycheck.ExpectResourceKnownValues("pbs_notification_endpoint_gotify.all", queryfilter.ByResourceIdentity(identity(gotify)),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("server"), KnownValue: knownvalue.StringExact("https://gotify.invalid")},
							{Path: tfjsonpath.New("token_wo_version"), KnownValue: knownvalue.Null()},
							{Path: tfjsonpath.New("send_test_on_apply"), KnownValue: knownvalue.Bool(false)},
						}),
					querycheck.ExpectResourceKnownValues("pbs_notification_matcher.all", queryfilter.ByResourceIdentity(identity(matcher)),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("target"), KnownValue: knownvalue.SetExact([]knownvalue.Check{
								knownvalue.StringExact(sendmail), knownvalue.StringExact(smtp),
							})},
							{Path: tfjsonpath.New("match_severity"), KnownValue: knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("error")})},
						}),
				},
			},
			// What -generate-config-out writes for an object is the
			// configuration Terraform generates from its imported state: for
			// the types without a required secret, it plans no change.
			testAccGeneratedConfigStep(config, "pbs_notification_endpoint_sendmail.test"),
			testAccGeneratedConfigStep(config, "pbs_notification_endpoint_smtp.test"),
			testAccGeneratedConfigStep(config, "pbs_notification_matcher.test"),
		},
	})
}
