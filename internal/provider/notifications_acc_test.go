package provider

import (
	"context"
	"fmt"
	"slices"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_notification_endpoint_smtp and
// pbs_notification_matcher. PBS saves an SMTP endpoint without contacting its
// server, so none is needed. The tests that change the built-in
// default-matcher reset it when they end.

// testAccNotificationName returns a fresh endpoint or matcher name.
func testAccNotificationName() string {
	return "tfacc-" + testAccRandom(8)
}

// testAccCheckNotificationsDestroyed checks that the endpoints and matchers
// are gone, and that default-matcher has its built-in settings again.
func testAccCheckNotificationsDestroyed(endpoints, matchers []string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		ctx := context.Background()
		for _, name := range endpoints {
			if _, err := client.GetSMTPEndpoint(ctx, name); err == nil {
				return fmt.Errorf("SMTP endpoint %s still exists", name)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		for _, name := range matchers {
			if _, err := client.GetNotificationMatcher(ctx, name); err == nil {
				return fmt.Errorf("matcher %s still exists", name)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		return testAccCheckDefaultMatcherBuiltin(nil)
	}
}

// testAccCheckDefaultMatcherBuiltin checks that default-matcher has its
// built-in settings.
func testAccCheckDefaultMatcherBuiltin(*terraform.State) error {
	client, err := testAccClient()
	if err != nil {
		return err
	}
	matcher, err := client.GetNotificationMatcher(context.Background(), defaultMatcher)
	if err != nil {
		return err
	}
	if matcher.Origin != pbsclient.OriginBuiltin || !slices.Equal(matcher.Target, []string{"mail-to-root"}) {
		return fmt.Errorf("default-matcher is not back to its built-in settings: %+v", matcher)
	}
	return nil
}

func TestAccNotificationEndpointSMTP(t *testing.T) {
	name := testAccNotificationName()
	const resourceName = "pbs_notification_endpoint_smtp.test"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckNotificationsDestroyed([]string{name}, nil),
		Steps: []acc.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_smtp" "test" {
  name                = %q
  server              = "smtp.example.com"
  from_address        = "pbs@example.com"
  author              = "terraform-provider-pbs"
  username            = "pbs"
  password_wo         = "first-password"
  password_wo_version = 1
  mailto              = ["ops@example.com", "admin@example.com"]
  comment             = "terraform-provider-pbs acceptance tests"
}
`, name),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", name),
					acc.TestCheckResourceAttr(resourceName, "mode", "tls"),
					acc.TestCheckNoResourceAttr(resourceName, "port"),
					acc.TestCheckResourceAttr(resourceName, "origin", pbsclient.OriginUserCreated),
					acc.TestCheckResourceAttr(resourceName, "mailto.#", "2"),
					acc.TestCheckNoResourceAttr(resourceName, "password_wo"),
					acc.TestCheckResourceAttr(resourceName, "disable", "false"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_smtp" "test" {
  name                = %q
  server              = "relay.example.com"
  port                = 587
  mode                = "starttls"
  from_address        = "backup@example.com"
  username            = "pbs"
  password_wo         = "second-password"
  password_wo_version = 2
  mailto_user         = ["root@pam"]
  disable             = true
}
`, name),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "port", "587"),
					acc.TestCheckResourceAttr(resourceName, "mode", "starttls"),
					acc.TestCheckNoResourceAttr(resourceName, "mailto"),
					acc.TestCheckNoResourceAttr(resourceName, "author"),
					acc.TestCheckResourceAttr(resourceName, "mailto_user.#", "1"),
					acc.TestCheckResourceAttr(resourceName, "password_wo_version", "2"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password_wo", "password_wo_version"},
			},
			{
				// Without authentication, and with mode back at its default,
				// which PBS cannot delete and the provider writes instead.
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_smtp" "test" {
  name         = %q
  server       = "relay.example.com"
  from_address = "backup@example.com"
  mailto       = ["ops@example.com"]
}
`, name),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "mode", "tls"),
					acc.TestCheckNoResourceAttr(resourceName, "username"),
					acc.TestCheckNoResourceAttr(resourceName, "port"),
					acc.TestCheckResourceAttr(resourceName, "disable", "false"),
				),
			},
		},
	})
}

// A matcher of its own routes failed syncs to an SMTP endpoint.
func TestAccNotificationMatcher(t *testing.T) {
	endpoint, matcher := testAccNotificationName(), testAccNotificationName()
	const resourceName = "pbs_notification_matcher.test"
	config := func(matcherBody string) string {
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
`, endpoint, matcher, matcherBody)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNotificationsDestroyed([]string{endpoint}, []string{matcher}),
		Steps: []acc.TestStep{
			{
				Config: config(`
  match_severity = ["warning,error"]
  match_field    = ["exact:type=sync,verify", "regex:hostname=^pbs"]
  match_calendar = ["mon..fri 8-17"]
  mode           = "any"
  comment        = "terraform-provider-pbs acceptance tests"
`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "origin", pbsclient.OriginUserCreated),
					acc.TestCheckResourceAttr(resourceName, "mode", "any"),
					acc.TestCheckResourceAttr(resourceName, "match_field.#", "2"),
					acc.TestCheckResourceAttr(resourceName, "invert_match", "false"),
				),
			},
			{ResourceName: resourceName, ImportState: true, ImportStateVerify: true},
			{
				Config: config(`
  match_severity = ["error"]
  invert_match   = true
  disable        = true
`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "mode", "all"),
					acc.TestCheckNoResourceAttr(resourceName, "match_field"),
					acc.TestCheckNoResourceAttr(resourceName, "match_calendar"),
					acc.TestCheckNoResourceAttr(resourceName, "comment"),
					acc.TestCheckResourceAttr(resourceName, "invert_match", "true"),
				),
			},
		},
	})
}

// The main scenario: every notification goes by SMTP through the built-in
// default-matcher, imported and pointed at the SMTP endpoint; destroying it
// resets it to mail-to-root.
func TestAccNotificationDefaultMatcher(t *testing.T) {
	endpoint := testAccNotificationName()
	const resourceName = "pbs_notification_matcher.default"
	smtp := providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_smtp" "test" {
  name         = %q
  server       = "smtp.example.com"
  from_address = "pbs@example.com"
  mailto       = ["ops@example.com"]
}
`, endpoint)
	withMatcher := smtp + `
import {
  to = pbs_notification_matcher.default
  id = "default-matcher"
}

resource "pbs_notification_matcher" "default" {
  name           = "default-matcher"
  comment        = "Route everything but successful prune job notifications to SMTP"
  mode           = "all"
  invert_match   = true
  match_field    = ["exact:type=prune"]
  match_severity = ["info"]
  target         = [pbs_notification_endpoint_smtp.test.name]
}
`

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		// Import blocks arrived in Terraform 1.5, before every supported
		// release.
		CheckDestroy: testAccCheckNotificationsDestroyed([]string{endpoint}, nil),
		Steps: []acc.TestStep{
			{
				Config: withMatcher,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "origin", pbsclient.OriginModifiedBuiltin),
					acc.TestCheckResourceAttr(resourceName, "target.#", "1"),
					acc.TestCheckTypeSetElemAttr(resourceName, "target.*", endpoint),
					acc.TestCheckResourceAttr(resourceName, "invert_match", "true"),
				),
			},
			{
				// Removing the resource resets default-matcher; the endpoint
				// it targeted can then go.
				Config: smtp,
				Check:  testAccCheckDefaultMatcherBuiltin,
			},
		},
	})
}

// From Terraform 1.12, the endpoint and the matcher import by identity too.
func TestAccNotificationResourcesImportByIdentity(t *testing.T) {
	endpoint, matcher := testAccNotificationName(), testAccNotificationName()
	config := providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_smtp" "test" {
  name         = %q
  server       = "smtp.example.com"
  from_address = "pbs@example.com"
  mailto       = ["ops@example.com"]
}

resource "pbs_notification_matcher" "test" {
  name           = %q
  target         = [pbs_notification_endpoint_smtp.test.name]
  match_severity = ["error"]
}
`, endpoint, matcher)

	steps := []acc.TestStep{{Config: config}}
	for _, name := range []string{"pbs_notification_endpoint_smtp.test", "pbs_notification_matcher.test"} {
		steps = append(steps,
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckNotificationsDestroyed([]string{endpoint}, []string{matcher}),
		Steps:                    steps,
	})
}
