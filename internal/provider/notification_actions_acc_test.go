package provider

import (
	"fmt"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// The action has PBS send a test notification through a webhook endpoint to
// a receiver the test runs: once the endpoint exists, and again once it is
// disabled, which PBS tests all the same.
func TestAccNotificationTestAction(t *testing.T) {
	receiver := newTestAccWebhookReceiver(t)
	name := testAccNotificationName()
	endpoint := func(disable bool) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_webhook" "test" {
  name    = %q
  url     = "%s/hook"
  body    = jsonencode({ title = "{{ title }}", severity = "{{ severity }}" })
  disable = %t
}
`, name, receiver.url, disable)
	}
	action := `
action "pbs_notification_test" "test" {
  config {
    name = pbs_notification_endpoint_webhook.test.name
  }
}
`
	nothingReceived := func(*terraform.State) error {
		receiver.mu.Lock()
		defer receiver.mu.Unlock()
		if len(receiver.requests) != 0 {
			return fmt.Errorf("the receiver got %+v", receiver.requests)
		}
		return nil
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		CheckDestroy:             testAccCheckEndpointsDestroyed(map[string][]string{"webhook": {name}}),
		Steps: []acc.TestStep{
			{Config: endpoint(false), Check: nothingReceived},
			{
				Config: endpoint(false) + action + testAccActionTrigger("action.pbs_notification_test.test", "1"),
				Check:  receiver.received(1, "/hook", ""),
			},
			{
				Config: endpoint(true) + action + testAccActionTrigger("action.pbs_notification_test.test", "2"),
				Check:  receiver.received(2, "/hook", ""),
			},
		},
	})
}
