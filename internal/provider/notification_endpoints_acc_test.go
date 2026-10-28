package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_notification_endpoint_sendmail, _gotify and
// _webhook, send_test_on_apply and the notification data sources. PBS saves
// Gotify and webhook endpoints without contacting their servers, so the
// tests point them at hosts that do not exist; send_test_on_apply sends to a
// receiver the test runs, at PBS_ACC_HOST_ADDRESS.

// envAccHostAddress is the address at which the PBS container reaches the
// host the tests run on.
const envAccHostAddress = "PBS_ACC_HOST_ADDRESS"

// testAccCheckEndpointsDestroyed checks that the endpoints, by type, are gone,
// and that mail-to-root has its built-in settings again.
func testAccCheckEndpointsDestroyed(endpoints map[string][]string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		ctx := context.Background()
		for kind, names := range endpoints {
			for _, name := range names {
				var err error
				switch kind {
				case "sendmail":
					_, err = client.GetSendmailEndpoint(ctx, name)
				case "gotify":
					_, err = client.GetGotifyEndpoint(ctx, name)
				case "webhook":
					_, err = client.GetWebhookEndpoint(ctx, name)
				default:
					return fmt.Errorf("unknown endpoint type %s", kind)
				}
				if err == nil {
					return fmt.Errorf("%s endpoint %s still exists", kind, name)
				} else if !pbsclient.IsNotFound(err) {
					return err
				}
			}
		}
		return testAccCheckMailToRootBuiltin(nil)
	}
}

// testAccCheckMailToRootBuiltin checks that mail-to-root has its built-in
// settings.
func testAccCheckMailToRootBuiltin(*terraform.State) error {
	client, err := testAccClient()
	if err != nil {
		return err
	}
	endpoint, err := client.GetSendmailEndpoint(context.Background(), mailToRoot)
	if err != nil {
		return err
	}
	if endpoint.Origin != pbsclient.OriginBuiltin || !slices.Equal(endpoint.MailtoUser, []string{"root@pam"}) || len(endpoint.Mailto) != 0 {
		return fmt.Errorf("mail-to-root is not back to its built-in settings: %+v", endpoint)
	}
	return nil
}

func TestAccNotificationEndpointSendmail(t *testing.T) {
	name := testAccNotificationName()
	const resourceName = "pbs_notification_endpoint_sendmail.test"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckEndpointsDestroyed(map[string][]string{"sendmail": {name}}),
		Steps: []acc.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_sendmail" "test" {
  name         = %q
  mailto       = ["ops@example.com", "admin@example.com"]
  from_address = "pbs@example.com"
  author       = "terraform-provider-pbs"
  comment      = "terraform-provider-pbs acceptance tests"
}
`, name),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", name),
					acc.TestCheckResourceAttr(resourceName, "origin", pbsclient.OriginUserCreated),
					acc.TestCheckResourceAttr(resourceName, "mailto.#", "2"),
					acc.TestCheckResourceAttr(resourceName, "disable", "false"),
					acc.TestCheckResourceAttr(resourceName, "send_test_on_apply", "false"),
				),
			},
			{ResourceName: resourceName, ImportState: true, ImportStateVerify: true},
			{
				// Sender and author back to PBS's defaults.
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_sendmail" "test" {
  name        = %q
  mailto_user = ["root@pam"]
  disable     = true
}
`, name),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "mailto"),
					acc.TestCheckNoResourceAttr(resourceName, "from_address"),
					acc.TestCheckNoResourceAttr(resourceName, "author"),
					acc.TestCheckResourceAttr(resourceName, "mailto_user.#", "1"),
					acc.TestCheckResourceAttr(resourceName, "disable", "true"),
				),
			},
		},
	})
}

// The built-in mail-to-root is imported and changed; removing the resource
// resets it, while default-matcher keeps targeting it.
func TestAccNotificationEndpointMailToRoot(t *testing.T) {
	const resourceName = "pbs_notification_endpoint_sendmail.root"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckMailToRootBuiltin,
		Steps: []acc.TestStep{
			{
				Config: providerConfig + `
import {
  to = pbs_notification_endpoint_sendmail.root
  id = "mail-to-root"
}

resource "pbs_notification_endpoint_sendmail" "root" {
  name        = "mail-to-root"
  comment     = "Send mails to root@pam's email address"
  mailto_user = ["root@pam"]
  mailto      = ["ops@example.com"]
}
`,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "origin", pbsclient.OriginModifiedBuiltin),
					acc.TestCheckResourceAttr(resourceName, "mailto.#", "1"),
				),
			},
			{
				Config: providerConfig,
				Check:  testAccCheckMailToRootBuiltin,
			},
		},
	})
}

func TestAccNotificationEndpointGotify(t *testing.T) {
	name := testAccNotificationName()
	const resourceName = "pbs_notification_endpoint_gotify.test"
	config := func(server string, version int, extra string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_gotify" "test" {
  name             = %q
  server           = %q
  token_wo         = "token-%d"
  token_wo_version = %d
%s
}
`, name, server, version, version, extra)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckEndpointsDestroyed(map[string][]string{"gotify": {name}}),
		Steps: []acc.TestStep{
			{
				// The host does not exist: PBS does not contact it.
				Config: config("https://gotify.invalid", 1, `  comment = "terraform-provider-pbs acceptance tests"`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "server", "https://gotify.invalid"),
					acc.TestCheckResourceAttr(resourceName, "origin", pbsclient.OriginUserCreated),
					acc.TestCheckNoResourceAttr(resourceName, "token_wo"),
					acc.TestCheckResourceAttr(resourceName, "token_wo_version", "1"),
				),
			},
			{
				Config: config("http://gotify.invalid:8080/push", 2, `  disable = true`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "server", "http://gotify.invalid:8080/push"),
					acc.TestCheckNoResourceAttr(resourceName, "comment"),
					acc.TestCheckResourceAttr(resourceName, "disable", "true"),
					acc.TestCheckResourceAttr(resourceName, "token_wo_version", "2"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"token_wo", "token_wo_version"},
			},
		},
	})
}

func TestAccNotificationEndpointWebhook(t *testing.T) {
	name := testAccNotificationName()
	const resourceName = "pbs_notification_endpoint_webhook.test"
	config := func(body string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_webhook" "test" {
  name = %q
  url  = "https://hooks.invalid/{{ secrets.channel }}?title={{ url-encode title }}"
%s
}
`, name, body)
	}
	checkSecretNames := func(want ...string) acc.TestCheckFunc {
		return func(*terraform.State) error {
			client, err := testAccClient()
			if err != nil {
				return err
			}
			endpoint, err := client.GetWebhookEndpoint(context.Background(), name)
			if err != nil {
				return err
			}
			var names []string
			for _, s := range endpoint.Secret {
				secretName, value, err := pbsclient.ParseNotificationKeyValue(s)
				if err != nil || value != nil {
					return fmt.Errorf("PBS returned the secret %q, want a name without a value", s)
				}
				names = append(names, secretName)
			}
			if !slices.Equal(names, want) {
				return fmt.Errorf("PBS has the secrets %v, want %v", names, want)
			}
			return nil
		}
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckEndpointsDestroyed(map[string][]string{"webhook": {name}}),
		Steps: []acc.TestStep{
			{
				Config: config(`
  method = "put"
  body   = jsonencode({ text = "{{ escape title }}", severity = "{{ severity }}" })
  header = [
    { name = "Content-Type", value = "application/json" },
    { name = "Authorization", value = "Bearer {{ secrets.token }}" },
  ]
  secret = [
    { name = "token", value_wo = "t0ken", value_wo_version = 1 },
    { name = "channel", value_wo = "alerts", value_wo_version = 1 },
  ]
  comment = "terraform-provider-pbs acceptance tests"
`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "method", "put"),
					acc.TestCheckResourceAttr(resourceName, "header.1.value", "Bearer {{ secrets.token }}"),
					acc.TestCheckResourceAttr(resourceName, "body", `{"severity":"{{ severity }}","text":"{{ escape title }}"}`),
					acc.TestCheckResourceAttr(resourceName, "secret.#", "2"),
					acc.TestCheckNoResourceAttr(resourceName, "secret.0.value_wo"),
					acc.TestCheckResourceAttr(resourceName, "origin", pbsclient.OriginUserCreated),
					checkSecretNames("token", "channel"),
				),
			},
			{
				// PBS never returns the secrets' values, so an import
				// leaves every value_wo_version null.
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"secret.0.value_wo", "secret.0.value_wo_version", "secret.1.value_wo", "secret.1.value_wo_version",
				},
			},
			{
				// A new version of one secret, another kept by name, a new
				// one added.
				Config: config(`
  method = "put"
  body   = jsonencode({ text = "{{ escape title }}", severity = "{{ severity }}" })
  header = [
    { name = "Content-Type", value = "application/json" },
    { name = "Authorization", value = "Bearer {{ secrets.token }}" },
  ]
  secret = [
    { name = "token", value_wo = "t0ken-2", value_wo_version = 2 },
    { name = "channel", value_wo = "alerts", value_wo_version = 1 },
    { name = "extra", value_wo = "x", value_wo_version = 1 },
  ]
`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "secret.0.value_wo_version", "2"),
					acc.TestCheckNoResourceAttr(resourceName, "comment"),
					checkSecretNames("token", "channel", "extra"),
				),
			},
			{
				// Everything optional left out: secrets, headers and body
				// are deleted, and method goes back to post.
				Config: config(""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "method", "post"),
					acc.TestCheckNoResourceAttr(resourceName, "secret"),
					acc.TestCheckNoResourceAttr(resourceName, "header"),
					acc.TestCheckNoResourceAttr(resourceName, "body"),
					checkSecretNames(),
				),
			},
		},
	})
}

// testAccWebhookReceiver receives what PBS sends to a webhook: a server on
// every interface of the host, which the PBS container reaches at
// PBS_ACC_HOST_ADDRESS. The test skips without that address.
type testAccWebhookReceiver struct {
	url      string
	mu       sync.Mutex
	requests []testAccWebhookRequest
}

type testAccWebhookRequest struct {
	method, path, authorization string
	body                        map[string]any
}

func newTestAccWebhookReceiver(t *testing.T) *testAccWebhookReceiver {
	t.Helper()
	host := os.Getenv(envAccHostAddress)
	if host == "" {
		t.Skipf("%s is not set, so PBS cannot reach a receiver on this host", envAccHostAddress)
	}
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	r := &testAccWebhookReceiver{
		url: "http://" + net.JoinHostPort(host, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)),
	}
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		r.mu.Lock()
		r.requests = append(r.requests, testAccWebhookRequest{
			method: req.Method, path: req.URL.Path, authorization: req.Header.Get("Authorization"), body: body,
		})
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return r
}

// received checks the requests PBS sent so far: count of them, the last one
// rendered with the secrets' values.
func (r *testAccWebhookReceiver) received(count int, path, authorization string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.requests) != count {
			return fmt.Errorf("the receiver got %d requests, want %d: %+v", len(r.requests), count, r.requests)
		}
		last := r.requests[len(r.requests)-1]
		title, _ := last.body["title"].(string)
		if last.method != http.MethodPost || last.path != path || last.authorization != authorization ||
			last.body["severity"] != "info" || title == "" {
			return fmt.Errorf("the receiver got %+v, want a POST to %s with Authorization %q and a rendered body", last, path, authorization)
		}
		return nil
	}
}

// send_test_on_apply has PBS send a test notification through the webhook,
// rendered with its secrets, after the create and after a change; a test
// that cannot be delivered fails the apply.
func TestAccNotificationEndpointSendTestOnApply(t *testing.T) {
	receiver := newTestAccWebhookReceiver(t)
	name, unreachable := testAccNotificationName(), testAccNotificationName()
	config := func(token string, version int, comment string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_webhook" "test" {
  name               = %q
  url                = "%s/{{ secrets.path }}"
  body               = jsonencode({ title = "{{ title }}", severity = "{{ severity }}" })
  header             = [{ name = "Authorization", value = "Bearer {{ secrets.token }}" }]
  secret             = [
    { name = "path", value_wo = "hook", value_wo_version = 1 },
    { name = "token", value_wo = %q, value_wo_version = %d },
  ]
  comment            = %q
  send_test_on_apply = true
}
`, name, receiver.url, token, version, comment)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckEndpointsDestroyed(map[string][]string{"webhook": {name, unreachable}}),
		Steps: []acc.TestStep{
			{
				Config: config("t0ken", 1, "first"),
				Check:  receiver.received(1, "/hook", "Bearer t0ken"),
			},
			{
				// A refresh and an unchanged plan send nothing, as the next
				// step's count shows.
				Config:   config("t0ken", 1, "first"),
				PlanOnly: true,
			},
			{
				Config: config("t0ken-2", 2, "second"),
				Check:  receiver.received(2, "/hook", "Bearer t0ken-2"),
			},
			{
				// Nothing listens on port 1 of the PBS host.
				Config: config("t0ken-2", 2, "second") + fmt.Sprintf(`
resource "pbs_notification_endpoint_webhook" "unreachable" {
  name               = %q
  url                = "http://127.0.0.1:1/"
  send_test_on_apply = true
}
`, unreachable),
				ExpectError: regexp.MustCompile(`PBS test notification failed`),
			},
		},
	})
}

// The data sources list the endpoints, mail-to-root among them, and the
// matcher fields with the values PBS knows.
func TestAccNotificationDataSources(t *testing.T) {
	name := testAccNotificationName()

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckEndpointsDestroyed(map[string][]string{"webhook": {name}}),
		Steps: []acc.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_webhook" "test" {
  name    = %q
  url     = "https://hooks.invalid/"
  disable = true
}

data "pbs_notification_targets" "all" {
  depends_on = [pbs_notification_endpoint_webhook.test]
}

data "pbs_notification_matcher_fields" "all" {}
`, name),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckTypeSetElemNestedAttrs("data.pbs_notification_targets.all", "targets.*", map[string]string{
						"name": name, "type": "webhook", "origin": pbsclient.OriginUserCreated, "disable": "true",
					}),
					acc.TestCheckTypeSetElemNestedAttrs("data.pbs_notification_targets.all", "targets.*", map[string]string{
						"name": mailToRoot, "type": "sendmail",
					}),
					testAccCheckMatcherFieldValue("data.pbs_notification_matcher_fields.all", "type", "gc"),
					testAccCheckMatcherFieldValue("data.pbs_notification_matcher_fields.all", "datastore", os.Getenv(envAccDatastore)),
				),
			},
		},
	})
}

// testAccCheckMatcherFieldValue checks that a pbs_notification_matcher_fields
// lists value under field; an empty value only that the field is there.
func testAccCheckMatcherFieldValue(resourceName, field, value string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("%s is not in state", resourceName)
		}
		attrs := rs.Primary.Attributes
		fields, _ := strconv.Atoi(attrs["fields.#"])
		for i := range fields {
			if attrs[fmt.Sprintf("fields.%d.name", i)] != field {
				continue
			}
			values, _ := strconv.Atoi(attrs[fmt.Sprintf("fields.%d.values.#", i)])
			for j := range values {
				if value == "" || attrs[fmt.Sprintf("fields.%d.values.%d.value", i, j)] == value {
					return nil
				}
			}
			if value == "" {
				return nil
			}
			return fmt.Errorf("%s lists no value %q for the field %s", resourceName, value, field)
		}
		return fmt.Errorf("%s lists no field %s", resourceName, field)
	}
}

// From Terraform 1.12, the new endpoints import by identity too. The
// write-only values cannot be imported, so the Gotify endpoint's token
// version plans a change.
func TestAccNotificationEndpointsImportByIdentity(t *testing.T) {
	sendmail, gotify, webhook := testAccNotificationName(), testAccNotificationName(), testAccNotificationName()
	config := providerConfig + fmt.Sprintf(`
resource "pbs_notification_endpoint_sendmail" "test" {
  name   = %q
  mailto = ["ops@example.com"]
}

resource "pbs_notification_endpoint_gotify" "test" {
  name             = %q
  server           = "https://gotify.invalid"
  token_wo         = "token"
  token_wo_version = 1
}

resource "pbs_notification_endpoint_webhook" "test" {
  name   = %q
  url    = "https://hooks.invalid/"
  header = [{ name = "Content-Type", value = "text/plain" }]
}
`, sendmail, gotify, webhook)

	steps := []acc.TestStep{{Config: config}}
	for _, name := range []string{"pbs_notification_endpoint_sendmail.test", "pbs_notification_endpoint_gotify.test", "pbs_notification_endpoint_webhook.test"} {
		changes := name == "pbs_notification_endpoint_gotify.test"
		steps = append(steps,
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity, ExpectNonEmptyPlan: changes},
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithID, ExpectNonEmptyPlan: changes},
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy: testAccCheckEndpointsDestroyed(map[string][]string{
			"sendmail": {sendmail}, "gotify": {gotify}, "webhook": {webhook},
		}),
		Steps: steps,
	})
}
