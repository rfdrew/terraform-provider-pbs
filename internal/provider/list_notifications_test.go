package provider

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Tests of the list resources of the notification endpoints and matchers,
// and the helpers the tests of the other configuration lists share.

// newNotificationListHarness is newNotificationsHarness with
// GET /config/notifications/matchers, which the fake does not serve: every
// matcher, the built-in one included, as a read reports it, in the order
// of a map.
func newNotificationListHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeNotifications) {
	t.Helper()
	h, fake, notifications := newNotificationsHarness(t)
	fake.handle("GET /config/notifications/matchers", func(w http.ResponseWriter, _ *http.Request) {
		notifications.mu.Lock()
		defer notifications.mu.Unlock()
		matchers := []fakeProperties{}
		for name := range notifications.namesLocked() {
			if e, _ := notifications.lookupLocked(name); e.kind == "matcher" {
				matchers = append(matchers, e.props)
			}
		}
		writeData(w, matchers, "")
	})
	return h, fake, notifications
}

// generatedError is an error that validating a generated configuration
// reports: its summary, and the attribute it is about.
type generatedError struct {
	summary   string
	attribute *tftypes.AttributePath
}

func (e generatedError) String() string { return fmt.Sprintf("%s on %s", e.summary, e.attribute) }

// Errors of the generated configurations.
const (
	missingRequiredSummary    = "Missing Configuration for Required Attribute"
	invalidCombinationSummary = "Invalid Attribute Combination"
)

// generatedAttributePath is the path of a top-level attribute, or of one in
// a list of nested objects: secret, 0, value_wo.
func generatedAttributePath(steps ...any) *tftypes.AttributePath {
	p := tftypes.NewAttributePath()
	for _, step := range steps {
		switch s := step.(type) {
		case string:
			p = p.WithAttributeName(s)
		case int:
			p = p.WithElementKeyInt(s)
		}
	}
	return p
}

// requireListedNeedsValues checks a listed object whose generated
// configuration needs values the list cannot know, as
// requireListedLikeImport checks one whose configuration is complete: the
// listed identity and state are what importing the object gives, but for
// sensitive values, and validating the configuration generated from it
// fails with exactly the errors want, in any order. It returns the
// generated configuration.
func (h *protocolHarness) requireListedNeedsValues(t *testing.T, typeName string, result listedResult, want ...generatedError) tftypes.Value {
	t.Helper()
	if result.resource.IsNull() {
		t.Fatalf("%s: the result %q includes no resource", typeName, result.displayName)
	}
	generated := h.planGenerated(t, typeName, result)
	if got := h.identityValue(t, typeName, generated.imported.identity); !got.Equal(result.identity) {
		t.Fatalf("%s: listed identity %s, imported %s", typeName, result.identity, got)
	}
	wantState := withoutSensitive(t, h.resourceSchema(t, typeName).Block, generated.imported.state)
	if !result.resource.Equal(wantState) {
		t.Fatalf("%s: listed state differs from the imported one\nlisted:   %s\nimported: %s", typeName, result.resource, wantState)
	}
	var got []string
	for _, d := range generated.validation {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			got = append(got, generatedError{d.Summary, d.Attribute}.String())
		}
	}
	wanted := make([]string, 0, len(want))
	for _, e := range want {
		wanted = append(wanted, e.String())
	}
	slices.Sort(got)
	slices.Sort(wanted)
	if !slices.Equal(got, wanted) {
		t.Fatalf("%s: validating the generated configuration of %q reported %q, want %q", typeName, result.displayName, got, wanted)
	}
	return generated.config
}

// filledIn returns the configuration config, an object, with the
// top-level attributes attrs set, as a user fills in a generated
// configuration.
func filledIn(t *testing.T, config tftypes.Value, attrs map[string]tftypes.Value) tftypes.Value {
	t.Helper()
	values := harnessObjectAttributes(t, config)
	for name, v := range attrs {
		values[name] = v
	}
	return tftypes.NewValue(config.Type(), values)
}

// requireFilledInPlansOnly plans config, a filled-in generated
// configuration, for the object imported from result, and fails the test
// unless the plan is valid, replaces nothing and changes exactly the
// attributes named in changes.
func (h *protocolHarness) requireFilledInPlansOnly(t *testing.T, typeName string, result listedResult, config tftypes.Value, changes ...string) {
	t.Helper()
	requireNoProtocolErrors(t, h.validateResource(t, typeName, config))
	imported := h.importListed(t, typeName, result)
	plan := h.plan(t, typeName, imported, config)
	requireNoProtocolErrors(t, plan.Diagnostics)
	if len(plan.RequiresReplace) > 0 {
		t.Fatalf("%s: the filled-in configuration replaces the object: %v", typeName, plan.RequiresReplace)
	}
	planned := harnessObjectAttributes(t, h.decodeResource(t, typeName, plan.PlannedState))
	var changed []string
	for name, value := range harnessObjectAttributes(t, imported.state) {
		if !planned[name].Equal(value) {
			changed = append(changed, name)
		}
	}
	slices.Sort(changed)
	slices.Sort(changes)
	if !slices.Equal(changed, changes) {
		t.Fatalf("%s: the filled-in configuration changes %q, want %q", typeName, changed, changes)
	}
}

// requireListedDisplayNames fails the test unless the results have the
// display names want, in order.
func requireListedDisplayNames(t *testing.T, results []listedResult, want ...string) {
	t.Helper()
	got := make([]string, 0, len(results))
	for _, result := range results {
		got = append(got, result.displayName)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("display names %q, want %q", got, want)
	}
}

const (
	smtpType    = "pbs_notification_endpoint_smtp"
	matcherType = "pbs_notification_matcher"
)

func TestNotificationEndpointListResources(t *testing.T) {
	h, fake, _ := newNotificationListHarness(t)
	h.create(t, sendmailType, sendmailConfig(t, h, map[string]any{"mailto": []any{"ops@example.com"}, "comment": "Operations"}))
	h.create(t, smtpType, smtpConfig(t, h, map[string]any{"mailto": []any{"ops@example.com"}, "mode": "starttls", "port": 2525}))
	h.create(t, smtpType, smtpConfig(t, h, map[string]any{
		"name": "relay", "mailto_user": []any{"root@pam"}, "username": "pbs-mailer", "password_wo": "sm7p-pa55",
		"password_wo_version": 1, "comment": "Authenticated relay",
	}))
	h.create(t, gotifyType, gotifyConfig(t, h, map[string]any{"comment": "Phones", "disable": true}))
	h.create(t, webhookType, webhookConfig(t, h, map[string]any{
		"secret": []any{webhookSecret("channel", "alerts", 3)},
		"header": []any{webhookHeader("Content-Type", "application/json")},
		"body":   `{"text": "{{ escape title }}"}`,
	}))
	h.create(t, webhookType, webhookConfig(t, h, map[string]any{"name": "plain", "url": "https://hooks.example.com/plain", "method": "put"}))
	h.create(t, webhookType, webhookConfig(t, h, map[string]any{
		"name": "pretty", "url": "https://hooks.example.com/pretty",
		"body": "{\n  \"title\": \"{{ title }}\",\n  \"text\": \"a & b\"\n}\n",
	}))

	// Without resources, each list names the endpoints of its type, the
	// built-in mail-to-root among the sendmail ones, from one call.
	for typeName, want := range map[string][]string{
		sendmailType: {mailToRoot, "ops-mail"},
		smtpType:     {"mail", "relay"},
		gotifyType:   {"push"},
		webhookType:  {"hook", "plain", "pretty"},
	} {
		before := fake.count("GET /config/notifications/targets")
		results := h.listedObjects(t, typeName, listRequest{})
		if got := listedIdentities(t, results, "name"); !slices.Equal(got, want) {
			t.Fatalf("%s listed %q, want %q", typeName, got, want)
		}
		if fake.count("GET /config/notifications/targets") != before+1 || !results[0].resource.IsNull() {
			t.Fatalf("%s: a list without resources made %d calls", typeName, fake.count("GET /config/notifications/targets")-before)
		}
	}
	requireListedDisplayNames(t, h.listedObjects(t, sendmailType, listRequest{}),
		"mail-to-root — Send mails to root@pam's email address", "ops-mail — Operations")
	requireListedDisplayNames(t, h.listedObjects(t, smtpType, listRequest{}), "mail", "relay — Authenticated relay")

	// With resources, each result is what importing the endpoint gives;
	// send_test_on_apply is false, as an import sets it.
	sendmail := h.listedObjects(t, sendmailType, listRequest{includeResource: true})
	for _, result := range sendmail {
		h.requireListedLikeImport(t, sendmailType, result)
		if isNullAt(t, result.resource, "send_test_on_apply") || boolAt(t, result.resource, "send_test_on_apply") {
			t.Fatalf("listed %s", result.resource)
		}
	}
	if stringAt(t, sendmail[0].resource, "origin") != pbsclient.OriginBuiltin || stringAt(t, sendmail[0].resource, "mailto_user", 0) != "root@pam" {
		t.Fatalf("listed mail-to-root as %s", sendmail[0].resource)
	}

	// An SMTP endpoint without a user name plans no change. One with a user
	// name needs the password: username requires password_wo, which needs
	// its version, and once both are filled in, the plan sends the password
	// and changes nothing else.
	smtp := h.listedObjects(t, smtpType, listRequest{includeResource: true})
	h.requireListedLikeImport(t, smtpType, smtp[0])
	if int64At(t, smtp[0].resource, "port") != 2525 || stringAt(t, smtp[0].resource, "mode") != "starttls" {
		t.Fatalf("listed %s", smtp[0].resource)
	}
	config := h.requireListedNeedsValues(t, smtpType, smtp[1], generatedError{invalidCombinationSummary, generatedAttributePath("username")})
	h.requireFilledInPlansOnly(t, smtpType, smtp[1], filledIn(t, config, map[string]tftypes.Value{
		"password_wo": tftypes.NewValue(tftypes.String, "sm7p-pa55"), "password_wo_version": tftypes.NewValue(tftypes.Number, 1),
	}), "password_wo_version")

	// A Gotify endpoint's generated configuration lacks the token and its
	// version, which are required.
	gotify := h.listedObjects(t, gotifyType, listRequest{includeResource: true})
	config = h.requireListedNeedsValues(t, gotifyType, gotify[0],
		generatedError{missingRequiredSummary, generatedAttributePath("token_wo")},
		generatedError{missingRequiredSummary, generatedAttributePath("token_wo_version")})
	if !boolAt(t, gotify[0].resource, "disable") || stringAt(t, gotify[0].resource, "comment") != "Phones" {
		t.Fatalf("listed %s", gotify[0].resource)
	}
	h.requireFilledInPlansOnly(t, gotifyType, gotify[0], filledIn(t, config, map[string]tftypes.Value{
		"token_wo": tftypes.NewValue(tftypes.String, "first-token"), "token_wo_version": tftypes.NewValue(tftypes.Number, 1),
	}), "token_wo_version")

	// A webhook's secrets are listed by name, each lacking its value and
	// version; a webhook without secrets plans no change.
	webhooks := h.listedObjects(t, webhookType, listRequest{includeResource: true})
	h.requireListedNeedsValues(t, webhookType, webhooks[0],
		generatedError{missingRequiredSummary, generatedAttributePath("secret", 0, "value_wo")},
		generatedError{missingRequiredSummary, generatedAttributePath("secret", 0, "value_wo_version")})
	if stringAt(t, webhooks[0].resource, "secret", 0, "name") != "channel" || stringAt(t, webhooks[0].resource, "body") != `{"text": "{{ escape title }}"}` {
		t.Fatalf("listed %s", webhooks[0].resource)
	}
	h.requireListedLikeImport(t, webhookType, webhooks[1])
	// Terraform writes a JSON body as jsonencode() of it, which compacts it:
	// the same document, so no change either.
	h.requireListedLikeImport(t, webhookType, webhooks[2])
	if generated := h.generateConfig(t, webhookType, webhooks[2].resource); stringAt(t, generated, "body") !=
		`{"text":"a \u0026 b","title":"{{ title }}"}` {
		t.Fatalf("generated %s", generated)
	}

	// The limit Terraform sends bounds the results.
	if got := h.listedObjects(t, sendmailType, listRequest{limit: 1, includeResource: true}); len(got) != 1 {
		t.Fatalf("a limit of 1 listed %d", len(got))
	}
}

func TestNotificationMatcherListResource(t *testing.T) {
	h, fake, notifications := newNotificationListHarness(t)
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"}}, "")
	h.create(t, matcherType, h.resourceValue(t, matcherType, map[string]any{
		"name": "ops", "target": []any{"mail"}, "match_severity": []any{"warning", "error"},
		"match_calendar": []any{"mon..fri 8-18"}, "mode": "any", "comment": "Office hours",
	}))
	h.create(t, matcherType, h.resourceValue(t, matcherType, map[string]any{
		"name": "audit", "target": []any{"mail"}, "match_field": []any{"exact:type=gc,verify"}, "invert_match": true, "disable": true,
	}))

	before := fake.count("GET /config/notifications/matchers/ops")
	results := h.listedObjects(t, matcherType, listRequest{})
	if got, want := listedIdentities(t, results, "name"), []string{"audit", defaultMatcher, "ops"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	requireListedDisplayNames(t, results, "audit",
		"default-matcher — Route everything but successful prune job notifications to mail-to-root", "ops — Office hours")
	if fake.count("GET /config/notifications/matchers/ops") != before {
		t.Fatal("a list without resources read the matchers")
	}

	// default-matcher is listed as built in, and once changed, as
	// modified-builtin; either way, its generated configuration plans no
	// change, as every other matcher's.
	for _, origin := range []string{pbsclient.OriginBuiltin, pbsclient.OriginModifiedBuiltin} {
		if origin == pbsclient.OriginModifiedBuiltin {
			builtin, _ := notifications.entry(defaultMatcher)
			changed := cloneProperties(builtin)
			delete(changed, "origin")
			delete(changed, "name")
			changed["target"] = []string{"mail"}
			notifications.addMatcher(defaultMatcher, changed)
		}
		results = h.listedObjects(t, matcherType, listRequest{includeResource: true})
		for _, result := range results {
			h.requireListedLikeImport(t, matcherType, result)
		}
		if got := stringAt(t, results[1].resource, "origin"); got != origin {
			t.Fatalf("default-matcher listed as %s, want %s", got, origin)
		}
	}
	if !boolAt(t, results[0].resource, "invert_match") || stringAt(t, results[2].resource, "mode") != "any" {
		t.Fatalf("listed %s, %s", results[0].resource, results[2].resource)
	}
}

// A matcher whose rules PBS holds as an expression is listed with it, as
// PBS stores it, and its generated configuration — the expression written
// as jsonencode(…), with its keys sorted — plans no change.
func TestNotificationMatcherListResourceExpression(t *testing.T) {
	h, _, notifications := newNotificationListHarness(t)
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"}}, "")
	notifications.addMatcher("gc-alerts", fakeProperties{"expression": testMatcherExpressionStored, "target": []string{"mail"}, "comment": "GC alerts"})

	results := h.listedObjects(t, matcherType, listRequest{})
	requireListedDisplayNames(t, results,
		"default-matcher — Route everything but successful prune job notifications to mail-to-root",
		"gc-alerts — GC alerts")

	results = h.listedObjects(t, matcherType, listRequest{includeResource: true})
	for _, result := range results {
		h.requireListedLikeImport(t, matcherType, result)
		if len(result.diagnostics) != 0 {
			t.Fatalf("%s listed with %v", result.displayName, result.diagnostics)
		}
	}
	listed := results[1].resource
	if stringAt(t, listed, "expression") != testMatcherExpressionStored || !isNullAt(t, listed, "match_severity") ||
		stringAt(t, listed, "mode") != "all" || boolAt(t, listed, "invert_match") || stringAt(t, listed, "target", 0) != "mail" {
		t.Fatalf("listed %s", listed)
	}
	if got := stringAt(t, h.generateConfig(t, matcherType, listed), "expression"); got != testMatcherExpressionEncoded {
		t.Fatalf("generated expression = %s, want %s", got, testMatcherExpressionEncoded)
	}
	if !isNullAt(t, results[0].resource, "expression") {
		t.Fatalf("default-matcher listed with %s", results[0].resource)
	}
}

// A failed listing fails the list block, with the privilege it needs.
func TestNotificationListResourcesListFails(t *testing.T) {
	h, fake, _ := newNotificationListHarness(t)
	fake.reply("GET /config/notifications/targets", http.StatusForbidden, "permission check failed")
	fake.reply("GET /config/notifications/matchers", http.StatusForbidden, "permission check failed")
	for typeName, summary := range map[string]string{
		sendmailType: "Unable to list PBS sendmail notification endpoints",
		smtpType:     "Unable to list PBS SMTP notification endpoints",
		gotifyType:   "Unable to list PBS Gotify notification endpoints",
		webhookType:  "Unable to list PBS webhook notification endpoints",
		matcherType:  "Unable to list PBS notification matchers",
	} {
		results := h.listResources(t, typeName, listRequest{includeResource: true})
		if len(results) != 1 {
			t.Fatalf("%s: got %d results", typeName, len(results))
		}
		requireProtocolErrorContaining(t, results[0].diagnostics, summary)
		requireProtocolErrorContaining(t, results[0].diagnostics, notificationsReadPrivilege)
	}
}

// An endpoint that disappears between the listing and its read is left out
// without an error; one PBS will not show is left out with a warning.
func TestNotificationEndpointListResourceVanishedAndUnreadable(t *testing.T) {
	h, fake, notifications := newNotificationListHarness(t)
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		notifications.addEndpoint("gotify", name, fakeProperties{"server": "https://gotify.example.com"}, "token")
	}
	fake.reply("GET /config/notifications/endpoints/gotify/alpha", http.StatusNotFound, "endpoint 'alpha' not found")
	fake.reply("GET /config/notifications/endpoints/gotify/bravo", http.StatusInternalServerError, "internal error")
	var listed []string
	warned := false
	for _, result := range h.listResources(t, gotifyType, listRequest{includeResource: true}) {
		requireNoProtocolErrors(t, result.diagnostics)
		if result.identity.IsNull() {
			requireProtocolWarningContaining(t, result.diagnostics, "Left out bravo")
			warned = true
			continue
		}
		listed = append(listed, stringAt(t, result.identity, "name"))
	}
	if !warned || !slices.Equal(listed, []string{"charlie"}) {
		t.Fatalf("listed %q, warned %v", listed, warned)
	}
}
