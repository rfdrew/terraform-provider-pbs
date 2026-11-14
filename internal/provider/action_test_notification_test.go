package provider

import (
	"net/http"
	"slices"
	"testing"
)

func TestNotificationTestAction(t *testing.T) {
	h, _, notifications := newNotificationsHarness(t)
	notifications.addEndpoint("webhook", "hook", fakeProperties{"url": "https://hooks.example.org/pbs", "method": "post"}, "")

	got := h.invokeAction(t, "pbs_notification_test", map[string]any{"name": "hook"})
	requireNoProtocolErrors(t, got.diagnostics)
	if len(got.diagnostics) != 0 {
		t.Fatalf("diagnostics: %v", got.diagnostics)
	}
	requireProgressContaining(t, got, "PBS delivered the test notification through webhook endpoint hook")

	got = h.invokeAction(t, "pbs_notification_test", map[string]any{"name": mailToRoot})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "sendmail endpoint mail-to-root to the node's mail system")
	if tested := notifications.tested(); !slices.Equal(tested, []string{"hook", mailToRoot}) {
		t.Fatalf("tested = %v", tested)
	}
}

// PBS tests a disabled endpoint all the same; the action warns that it
// sends the endpoint nothing else.
func TestNotificationTestActionDisabledEndpoint(t *testing.T) {
	h, _, notifications := newNotificationsHarness(t)
	notifications.addSMTP("mail", fakeProperties{"server": "mail.example.org", "from-address": "pbs@example.org",
		"mailto": []string{"ops@example.org"}, "disable": true}, "")
	got := h.invokeAction(t, "pbs_notification_test", map[string]any{"name": "mail"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "PBS notification endpoint is disabled")
	requireProgressContaining(t, got, "smtp endpoint mail")
}

func TestNotificationTestActionErrors(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)
	notifications.addEndpoint("gotify", "phone", fakeProperties{"server": "https://gotify.example.org"}, "t0ken")
	notifications.addMatcher("route", fakeProperties{"target": []string{"phone"}})
	notifications.failTests("phone", "could not notify via endpoint(s): phone: HTTP request failed: connection refused")

	got := h.invokeAction(t, "pbs_notification_test", map[string]any{"name": "phone"})
	requireProtocolErrorContaining(t, got.diagnostics, "PBS test notification failed")
	requireProtocolErrorContaining(t, got.diagnostics, "the node — not the machine Terraform runs on — reaches its server")
	requireProtocolErrorContaining(t, got.diagnostics, "connection refused")

	// A matcher is no endpoint.
	got = h.invokeAction(t, "pbs_notification_test", map[string]any{"name": "route"})
	requireProtocolErrorContaining(t, got.diagnostics, `PBS has no notification endpoint "route" it can use`)
	requireProtocolErrorContaining(t, got.diagnostics, "matcher, which PBS cannot test")

	fake.reply("POST /config/notifications/targets/phone/test", http.StatusForbidden, "permission check failed")
	got = h.invokeAction(t, "pbs_notification_test", map[string]any{"name": "phone"})
	requireProtocolErrorContaining(t, got.diagnostics, "Sys.Modify on /system/notifications")

	fake.reply("POST /config/notifications/targets/phone/test", http.StatusInternalServerError,
		"Could not instantiate notification bus: could not deserialize config")
	got = h.invokeAction(t, "pbs_notification_test", map[string]any{"name": "phone"})
	requireProtocolErrorContaining(t, got.diagnostics, "Could not instantiate notification bus")
}

// Without Sys.Audit, PBS lists no endpoints: the test is reported all the
// same, with less detail.
func TestNotificationTestActionWithoutAudit(t *testing.T) {
	h, fake, _ := newNotificationsHarness(t)
	fake.reply("GET /config/notifications/targets", http.StatusForbidden, "permission check failed")
	got := h.invokeAction(t, "pbs_notification_test", map[string]any{"name": mailToRoot})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "PBS delivered the test notification through endpoint mail-to-root")
}

func TestNotificationTestActionValidation(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, name := range []string{"x", "-leading", "has space", "a-very-long-endpoint-name-over-32-chars"} {
		requireProtocolErrorContaining(t, h.validateAction(t, "pbs_notification_test",
			h.actionValue(t, "pbs_notification_test", map[string]any{"name": name})), "name")
	}
	unknown := h.actionValue(t, "pbs_notification_test", map[string]any{"name": tfUnknown})
	requireNoProtocolErrors(t, h.validateAction(t, "pbs_notification_test", unknown))
	requireNoProtocolErrors(t, h.planAction(t, "pbs_notification_test", unknown))
}
