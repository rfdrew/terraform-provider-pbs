package provider

import (
	"net/http"
	"testing"
)

func TestNotificationDataSourceSchemasAreValid(t *testing.T) {
	requireValidDataSourceSchema(t, &notificationTargetsDataSource{})
	requireValidDataSourceSchema(t, &notificationMatcherFieldsDataSource{})
}

// Every endpoint, of every type and the built-in mail-to-root included,
// sorted by name; a missing comment is null and a missing disable false.
func TestNotificationTargetsDataSource(t *testing.T) {
	h, _, notifications := newNotificationsHarness(t)
	notifications.addEndpoint("gotify", "push", fakeProperties{"server": "https://gotify.example.com", "disable": true}, "token")
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com",
		"mailto": []string{"ops@example.com"}, "comment": "Relay"}, "")
	notifications.addMatcher("ops", fakeProperties{"target": []string{"push"}})

	state := h.readDataSource(t, "pbs_notification_targets", h.dataSourceValue(t, "pbs_notification_targets", map[string]any{}))
	want := h.dataSourceValue(t, "pbs_notification_targets", map[string]any{
		"targets": []any{
			map[string]any{"name": "mail", "type": "smtp", "origin": "user-created", "disable": false, "comment": "Relay"},
			map[string]any{"name": mailToRoot, "type": "sendmail", "origin": "builtin", "disable": false,
				"comment": "Send mails to root@pam's email address"},
			map[string]any{"name": "push", "type": "gotify", "origin": "user-created", "disable": true},
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
}

// Values are grouped under their field, sorted; a field without values has
// an empty list, and a field PBS lists values for but not among the fields
// is still there.
func TestNotificationMatcherFieldsDataSource(t *testing.T) {
	h, fake, _ := newNotificationsHarness(t)
	state := h.readDataSource(t, "pbs_notification_matcher_fields", h.dataSourceValue(t, "pbs_notification_matcher_fields", map[string]any{}))
	want := h.dataSourceValue(t, "pbs_notification_matcher_fields", map[string]any{
		"fields": []any{
			map[string]any{"name": "datastore", "values": []any{map[string]any{"value": "store1", "comment": "Main datastore"}}},
			map[string]any{"name": "hostname", "values": []any{map[string]any{"value": "pbs"}}},
			map[string]any{"name": "job-id", "values": []any{map[string]any{"value": "daily-prune"}}},
			map[string]any{"name": "media-pool", "values": []any{}},
			map[string]any{"name": "type", "values": []any{map[string]any{"value": "gc"}, map[string]any{"value": "prune"}}},
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}

	fake.reply("GET /config/notifications/matcher-fields", http.StatusOK, `{"data":[{"name":"type"}]}`)
	fake.reply("GET /config/notifications/matcher-field-values", http.StatusOK,
		`{"data":[{"field":"type","value":"verify"},{"field":"type","value":"acme"},{"field":"thresholds","value":"store1"}]}`)
	state = h.readDataSource(t, "pbs_notification_matcher_fields", h.dataSourceValue(t, "pbs_notification_matcher_fields", map[string]any{}))
	want = h.dataSourceValue(t, "pbs_notification_matcher_fields", map[string]any{
		"fields": []any{
			map[string]any{"name": "thresholds", "values": []any{map[string]any{"value": "store1"}}},
			map[string]any{"name": "type", "values": []any{map[string]any{"value": "acme"}, map[string]any{"value": "verify"}}},
		},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
}

// Without Sys.Audit on /system/notifications, reading fails with the
// privilege named.
func TestNotificationDataSourcesErrors(t *testing.T) {
	for typeName, route := range map[string]string{
		"pbs_notification_targets":        "GET /config/notifications/targets",
		"pbs_notification_matcher_fields": "GET /config/notifications/matcher-fields",
	} {
		t.Run(typeName, func(t *testing.T) {
			h, fake, _ := newNotificationsHarness(t)
			fake.reply(route, http.StatusForbidden, "permission check failed")
			resp := h.readDataSourceResponse(t, typeName, h.dataSourceValue(t, typeName, map[string]any{}))
			requireProtocolErrorContaining(t, resp.Diagnostics, notificationsReadPrivilege)
		})
	}

	h, fake, _ := newNotificationsHarness(t)
	fake.reply("GET /config/notifications/matcher-field-values", http.StatusInternalServerError, "could not list prune jobs")
	resp := h.readDataSourceResponse(t, "pbs_notification_matcher_fields", h.dataSourceValue(t, "pbs_notification_matcher_fields", map[string]any{}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS notification matcher field values")
}
