package provider

import (
	"testing"
)

// A null element of a set, list or map, such as a variable left null in
// `mailto = ["ops@example.com", var.extra]`, is refused in validation. The
// element validators skip nulls, and the provider would otherwise drop the
// element on its way to PBS — reading back one element fewer than planned,
// "inconsistent result after apply" — or fail converting it.
func TestNullElementsAreRefused(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	header := map[string]any{"name": "Content-Type", "value": "text/plain"}
	secret := map[string]any{"name": "token", "value_wo": "s3cret", "value_wo_version": 1}

	for name, tc := range map[string]struct {
		typeName string
		config   map[string]any
	}{
		"sendmail mailto": {"pbs_notification_endpoint_sendmail",
			map[string]any{"name": "mail", "mailto": []any{"ops@example.com", nil}}},
		"sendmail mailto_user": {"pbs_notification_endpoint_sendmail",
			map[string]any{"name": "mail", "mailto_user": []any{nil}}},
		"smtp mailto": {"pbs_notification_endpoint_smtp", map[string]any{"name": "mail", "server": "smtp.example.com",
			"from_address": "pbs@example.com", "mailto": []any{"ops@example.com", nil}}},
		"smtp mailto_user": {"pbs_notification_endpoint_smtp", map[string]any{"name": "mail", "server": "smtp.example.com",
			"from_address": "pbs@example.com", "mailto_user": []any{"root@pam", nil}}},
		"matcher target": {"pbs_notification_matcher",
			map[string]any{"name": "errors", "target": []any{"mail", nil}}},
		"matcher match_severity": {"pbs_notification_matcher",
			map[string]any{"name": "errors", "target": []any{"mail"}, "match_severity": []any{"error", nil}}},
		"matcher match_field": {"pbs_notification_matcher",
			map[string]any{"name": "errors", "target": []any{"mail"}, "match_field": []any{"exact:type=gc", nil}}},
		"matcher match_calendar": {"pbs_notification_matcher",
			map[string]any{"name": "errors", "target": []any{"mail"}, "match_calendar": []any{"8-12", nil}}},
		"sync job group_filter": {"pbs_sync_job", map[string]any{"id": "pull-offsite", "store": "store1",
			"remote": "offsite", "remote_store": "store2", "group_filter": []any{"type:vm", nil}}},
		"webhook header": {"pbs_notification_endpoint_webhook",
			map[string]any{"name": "hook", "url": "https://hooks.example.com/", "header": []any{header, nil}}},
		"webhook secret": {"pbs_notification_endpoint_webhook",
			map[string]any{"name": "hook", "url": "https://hooks.example.com/", "secret": []any{secret, nil}}},
		"node acme domains": {"pbs_node_acme",
			map[string]any{"account": "le", "domains": []any{map[string]any{"domain": "pbs.example.org"}, nil}}},
		"acme plugin data": {"pbs_acme_plugin",
			map[string]any{"id": "cloudflare", "api": "cf", "data": map[string]any{"CF_Token": "token", "CF_Zone_ID": nil}}},
	} {
		t.Run(name, func(t *testing.T) {
			diags := h.validateResource(t, tc.typeName, h.resourceValue(t, tc.typeName, tc.config))
			requireProtocolErrorContaining(t, diags, "This attribute contains a null value")
		})
	}
}
