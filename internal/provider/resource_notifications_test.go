package provider

import (
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// newNotificationsHarness is a fake PBS with the notification API and a
// provider signed in to it.
func newNotificationsHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeNotifications) {
	t.Helper()
	fake := newFakePBS()
	notifications := newFakeNotifications(fake)
	return newProtocolHarness(t, fake), fake, notifications
}

// smtpConfig is the configuration of an SMTP endpoint "mail", with attrs on
// top of what it needs.
func smtpConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"name": "mail", "server": "smtp.example.com", "from_address": "pbs@example.com"}
	for k, v := range attrs {
		config[k] = v
	}
	return h.resourceValue(t, "pbs_notification_endpoint_smtp", config)
}

func TestSMTPEndpointResourceLifecycle(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)

	config := smtpConfig(t, h, map[string]any{
		"username":            "pbs",
		"password_wo":         "first-password",
		"password_wo_version": 1,
		"author":              "Backup server",
		"mailto":              []any{"ops@example.com", "admin@example.com"},
	})
	inst := h.create(t, "pbs_notification_endpoint_smtp", config)

	created := fake.lastCall(t, "POST /config/notifications/endpoints/smtp")
	if got := created.form.Get("password"); got != "first-password" {
		t.Errorf("POST password = %q", got)
	}
	if got := strings.Join(created.form["mailto"], ","); got != "admin@example.com,ops@example.com" {
		t.Errorf("POST mailto = %q, want both, sorted", got)
	}
	for _, name := range []string{"mode", "port", "disable", "mailto-user"} {
		if _, sent := created.form[name]; sent {
			t.Errorf("POST sent %s: %v", name, created.form)
		}
	}
	if stringAt(t, inst.state, "mode") != "tls" || stringAt(t, inst.state, "origin") != pbsclient.OriginUserCreated ||
		!isNullAt(t, inst.state, "port") || !isNullAt(t, inst.state, "password_wo") || int64At(t, inst.state, "password_wo_version") != 1 ||
		lengthAt(t, inst.state, "mailto") != 2 {
		t.Errorf("state = %s", inst.state)
	}
	replan := h.plan(t, "pbs_notification_endpoint_smtp", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_notification_endpoint_smtp", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	// Recipients, port and mode change, the author goes; the password, at
	// the same version, is not sent again.
	inst = h.update(t, inst, smtpConfig(t, h, map[string]any{
		"username":            "pbs",
		"password_wo":         "first-password",
		"password_wo_version": 1,
		"mode":                "starttls",
		"port":                587,
		"mailto_user":         []any{"root@pam"},
	}))
	updated := fake.lastCall(t, "PUT /config/notifications/endpoints/smtp/mail")
	if got := strings.Join(updated.form["delete"], ","); got != "author,mailto" {
		t.Errorf("delete = %q, want author,mailto", got)
	}
	if updated.form.Get("mode") != "starttls" || updated.form.Get("port") != "587" || updated.form.Get("mailto-user") != "root@pam" {
		t.Errorf("PUT form = %v", updated.form)
	}
	if _, sent := updated.form["password"]; sent {
		t.Error("an unchanged password_wo_version sent the password again")
	}

	// A new version sends the new password in the same call; leaving mode out
	// writes tls, which PBS cannot delete.
	inst = h.update(t, inst, smtpConfig(t, h, map[string]any{
		"username":            "pbs",
		"password_wo":         "second-password",
		"password_wo_version": 2,
		"port":                587,
		"mailto_user":         []any{"root@pam"},
	}))
	updated = fake.lastCall(t, "PUT /config/notifications/endpoints/smtp/mail")
	if updated.form.Get("password") != "second-password" || updated.form.Get("mode") != "tls" || len(updated.form["delete"]) != 0 {
		t.Errorf("PUT form = %v", updated.form)
	}
	if got, _ := notifications.password("mail"); got != "second-password" {
		t.Errorf("stored password = %q", got)
	}

	// Removing the password with its user name leaves the password as it is.
	inst = h.update(t, inst, smtpConfig(t, h, map[string]any{"mailto_user": []any{"root@pam"}, "port": 587}))
	if got := strings.Join(fake.lastCall(t, "PUT /config/notifications/endpoints/smtp/mail").form["delete"], ","); got != "username" {
		t.Errorf("delete = %q, want username", got)
	}
	if got, _ := notifications.password("mail"); got != "second-password" {
		t.Errorf("removing password_wo changed the password to %q", got)
	}

	h.destroy(t, inst)
	if _, exists := notifications.entry("mail"); exists {
		t.Error("the endpoint still exists")
	}
	if _, exists := notifications.password("mail"); exists {
		t.Error("the endpoint's password is left")
	}
}

func TestSMTPEndpointResourceImportAndErrors(t *testing.T) {
	h, _, notifications := newNotificationsHarness(t)
	notifications.addSMTP("relay", fakeProperties{
		"server": "relay.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"},
		"mode": "insecure", "port": int64(25), "disable": true,
	}, "secret")

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_notification_endpoint_smtp", "relay"),
		"identity": h.importByIdentity(t, "pbs_notification_endpoint_smtp", map[string]any{"name": "relay"}),
	} {
		if stringAt(t, inst.state, "mode") != "insecure" || int64At(t, inst.state, "port") != 25 || !boolAt(t, inst.state, "disable") ||
			!isNullAt(t, inst.state, "password_wo_version") || !isNullAt(t, inst.state, "username") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
	}

	// The built-in mail-to-root holds its name.
	config := h.resourceValue(t, "pbs_notification_endpoint_smtp", map[string]any{
		"name": "mail-to-root", "server": "smtp.example.com", "from_address": "pbs@example.com", "mailto": []any{"ops@example.com"},
	})
	planned := h.plan(t, "pbs_notification_endpoint_smtp", nil, config)
	applied := h.apply(t, "pbs_notification_endpoint_smtp", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "share one namespace")

	// PBS refuses to delete an endpoint a matcher targets.
	notifications.addMatcher("ops", fakeProperties{"target": []string{"relay"}})
	inst := h.importByID(t, "pbs_notification_endpoint_smtp", "relay")
	planned = h.plan(t, "pbs_notification_endpoint_smtp", inst, tftypes.NewValue(h.resourceType(t, "pbs_notification_endpoint_smtp"), nil))
	applied = h.apply(t, "pbs_notification_endpoint_smtp", inst, tftypes.NewValue(h.resourceType(t, "pbs_notification_endpoint_smtp"), nil), planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Matchers still target endpoint")
}

func TestSMTPEndpointResourceValidation(t *testing.T) {
	h, _, _ := newNotificationsHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"no recipient":          {map[string]any{}, "mailto"},
		"empty mailto":          {map[string]any{"mailto": []any{}}, "mailto"},
		"password without user": {map[string]any{"mailto": []any{"ops@example.com"}, "password_wo": "x", "password_wo_version": 1}, "username"},
		"user without password": {map[string]any{"mailto": []any{"ops@example.com"}, "username": "pbs"}, "password_wo"},
		"version without secret": {map[string]any{"mailto": []any{"ops@example.com"}, "username": "pbs", "password_wo_version": 1},
			"password_wo"},
		"bad mode":      {map[string]any{"mailto": []any{"ops@example.com"}, "mode": "ssl"}, "mode"},
		"port zero":     {map[string]any{"mailto": []any{"ops@example.com"}, "port": 0}, "port"},
		"bad user":      {map[string]any{"mailto_user": []any{"root"}}, "mailto_user"},
		"padded server": {map[string]any{"mailto": []any{"ops@example.com"}, "server": " smtp.example.com"}, "server"},
		"padded password": {map[string]any{"mailto": []any{"ops@example.com"}, "username": "pbs", "password_wo": "secret ",
			"password_wo_version": 1}, "password_wo"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_notification_endpoint_smtp", smtpConfig(t, h, tc.attrs)), tc.want)
		})
	}
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_notification_endpoint_smtp", smtpConfig(t, h, map[string]any{
		"mailto": []any{"ops@example.com"}, "username": "pbs", "password_wo": "secret", "password_wo_version": 1,
	})))
}

func TestNotificationMatcherResourceLifecycle(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"}}, "")

	config := h.resourceValue(t, "pbs_notification_matcher", map[string]any{
		"name":           "sync-errors",
		"target":         []any{"mail"},
		"match_severity": []any{"warning,error"},
		"match_field":    []any{"exact:type=sync,verify"},
		"mode":           "any",
		"comment":        "Failed syncs",
	})
	inst := h.create(t, "pbs_notification_matcher", config)
	created := fake.lastCall(t, "POST /config/notifications/matchers")
	if created.form.Get("mode") != "any" || created.form.Get("match-field") != "exact:type=sync,verify" || created.form.Get("target") != "mail" {
		t.Errorf("POST form = %v", created.form)
	}
	for _, name := range []string{"invert-match", "disable", "match-calendar"} {
		if _, sent := created.form[name]; sent {
			t.Errorf("POST sent %s: %v", name, created.form)
		}
	}
	if stringAt(t, inst.state, "origin") != pbsclient.OriginUserCreated || boolAt(t, inst.state, "invert_match") || !isNullAt(t, inst.state, "match_calendar") {
		t.Errorf("state = %s", inst.state)
	}
	replan := h.plan(t, "pbs_notification_matcher", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_notification_matcher", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	// Back to mode all, PBS's default: the property is deleted.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_notification_matcher", map[string]any{
		"name":           "sync-errors",
		"target":         []any{"mail"},
		"match_severity": []any{"warning,error"},
		"match_calendar": []any{"mon..fri 8-17"},
		"invert_match":   true,
	}))
	updated := fake.lastCall(t, "PUT /config/notifications/matchers/sync-errors")
	if got := strings.Join(updated.form["delete"], ","); got != "comment,match-field,mode" {
		t.Errorf("delete = %q", got)
	}
	if updated.form.Get("invert-match") != "true" || updated.form.Get("match-calendar") != "mon..fri 8-17" {
		t.Errorf("PUT form = %v", updated.form)
	}

	// A target that is not an endpoint is refused.
	config = h.resourceValue(t, "pbs_notification_matcher", map[string]any{"name": "sync-errors", "target": []any{"default-matcher"}})
	planned := h.plan(t, "pbs_notification_matcher", inst, config)
	applied := h.apply(t, "pbs_notification_matcher", inst, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "not a notification endpoint")

	// A matcher gone since the refresh is not blamed on its targets.
	notifications.mu.Lock()
	delete(notifications.entries, "sync-errors")
	notifications.mu.Unlock()
	config = h.resourceValue(t, "pbs_notification_matcher", map[string]any{"name": "sync-errors", "target": []any{"mail"}})
	planned = h.plan(t, "pbs_notification_matcher", inst, config)
	applied = h.apply(t, "pbs_notification_matcher", inst, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "matcher 'sync-errors' not found")
	for _, d := range applied.Diagnostics {
		if strings.Contains(d.Detail, "not a notification endpoint") {
			t.Errorf("a missing matcher was explained as a missing target: %s", d.Detail)
		}
	}
	h.destroy(t, inst)
}

// When reading a matcher back after an update fails, state still gets a
// known origin.
func TestNotificationMatcherResourceReadBackFailure(t *testing.T) {
	h, fake, _ := newNotificationsHarness(t)
	inst := h.create(t, "pbs_notification_matcher", h.resourceValue(t, "pbs_notification_matcher", map[string]any{"name": "errors"}))
	fake.reply("GET /config/notifications/matchers/errors", 500, "internal error")

	config := h.resourceValue(t, "pbs_notification_matcher", map[string]any{"name": "errors", "comment": "changed"})
	planned := h.plan(t, "pbs_notification_matcher", inst, config)
	applied := h.apply(t, "pbs_notification_matcher", inst, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "reading it back failed")
	state := h.decodeResource(t, "pbs_notification_matcher", applied.NewState)
	if stringAt(t, state, "origin") != pbsclient.OriginUserCreated || stringAt(t, state, "comment") != "changed" {
		t.Errorf("state = %s", state)
	}
}

// The built-in default-matcher cannot be created, only imported; changing it
// makes it modified-builtin, and destroying the resource resets it.
func TestNotificationMatcherResourceDefaultMatcher(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"}}, "")
	builtin, _ := notifications.entry(defaultMatcher)

	toSMTP := h.resourceValue(t, "pbs_notification_matcher", map[string]any{
		"name":           defaultMatcher,
		"comment":        "Route everything but successful prune job notifications to mail-to-root",
		"mode":           "all",
		"invert_match":   true,
		"match_field":    []any{"exact:type=prune"},
		"match_severity": []any{"info"},
		"target":         []any{"mail"},
	})
	planned := h.plan(t, "pbs_notification_matcher", nil, toSMTP)
	applied := h.apply(t, "pbs_notification_matcher", nil, toSMTP, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "built-in default-matcher, which always exists")

	inst := h.importByID(t, "pbs_notification_matcher", defaultMatcher)
	if stringAt(t, inst.state, "origin") != pbsclient.OriginBuiltin || !boolAt(t, inst.state, "invert_match") ||
		stringAt(t, inst.state, "target", 0) != "mail-to-root" {
		t.Errorf("imported state = %s", inst.state)
	}

	// Pointing it at the SMTP endpoint changes the target alone.
	planned = h.plan(t, "pbs_notification_matcher", inst, toSMTP)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if !isUnknownAt(t, h.decodeResource(t, "pbs_notification_matcher", planned.PlannedState), "origin") {
		t.Error("origin is not unknown in a plan that changes the matcher")
	}
	inst = h.update(t, inst, toSMTP)
	updated := fake.lastCall(t, "PUT /config/notifications/matchers/"+defaultMatcher)
	if len(updated.form) != 1 || updated.form.Get("target") != "mail" {
		t.Errorf("PUT form = %v, want the target alone", updated.form)
	}
	if stringAt(t, inst.state, "origin") != pbsclient.OriginModifiedBuiltin {
		t.Errorf("origin = %q", stringAt(t, inst.state, "origin"))
	}
	replan := h.plan(t, "pbs_notification_matcher", inst, toSMTP)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_notification_matcher", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	// Destroying resets it to the built-in settings.
	h.destroy(t, inst)
	if reset, exists := notifications.entry(defaultMatcher); !exists || !reflect.DeepEqual(reset, builtin) {
		t.Errorf("default-matcher after destroy = %v, want the built-in %v", reset, builtin)
	}
}

func TestNotificationMatcherResourceValidation(t *testing.T) {
	h, _, _ := newNotificationsHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"field without prefix":  {map[string]any{"match_field": []any{"type=prune"}}, "match_field"},
		"field spaces":          {map[string]any{"match_field": []any{"exact:type=prune, gc"}}, "match_field"},
		"field without value":   {map[string]any{"match_field": []any{"exact:type="}}, "match_field"},
		"regex padded":          {map[string]any{"match_field": []any{"regex:hostname= ^pbs"}}, "match_field"},
		"severity spaces":       {map[string]any{"match_severity": []any{"warning, error"}}, "match_severity"},
		"unknown severity":      {map[string]any{"match_severity": []any{"critical"}}, "match_severity"},
		"bad mode":              {map[string]any{"mode": "none"}, "mode"},
		"empty target":          {map[string]any{"target": []any{}}, "target"},
		"one-letter name":       {map[string]any{"name": "m"}, "name"},
		"empty calendar string": {map[string]any{"match_calendar": []any{""}}, "match_calendar"},
	} {
		t.Run(name, func(t *testing.T) {
			attrs := map[string]any{"name": "matcher"}
			for k, v := range tc.attrs {
				attrs[k] = v
			}
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_notification_matcher", h.resourceValue(t, "pbs_notification_matcher", attrs)), tc.want)
		})
	}
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_notification_matcher", h.resourceValue(t, "pbs_notification_matcher", map[string]any{
		"name": "matcher", "match_field": []any{"exact:type=prune,gc", "regex:hostname=^pbs-[0-9]+$"}, "match_severity": []any{"error"},
	})))
}
