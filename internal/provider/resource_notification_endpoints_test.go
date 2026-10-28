package provider

import (
	"encoding/base64"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Tests of pbs_notification_endpoint_sendmail, _gotify and _webhook, and of
// send_test_on_apply, which every endpoint resource has.

func TestNotificationEndpointResourceSchemasAreValid(t *testing.T) {
	for _, r := range []resource.Resource{&sendmailEndpointResource{}, &gotifyEndpointResource{}, &webhookEndpointResource{}, &smtpEndpointResource{}} {
		requireValidResourceSchema(t, r)
	}
}

// resourceConfig is the configuration of typeName: base with attrs on top.
func resourceConfig(t *testing.T, h *protocolHarness, typeName string, base, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{}
	for k, v := range base {
		config[k] = v
	}
	for k, v := range attrs {
		config[k] = v
	}
	return h.resourceValue(t, typeName, config)
}

// requireNoPlannedChange fails the test when planning config for inst
// changes anything.
func requireNoPlannedChange(t *testing.T, h *protocolHarness, inst *resourceInstance, config tftypes.Value) {
	t.Helper()
	replan := h.plan(t, inst.typeName, inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, inst.typeName, replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// --- sendmail -------------------------------------------------------------------

const sendmailType = "pbs_notification_endpoint_sendmail"

func sendmailConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	return resourceConfig(t, h, sendmailType, map[string]any{"name": "ops-mail"}, attrs)
}

func TestSendmailEndpointResourceLifecycle(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)

	config := sendmailConfig(t, h, map[string]any{
		"mailto":       []any{"ops@example.com", "admin@example.com"},
		"from_address": "pbs@example.com",
		"author":       "Backup server",
		"comment":      "Operations",
	})
	planned := h.plan(t, sendmailType, nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if got := stringAt(t, h.decodeResource(t, sendmailType, planned.PlannedState), "origin"); got != pbsclient.OriginUserCreated {
		t.Errorf("planned origin = %q, want it known as user-created", got)
	}
	inst := h.create(t, sendmailType, config)
	created := fake.lastCall(t, "POST /config/notifications/endpoints/sendmail")
	if got := strings.Join(created.form["mailto"], ","); got != "admin@example.com,ops@example.com" {
		t.Errorf("POST mailto = %q, want both, sorted", got)
	}
	if created.form.Get("from-address") != "pbs@example.com" || created.form.Get("author") != "Backup server" ||
		created.form.Get("comment") != "Operations" {
		t.Errorf("POST form = %v", created.form)
	}
	for _, name := range []string{"disable", "mailto-user"} {
		if _, sent := created.form[name]; sent {
			t.Errorf("POST sent %s: %v", name, created.form)
		}
	}
	if stringAt(t, inst.state, "origin") != pbsclient.OriginUserCreated || boolAt(t, inst.state, "disable") ||
		boolAt(t, inst.state, "send_test_on_apply") || lengthAt(t, inst.state, "mailto") != 2 {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// Sender and author go back to PBS's defaults, the recipients change.
	inst = h.update(t, inst, sendmailConfig(t, h, map[string]any{"mailto_user": []any{"root@pam"}, "disable": true}))
	updated := fake.lastCall(t, "PUT /config/notifications/endpoints/sendmail/ops-mail")
	if got := strings.Join(updated.form["delete"], ","); got != "author,comment,from-address,mailto" {
		t.Errorf("delete = %q", got)
	}
	if updated.form.Get("mailto-user") != "root@pam" || updated.form.Get("disable") != "true" {
		t.Errorf("PUT form = %v", updated.form)
	}
	if !isNullAt(t, inst.state, "from_address") || !isNullAt(t, inst.state, "mailto") || !boolAt(t, inst.state, "disable") {
		t.Errorf("state = %s", inst.state)
	}

	// PBS refuses to delete an endpoint a matcher targets.
	notifications.addMatcher("ops", fakeProperties{"target": []string{"ops-mail"}})
	null := tftypes.NewValue(h.resourceType(t, sendmailType), nil)
	applied := h.apply(t, sendmailType, inst, null, h.plan(t, sendmailType, inst, null))
	requireProtocolErrorContaining(t, applied.Diagnostics, "Matchers still target endpoint")

	notifications.mu.Lock()
	delete(notifications.entries, "ops")
	notifications.mu.Unlock()
	h.destroy(t, inst)
	if _, exists := notifications.entry("ops-mail"); exists {
		t.Error("the endpoint still exists")
	}
}

// The built-in mail-to-root cannot be created, only imported; changing it
// makes it modified-builtin, and destroying the resource resets it, though
// default-matcher targets it.
func TestSendmailEndpointResourceMailToRoot(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)
	builtin, _ := notifications.entry(mailToRoot)

	config := resourceConfig(t, h, sendmailType, nil, map[string]any{
		"name":        mailToRoot,
		"comment":     "Send mails to root@pam's email address",
		"mailto_user": []any{"root@pam"},
		"mailto":      []any{"ops@example.com"},
	})
	applied := h.apply(t, sendmailType, nil, config, h.plan(t, sendmailType, nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "the built-in mail-to-root, which always exists")

	inst := h.importByID(t, sendmailType, mailToRoot)
	if stringAt(t, inst.state, "origin") != pbsclient.OriginBuiltin || stringAt(t, inst.state, "mailto_user", 0) != "root@pam" ||
		boolAt(t, inst.state, "send_test_on_apply") {
		t.Errorf("imported state = %s", inst.state)
	}

	planned := h.plan(t, sendmailType, inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if !isUnknownAt(t, h.decodeResource(t, sendmailType, planned.PlannedState), "origin") {
		t.Error("origin of mail-to-root is not unknown in a plan that changes it")
	}
	inst = h.update(t, inst, config)
	if updated := fake.lastCall(t, "PUT /config/notifications/endpoints/sendmail/"+mailToRoot); len(updated.form) != 1 ||
		updated.form.Get("mailto") != "ops@example.com" {
		t.Errorf("PUT form = %v, want mailto alone", updated.form)
	}
	if stringAt(t, inst.state, "origin") != pbsclient.OriginModifiedBuiltin {
		t.Errorf("origin = %q", stringAt(t, inst.state, "origin"))
	}
	requireNoPlannedChange(t, h, inst, config)

	h.destroy(t, inst)
	if reset, exists := notifications.entry(mailToRoot); !exists || !reflect.DeepEqual(reset, builtin) {
		t.Errorf("mail-to-root after destroy = %v, want the built-in %v", reset, builtin)
	}
}

func TestSendmailEndpointResourceValidation(t *testing.T) {
	h, _, _ := newNotificationsHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"no recipient":    {map[string]any{}, "mailto"},
		"empty mailto":    {map[string]any{"mailto": []any{}}, "mailto"},
		"bad user":        {map[string]any{"mailto_user": []any{"root"}}, "mailto_user"},
		"padded sender":   {map[string]any{"mailto": []any{"ops@example.com"}, "from_address": "pbs@example.com "}, "from_address"},
		"one-letter name": {map[string]any{"mailto": []any{"ops@example.com"}, "name": "m"}, "name"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, sendmailType, sendmailConfig(t, h, tc.attrs)), tc.want)
		})
	}
	requireNoProtocolErrors(t, h.validateResource(t, sendmailType, sendmailConfig(t, h, map[string]any{"mailto_user": []any{"root@pam"}})))
}

// --- Gotify ---------------------------------------------------------------------

const gotifyType = "pbs_notification_endpoint_gotify"

func gotifyConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	return resourceConfig(t, h, gotifyType, map[string]any{
		"name": "push", "server": "https://gotify.example.com", "token_wo": "first-token", "token_wo_version": 1,
	}, attrs)
}

func TestGotifyEndpointResourceLifecycle(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)

	config := gotifyConfig(t, h, map[string]any{"comment": "Phones"})
	inst := h.create(t, gotifyType, config)
	created := fake.lastCall(t, "POST /config/notifications/endpoints/gotify")
	if created.form.Get("server") != "https://gotify.example.com" || created.form.Get("token") != "first-token" ||
		created.form.Get("comment") != "Phones" || created.form.Has("disable") {
		t.Errorf("POST form = %v", created.form)
	}
	if !isNullAt(t, inst.state, "token_wo") || int64At(t, inst.state, "token_wo_version") != 1 ||
		stringAt(t, inst.state, "origin") != pbsclient.OriginUserCreated {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// The server changes and the comment goes; the token, at the same
	// version, is not sent again.
	inst = h.update(t, inst, gotifyConfig(t, h, map[string]any{"server": "http://gotify.lan:8080/push"}))
	updated := fake.lastCall(t, "PUT /config/notifications/endpoints/gotify/push")
	if updated.form.Get("server") != "http://gotify.lan:8080/push" || strings.Join(updated.form["delete"], ",") != "comment" ||
		updated.form.Has("token") {
		t.Errorf("PUT form = %v", updated.form)
	}

	// A new version sends the new token, alone.
	inst = h.update(t, inst, gotifyConfig(t, h, map[string]any{
		"server": "http://gotify.lan:8080/push", "token_wo": "second-token", "token_wo_version": 2,
	}))
	if updated := fake.lastCall(t, "PUT /config/notifications/endpoints/gotify/push"); len(updated.form) != 1 ||
		updated.form.Get("token") != "second-token" {
		t.Errorf("PUT form = %v, want the token alone", updated.form)
	}
	if got, _ := notifications.password("push"); got != "second-token" {
		t.Errorf("stored token = %q", got)
	}

	for name, imported := range map[string]*resourceInstance{
		"id":       h.importByID(t, gotifyType, "push"),
		"identity": h.importByIdentity(t, gotifyType, map[string]any{"name": "push"}),
	} {
		if stringAt(t, imported.state, "server") != "http://gotify.lan:8080/push" || !isNullAt(t, imported.state, "token_wo_version") ||
			boolAt(t, imported.state, "send_test_on_apply") {
			t.Errorf("import by %s = %s", name, imported.state)
		}
	}

	h.destroy(t, inst)
	if _, exists := notifications.password("push"); exists {
		t.Error("the endpoint's token is left")
	}
}

func TestGotifyEndpointResourceValidation(t *testing.T) {
	h, _, _ := newNotificationsHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"trailing slash":  {map[string]any{"server": "https://gotify.example.com/"}, "server"},
		"no scheme":       {map[string]any{"server": "gotify.example.com"}, "server"},
		"other scheme":    {map[string]any{"server": "ftp://gotify.example.com"}, "server"},
		"query":           {map[string]any{"server": "https://gotify.example.com?x=1"}, "server"},
		"credentials":     {map[string]any{"server": "https://u:p@gotify.example.com"}, "server"},
		"padded token":    {map[string]any{"token_wo": " token"}, "token_wo"},
		"no token":        {map[string]any{"token_wo": nil}, "token_wo"},
		"no version":      {map[string]any{"token_wo_version": nil}, "token_wo_version"},
		"one-letter name": {map[string]any{"name": "g"}, "name"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, gotifyType, gotifyConfig(t, h, tc.attrs)), tc.want)
		})
	}
	requireNoProtocolErrors(t, h.validateResource(t, gotifyType, gotifyConfig(t, h, map[string]any{"server": "http://10.0.0.5:8080"})))
}

// --- webhook --------------------------------------------------------------------

const webhookType = "pbs_notification_endpoint_webhook"

func webhookConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	return resourceConfig(t, h, webhookType, map[string]any{
		"name": "hook", "url": "https://hooks.example.com/notify/{{ secrets.channel }}",
	}, attrs)
}

func webhookSecret(name, value string, version int) map[string]any {
	return map[string]any{"name": name, "value_wo": value, "value_wo_version": version}
}

func webhookHeader(name, value string) map[string]any {
	return map[string]any{"name": name, "value": value}
}

func TestWebhookEndpointResourceLifecycle(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)
	const route = "PUT /config/notifications/endpoints/webhook/hook"
	body := `{"text": "{{ escape title }}", "severity": "{{ severity }}"}`
	headers := []any{
		webhookHeader("Content-Type", "application/json"),
		webhookHeader("Authorization", "Bearer {{ secrets.token }}"),
	}

	config := webhookConfig(t, h, map[string]any{
		"method": "put",
		"body":   body,
		"header": headers,
		"secret": []any{webhookSecret("token", "t0ken", 1), webhookSecret("channel", "alerts", 1)},
	})
	inst := h.create(t, webhookType, config)
	created := fake.lastCall(t, "POST /config/notifications/endpoints/webhook")
	wantHeaders := []string{"name=Content-Type,value=" + b64("application/json"), "name=Authorization,value=" + b64("Bearer {{ secrets.token }}")}
	wantSecrets := []string{"name=token,value=" + b64("t0ken"), "name=channel,value=" + b64("alerts")}
	if created.form.Get("method") != "put" || created.form.Get("body") != b64(body) ||
		!slices.Equal(created.form["header"], wantHeaders) || !slices.Equal(created.form["secret"], wantSecrets) {
		t.Errorf("POST form = %v", created.form)
	}
	if got := notifications.secrets("hook"); !reflect.DeepEqual(got, map[string]string{"token": "t0ken", "channel": "alerts"}) {
		t.Errorf("stored secrets = %v", got)
	}
	if stringAt(t, inst.state, "body") != body || stringAt(t, inst.state, "header", 1, "value") != "Bearer {{ secrets.token }}" ||
		stringAt(t, inst.state, "secret", 1, "name") != "channel" || !isNullAt(t, inst.state, "secret", 0, "value_wo") ||
		int64At(t, inst.state, "secret", 0, "value_wo_version") != 1 || stringAt(t, inst.state, "origin") != pbsclient.OriginUserCreated {
		t.Errorf("state = %s", inst.state)
	}
	requireNoPlannedChange(t, h, inst, config)

	// A new version sends the token's new value; the channel, at the same
	// version, goes by name and keeps its value; the new secret is sent
	// with its value.
	config = webhookConfig(t, h, map[string]any{
		"method": "put", "body": body, "header": headers,
		"secret": []any{webhookSecret("token", "t0ken-2", 2), webhookSecret("channel", "changed but not sent", 1), webhookSecret("extra", "x", 1)},
	})
	inst = h.update(t, inst, config)
	updated := fake.lastCall(t, route)
	if want := []string{"name=token,value=" + b64("t0ken-2"), "name=channel", "name=extra,value=" + b64("x")}; !slices.Equal(updated.form["secret"], want) ||
		len(updated.form) != 1 {
		t.Errorf("PUT form = %v, want the secrets %v alone", updated.form, want)
	}
	if got := notifications.secrets("hook"); !reflect.DeepEqual(got, map[string]string{"token": "t0ken-2", "channel": "alerts", "extra": "x"}) {
		t.Errorf("stored secrets = %v", got)
	}
	requireNoPlannedChange(t, h, inst, config)

	// A change elsewhere sends no secret.
	config = webhookConfig(t, h, map[string]any{
		"method": "put", "body": body, "header": headers, "comment": "Chat",
		"secret": []any{webhookSecret("token", "t0ken-2", 2), webhookSecret("channel", "alerts", 1), webhookSecret("extra", "x", 1)},
	})
	inst = h.update(t, inst, config)
	if updated := fake.lastCall(t, route); len(updated.form) != 1 || updated.form.Get("comment") != "Chat" {
		t.Errorf("PUT form = %v, want the comment alone", updated.form)
	}

	// Dropping a secret sends the others by name; dropping them all, the
	// headers and the body deletes them, and method goes back to post,
	// which PBS cannot delete.
	config = webhookConfig(t, h, map[string]any{
		"method": "put", "body": body, "header": headers, "comment": "Chat",
		"secret": []any{webhookSecret("channel", "alerts", 1)},
	})
	inst = h.update(t, inst, config)
	if updated := fake.lastCall(t, route); !slices.Equal(updated.form["secret"], []string{"name=channel"}) {
		t.Errorf("PUT form = %v", updated.form)
	}
	if got := notifications.secrets("hook"); !reflect.DeepEqual(got, map[string]string{"channel": "alerts"}) {
		t.Errorf("stored secrets = %v", got)
	}
	inst = h.update(t, inst, webhookConfig(t, h, map[string]any{}))
	updated = fake.lastCall(t, route)
	if got := strings.Join(updated.form["delete"], ","); got != "body,comment,header,secret" || updated.form.Get("method") != "post" {
		t.Errorf("PUT form = %v", updated.form)
	}
	if got := notifications.secrets("hook"); len(got) != 0 {
		t.Errorf("stored secrets = %v, want none", got)
	}
	if !isNullAt(t, inst.state, "secret") || !isNullAt(t, inst.state, "header") || !isNullAt(t, inst.state, "body") ||
		stringAt(t, inst.state, "method") != "post" {
		t.Errorf("state = %s", inst.state)
	}

	h.destroy(t, inst)
	if _, exists := notifications.entry("hook"); exists {
		t.Error("the endpoint still exists")
	}
}

// PBS requires a method, which the provider sends at its default.
func TestWebhookEndpointResourceDefaultMethod(t *testing.T) {
	h, fake, _ := newNotificationsHarness(t)
	inst := h.create(t, webhookType, webhookConfig(t, h, map[string]any{}))
	if created := fake.lastCall(t, "POST /config/notifications/endpoints/webhook"); created.form.Get("method") != "post" ||
		created.form.Has("secret") || created.form.Has("header") || created.form.Has("body") {
		t.Errorf("POST form = %v", created.form)
	}
	if stringAt(t, inst.state, "method") != "post" || !isNullAt(t, inst.state, "secret") {
		t.Errorf("state = %s", inst.state)
	}
}

// Import cannot know the secrets' values: their versions are null, and the
// first apply sends every value. A secret removed outside Terraform is
// added again with its value; one added there is removed.
func TestWebhookEndpointResourceImportAndDrift(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)
	const route = "PUT /config/notifications/endpoints/webhook/hook"
	config := webhookConfig(t, h, map[string]any{
		"secret": []any{webhookSecret("token", "t0ken", 1), webhookSecret("channel", "alerts", 1)},
	})
	h.create(t, webhookType, config)

	inst := h.importByID(t, webhookType, "hook")
	if stringAt(t, inst.state, "secret", 0, "name") != "token" || !isNullAt(t, inst.state, "secret", 0, "value_wo_version") {
		t.Errorf("imported state = %s", inst.state)
	}
	inst = h.update(t, inst, config)
	if want := []string{"name=token,value=" + b64("t0ken"), "name=channel,value=" + b64("alerts")}; !slices.Equal(fake.lastCall(t, route).form["secret"], want) {
		t.Errorf("PUT form = %v, want every value", fake.lastCall(t, route).form)
	}
	requireNoPlannedChange(t, h, inst, config)

	notifications.mu.Lock()
	notifications.webhookSecrets["hook"] = []string{"name=token,value=" + b64("t0ken"), "name=stray,value=" + b64("s")}
	notifications.mu.Unlock()
	inst = h.refresh(t, inst)
	if lengthAt(t, inst.state, "secret") != 2 || stringAt(t, inst.state, "secret", 1, "name") != "stray" ||
		!isNullAt(t, inst.state, "secret", 1, "value_wo_version") || int64At(t, inst.state, "secret", 0, "value_wo_version") != 1 {
		t.Errorf("refreshed state = %s", inst.state)
	}
	inst = h.update(t, inst, config)
	if want := []string{"name=token", "name=channel,value=" + b64("alerts")}; !slices.Equal(fake.lastCall(t, route).form["secret"], want) {
		t.Errorf("PUT form = %v, want %v", fake.lastCall(t, route).form, want)
	}
	if got := notifications.secrets("hook"); !reflect.DeepEqual(got, map[string]string{"token": "t0ken", "channel": "alerts"}) {
		t.Errorf("stored secrets = %v", got)
	}
	requireNoPlannedChange(t, h, inst, config)
}

// What PBS stores in a form the provider cannot decode is shown as stored,
// with a warning, and a header without a name is left out.
func TestWebhookEndpointResourceReadsUndecodableValues(t *testing.T) {
	h, fake, _ := newNotificationsHarness(t)
	fake.reply("GET /config/notifications/endpoints/webhook/raw", http.StatusOK, `{"data":{"name":"raw","url":"https://hooks.example.com",`+
		`"method":"get","body":"not base64!","header":["name=X-Raw,value=%%%","value=YQ==","name=X-Ok,value=`+b64("ok")+`"],`+
		`"secret":["name=token","broken"],"origin":"user-created"}}`)
	imported := h.importResource(t, webhookType, "raw", nil)
	requireNoProtocolErrors(t, imported.Diagnostics)
	read := h.read(t, &resourceInstance{typeName: webhookType, state: h.decodeResource(t, webhookType, imported.ImportedResources[0].State)})
	requireNoProtocolErrors(t, read.Diagnostics)
	for _, want := range []string{"PBS has a body for webhook endpoint \"raw\"", "header \"X-Raw\"", "the provider cannot read, \"value=YQ==\"",
		"PBS has a secret for webhook endpoint \"raw\""} {
		requireProtocolWarningContaining(t, read.Diagnostics, want)
	}
	state := h.decodeResource(t, webhookType, read.NewState)
	if stringAt(t, state, "body") != "not base64!" || lengthAt(t, state, "header") != 2 || stringAt(t, state, "header", 0, "value") != "%%%" ||
		stringAt(t, state, "header", 1, "value") != "ok" || lengthAt(t, state, "secret") != 1 || stringAt(t, state, "method") != "get" {
		t.Errorf("state = %s", state)
	}
}

func TestWebhookEndpointResourceValidation(t *testing.T) {
	h, _, _ := newNotificationsHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"no scheme":            {map[string]any{"url": "hooks.example.com/x"}, "url"},
		"padded url":           {map[string]any{"url": " https://hooks.example.com"}, "url"},
		"scheme only":          {map[string]any{"url": "https://"}, "url"},
		"bad method":           {map[string]any{"method": "patch"}, "method"},
		"empty body":           {map[string]any{"body": ""}, "body"},
		"header name":          {map[string]any{"header": []any{webhookHeader("Content Type", "x")}}, "name"},
		"header value newline": {map[string]any{"header": []any{webhookHeader("X-A", "a\nb")}}, "value"},
		"empty headers":        {map[string]any{"header": []any{}}, "header"},
		"secret name":          {map[string]any{"secret": []any{webhookSecret("my.token", "x", 1)}}, "name"},
		"duplicate secrets": {map[string]any{"secret": []any{webhookSecret("token", "x", 1), webhookSecret("token", "y", 1)}},
			"more than once"},
		"empty secret value": {map[string]any{"secret": []any{webhookSecret("token", "", 1)}}, "value_wo"},
		"no secret version": {map[string]any{"secret": []any{map[string]any{"name": "token", "value_wo": "x"}}},
			"value_wo_version"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, webhookType, webhookConfig(t, h, tc.attrs)), tc.want)
		})
	}
	requireNoProtocolErrors(t, h.validateResource(t, webhookType, webhookConfig(t, h, map[string]any{
		"url":    "http://10.0.0.5:8080/hook?topic={{ url-encode title }}",
		"header": []any{webhookHeader("X-A", "a"), webhookHeader("X-A", "b")},
		"secret": []any{webhookSecret("token", "x\ny ", 1)},
	})))
}

// --- send_test_on_apply -----------------------------------------------------------

// A test goes out after a create, and after an update that changes the
// endpoint, unless it is disabled; turning the option on, or a plan that
// changes nothing in PBS, sends none.
func TestNotificationEndpointSendTestOnApply(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)

	inst := h.create(t, gotifyType, gotifyConfig(t, h, map[string]any{"send_test_on_apply": true}))
	if got := notifications.tested(); !slices.Equal(got, []string{"push"}) || !boolAt(t, inst.state, "send_test_on_apply") {
		t.Fatalf("tested %v after create, state %s", got, inst.state)
	}
	inst = h.update(t, inst, gotifyConfig(t, h, map[string]any{}))
	inst = h.update(t, inst, gotifyConfig(t, h, map[string]any{"send_test_on_apply": true}))
	if got := notifications.tested(); len(got) != 1 {
		t.Errorf("tested %v, want no test from toggling send_test_on_apply", got)
	}
	inst = h.update(t, inst, gotifyConfig(t, h, map[string]any{"send_test_on_apply": true, "comment": "Phones"}))
	if got := notifications.tested(); len(got) != 2 {
		t.Errorf("tested %v, want a test after a change", got)
	}
	inst = h.update(t, inst, gotifyConfig(t, h, map[string]any{"send_test_on_apply": true, "comment": "Phones", "disable": true}))
	if got := notifications.tested(); len(got) != 2 {
		t.Errorf("tested %v, want none through a disabled endpoint", got)
	}

	// A failed test after an update fails the apply with the change
	// recorded.
	notifications.failTests("push", "could not notify via target `push`: connection refused")
	config := gotifyConfig(t, h, map[string]any{"send_test_on_apply": true, "comment": "Tablets"})
	applied := h.apply(t, gotifyType, inst, config, h.plan(t, gotifyType, inst, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "connection refused")
	requireProtocolErrorContaining(t, applied.Diagnostics, "tests it again only if the endpoint changes again")
	if state := h.decodeResource(t, gotifyType, applied.NewState); stringAt(t, state, "comment") != "Tablets" {
		t.Errorf("state after the failed test = %s", state)
	}

	// After a create, the endpoint is deleted again, leaving nothing for
	// Terraform to taint: under create_before_destroy, a tainted endpoint's
	// replacement would need the name it holds.
	notifications.failTests("hook", "could not notify via target `hook`: HTTP 500")
	config = webhookConfig(t, h, map[string]any{"send_test_on_apply": true, "secret": []any{webhookSecret("token", "t0ken", 1)}})
	applied = h.apply(t, webhookType, nil, config, h.plan(t, webhookType, nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "the provider deleted the endpoint again")
	if state := h.decodeResource(t, webhookType, applied.NewState); !state.IsNull() {
		t.Errorf("state after the failed test = %s, want none", state)
	}
	if _, exists := notifications.entry("hook"); exists {
		t.Error("the endpoint whose test failed still exists")
	}
	if got := notifications.secrets("hook"); len(got) != 0 {
		t.Errorf("its secrets are left: %v", got)
	}

	// Only when that delete fails too is it recorded, for Terraform to taint.
	fake.reply("DELETE /config/notifications/endpoints/webhook/hook", http.StatusInternalServerError, "could not save config")
	applied = h.apply(t, webhookType, nil, config, h.plan(t, webhookType, nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "run `terraform untaint` on it instead")
	if state := h.decodeResource(t, webhookType, applied.NewState); state.IsNull() || stringAt(t, state, "name") != "hook" {
		t.Errorf("state after the failed test and delete = %s", state)
	}
}

// PBS masks a webhook secret in a failed test's error only as it is; the
// provider also hides the forms a template helper gives it.
func TestNotificationEndpointSendTestOnApplyRedactsSecrets(t *testing.T) {
	h, _, notifications := newNotificationsHarness(t)
	const secret = "ab+c/d= é"
	notifications.failTests("hook", "could not notify via target `hook`: GET https://h/?auth="+
		"ab%2Bc%2Fd%3D%20%C3%A9: status code 401 (raw "+secret+")")
	config := webhookConfig(t, h, map[string]any{
		"url":                "https://h/?auth={{ url-encode secrets.token }}",
		"send_test_on_apply": true,
		"secret":             []any{webhookSecret("token", secret, 1)},
	})
	applied := h.apply(t, webhookType, nil, config, h.plan(t, webhookType, nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "status code 401")
	for _, d := range applied.Diagnostics {
		if strings.Contains(d.Detail, "ab%2B") || strings.Contains(d.Detail, secret) {
			t.Errorf("the diagnostic shows the secret: %s", d.Detail)
		}
	}
}

// A secret's value that fails validation is not repeated in the error.
func TestSecretValidationErrorsHideTheValue(t *testing.T) {
	h, _, _ := newNotificationsHarness(t)
	const value = "SuperSecretToken\n"
	for typeName, config := range map[string]tftypes.Value{
		gotifyType: gotifyConfig(t, h, map[string]any{"token_wo": value}),
		"pbs_notification_endpoint_smtp": smtpConfig(t, h, map[string]any{
			"mailto": []any{"ops@example.com"}, "username": "pbs", "password_wo": value, "password_wo_version": 1,
		}),
		"pbs_user":        h.resourceValue(t, "pbs_user", map[string]any{"userid": "alice@pbs", "password_wo": value, "password_wo_version": 1}),
		"pbs_acme_plugin": pluginConfig(t, h, map[string]any{"data": map[string]any{"CF_Token": value}}),
	} {
		diags := h.validateResource(t, typeName, config)
		requireProtocolErrorContaining(t, diags, "the value is not shown")
		for _, d := range diags {
			if strings.Contains(d.Detail, "SuperSecret") {
				t.Errorf("%s: the diagnostic shows the value: %s", typeName, d.Detail)
			}
		}
	}
}

// Every endpoint resource sends tests, the sendmail and SMTP ones included,
// and mail-to-root once imported.
func TestNotificationEndpointSendTestOnApplyEveryType(t *testing.T) {
	h, _, notifications := newNotificationsHarness(t)
	h.create(t, sendmailType, sendmailConfig(t, h, map[string]any{"mailto": []any{"ops@example.com"}, "send_test_on_apply": true}))
	h.create(t, "pbs_notification_endpoint_smtp", smtpConfig(t, h, map[string]any{"mailto": []any{"ops@example.com"}, "send_test_on_apply": true}))
	h.create(t, webhookType, webhookConfig(t, h, map[string]any{"send_test_on_apply": true}))
	root := h.importByID(t, sendmailType, mailToRoot)
	h.update(t, root, resourceConfig(t, h, sendmailType, nil, map[string]any{
		"name": mailToRoot, "mailto_user": []any{"root@pam"}, "send_test_on_apply": true,
	}))
	if got, want := notifications.tested(), []string{"ops-mail", "mail", "hook", mailToRoot}; !slices.Equal(got, want) {
		t.Errorf("tested %v, want %v", got, want)
	}
}

// State written before send_test_on_apply existed reads as its default, so
// that upgrading the provider plans no change.
func TestSMTPEndpointResourceUpgradeWithoutSendTestOnApply(t *testing.T) {
	h, _, _ := newNotificationsHarness(t)
	config := smtpConfig(t, h, map[string]any{"mailto": []any{"ops@example.com"}})
	inst := h.create(t, "pbs_notification_endpoint_smtp", config)
	attrs := maps.Clone(harnessObjectAttributes(t, inst.state))
	attrs["send_test_on_apply"] = tftypes.NewValue(tftypes.Bool, nil)
	inst.state = tftypes.NewValue(inst.state.Type(), attrs)

	inst = h.refresh(t, inst)
	if boolAt(t, inst.state, "send_test_on_apply") {
		t.Errorf("send_test_on_apply = true, want false")
	}
	requireNoPlannedChange(t, h, inst, config)
}

// --- errors ---------------------------------------------------------------------

// Every endpoint resource reports PBS's errors on each operation, keeps in
// state what PBS saved before reading it back failed, drops an endpoint gone
// since, and refuses an import ID that cannot be an endpoint name.
func TestNotificationEndpointResourceErrors(t *testing.T) {
	tests := map[string]struct {
		typeName, kind, what string
		config               func(*testing.T, *protocolHarness) tftypes.Value
	}{
		"sendmail": {sendmailType, "sendmail", "sendmail", func(t *testing.T, h *protocolHarness) tftypes.Value {
			return sendmailConfig(t, h, map[string]any{"mailto": []any{"ops@example.com"}})
		}},
		"gotify": {gotifyType, "gotify", "Gotify", func(t *testing.T, h *protocolHarness) tftypes.Value {
			return gotifyConfig(t, h, map[string]any{})
		}},
		"webhook": {webhookType, "webhook", "webhook", func(t *testing.T, h *protocolHarness) tftypes.Value {
			return webhookConfig(t, h, map[string]any{"secret": []any{webhookSecret("token", "t0ken", 1)}})
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h, fake, notifications := newNotificationsHarness(t)
			config := tc.config(t, h)
			endpoint := stringAt(t, config, "name")
			createRoute := "POST " + fakeNotificationPath(tc.kind)
			itemRoute := fakeNotificationPath(tc.kind) + "/" + endpoint
			attempt := func(prior *resourceInstance, config tftypes.Value) *tfprotov6.ApplyResourceChangeResponse {
				t.Helper()
				planned := h.plan(t, tc.typeName, prior, config)
				requireNoProtocolErrors(t, planned.Diagnostics)
				return h.apply(t, tc.typeName, prior, config, planned)
			}

			// A name a matcher has.
			notifications.addMatcher(endpoint, fakeProperties{})
			requireProtocolErrorContaining(t, attempt(nil, config).Diagnostics, "If it is a "+tc.what+" endpoint")
			notifications.mu.Lock()
			delete(notifications.entries, endpoint)
			notifications.mu.Unlock()

			fake.reply(createRoute, http.StatusInternalServerError, "could not save endpoint")
			requireProtocolErrorContaining(t, attempt(nil, config).Diagnostics, "Unable to create PBS "+tc.what)
			fake.handle(createRoute, notifications.create(tc.kind))

			fake.reply("GET "+itemRoute, http.StatusInternalServerError, "could not read endpoint")
			applied := attempt(nil, config)
			requireProtocolErrorContaining(t, applied.Diagnostics, "marked tainted")
			inst := &resourceInstance{typeName: tc.typeName, state: h.decodeResource(t, tc.typeName, applied.NewState), identity: applied.NewIdentity}
			if stringAt(t, inst.state, "origin") != "user-created" || stringAt(t, inst.state, "id") != endpoint {
				t.Errorf("state after the failed read = %s", inst.state)
			}
			requireProtocolErrorContaining(t, h.read(t, inst).Diagnostics, "Unable to read PBS "+tc.what)
			fake.handle("GET "+itemRoute, nil)
			inst = h.refresh(t, inst)

			changedAttrs := maps.Clone(harnessObjectAttributes(t, config))
			changedAttrs["comment"] = tftypes.NewValue(tftypes.String, "changed")
			changed := tftypes.NewValue(config.Type(), changedAttrs)
			fake.reply("PUT "+itemRoute, http.StatusBadRequest, "parameter verification failed")
			requireProtocolErrorContaining(t, attempt(inst, changed).Diagnostics, "Unable to update PBS "+tc.what)
			fake.handle("PUT "+itemRoute, nil)

			fake.reply("GET "+itemRoute, http.StatusInternalServerError, "could not read endpoint")
			applied = attempt(inst, changed)
			requireProtocolErrorContaining(t, applied.Diagnostics, "reading it back failed")
			if state := h.decodeResource(t, tc.typeName, applied.NewState); stringAt(t, state, "comment") != "changed" || !knownAt(t, state, "origin").IsKnown() {
				t.Errorf("state after the failed read = %s", state)
			}
			fake.handle("GET "+itemRoute, nil)
			inst = h.refresh(t, inst)

			fake.reply("DELETE "+itemRoute, http.StatusInternalServerError, "could not save config")
			requireProtocolErrorContaining(t, attempt(inst, tftypes.NewValue(config.Type(), nil)).Diagnostics, "Unable to delete PBS "+tc.what)
			fake.handle("DELETE "+itemRoute, nil)

			// Gone since: a refresh drops it, and destroying it is no error.
			notifications.mu.Lock()
			delete(notifications.entries, endpoint)
			notifications.mu.Unlock()
			if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
				t.Errorf("refresh kept an endpoint that is gone: %s", refreshed.state)
			}
			h.destroy(t, inst)

			requireProtocolErrorContaining(t, h.importResource(t, tc.typeName, "not/a name", nil).Diagnostics, "Unexpected import identifier")
		})
	}
}
