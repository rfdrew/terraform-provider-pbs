package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// The sendmail, Gotify and webhook endpoints take the routes of their type,
// reads decode in the shape PBS 4.2 sends, and deletes send nothing but the
// path.
func TestNotificationEndpointCallsHitTheirRoutes(t *testing.T) {
	yes := true
	tests := map[string]struct {
		kind   string
		answer string
		read   func(*Client) (any, error)
		want   any
		create func(*Client, url.Values) error
		update func(*Client, url.Values) error
		del    func(*Client) error
	}{
		"sendmail": {
			kind: "sendmail",
			answer: `{"data":{"name":"probe","mailto":["ops@example.com"],"mailto-user":["root@pam"],` +
				`"from-address":"pbs@example.com","author":"Backup Server","comment":"acc","disable":true,` +
				`"origin":"modified-builtin"},"digest":"9f86d081884c7d65"}`,
			read: func(c *Client) (any, error) { return c.GetSendmailEndpoint(context.Background(), "probe") },
			want: SendmailEndpoint{Name: "probe", Mailto: []string{"ops@example.com"}, MailtoUser: []string{"root@pam"},
				FromAddress: "pbs@example.com", Author: "Backup Server", Comment: "acc", Disable: &yes, Origin: OriginModifiedBuiltin},
			create: func(c *Client, p url.Values) error { return c.CreateSendmailEndpoint(context.Background(), p) },
			update: func(c *Client, p url.Values) error { return c.UpdateSendmailEndpoint(context.Background(), "probe", p) },
			del:    func(c *Client) error { return c.DeleteSendmailEndpoint(context.Background(), "probe") },
		},
		"gotify": {
			kind:   "gotify",
			answer: `{"data":{"name":"probe","server":"https://gotify.example.com","comment":"acc","origin":"user-created"},"digest":"9f86"}`,
			read:   func(c *Client) (any, error) { return c.GetGotifyEndpoint(context.Background(), "probe") },
			want:   GotifyEndpoint{Name: "probe", Server: "https://gotify.example.com", Comment: "acc", Origin: OriginUserCreated},
			create: func(c *Client, p url.Values) error { return c.CreateGotifyEndpoint(context.Background(), p) },
			update: func(c *Client, p url.Values) error { return c.UpdateGotifyEndpoint(context.Background(), "probe", p) },
			del:    func(c *Client) error { return c.DeleteGotifyEndpoint(context.Background(), "probe") },
		},
		"webhook": {
			kind: "webhook",
			answer: `{"data":{"name":"probe","url":"https://hooks.example.com/{{ secrets.path }}","method":"put",` +
				`"body":"e3sgbWVzc2FnZSB9fQ==","header":["name=Content-Type,value=dGV4dC9wbGFpbg=="],` +
				`"secret":["name=path"],"disable":true,"origin":"user-created"},"digest":"9f86"}`,
			read: func(c *Client) (any, error) { return c.GetWebhookEndpoint(context.Background(), "probe") },
			want: WebhookEndpoint{Name: "probe", URL: "https://hooks.example.com/{{ secrets.path }}", Method: "put",
				Body: "e3sgbWVzc2FnZSB9fQ==", Header: []string{"name=Content-Type,value=dGV4dC9wbGFpbg=="},
				Secret: []string{"name=path"}, Disable: &yes, Origin: OriginUserCreated},
			create: func(c *Client, p url.Values) error { return c.CreateWebhookEndpoint(context.Background(), p) },
			update: func(c *Client, p url.Values) error { return c.UpdateWebhookEndpoint(context.Background(), "probe", p) },
			del:    func(c *Client) error { return c.DeleteWebhookEndpoint(context.Background(), "probe") },
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			base := "/config/notifications/endpoints/" + tc.kind
			getRoute, createRoute := "GET "+base+"/probe", "POST "+base
			updateRoute, deleteRoute := "PUT "+base+"/probe", "DELETE "+base+"/probe"
			fake := newFakePBS()
			fake.reply(getRoute, http.StatusOK, tc.answer)
			for _, route := range []string{createRoute, updateRoute, deleteRoute} {
				fake.reply(route, http.StatusOK, `{"data":null}`)
			}
			c := fake.client(t)

			got, err := tc.read(c)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("read = %+v, want %+v", got, tc.want)
			}
			create := url.Values{"name": {"probe"}, "comment": {"acc"}}
			if err := tc.create(c, create); err != nil {
				t.Fatalf("create = %v", err)
			}
			update := url.Values{"comment": {"changed"}, "delete": {"disable"}}
			if err := tc.update(c, update); err != nil {
				t.Fatalf("update = %v", err)
			}
			if err := tc.del(c); err != nil {
				t.Fatalf("delete = %v", err)
			}

			if got, want := fake.routes(), []string{getRoute, createRoute, updateRoute, deleteRoute}; !reflect.DeepEqual(got, want) {
				t.Fatalf("routes = %v, want %v", got, want)
			}
			if call := fake.lastCall(t, createRoute); !reflect.DeepEqual(call.form, create) {
				t.Errorf("create form = %v, want %v", call.form, create)
			}
			if call := fake.lastCall(t, updateRoute); !reflect.DeepEqual(call.form, update) {
				t.Errorf("update form = %v, want %v", call.form, update)
			}
			if call := fake.lastCall(t, deleteRoute); len(call.query) != 0 || len(call.form) != 0 {
				t.Errorf("delete query = %v, form = %v, want neither", call.query, call.form)
			}
		})
	}
}

// PBS may quote a rejected value in its error. The Gotify token and the
// webhook's secret values — as sent, in base64, and as the text they stand
// for — are kept out of it, while a secret sent without a value redacts
// nothing.
func TestNotificationEndpointWritesRedactSecrets(t *testing.T) {
	const token = "AbC.t0ken-123"
	secret := "hunter2-but-longer"
	encoded := FormatNotificationKeyValue("token", &secret)
	encodedValue := strings.TrimPrefix(encoded, "name=token,value=")
	tests := map[string]struct {
		route  string
		params url.Values
		echo   string
		leaks  []string
		write  func(*Client, url.Values) error
	}{
		"gotify create": {"POST /config/notifications/endpoints/gotify", url.Values{"name": {"probe"}, "token": {token}},
			"parameter verification failed - 'token': " + token, []string{token},
			func(c *Client, p url.Values) error { return c.CreateGotifyEndpoint(context.Background(), p) }},
		"gotify update": {"PUT /config/notifications/endpoints/gotify/probe", url.Values{"token": {token}},
			"value " + token + " rejected", []string{token},
			func(c *Client, p url.Values) error { return c.UpdateGotifyEndpoint(context.Background(), "probe", p) }},
		"webhook create": {"POST /config/notifications/endpoints/webhook",
			url.Values{"name": {"probe"}, "secret": {encoded, "name=kept"}},
			"secret " + encodedValue + " (" + secret + ") rejected", []string{encodedValue, secret},
			func(c *Client, p url.Values) error { return c.CreateWebhookEndpoint(context.Background(), p) }},
		"webhook update": {"PUT /config/notifications/endpoints/webhook/probe",
			url.Values{"secret": {"name=kept", encoded}},
			"could not render " + secret, []string{secret},
			func(c *Client, p url.Values) error { return c.UpdateWebhookEndpoint(context.Background(), "probe", p) }},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(tc.route, http.StatusBadRequest, tc.echo)
			err := tc.write(fake.client(t), tc.params)
			apiErr, ok := asError(err)
			if !ok || apiErr.StatusCode != http.StatusBadRequest || !strings.Contains(err.Error(), redactedMarker) {
				t.Fatalf("error = %v, want PBS's 400, redacted", err)
			}
			for _, leak := range tc.leaks {
				if strings.Contains(err.Error(), leak) || strings.Contains(apiErr.Body, leak) {
					t.Fatalf("error = %v, body = %q, leaks %q", err, apiErr.Body, leak)
				}
			}
			if call := fake.lastCall(t, tc.route); !reflect.DeepEqual(call.form, tc.params) {
				t.Fatalf("form = %v, want %v", call.form, tc.params)
			}
		})
	}

	// A secret that PBS keeps, or one whose value does not decode, leaves
	// nothing to redact but what was sent.
	if got := webhookSecretValues(url.Values{"secret": {"name=kept", "name=raw,value=%%%", "broken"}}); !reflect.DeepEqual(got, []string{"%%%"}) {
		t.Errorf("webhookSecretValues() = %q", got)
	}
}

// Headers and secrets go as "name=<name>,value=<base64>", unquoted, the way
// PBS's own web interface sends them; reads take quoted values too, and
// base64 with or without padding.
func TestNotificationKeyValues(t *testing.T) {
	value := "Bearer {{ secrets.token }}"
	if got, want := FormatNotificationKeyValue("Authorization", &value), "name=Authorization,value=QmVhcmVyIHt7IHNlY3JldHMudG9rZW4gfX0="; got != want {
		t.Errorf("FormatNotificationKeyValue() = %q, want %q", got, want)
	}
	if got := FormatNotificationKeyValue("token", nil); got != "name=token" {
		t.Errorf("FormatNotificationKeyValue(no value) = %q", got)
	}

	for input, want := range map[string]struct {
		name  string
		value *string
	}{
		"name=Authorization,value=QmVhcmVyIHt7IHNlY3JldHMudG9rZW4gfX0=":   {"Authorization", &value},
		`name=Authorization,value="QmVhcmVyIHt7IHNlY3JldHMudG9rZW4gfX0="`: {"Authorization", &value},
		"value=QmVhcmVyIHt7IHNlY3JldHMudG9rZW4gfX0,name=Authorization":    {"Authorization", &value},
		"name=token": {"token", nil},
	} {
		name, got, err := ParseNotificationKeyValue(input)
		if err != nil || name != want.name || !reflect.DeepEqual(got, want.value) {
			t.Errorf("ParseNotificationKeyValue(%q) = %q, %v, %v", input, name, got, err)
		}
	}
	for input, want := range map[string]string{
		"value=YQ==":             "has no name",
		"name=,value=YQ==":       "has no name",
		"name=x,value=%%%":       "not base64",
		"name=x,value=/w==":      "UTF-8",
		`name="unterminated`:     "unterminated",
		"name=x,value=YQ==,name": "without a key",
	} {
		if _, _, err := ParseNotificationKeyValue(input); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseNotificationKeyValue(%q) error = %v, want %q", input, err, want)
		}
	}
}

func TestNotificationTargetsAndMatcherFields(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/notifications/targets", http.StatusOK, `{"data":[`+
		`{"name":"gotify","type":"gotify","origin":"user-created","disable":true},`+
		`{"name":"mail-to-root","type":"sendmail","origin":"builtin","comment":"Send mails to root@pam's email address"}]}`)
	fake.reply("GET /config/notifications/matcher-fields", http.StatusOK,
		`{"data":[{"name":"datastore"},{"name":"hostname"},{"name":"type"}]}`)
	fake.reply("GET /config/notifications/matcher-field-values", http.StatusOK, `{"data":[`+
		`{"field":"datastore","value":"store1","comment":"main"},{"field":"type","value":"gc"}]}`)
	fake.reply("POST /config/notifications/targets/gotify/test", http.StatusOK, `{"data":null}`)
	fake.reply("POST /config/notifications/targets/broken/test", http.StatusInternalServerError,
		"Could not test target: could not notify via target `broken`: connection refused")
	c := fake.client(t)
	ctx := context.Background()

	yes := true
	targets, err := c.ListNotificationTargets(ctx)
	wantTargets := []NotificationTarget{
		{Name: "gotify", Type: "gotify", Origin: OriginUserCreated, Disable: &yes},
		{Name: "mail-to-root", Type: "sendmail", Origin: OriginBuiltin, Comment: "Send mails to root@pam's email address"},
	}
	if err != nil || !reflect.DeepEqual(targets, wantTargets) {
		t.Errorf("ListNotificationTargets() = %+v, %v", targets, err)
	}
	fields, err := c.ListMatcherFields(ctx)
	if err != nil || !reflect.DeepEqual(fields, []string{"datastore", "hostname", "type"}) {
		t.Errorf("ListMatcherFields() = %v, %v", fields, err)
	}
	values, err := c.ListMatcherFieldValues(ctx)
	wantValues := []MatcherFieldValue{{Field: "datastore", Value: "store1", Comment: "main"}, {Field: "type", Value: "gc"}}
	if err != nil || !reflect.DeepEqual(values, wantValues) {
		t.Errorf("ListMatcherFieldValues() = %+v, %v", values, err)
	}

	if err := c.TestNotificationTarget(ctx, "gotify"); err != nil {
		t.Errorf("TestNotificationTarget() = %v", err)
	}
	if call := fake.lastCall(t, "POST /config/notifications/targets/gotify/test"); len(call.form) != 0 {
		t.Errorf("test form = %v, want none", call.form)
	}
	if err := c.TestNotificationTarget(ctx, "broken"); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("TestNotificationTarget(broken) = %v", err)
	}

	fake.reply("GET /config/notifications/matcher-fields", http.StatusForbidden, "permission check failed")
	if _, err := c.ListMatcherFields(ctx); !IsForbidden(err) {
		t.Errorf("ListMatcherFields() = %v, want a 403", err)
	}
}

// A failed test keeps the secrets it is given out of the error, as they are
// and as PBS's url-encode template helper writes them, which PBS's own
// masking misses.
func TestTestNotificationTargetRedactsSecrets(t *testing.T) {
	const secret = "ab+c/d= é"
	if got, want := templateURLEncode(secret), "ab%2Bc%2Fd%3D%20%C3%A9"; got != want {
		t.Fatalf("templateURLEncode() = %q, want %q", got, want)
	}
	if got, want := templateURLEncode(`A-z_0.9~"<>{}`), `A-z_0.9~"<>{}`; got != want {
		t.Errorf("templateURLEncode() = %q, want what the helper leaves as it is", got)
	}
	fake := newFakePBS()
	fake.reply("POST /config/notifications/targets/hook/test", http.StatusInternalServerError,
		"Could not test target: GET https://h/?auth=ab%2Bc%2Fd%3D%20%C3%A9: status code 401 (raw "+secret+")")
	err := fake.client(t).TestNotificationTarget(context.Background(), "hook", secret)
	if err == nil || strings.Contains(err.Error(), "ab%2B") || strings.Contains(err.Error(), secret) ||
		!strings.Contains(err.Error(), "status code 401") {
		t.Errorf("TestNotificationTarget() = %v", err)
	}
}
