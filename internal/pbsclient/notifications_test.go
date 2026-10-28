package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// A read in the shape PBS 4.2 sends: the recipients are arrays, the port is
// left out at the mode's default, and the password is never there.
func TestGetSMTPEndpointDecodesTheEndpoint(t *testing.T) {
	port := int64(2525)
	yes := true
	tests := map[string]struct {
		answer string
		want   SMTPEndpoint
	}{
		"every property": {
			`{"data":{"name":"probe-smtp","server":"smtp.example.com","port":2525,"mode":"starttls","username":"pbs-mailer",` +
				`"from-address":"pbs@example.com","author":"Backup Server","mailto":["ops@example.com","dev@example.com"],` +
				`"mailto-user":["root@pam","alice@pbs"],"comment":"acc","disable":true,"origin":"user-created"},"digest":"9f86d081884c7d65"}`,
			SMTPEndpoint{
				Name: "probe-smtp", Server: "smtp.example.com", Port: &port, Mode: "starttls", Username: "pbs-mailer",
				FromAddress: "pbs@example.com", Author: "Backup Server", Mailto: []string{"ops@example.com", "dev@example.com"},
				MailtoUser: []string{"root@pam", "alice@pbs"}, Comment: "acc", Disable: &yes, Origin: OriginUserCreated,
			},
		},
		"defaults left out": {
			`{"data":{"name":"probe-smtp","server":"smtp.example.com","from-address":"pbs@example.com",` +
				`"mailto-user":["root@pam"],"origin":"user-created"},"digest":"9f86d081884c7d65"}`,
			SMTPEndpoint{
				Name: "probe-smtp", Server: "smtp.example.com", FromAddress: "pbs@example.com",
				MailtoUser: []string{"root@pam"}, Origin: OriginUserCreated,
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/notifications/endpoints/smtp/probe-smtp", http.StatusOK, tc.answer)
			endpoint, err := fake.client(t).GetSMTPEndpoint(context.Background(), "probe-smtp")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(endpoint, tc.want) {
				t.Fatalf("GetSMTPEndpoint() = %+v, want %+v", endpoint, tc.want)
			}
		})
	}
}

// Arrays reach PBS as the key repeated, which is the only form it takes; the
// password goes as it is, and the delete sends nothing but the path.
func TestSMTPEndpointCallsHitTheirRoutes(t *testing.T) {
	const (
		createRoute = "POST /config/notifications/endpoints/smtp"
		updateRoute = "PUT /config/notifications/endpoints/smtp/probe-smtp"
		deleteRoute = "DELETE /config/notifications/endpoints/smtp/probe-smtp"
	)
	fake := newFakePBS()
	fake.reply(createRoute, http.StatusOK, `{"data":null}`)
	fake.reply(updateRoute, http.StatusOK, `{"data":null}`)
	fake.reply(deleteRoute, http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	create := url.Values{"name": {"probe-smtp"}, "server": {"smtp.example.com"}, "from-address": {"pbs@example.com"},
		"mailto": {"ops@example.com", "dev@example.com"}, "mailto-user": {"root@pam", "alice@pbs"},
		"username": {"pbs-mailer"}, "password": {"sm7p-pa55-w0rd"}}
	if err := c.CreateSMTPEndpoint(ctx, create); err != nil {
		t.Fatalf("CreateSMTPEndpoint() = %v", err)
	}
	update := url.Values{"mailto": {"ops@example.com"}, "mailto-user": {"root@pam", "bob@pbs"}, "delete": {"author", "port"}}
	if err := c.UpdateSMTPEndpoint(ctx, "probe-smtp", update); err != nil {
		t.Fatalf("UpdateSMTPEndpoint() = %v", err)
	}
	if err := c.DeleteSMTPEndpoint(ctx, "probe-smtp"); err != nil {
		t.Fatalf("DeleteSMTPEndpoint() = %v", err)
	}

	if got, want := fake.routes(), []string{createRoute, updateRoute, deleteRoute}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if call := fake.lastCall(t, createRoute); !reflect.DeepEqual(call.form, create) {
		t.Errorf("CreateSMTPEndpoint form = %v, want %v", call.form, create)
	}
	if call := fake.lastCall(t, updateRoute); !reflect.DeepEqual(call.form, update) {
		t.Errorf("UpdateSMTPEndpoint form = %v, want %v", call.form, update)
	}
	if call := fake.lastCall(t, deleteRoute); len(call.query) != 0 || len(call.form) != 0 {
		t.Errorf("DeleteSMTPEndpoint query = %v, form = %v, want neither", call.query, call.form)
	}
}

// PBS may quote a rejected value in its error, and the SMTP password is a
// secret the client does not otherwise hold, so both writes redact it
// themselves, in every form the error may quote it.
func TestSMTPEndpointWritesRedactThePassword(t *testing.T) {
	const password = `sm7p "pa55" w0rd`
	const echo = `parameter verification failed - 'password': value "sm7p \"pa55\" w0rd" rejected: sm7p "pa55" w0rd`
	tests := map[string]struct {
		route string
		write func(*Client, url.Values) error
	}{
		"create": {"POST /config/notifications/endpoints/smtp", func(c *Client, params url.Values) error {
			return c.CreateSMTPEndpoint(context.Background(), params)
		}},
		"update": {"PUT /config/notifications/endpoints/smtp/probe-smtp", func(c *Client, params url.Values) error {
			return c.UpdateSMTPEndpoint(context.Background(), "probe-smtp", params)
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(tc.route, http.StatusBadRequest, echo)
			params := url.Values{"name": {"probe-smtp"}, "server": {"smtp.example.com"}, "password": {password}}

			err := tc.write(fake.client(t), params)
			apiErr, ok := asError(err)
			if !ok || apiErr.StatusCode != http.StatusBadRequest {
				t.Fatalf("error = %v, want PBS's 400", err)
			}
			if strings.Contains(err.Error(), "pa55") || strings.Contains(apiErr.Body, "pa55") || !strings.Contains(err.Error(), redactedMarker) {
				t.Fatalf("error = %v, body = %q", err, apiErr.Body)
			}
			if call := fake.lastCall(t, tc.route); !reflect.DeepEqual(call.form, params) {
				t.Fatalf("form = %v, want %v", call.form, params)
			}
		})
	}
}

func TestNotificationMatcherCallsHitTheirRoutes(t *testing.T) {
	const (
		getRoute    = "GET /config/notifications/matchers/probe-matcher"
		createRoute = "POST /config/notifications/matchers"
		updateRoute = "PUT /config/notifications/matchers/probe-matcher"
		deleteRoute = "DELETE /config/notifications/matchers/probe-matcher"
	)
	fake := newFakePBS()
	fake.reply(getRoute, http.StatusOK, `{"data":{"name":"probe-matcher","target":["probe-smtp","mail-to-root"],`+
		`"match-severity":["warning","error"],"match-field":["exact:type=prune","regex:datastore=^probe-"],`+
		`"match-calendar":["mon-fri 9-17"],"mode":"any","invert-match":true,"comment":"acc","origin":"user-created"},`+
		`"digest":"9f86d081884c7d65"}`)
	fake.reply(createRoute, http.StatusOK, `{"data":null}`)
	fake.reply(updateRoute, http.StatusOK, `{"data":null}`)
	fake.reply(deleteRoute, http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	matcher, err := c.GetNotificationMatcher(ctx, "probe-matcher")
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	wantMatcher := NotificationMatcher{
		Name: "probe-matcher", Target: []string{"probe-smtp", "mail-to-root"}, MatchSeverity: []string{"warning", "error"},
		MatchField: []string{"exact:type=prune", "regex:datastore=^probe-"}, MatchCalendar: []string{"mon-fri 9-17"},
		Mode: "any", InvertMatch: &yes, Comment: "acc", Origin: OriginUserCreated,
	}
	if !reflect.DeepEqual(matcher, wantMatcher) {
		t.Fatalf("GetNotificationMatcher() = %+v, want %+v", matcher, wantMatcher)
	}

	create := url.Values{"name": {"probe-matcher"}, "target": {"probe-smtp", "mail-to-root"},
		"match-severity": {"warning", "error"}, "mode": {"any"}}
	if err := c.CreateNotificationMatcher(ctx, create); err != nil {
		t.Fatalf("CreateNotificationMatcher() = %v", err)
	}
	update := url.Values{"match-field": {"exact:type=prune", "regex:datastore=^probe-"}, "delete": {"comment", "invert-match"}}
	if err := c.UpdateNotificationMatcher(ctx, "probe-matcher", update); err != nil {
		t.Fatalf("UpdateNotificationMatcher() = %v", err)
	}
	if err := c.DeleteNotificationMatcher(ctx, "probe-matcher"); err != nil {
		t.Fatalf("DeleteNotificationMatcher() = %v", err)
	}

	if got, want := fake.routes(), []string{getRoute, createRoute, updateRoute, deleteRoute}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if call := fake.lastCall(t, createRoute); !reflect.DeepEqual(call.form, create) {
		t.Errorf("CreateNotificationMatcher form = %v, want %v", call.form, create)
	}
	if call := fake.lastCall(t, updateRoute); !reflect.DeepEqual(call.form, update) {
		t.Errorf("UpdateNotificationMatcher form = %v, want %v", call.form, update)
	}
	for _, route := range []string{getRoute, deleteRoute} {
		if call := fake.lastCall(t, route); len(call.query) != 0 || len(call.form) != 0 {
			t.Errorf("%s query = %v, form = %v, want neither", route, call.query, call.form)
		}
	}
}

// A missing entry is a 404 that names its kind, on read and delete alike; a
// name any entry already has, of whatever kind, is a 400 on create. The
// provider tells them apart, the SMTP endpoint's redaction notwithstanding.
func TestNotificationErrorsAreRecognised(t *testing.T) {
	const taken = "Cannot create 'probe-taken', an entity with the same name already exists"
	fake := newFakePBS()
	fake.reply("GET /config/notifications/endpoints/smtp/probe-missing", http.StatusNotFound, "endpoint 'probe-missing' not found")
	fake.reply("DELETE /config/notifications/endpoints/smtp/probe-missing", http.StatusNotFound, "endpoint 'probe-missing' not found")
	fake.reply("GET /config/notifications/matchers/probe-missing", http.StatusNotFound, "matcher 'probe-missing' not found")
	fake.reply("DELETE /config/notifications/matchers/probe-missing", http.StatusNotFound, "matcher 'probe-missing' not found")
	fake.reply("POST /config/notifications/endpoints/smtp", http.StatusBadRequest, taken)
	fake.reply("POST /config/notifications/matchers", http.StatusBadRequest, taken)
	c := fake.client(t)
	ctx := context.Background()

	if _, err := c.GetSMTPEndpoint(ctx, "probe-missing"); !IsNotFound(err) || IsEndpointMissing(err) {
		t.Errorf("GetSMTPEndpoint() = %v, want a not-found error", err)
	}
	if err := c.DeleteSMTPEndpoint(ctx, "probe-missing"); !IsNotFound(err) {
		t.Errorf("DeleteSMTPEndpoint() = %v, want a not-found error", err)
	}
	if _, err := c.GetNotificationMatcher(ctx, "probe-missing"); !IsNotFound(err) || IsEndpointMissing(err) {
		t.Errorf("GetNotificationMatcher() = %v, want a not-found error", err)
	}
	if err := c.DeleteNotificationMatcher(ctx, "probe-missing"); !IsNotFound(err) {
		t.Errorf("DeleteNotificationMatcher() = %v, want a not-found error", err)
	}

	params := url.Values{"name": {"probe-taken"}, "server": {"smtp.example.com"}, "from-address": {"pbs@example.com"},
		"password": {"sm7p-pa55-w0rd"}}
	if err := c.CreateSMTPEndpoint(ctx, params); !IsAlreadyExists(err) || IsNotFound(err) {
		t.Errorf("CreateSMTPEndpoint() = %v, want an already-exists error", err)
	}
	if err := c.CreateNotificationMatcher(ctx, url.Values{"name": {"probe-taken"}}); !IsAlreadyExists(err) || IsNotFound(err) {
		t.Errorf("CreateNotificationMatcher() = %v, want an already-exists error", err)
	}
}
