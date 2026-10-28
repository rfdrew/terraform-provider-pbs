package pbsclient

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// The notification system: endpoints, which deliver a notification — by
// sendmail, SMTP, Gotify or a webhook — and matchers, which route each
// notification to endpoints. All of them live in notifications.cfg, their
// secrets in notifications-priv.cfg. What PBS 4.0 and 4.2 do, as observed on
// real servers:
//
//   - Endpoint and matcher names are one namespace, across all kinds.
//   - PBS ships two built-in entries, the sendmail endpoint mail-to-root and
//     the matcher default-matcher, which routes everything but successful
//     prune jobs to it. They cannot be created or deleted: DELETE answers
//     200 and resets one to its built-in settings. A read reports where an
//     entry comes from in "origin": user-created, builtin, or
//     modified-builtin for a built-in entry that differs from its defaults.
//   - A read never returns a secret, such as an SMTP password. A missing
//     entry is 404 "endpoint 'x' not found" or "matcher 'x' not found", on
//     GET and DELETE alike; IsNotFound covers them.
//   - A single entry's read carries the digest of notifications.cfg; the
//     lists carry none.
//   - Sending a test notification through an endpoint (TestNotificationTarget)
//     goes through it even when it is disabled, and waits for the delivery:
//     PBS answers 500 "Could not test target: ..." when it fails, and 404
//     "endpoint 'x' does not exist" for a name that is no endpoint.

// Where a notification entry comes from, as "origin" reports it.
const (
	OriginUserCreated     = "user-created"
	OriginBuiltin         = "builtin"
	OriginModifiedBuiltin = "modified-builtin"
)

// SMTPEndpoint is an SMTP endpoint as PBS reports it. The password is never
// part of it.
type SMTPEndpoint struct {
	Name   string `json:"name"`
	Server string `json:"server"`
	// Port is unset for the default of Mode: 25, 465 or 587.
	Port *int64 `json:"port,omitempty"`
	// Mode is insecure, starttls or tls; unset means tls.
	Mode        string   `json:"mode,omitempty"`
	Username    string   `json:"username,omitempty"`
	FromAddress string   `json:"from-address"`
	Author      string   `json:"author,omitempty"`
	Mailto      []string `json:"mailto,omitempty"`
	MailtoUser  []string `json:"mailto-user,omitempty"`
	Comment     string   `json:"comment,omitempty"`
	Disable     *bool    `json:"disable,omitempty"`
	Origin      string   `json:"origin,omitempty"`
}

// NotificationMatcher is a notification matcher as PBS reports it.
type NotificationMatcher struct {
	Name          string   `json:"name"`
	Target        []string `json:"target,omitempty"`
	MatchSeverity []string `json:"match-severity,omitempty"`
	MatchField    []string `json:"match-field,omitempty"`
	MatchCalendar []string `json:"match-calendar,omitempty"`
	// Mode is all or any; unset means all.
	Mode        string `json:"mode,omitempty"`
	InvertMatch *bool  `json:"invert-match,omitempty"`
	Disable     *bool  `json:"disable,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Origin      string `json:"origin,omitempty"`
}

// GetSMTPEndpoint reads one SMTP endpoint.
func (c *Client) GetSMTPEndpoint(ctx context.Context, name string) (SMTPEndpoint, error) {
	var endpoint SMTPEndpoint
	_, err := c.Get(ctx, Path("config", "notifications", "endpoints", "smtp", name), nil, &endpoint)
	return endpoint, err
}

// CreateSMTPEndpoint creates an SMTP endpoint from params, which must hold
// "name", "server" and "from-address". The password is kept out of any
// error.
func (c *Client) CreateSMTPEndpoint(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/notifications/endpoints/smtp", params, nil)
	return redactAPIError(err, params.Get("password"))
}

// UpdateSMTPEndpoint changes the properties params carries, and deletes
// those named in its delete parameter. The password is kept out of any
// error.
func (c *Client) UpdateSMTPEndpoint(ctx context.Context, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "notifications", "endpoints", "smtp", name), params, nil)
	return redactAPIError(err, params.Get("password"))
}

// DeleteSMTPEndpoint deletes an SMTP endpoint.
func (c *Client) DeleteSMTPEndpoint(ctx context.Context, name string) error {
	_, err := c.Delete(ctx, Path("config", "notifications", "endpoints", "smtp", name), nil, nil)
	return err
}

// GetNotificationMatcher reads one notification matcher.
func (c *Client) GetNotificationMatcher(ctx context.Context, name string) (NotificationMatcher, error) {
	var matcher NotificationMatcher
	_, err := c.Get(ctx, Path("config", "notifications", "matchers", name), nil, &matcher)
	return matcher, err
}

// CreateNotificationMatcher creates a notification matcher from params,
// which must hold "name".
func (c *Client) CreateNotificationMatcher(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/notifications/matchers", params, nil)
	return err
}

// UpdateNotificationMatcher changes the properties params carries, and
// deletes those named in its delete parameter.
func (c *Client) UpdateNotificationMatcher(ctx context.Context, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "notifications", "matchers", name), params, nil)
	return err
}

// DeleteNotificationMatcher deletes a notification matcher; a built-in one
// is reset to its built-in settings instead.
func (c *Client) DeleteNotificationMatcher(ctx context.Context, name string) error {
	_, err := c.Delete(ctx, Path("config", "notifications", "matchers", name), nil, nil)
	return err
}

// SendmailEndpoint is a sendmail endpoint as PBS reports it: mail handed to
// the local mail transport agent, like the built-in mail-to-root.
type SendmailEndpoint struct {
	Name        string   `json:"name"`
	Mailto      []string `json:"mailto,omitempty"`
	MailtoUser  []string `json:"mailto-user,omitempty"`
	FromAddress string   `json:"from-address,omitempty"`
	Author      string   `json:"author,omitempty"`
	Comment     string   `json:"comment,omitempty"`
	Disable     *bool    `json:"disable,omitempty"`
	Origin      string   `json:"origin,omitempty"`
}

// GotifyEndpoint is a Gotify endpoint as PBS reports it. The token is never
// part of it.
type GotifyEndpoint struct {
	Name    string `json:"name"`
	Server  string `json:"server"`
	Comment string `json:"comment,omitempty"`
	Disable *bool  `json:"disable,omitempty"`
	Origin  string `json:"origin,omitempty"`
}

// WebhookEndpoint is a webhook endpoint as PBS reports it. Header and Secret
// are property strings, "name=<name>,value=<base64>" (see
// FormatNotificationKeyValue); a secret comes without its value, which PBS
// never returns. Body is base64 too.
type WebhookEndpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// Method is post, put or get.
	Method  string   `json:"method,omitempty"`
	Body    string   `json:"body,omitempty"`
	Header  []string `json:"header,omitempty"`
	Secret  []string `json:"secret,omitempty"`
	Comment string   `json:"comment,omitempty"`
	Disable *bool    `json:"disable,omitempty"`
	Origin  string   `json:"origin,omitempty"`
}

// FormatNotificationKeyValue writes one header or secret of a webhook
// endpoint as PBS takes it: the name, and the value base64-encoded, or no
// value at all for a secret that keeps the one PBS has. The name goes as it
// is: header and secret names hold no character a property string quotes.
func FormatNotificationKeyValue(name string, value *string) string {
	if value == nil {
		return "name=" + name
	}
	return "name=" + name + ",value=" + base64.StdEncoding.EncodeToString([]byte(*value))
}

// ParseNotificationKeyValue reads one header or secret of a webhook endpoint
// as PBS returns it, decoding the value; value is nil when the entry has
// none, as secrets never do in a read.
func ParseNotificationKeyValue(s string) (name string, value *string, err error) {
	p, err := ParsePropertyString(s, "")
	if err != nil {
		return "", nil, err
	}
	name, ok := p["name"]
	if !ok || name == "" {
		return "", nil, fmt.Errorf("%q has no name", s)
	}
	raw, ok := p["value"]
	if !ok {
		return name, nil, nil
	}
	decoded, err := DecodeNotificationBase64(raw)
	if err != nil {
		return name, nil, fmt.Errorf("the value of %q: %w", name, err)
	}
	return name, &decoded, nil
}

// DecodeNotificationBase64 decodes a base64 value of a webhook endpoint — a
// header's or secret's value, or the body — into the text it stands for, with
// or without padding, as PBS accepts it.
func DecodeNotificationBase64(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		var rawErr error
		if decoded, rawErr = base64.RawStdEncoding.DecodeString(s); rawErr != nil {
			return "", fmt.Errorf("not base64: %w", err)
		}
	}
	if !utf8.Valid(decoded) {
		return "", errors.New("not base64-encoded UTF-8 text")
	}
	return string(decoded), nil
}

// GetSendmailEndpoint reads one sendmail endpoint, mail-to-root included.
func (c *Client) GetSendmailEndpoint(ctx context.Context, name string) (SendmailEndpoint, error) {
	var endpoint SendmailEndpoint
	_, err := c.Get(ctx, Path("config", "notifications", "endpoints", "sendmail", name), nil, &endpoint)
	return endpoint, err
}

// CreateSendmailEndpoint creates a sendmail endpoint from params, which must
// hold "name" and a recipient.
func (c *Client) CreateSendmailEndpoint(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/notifications/endpoints/sendmail", params, nil)
	return err
}

// UpdateSendmailEndpoint changes the properties params carries, and deletes
// those named in its delete parameter.
func (c *Client) UpdateSendmailEndpoint(ctx context.Context, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "notifications", "endpoints", "sendmail", name), params, nil)
	return err
}

// DeleteSendmailEndpoint deletes a sendmail endpoint; the built-in
// mail-to-root is reset to its built-in settings instead.
func (c *Client) DeleteSendmailEndpoint(ctx context.Context, name string) error {
	_, err := c.Delete(ctx, Path("config", "notifications", "endpoints", "sendmail", name), nil, nil)
	return err
}

// GetGotifyEndpoint reads one Gotify endpoint.
func (c *Client) GetGotifyEndpoint(ctx context.Context, name string) (GotifyEndpoint, error) {
	var endpoint GotifyEndpoint
	_, err := c.Get(ctx, Path("config", "notifications", "endpoints", "gotify", name), nil, &endpoint)
	return endpoint, err
}

// CreateGotifyEndpoint creates a Gotify endpoint from params, which must hold
// "name", "server" and "token". The token is kept out of any error.
func (c *Client) CreateGotifyEndpoint(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/notifications/endpoints/gotify", params, nil)
	return redactAPIError(err, params.Get("token"))
}

// UpdateGotifyEndpoint changes the properties params carries, and deletes
// those named in its delete parameter. The token is kept out of any error.
func (c *Client) UpdateGotifyEndpoint(ctx context.Context, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "notifications", "endpoints", "gotify", name), params, nil)
	return redactAPIError(err, params.Get("token"))
}

// DeleteGotifyEndpoint deletes a Gotify endpoint and its token.
func (c *Client) DeleteGotifyEndpoint(ctx context.Context, name string) error {
	_, err := c.Delete(ctx, Path("config", "notifications", "endpoints", "gotify", name), nil, nil)
	return err
}

// GetWebhookEndpoint reads one webhook endpoint, with the names of its
// secrets but not their values.
func (c *Client) GetWebhookEndpoint(ctx context.Context, name string) (WebhookEndpoint, error) {
	var endpoint WebhookEndpoint
	_, err := c.Get(ctx, Path("config", "notifications", "endpoints", "webhook", name), nil, &endpoint)
	return endpoint, err
}

// CreateWebhookEndpoint creates a webhook endpoint from params, which must
// hold "name", "url" and "method". The secrets' values, as given and in
// base64, are kept out of any error.
func (c *Client) CreateWebhookEndpoint(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/notifications/endpoints/webhook", params, nil)
	return redactAPIError(err, webhookSecretValues(params)...)
}

// UpdateWebhookEndpoint changes the properties params carries, and deletes
// those named in its delete parameter. A "secret" parameter replaces every
// secret: one sent without a value keeps the value PBS has, and one left out
// is removed. The secrets' values are kept out of any error.
func (c *Client) UpdateWebhookEndpoint(ctx context.Context, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "notifications", "endpoints", "webhook", name), params, nil)
	return redactAPIError(err, webhookSecretValues(params)...)
}

// DeleteWebhookEndpoint deletes a webhook endpoint and its secrets.
func (c *Client) DeleteWebhookEndpoint(ctx context.Context, name string) error {
	_, err := c.Delete(ctx, Path("config", "notifications", "endpoints", "webhook", name), nil, nil)
	return err
}

// webhookSecretValues returns the values of the secrets params carries, both
// in base64 and decoded, for redaction.
func webhookSecretValues(params url.Values) []string {
	var values []string
	for _, s := range params["secret"] {
		p, err := ParsePropertyString(s, "")
		if err != nil || p["value"] == "" {
			continue
		}
		values = append(values, p["value"])
		if decoded, err := DecodeNotificationBase64(p["value"]); err == nil && decoded != "" {
			values = append(values, decoded)
		}
	}
	return values
}

// NotificationTarget is one entry of the notification targets PBS lists:
// every endpoint, of any type.
type NotificationTarget struct {
	Name string `json:"name"`
	// Type is sendmail, smtp, gotify or webhook.
	Type    string `json:"type"`
	Origin  string `json:"origin,omitempty"`
	Disable *bool  `json:"disable,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// ListNotificationTargets lists every notification endpoint, built-in ones
// included.
func (c *Client) ListNotificationTargets(ctx context.Context) ([]NotificationTarget, error) {
	var targets []NotificationTarget
	_, err := c.Get(ctx, "/config/notifications/targets", nil, &targets)
	return targets, err
}

// TestNotificationTarget has PBS send a test notification through the
// endpoint name, as it is saved, and waits for the delivery. secrets — a
// webhook's secret values — are kept out of any error, also in the form
// PBS's url-encode template helper gives them: PBS masks only their exact
// text in the errors of a webhook, and an HTTP client's error may quote the
// URL they were rendered into.
func (c *Client) TestNotificationTarget(ctx context.Context, name string, secrets ...string) error {
	_, err := c.Post(ctx, Path("config", "notifications", "targets", name, "test"), nil, nil)
	forms := make([]string, 0, 2*len(secrets))
	for _, s := range secrets {
		forms = append(forms, s, templateURLEncode(s))
	}
	return redactAPIError(err, forms...)
}

// templateURLEncode encodes s as the url-encode helper of PBS's webhook
// templates does: control characters, space and :/?#[]@!$&'()*+,;=% are
// percent-encoded, and so is every byte outside ASCII.
func templateURLEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || strings.IndexByte(" :/?#[]@!$&'()*+,;=%", c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// MatcherFieldValue is one value of a notification metadata field PBS knows,
// such as the datastore "store1" of the field "datastore".
type MatcherFieldValue struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

// ListMatcherFields lists the names of the metadata fields a matcher's
// match-field can match, such as "type" or "datastore".
func (c *Client) ListMatcherFields(ctx context.Context) ([]string, error) {
	var fields []struct {
		Name string `json:"name"`
	}
	if _, err := c.Get(ctx, "/config/notifications/matcher-fields", nil, &fields); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, f.Name)
	}
	return names, nil
}

// ListMatcherFieldValues lists the values PBS knows for the metadata fields:
// its datastores, media pools, job IDs, host name and notification types.
func (c *Client) ListMatcherFieldValues(ctx context.Context) ([]MatcherFieldValue, error) {
	var values []MatcherFieldValue
	_, err := c.Get(ctx, "/config/notifications/matcher-field-values", nil, &values)
	return values, err
}
