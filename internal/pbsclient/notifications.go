package pbsclient

import (
	"context"
	"net/url"
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
