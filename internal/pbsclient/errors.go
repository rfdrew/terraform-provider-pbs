package pbsclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	// ErrBadCredentials means PBS did not accept the username and password
	// at sign-in.
	ErrBadCredentials = errors.New("PBS rejected the username or password")

	// ErrSecondFactor means the password was right, but the user has a
	// second factor (TOTP, WebAuthn, recovery keys), which a ticket sign-in
	// cannot complete without a person. Such a user must use an API token.
	ErrSecondFactor = errors.New("the user has two-factor authentication enabled, which a password sign-in cannot complete; use an API token instead")
)

// Error is a non-2xx response from a PBS API call.
//
// Through /api2/json, PBS sends an error as plain text — "no such remote
// 'x'", "permission check failed", "parameter verification failed -
// 'name': ..." — although the Content-Type says application/json. Message
// is that text, trimmed; JSON is only recognised as a fallback, for a proxy
// or a future release that sends some.
type Error struct {
	// Method and Path name the request, without the query string; Path
	// starts after /api2/json.
	Method string
	Path   string
	// StatusCode is the HTTP status.
	StatusCode int
	// Message is PBS's error text.
	Message string
	// Body is the raw response body.
	Body string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("PBS API error: ")
	if e.Method != "" {
		fmt.Fprintf(&b, "%s %s: ", e.Method, e.Path)
	}
	fmt.Fprintf(&b, "HTTP %d", e.StatusCode)
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", truncate(e.Message, 512))
	}
	return b.String()
}

// newError builds the Error for a non-2xx response. header is consulted for
// Location on a redirect.
func newError(method, path string, status int, header http.Header, raw []byte) *Error {
	apiErr := &Error{
		Method:     method,
		Path:       path,
		StatusCode: status,
		Body:       string(raw),
		Message:    strings.TrimSpace(string(raw)),
	}

	// The ExtJS formatter's shape, {"message": ..., "errors": ...}, and the
	// envelope's {"data": null, "message": ...}.
	var envelope struct {
		Message string `json:"message"`
	}
	if strings.HasPrefix(apiErr.Message, "{") && json.Unmarshal(raw, &envelope) == nil && envelope.Message != "" {
		apiErr.Message = strings.TrimSpace(envelope.Message)
	}

	// The client never follows redirects (see New), so a 3xx is reported as an
	// error; where it pointed is the useful part.
	if status >= 300 && status < 400 {
		if location := header.Get("Location"); location != "" {
			apiErr.Message = "redirected to " + location + "; set the endpoint to the address PBS answers on"
		}
	}
	return apiErr
}

// asError extracts the *Error from err, if there is one.
func asError(err error) (*Error, bool) {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

// IsNotFound reports whether PBS answered that the object does not exist.
//
// There is no single status for that. Reading a missing configuration entry
// answers 400 "no such remote 'x'" for most objects and 404 "endpoint 'x'
// not found" for notification targets; deleting one answers 404 "remote 'x'
// does not exist." for some objects and 400 "user 'x' does not exist." or
// "no such prune 'x'" for others, and an S3 endpoint's 404 "s3 client config
// 'x' do not exist.". The text is what identifies it. A 404
// "Path '...' not found." is not one of them: that is a route the server does
// not have, which IsEndpointMissing reports.
func IsNotFound(err error) bool {
	apiErr, ok := asError(err)
	if !ok || (apiErr.StatusCode != http.StatusBadRequest && apiErr.StatusCode != http.StatusNotFound) {
		return false
	}
	// A datastore PBS cannot open is reported with its maintenance message,
	// which may well end in "not found".
	if IsEndpointMissing(err) || IsDatastoreUnavailable(err) {
		return false
	}
	message := strings.ToLower(apiErr.Message)
	trimmed := strings.TrimSuffix(message, ".")
	return strings.HasPrefix(message, "no such ") ||
		strings.HasSuffix(trimmed, " does not exist") || strings.HasSuffix(trimmed, " do not exist") ||
		strings.HasSuffix(message, " not found")
}

// IsAlreadyExists reports whether PBS refused to create an object because one
// with the same ID exists: a 400 whose text ends in "already exists", such as
// "user 'x' already exists.", "token 'x' for user 'y' already exists.",
// "parameter verification failed - 'id': job 'x' already exists." or, for
// notification endpoints and matchers, "Cannot create 'x', an entity with
// the same name already exists".
func IsAlreadyExists(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest &&
		strings.HasSuffix(strings.TrimSuffix(strings.ToLower(apiErr.Message), "."), " already exists")
}

// IsEndpointMissing reports whether the API path does not exist on this
// server — a route a release does not have, or a method the route does not
// accept: 404 "Path '/api2/json/...' not found.".
func IsEndpointMissing(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusNotFound && strings.HasPrefix(apiErr.Message, "Path '")
}

// IsDigestConflict reports whether a write was refused because the
// configuration file changed since the digest it carried was read. PBS has no
// status of its own for this: it is a 400 with a fixed text.
func IsDigestConflict(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest && strings.Contains(apiErr.Message, "detected modified configuration")
}

// IsUnauthorized reports whether PBS did not accept the credentials: a 401
// "authentication failed - ...", or ErrBadCredentials from a sign-in.
func IsUnauthorized(err error) bool {
	if errors.Is(err, ErrBadCredentials) {
		return true
	}
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusUnauthorized
}

// IsForbidden reports whether PBS accepted the credentials but refused the
// call: 403 "permission check failed". An API token without an ACL of its
// own gets this for everything but the few calls open to every user.
func IsForbidden(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusForbidden
}

// redactedMarker replaces every secret Redact finds.
const redactedMarker = "<redacted>"

// Redact replaces every occurrence of each non-empty secret in text with
// "<redacted>", in the forms an error message is likely to quote it: as
// given, JSON-escaped, Go-quoted and URL-encoded. Longer secrets are replaced
// first, so a secret that contains a shorter one is not left half-redacted.
func Redact(text string, secrets ...string) string {
	var forms []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			forms = append(forms, s)
		}
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		add(secret)
		if encoded, err := json.Marshal(secret); err == nil {
			add(string(encoded[1 : len(encoded)-1]))
		}
		quoted := strconv.Quote(secret)
		add(quoted[1 : len(quoted)-1])
		add(url.QueryEscape(secret))
		add(url.PathEscape(secret))
	}
	sort.SliceStable(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	for _, form := range forms {
		text = strings.ReplaceAll(text, form, redactedMarker)
	}
	return text
}

// truncate shortens s to at most max bytes for an error message, without
// splitting a UTF-8 sequence.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…(truncated)"
}
