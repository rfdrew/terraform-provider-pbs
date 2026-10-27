package provider

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// userIDPattern is PBS's user ID: a name without white space, colons,
// slashes or control characters, then "@" and the realm.
var userIDPattern = regexp.MustCompile(`^[^\s:/\p{Cc}]+@[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// stringCheck adapts a predicate into a string validator. A failing value is
// reported as "Attribute <path> <description>, got: <value>".
type stringCheck struct {
	description string
	check       func(string) bool
}

func (v stringCheck) Description(_ context.Context) string { return v.description }

func (v stringCheck) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v stringCheck) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || v.check(req.ConfigValue.ValueString()) {
		return
	}
	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid Attribute Value",
		fmt.Sprintf("Attribute %s %s, got: %q", req.Path, v.description, req.ConfigValue.ValueString()),
	)
}

// httpsURLValidator accepts an absolute https:// URL with a host and without
// credentials, a query or a fragment: the shapes pbsclient.New accepts as an
// endpoint. PBS serves its API over HTTPS only.
func httpsURLValidator() validator.String {
	return stringCheck{
		description: "must be an https:// URL with a host, and no credentials, query or fragment",
		check: func(s string) bool {
			u, err := url.Parse(s)
			return err == nil && u.Scheme == "https" && u.Host != "" &&
				u.User == nil && u.RawQuery == "" && u.Fragment == ""
		},
	}
}

// apiTokenValidator accepts an API token in the form PBS shows it on
// creation, "<user>@<realm>!<token name>:<secret>". The value is not
// repeated in the error: it is a secret.
type apiTokenValidator struct{}

func (apiTokenValidator) Description(_ context.Context) string {
	return `must have the form "<user>@<realm>!<token name>:<secret>"`
}

func (v apiTokenValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v apiTokenValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, _, err := pbsclient.SplitAPIToken(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid Attribute Value",
			fmt.Sprintf("Attribute %s %s, as PBS shows it when the token is created.", req.Path, v.Description(ctx)))
	}
}

// certFingerprintValidator accepts a SHA-256 certificate fingerprint in any
// form pbsclient.NormaliseFingerprint takes: 64 hexadecimal digits, in either
// case, optionally separated by colons.
func certFingerprintValidator() validator.String {
	return stringCheck{
		description: "must be a SHA-256 certificate fingerprint: 64 hexadecimal digits, optionally separated by colons",
		check: func(s string) bool {
			_, err := pbsclient.NormaliseFingerprint(s)
			return err == nil
		},
	}
}

// positiveDurationValidator accepts a Go duration string greater than zero,
// such as "30s" or "1m30s".
func positiveDurationValidator() validator.String {
	return stringCheck{
		description: `must be a positive duration such as "30s" or "2m"`,
		check: func(s string) bool {
			_, err := parsePositiveDuration(s)
			return err == nil
		},
	}
}

// parsePositiveDuration parses a Go duration and requires it to be greater
// than zero. Its error completes a sentence that starts with the setting's
// name.
func parsePositiveDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf(`must be a positive duration such as "30s" or "2m", got %q`, s)
	}
	return d, nil
}
