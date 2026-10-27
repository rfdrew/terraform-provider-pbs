package pbsclient

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func apiError(status int, message string) error {
	return fmt.Errorf("wrapped: %w", newError(http.MethodGet, "/x", status, http.Header{}, []byte(message+"\n")))
}

// The answers below are what PBS 4.0 and 4.2 send for missing objects,
// recorded on real servers.
func TestIsNotFound(t *testing.T) {
	notFound := []struct {
		status  int
		message string
	}{
		{400, "no such remote 'probe-missing'"},
		{400, "no such datastore 'probe-missing'"},
		{400, "no such user 'probe-missing@pbs'"},
		{400, "no such token 'tfacc@pbs!probe-missing'"},
		{400, "no such verification 'probe-missing'"},
		{400, "no such s3-endpoint 'probe-missing'"},
		{400, "no such rule 'probe-missing'"},
		{400, "no such user."},
		{404, "endpoint 'probe-missing' not found"},
		{404, "matcher 'probe-missing' not found"},
		{404, "remote 'probe-missing' does not exist."},
		{404, "job 'probe-missing' does not exist."},
		{404, "traffic control rule 'probe-missing' does not exist."},
		{400, "user 'probe-missing@pbs' does not exist."},
		{400, "token 'probe-missing' of user 'tfacc@pbs' does not exist."},
		{400, "name 'probe-missing' does not exist."},
	}
	for _, tc := range notFound {
		if !IsNotFound(apiError(tc.status, tc.message)) {
			t.Errorf("IsNotFound(%d %q) = false, want true", tc.status, tc.message)
		}
	}

	found := []struct {
		status  int
		message string
	}{
		{404, "Path '/api2/json/config/encryption-keys' not found."},
		{400, "parameter verification failed - 'name': value must be at least 3 characters long"},
		{400, "detected modified configuration - file changed by other user? Try again."},
		{403, "permission check failed"},
		{500, "no such file or directory"},
	}
	for _, tc := range found {
		if IsNotFound(apiError(tc.status, tc.message)) {
			t.Errorf("IsNotFound(%d %q) = true, want false", tc.status, tc.message)
		}
	}
	if IsNotFound(errors.New("no such remote")) {
		t.Error("IsNotFound accepted an error that is not an API error")
	}
}

func TestErrorClassification(t *testing.T) {
	missingPath := apiError(404, "Path '/api2/json/config/encryption-keys' not found.")
	conflict := apiError(400, "detected modified configuration - file changed by other user? Try again.")
	unauthorized := apiError(401, "authentication failed - invalid credentials")
	forbidden := apiError(403, "permission check failed")

	if !IsEndpointMissing(missingPath) || IsEndpointMissing(apiError(404, "endpoint 'x' not found")) {
		t.Error("IsEndpointMissing")
	}
	if !IsDigestConflict(conflict) || IsDigestConflict(forbidden) {
		t.Error("IsDigestConflict")
	}
	if !IsUnauthorized(unauthorized) || !IsUnauthorized(ErrBadCredentials) || IsUnauthorized(forbidden) {
		t.Error("IsUnauthorized")
	}
	if !IsForbidden(forbidden) || IsForbidden(unauthorized) {
		t.Error("IsForbidden")
	}
}

func TestErrorMessage(t *testing.T) {
	err := newError(http.MethodPut, "/config/remote/r1", 400, http.Header{}, []byte("no such remote 'r1'\n"))
	if got := err.Error(); got != "PBS API error: PUT /config/remote/r1: HTTP 400: no such remote 'r1'" {
		t.Fatalf("Error() = %q", got)
	}

	// The ExtJS formatter's shape, in case a proxy or a release sends it.
	err = newError(http.MethodGet, "/x", 400, http.Header{}, []byte(`{"errors":{},"message":"no such remote 'r1'","status":400,"success":false}`))
	if err.Message != "no such remote 'r1'" {
		t.Fatalf("Message = %q", err.Message)
	}

	long := newError(http.MethodGet, "/x", 500, http.Header{}, []byte(strings.Repeat("é", 400)))
	if got := long.Error(); !strings.HasSuffix(got, "…(truncated)") {
		t.Fatalf("Error() = %q", got)
	}
}

func TestRedact(t *testing.T) {
	secret := `pa"ss word/&`
	text := `got pa"ss word/& and "pa\"ss word/&" and pa%22ss+word%2F%26`
	got := Redact(text, secret, "")
	if strings.Contains(got, "pa") {
		t.Fatalf("Redact() = %q", got)
	}
}
