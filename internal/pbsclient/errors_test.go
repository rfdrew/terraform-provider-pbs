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
		{404, "s3 client config 'probe-missing' do not exist."},
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

// IsOfOtherType takes PBS's 400 for an object of that name with another
// type, realm or metric server, and nothing else; IsRealmOfOtherType is the
// same test.
func TestIsOfOtherType(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{apiError(400, "got unexpected type 'ldap' for openid 'corp'"), true},
		{apiError(400, "got unexpected type 'influxdb-udp' for influxdb-http 'influx'"), true},
		{apiError(400, "got unexpected type 'influxdb-http' for influxdb-udp 'influx'"), true},
		{&Error{StatusCode: http.StatusBadRequest, Message: "got unexpected type 'openid' for ldap 'sso'"}, true},
		{apiError(404, "got unexpected type 'ldap' for openid 'corp'"), false},
		{apiError(500, "got unexpected type 'ldap' for openid 'corp'"), false},
		{apiError(400, "no such influxdb-http 'influx'"), false},
		{apiError(400, "name 'influx' does not exist."), false},
		{apiError(400, "metric server 'influx' already exists."), false},
		{apiError(400, "parameter verification failed - 'type': got unexpected type 'ldap' for openid 'corp'"), false},
		{errors.New("got unexpected type 'ldap' for openid 'corp'"), false},
		{nil, false},
	} {
		if got := IsOfOtherType(tc.err); got != tc.want {
			t.Errorf("IsOfOtherType(%v) = %v, want %v", tc.err, got, tc.want)
		}
		if got := IsRealmOfOtherType(tc.err); got != tc.want {
			t.Errorf("IsRealmOfOtherType(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// PBS's answers when the lock of a configuration or state file stays taken
// for its 10 s, from proxmox-sys' open_file_locked: only the lock of the
// datastore configuration is IsDatastoreConfigLocked, and a job's lock stays
// IsTaskAlreadyRunning.
const (
	datastoreConfigLockedText = `Unable to acquire lock "/etc/proxmox-backup/.datastore.lck" - Interrupted system call (os error 4)`
	jobLockedText             = `Unable to acquire lock "/var/lib/proxmox-backup/jobstates/syncjob-pull-offsite.lck" - Interrupted system call (os error 4)`
)

func TestIsDatastoreConfigLocked(t *testing.T) {
	for _, tc := range []struct {
		name           string
		err            error
		want           bool
		alreadyRunning bool
	}{
		{"datastore configuration", apiError(400, datastoreConfigLockedText), true, false},
		{"without the wrapping", &Error{StatusCode: http.StatusBadRequest, Message: datastoreConfigLockedText}, true, false},
		{"job state", apiError(400, jobLockedText), false, true},
		{"other status", apiError(500, datastoreConfigLockedText), false, false},
		{"maintenance mode", apiError(400, "datastore 'store1' is unavailable: S3 refresh maintenance mode: "), false, false},
		{"not an API error", errors.New(datastoreConfigLockedText), false, false},
		{"nil", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsDatastoreConfigLocked(tc.err); got != tc.want {
				t.Errorf("IsDatastoreConfigLocked(%v) = %v, want %v", tc.err, got, tc.want)
			}
			if got := IsTaskAlreadyRunning(tc.err); got != tc.alreadyRunning {
				t.Errorf("IsTaskAlreadyRunning(%v) = %v, want %v", tc.err, got, tc.alreadyRunning)
			}
		})
	}

	// Nothing else takes the datastore configuration's lock for its own.
	locked := apiError(400, datastoreConfigLockedText)
	for name, is := range map[string]func(error) bool{
		"IsNotFound": IsNotFound, "IsDatastoreUnavailable": IsDatastoreUnavailable, "IsDatastoreNotMounted": IsDatastoreNotMounted,
		"IsDigestConflict": IsDigestConflict, "IsAlreadyExists": IsAlreadyExists, "IsEndpointMissing": IsEndpointMissing,
	} {
		if is(locked) {
			t.Errorf("%s accepted the lock of the datastore configuration", name)
		}
	}
}
