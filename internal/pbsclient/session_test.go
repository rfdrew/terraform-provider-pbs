package pbsclient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPasswordSignsInOnceAndSendsTheTicket(t *testing.T) {
	fake := newFakePBS()
	fake.reply("PUT /config/remote/r1", http.StatusOK, `{"data":null}`)
	c := fake.passwordClient(t)
	ctx := context.Background()

	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(ctx, "/config/remote/r1", nil, nil); err != nil {
		t.Fatal(err)
	}
	if n := fake.count("POST /access/ticket"); n != 1 {
		t.Fatalf("signed in %d times, want once", n)
	}
	call := fake.lastCall(t, "PUT /config/remote/r1")
	if call.header.Get(csrfHeader) == "" || call.header.Get("Authorization") != "" ||
		!strings.Contains(call.header.Get("Cookie"), ticketCookieName+"=") {
		t.Fatalf("headers = %v", call.header)
	}
	login := fake.lastCall(t, "POST /access/ticket")
	if login.form.Get("username") != fakeUsername || login.form.Get("password") != fakePassword {
		t.Fatalf("sign-in form = %v", login.form)
	}
}

// A ticket the server no longer knows — after a restart — is renewed once,
// and the call retried.
func TestRejectedTicketIsRenewedOnce(t *testing.T) {
	fake := newFakePBS()
	c := fake.passwordClient(t)
	ctx := context.Background()
	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatal(err)
	}

	fake.expireTickets()
	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatalf("after the restart: %v", err)
	}
	if n := fake.count("POST /access/ticket"); n != 2 {
		t.Fatalf("signed in %d times, want twice", n)
	}
	if n := fake.count("GET /version"); n != 3 {
		t.Fatalf("GET /version ran %d times, want 3 (one retried)", n)
	}
}

// A 401 that a new ticket does not cure is reported, not retried forever.
func TestPersistentRejectionIsReported(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/remote", http.StatusUnauthorized, "authentication failed - user account or token disabled or expired.")
	c := fake.passwordClient(t)

	_, err := c.Get(context.Background(), "/config/remote", nil, nil)
	if !IsUnauthorized(err) {
		t.Fatalf("error = %v, want unauthorized", err)
	}
	if n := fake.count("GET /config/remote"); n != 2 {
		t.Fatalf("GET /config/remote ran %d times, want 2", n)
	}
}

func TestTicketIsRenewedBeforeItExpires(t *testing.T) {
	fake := newFakePBS()
	c := fake.passwordClient(t)
	ctx := context.Background()

	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return clock }
	t.Cleanup(func() { now = time.Now })

	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(59 * time.Minute)
	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatal(err)
	}
	if n := fake.count("POST /access/ticket"); n != 1 {
		t.Fatalf("signed in %d times within the hour, want once", n)
	}
	clock = clock.Add(2 * time.Minute)
	if _, err := c.ServerVersion(ctx); err != nil {
		t.Fatal(err)
	}
	if n := fake.count("POST /access/ticket"); n != 2 {
		t.Fatalf("signed in %d times after the hour, want twice", n)
	}
}

func TestParallelCallsShareOneSignIn(t *testing.T) {
	fake := newFakePBS()
	c := fake.passwordClient(t)

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.ServerVersion(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := fake.count("POST /access/ticket"); n != 1 {
		t.Fatalf("signed in %d times, want once", n)
	}
}

func TestWrongPassword(t *testing.T) {
	fake := newFakePBS()
	c, err := New(Options{Endpoint: "https://pbs.test", Username: fakeUsername, Password: "wrong-password", Transport: fake})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ServerVersion(context.Background())
	if !errors.Is(err, ErrBadCredentials) || !IsUnauthorized(err) {
		t.Fatalf("error = %v, want ErrBadCredentials", err)
	}
	if strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("error quotes the password: %v", err)
	}
}

func TestSecondFactorIsRefused(t *testing.T) {
	fake := newFakePBS()
	fake.tfa = true
	_, err := fake.passwordClient(t).ServerVersion(context.Background())
	if !errors.Is(err, ErrSecondFactor) {
		t.Fatalf("error = %v, want ErrSecondFactor", err)
	}
}
