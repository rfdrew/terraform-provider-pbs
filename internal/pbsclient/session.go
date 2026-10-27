package pbsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// A password session is a ticket: POST /access/ticket with username and
// password answers {"ticket", "CSRFPreventionToken", "username"}. Every later
// call sends the ticket as the PBSAuthCookie cookie, and every call but GET
// also the CSRF token as the CSRFPreventionToken header; without the header a
// write fails with 401 "missing CSRF prevention token".
//
// A ticket is valid for two hours. The client signs in again once its ticket
// is older than ticketRenewAfter, and Call does so on the first 401 as well,
// which covers a server restart that lost the signing key.
//
// Terraform calls resources in parallel, so the first request of a run can
// arrive many times at once. Tickets carry a generation number, and at most
// one sign-in is in flight: callers that need a ticket newer than the one they
// hold join it instead of starting another.

const (
	// ticketCookieName and csrfHeader are what PBS reads the ticket from.
	ticketCookieName = "PBSAuthCookie"
	csrfHeader       = "CSRFPreventionToken"
	// ticketRenewAfter is well inside a ticket's two hours, so that a call
	// never starts with a ticket that runs out during a long apply.
	ticketRenewAfter = time.Hour
)

// ticket is one sign-in. Tickets are immutable once published; a renewal
// creates a new one with a higher generation.
type ticket struct {
	gen      uint64
	ticket   string
	csrf     string
	issuedAt time.Time
}

// loginCall is a sign-in in flight. Callers that need a ticket while one is
// running wait for it instead of starting their own.
type loginCall struct {
	done   chan struct{}
	ticket *ticket
	err    error
}

// now is the clock tickets are aged by; tests replace it.
var now = time.Now

// ticketNewerThan returns a ticket with a generation above stale that is not
// due for renewal, signing in when there is none. Pass 0 for any current
// ticket, and the generation of a ticket the server rejected to get a new one.
func (c *Client) ticketNewerThan(ctx context.Context, stale uint64) (*ticket, error) {
	for {
		c.mu.Lock()
		if t := c.current; t != nil && t.gen > stale && now().Sub(t.issuedAt) < ticketRenewAfter {
			c.mu.Unlock()
			return t, nil
		}
		call := c.inflight
		if call == nil {
			call = &loginCall{done: make(chan struct{})}
			c.inflight = call
			c.mu.Unlock()
			return c.runLogin(ctx, call)
		}
		c.mu.Unlock()

		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if call.err != nil {
			// The caller that signed in may have been cancelled while this
			// one still has time; it then tries again itself rather than
			// inherit someone else's cancellation.
			if isContextError(call.err) && ctx.Err() == nil {
				continue
			}
			return nil, call.err
		}
		if call.ticket.gen > stale {
			return call.ticket, nil
		}
	}
}

// runLogin signs in for call, publishes the ticket and releases everyone
// waiting for it.
func (c *Client) runLogin(ctx context.Context, call *loginCall) (*ticket, error) {
	t, err := c.login(ctx)

	c.mu.Lock()
	if err == nil {
		c.gen++
		t.gen = c.gen
		c.current = t
	}
	call.ticket, call.err = t, err
	c.inflight = nil
	c.mu.Unlock()
	close(call.done)
	return t, err
}

// login exchanges the username and password for a ticket.
func (c *Client) login(ctx context.Context) (*ticket, error) {
	form := url.Values{"username": {c.username}, "password": {c.password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+apiPrefix+"/access/ticket", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building the sign-in request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.userAgent)

	tflog.Debug(ctx, "signing in to PBS", map[string]any{"username": c.username})
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /access/ticket: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading the sign-in response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := newError(http.MethodPost, "/access/ticket", resp.StatusCode, resp.Header, raw)
		apiErr.Message = Redact(apiErr.Message, c.password)
		apiErr.Body = Redact(apiErr.Body, c.password)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("%w: %w", ErrBadCredentials, apiErr)
		}
		return nil, apiErr
	}

	var answer struct {
		Data *struct {
			Ticket string `json:"ticket"`
			CSRF   string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("decoding the sign-in response: %w", err)
	}
	// A user with a second factor gets a ticket that only lets it complete
	// the second factor, marked by a "PBS:!tfa!" prefix, and no CSRF token.
	if answer.Data == nil || answer.Data.Ticket == "" {
		return nil, fmt.Errorf("%w: POST /access/ticket answered without a ticket", ErrBadCredentials)
	}
	if strings.Contains(answer.Data.Ticket, "!tfa!") || answer.Data.CSRF == "" {
		return nil, ErrSecondFactor
	}
	return &ticket{ticket: answer.Data.Ticket, csrf: answer.Data.CSRF, issuedAt: now()}, nil
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
