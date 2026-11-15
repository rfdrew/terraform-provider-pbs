package pbsclient

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServiceState(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/services/postfix/state", http.StatusOK,
		`{"data":{"service":"postfix","name":"postfix","desc":"Postfix Mail Transport Agent","state":"running","unit-state":"enabled"}}`)
	fake.reply("GET /nodes/localhost/services/chrony/state", http.StatusOK, `{"data":null}`)
	fake.reply("GET /nodes/localhost/services/cron/state", http.StatusBadRequest, "systemctl show failed with exit status: 1")
	c := fake.client(t)
	ctx := context.Background()

	state, ok, err := c.ServiceState(ctx, "localhost", "postfix")
	if err != nil || !ok || state.Service != "postfix" || state.State != "running" || state.UnitState != "enabled" ||
		state.Description != "Postfix Mail Transport Agent" {
		t.Fatalf("postfix: %+v, %v, %v", state, ok, err)
	}
	// systemctl showed no Description: PBS answers null.
	if state, ok, err := c.ServiceState(ctx, "localhost", "chrony"); err != nil || ok || state != (Service{}) {
		t.Fatalf("chrony: %+v, %v, %v", state, ok, err)
	}
	if _, _, err := c.ServiceState(ctx, "localhost", "cron"); err == nil || !strings.Contains(err.Error(), "systemctl show failed") {
		t.Fatalf("cron: %v", err)
	}
}

func TestStartServiceCommand(t *testing.T) {
	fake := newFakePBS()
	upid := "UPID:pbs1:000004D2:0000162E:00000003:6AE11CDF:srvreload:proxmox\\x2dbackup\\x2dproxy:root@pam:"
	fake.reply("POST /nodes/pbs1/services/proxmox-backup-proxy/restart", http.StatusOK, `{"data":"`+strings.ReplaceAll(upid, `\`, `\\`)+`"}`)
	fake.reply("POST /nodes/pbs1/services/postfix/start", http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	// PBS reloads its proxy when asked to restart it.
	got, err := c.StartServiceCommand(ctx, "pbs1", ServiceProxy, ServiceRestart)
	if err != nil || got.Raw != upid || got.WorkerType != "srvreload" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if call := fake.lastCall(t, "POST /nodes/pbs1/services/proxmox-backup-proxy/restart"); len(call.form) != 0 {
		t.Fatalf("the command sent parameters: %v", call.form)
	}
	if _, err := c.StartServiceCommand(ctx, "pbs1", "postfix", ServiceStart); err == nil || !strings.Contains(err.Error(), "instead of a task ID") {
		t.Fatalf("an answer without a UPID: %v", err)
	}

	// PBS hands any name to systemctl, as root: the client refuses what
	// PBS does not list, and the commands it does not send.
	calls := len(fake.routes())
	for _, tc := range []struct{ service, command, want string }{
		{"proxmox-backup.service", ServiceRestart, "is not one of the services PBS controls"},
		{"--now", ServiceStart, "is not one of the services PBS controls"},
		{"postfix", "stop", "is not a service command"},
		{"postfix", "kill", "is not a service command"},
	} {
		if _, err := c.StartServiceCommand(ctx, "pbs1", tc.service, tc.command); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %s: %v", tc.command, tc.service, err)
		}
	}
	if len(fake.routes()) != calls {
		t.Fatalf("a refused command reached PBS: %v", fake.routes())
	}
}

func TestServiceRunningAndStopped(t *testing.T) {
	for _, tc := range []struct {
		state            string
		running, stopped bool
	}{
		{"running", true, false},
		{"exited", true, false},
		{"dead", false, true},
		{"failed", false, true},
		// A oneshot unit that is not running reports its result.
		{"success", false, true},
		{"exit-code", false, true},
		{"reload", false, false},
		{"start", false, false},
		{"auto-restart", false, false},
		{"unknown", false, false},
	} {
		s := Service{State: tc.state}
		if s.Running() != tc.running || s.Stopped() != tc.stopped {
			t.Errorf("%s: running %v, stopped %v", tc.state, s.Running(), s.Stopped())
		}
	}
	for _, id := range ServiceIDs {
		if !IsServiceID(id) {
			t.Errorf("%s is not a service ID", id)
		}
	}
	for _, id := range []string{"", "ssh", "proxmox-backup.service", "Postfix"} {
		if IsServiceID(id) {
			t.Errorf("%q is a service ID", id)
		}
	}
}

// A certificate change waits while the certificate lock is held, as for a
// reload of the proxy.
func TestWithCertificateLockHoldsBackCertificateChanges(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK,
		`{"data":[{"filename":"proxy.pem","fingerprint":"`+strings.TrimSuffix(strings.Repeat("ab:", 32), ":")+`"}]}`)
	c := fake.client(t)

	changed := make(chan struct{})
	err := c.WithCertificateLock(func() error {
		go func() {
			_, _ = c.ChangeCertificate(context.Background(), "localhost", func(context.Context) error { return nil })
			close(changed)
		}()
		select {
		case <-changed:
			t.Error("a certificate change ran while the lock was held")
		case <-time.After(200 * time.Millisecond):
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("the certificate change did not run once the lock was let go")
	}
}
