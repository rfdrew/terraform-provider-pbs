package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNetworkReloadActionAppliesPendingChanges(t *testing.T) {
	h, fake, network := newNetworkHarness(t, true)
	network.edit("eno1", func(i *fakeIface) { i.Comments = "edited in the web interface" })

	got := h.invokeAction(t, "pbs_network_reload", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	if len(got.diagnostics) != 0 {
		t.Fatalf("diagnostics: %v", got.diagnostics)
	}
	requireProgressContaining(t, got, "applying the pending network changes of node localhost: ")
	requireProgressContaining(t, got, "added, ")
	requireProgressContaining(t, got, "PBS started task UPID:localhost:")
	requireProgressContaining(t, got, "PBS applied the network configuration of node localhost")
	if network.pendingChanges() || network.reloads != 1 || fake.count("PUT /nodes/localhost/network") != 1 {
		t.Fatalf("pending = %v, reloads = %d", network.pendingChanges(), network.reloads)
	}
}

// Nothing pending, nothing reloaded: ifreload -a would strip the addresses
// added outside the file. force reloads all the same.
func TestNetworkReloadActionNothingPending(t *testing.T) {
	h, fake, network := newNetworkHarness(t, true)
	got := h.invokeAction(t, "pbs_network_reload", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "nothing is pending on node localhost; not reloading")
	if network.reloads != 0 || fake.count("PUT /nodes/localhost/network") != 0 {
		t.Fatalf("reloaded: %v", fake.routes())
	}

	got = h.invokeAction(t, "pbs_network_reload", map[string]any{"force": true})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "PBS applied the network configuration of node localhost")
	if network.reloads != 1 || fake.count("GET /nodes/localhost/network") != 1 {
		t.Fatalf("reloads = %d, routes = %v", network.reloads, fake.routes())
	}
}

func TestNetworkReloadActionErrors(t *testing.T) {
	h, fake, network := newNetworkHarness(t, true)

	network.ifupdown2 = false
	got := h.invokeAction(t, "pbs_network_reload", map[string]any{"force": true})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to apply the network changes of PBS node localhost")
	requireProtocolErrorContaining(t, got.diagnostics, "Install ifupdown2")

	network.ifupdown2 = true
	network.reloadError = "error: vmbr1: cmd '/sbin/ip link set dev vmbr1 mtu 9000' failed"
	network.edit("eno1", func(i *fakeIface) { i.Comments = "x" })
	got = h.invokeAction(t, "pbs_network_reload", map[string]any{})
	requireProtocolErrorContaining(t, got.diagnostics, "PBS keeps no copy of the previous one")
	// PBS moved the file before ifreload failed: invoking the action again
	// reloads only with a new pending change, or with force.
	requireProtocolErrorContaining(t, got.diagnostics, "nothing is pending any more")
	requireProtocolErrorContaining(t, got.diagnostics, "invoke it with force = true to run ifreload again")
	requireProtocolErrorContaining(t, got.diagnostics, "vmbr1 mtu 9000")
	requireProtocolErrorContaining(t, got.diagnostics, "The changes PBS moved into /etc/network/interfaces:\n\n    --- /etc/network/interfaces")
	requireProtocolErrorContaining(t, got.diagnostics, "proxmox-backup-manager task log")

	// Without /etc/network/interfaces, PBS cannot show what is pending, and
	// the action applies it all the same.
	network.reloadError = ""
	network.mu.Lock()
	network.hasRunningFile = false
	network.mu.Unlock()
	network.edit("eno1", func(i *fakeIface) { i.Comments = "y" })
	got = h.invokeAction(t, "pbs_network_reload", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "PBS cannot compare the pending changes")
	if network.pendingChanges() {
		t.Fatal("the changes should be applied")
	}

	// A configuration PBS cannot read: the action cannot tell whether
	// anything is pending, unless force says not to ask.
	fake.reply("GET /nodes/localhost/network", http.StatusBadRequest, "line 7: unknown iface option auto")
	got = h.invokeAction(t, "pbs_network_reload", map[string]any{})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to read the pending network changes of PBS node localhost")
	requireProtocolErrorContaining(t, got.diagnostics, "unless `force` is set")
	requireProtocolErrorContaining(t, got.diagnostics, "Upgrade PBS to 4.2.7")

	fake.reply("PUT /nodes/localhost/network", http.StatusForbidden, "permission check failed")
	got = h.invokeAction(t, "pbs_network_reload", map[string]any{"force": true})
	requireProtocolErrorContaining(t, got.diagnostics, "Sys.Modify on /system/network/interfaces")
}

// A reload that cuts the node off is reported as lost contact once the
// wait ends.
func TestNetworkReloadActionLosesContact(t *testing.T) {
	fake := newFakePBS()
	network := newFakeNetwork(fake, "localhost", "eno1")
	transport := &networkTransport{fake: fake, network: network, cutOff: true}
	h := newProtocolHarness(t, fake, withTransport(transport))
	got := h.invokeAction(t, "pbs_network_reload", map[string]any{"force": true, "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "lost contact with it while waiting for the task")
	requireProtocolErrorContaining(t, got.diagnostics, "the Network Interfaces panel whether anything is still pending")
	// pending_changes is pbs_network_apply's, which the action's users may
	// not have.
	for _, d := range got.diagnostics {
		if strings.Contains(d.Detail, "pending_changes") || strings.Contains(d.Detail, "terraform plan") {
			t.Fatalf("detail points to pbs_network_apply: %s", d.Detail)
		}
	}
}

// An outage shorter than the grace is waited out.
func TestNetworkReloadActionWaitsOutAnOutage(t *testing.T) {
	fake := newFakePBS()
	network := newFakeNetwork(fake, "localhost", "eno1")
	transport := &networkTransport{fake: fake, network: network, failPolls: 2}
	h := newProtocolHarness(t, fake, withTransport(transport))
	network.edit("eno1", func(i *fakeIface) { i.Comments = "x" })
	got := h.invokeAction(t, "pbs_network_reload", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	if network.pendingChanges() || network.reloads != 1 {
		t.Fatalf("pending = %v, reloads = %d", network.pendingChanges(), network.reloads)
	}
}

func TestNetworkReloadActionTimeout(t *testing.T) {
	fake := newFakePBS()
	network := newFakeNetwork(fake, "localhost", "eno1")
	transport := &networkTransport{fake: fake, network: network, running: true}
	h := newProtocolHarness(t, fake, withTransport(transport))
	got := h.invokeAction(t, "pbs_network_reload", map[string]any{"force": true, "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "Network reload of PBS node localhost did not finish")
	requireProtocolErrorContaining(t, got.diagnostics, "Raise the action's `timeout`")
}

// When Terraform stops the action, it stops waiting at once, and lets go of
// the lock of the network configuration.
func TestNetworkReloadActionCancelled(t *testing.T) {
	fake := newFakePBS()
	network := newFakeNetwork(fake, "localhost", "eno1")
	transport := &networkTransport{fake: fake, network: network, running: true}
	h := newProtocolHarness(t, fake, withTransport(transport))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	start := time.Now()
	h.invokeActionWith(ctx, t, "pbs_network_reload", h.actionValue(t, "pbs_network_reload", map[string]any{"force": true}))
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the action went on for %s after it was cancelled", elapsed)
	}
	// A second invocation would wait for good if the first held on to the
	// lock.
	transport.mu.Lock()
	transport.running = false
	transport.mu.Unlock()
	done := make(chan actionInvocation)
	go func() {
		done <- h.invokeActionWith(context.Background(), t, "pbs_network_reload", h.actionValue(t, "pbs_network_reload", map[string]any{"force": true}))
	}()
	select {
	case got := <-done:
		requireNoProtocolErrors(t, got.diagnostics)
	case <-time.After(10 * time.Second):
		t.Fatal("the lock of the network configuration is still held")
	}
}

func TestNetworkReloadActionValidation(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, attribute := range h.actionSchema(t, "pbs_network_reload").Block.Attributes {
		if attribute.Name == "wait" {
			t.Fatal("a reload must be waited for")
		}
	}
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"node": "-bad"}, "node name"},
		{map[string]any{"timeout": "0s"}, "positive duration"},
	} {
		requireProtocolErrorContaining(t, h.validateAction(t, "pbs_network_reload", h.actionValue(t, "pbs_network_reload", tc.attrs)), tc.want)
	}
	unknown := h.actionValue(t, "pbs_network_reload", map[string]any{"node": tfUnknown, "force": tfUnknown, "timeout": tfUnknown})
	requireNoProtocolErrors(t, h.validateAction(t, "pbs_network_reload", unknown))
	requireNoProtocolErrors(t, h.planAction(t, "pbs_network_reload", unknown))
}

func TestDescribeNetworkChanges(t *testing.T) {
	diff := strings.Join([]string{
		"--- /etc/network/interfaces\t2026-11-14 10:00:00.000000000 +0100",
		"+++ /etc/network/interfaces.new\t2026-11-14 10:05:00.000000000 +0100",
		"@@ -5,3 +5,8 @@",
		" iface eno1 inet manual",
		"+",
		"+auto vmbr1",
		"+iface vmbr1 inet static",
		"-#--- old comment",
		"",
	}, "\n")
	if got, want := describeNetworkChanges(diff), "3 lines added, 1 line removed in /etc/network/interfaces"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
