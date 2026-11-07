package pbsclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testNetworkJSON is what PBS 4.2.8 answers for a host with a bridge on a
// VLAN-aware bond and changes pending: the digest of the file on every
// interface, the name again as iface, keys in snake_case and kebab-case,
// what is not set left out, and the diff next to data.
const testNetworkJSON = `{"data":[
 {"active":true,"autostart":true,"bond_mode":"active-backup","bond-primary":"eno1","bond_xmit_hash_policy":"layer2+3",
  "digest":"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b","iface":"bond0","method":"manual",
  "mtu":9000,"name":"bond0","options":["bond-miimon 100"],"slaves":["eno1","eno2"],"type":"bond"},
 {"active":false,"altnames":["enp3s0"],"autostart":false,"digest":"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
  "iface":"eno3","method":"manual","name":"eno3","type":"eth"},
 {"active":true,"autostart":true,"cidr":"198.51.100.5/24","digest":"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
  "iface":"vlan20","method":"static","name":"vlan20","type":"vlan","vlan-id":20,"vlan-raw-device":"bond0"},
 {"active":true,"autostart":true,"bridge_ports":["bond0"],"bridge_vlan_aware":true,"cidr6":"2001:db8::10/64",
  "comments":"Management","digest":"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b","iface":"vmbr0",
  "method6":"static","name":"vmbr0","options6":["accept_ra 2"],"type":"bridge"}],
"changes":"--- /etc/network/interfaces\n+++ /etc/network/interfaces.new\n@@ -1 +1 @@\n-auto eno3\n"}`

func TestNetworkInterfacesDecodesTheMixedKeysAndTheChanges(t *testing.T) {
	const route = "GET /nodes/pbs1/network"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, testNetworkJSON)
	c := fake.client(t)

	interfaces, changes, err := c.NetworkInterfaces(context.Background(), "pbs1")
	if err != nil {
		t.Fatal(err)
	}
	if changes != "--- /etc/network/interfaces\n+++ /etc/network/interfaces.new\n@@ -1 +1 @@\n-auto eno3\n" {
		t.Errorf("changes = %q", changes)
	}
	if len(interfaces) != 4 {
		t.Fatalf("NetworkInterfaces() = %+v", interfaces)
	}
	mtu, vlanID, vlanAware := int64(9000), int64(20), true
	const digest = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
	want := []NetworkInterface{
		{Name: "bond0", Type: "bond", Active: true, Autostart: true, Method: "manual", MTU: &mtu,
			Options: []string{"bond-miimon 100"}, Slaves: []string{"eno1", "eno2"}, BondMode: "active-backup",
			BondPrimary: "eno1", BondXmitHashPolicy: "layer2+3", Digest: digest},
		{Name: "eno3", Type: "eth", Method: "manual", AltNames: []string{"enp3s0"}, Digest: digest},
		{Name: "vlan20", Type: "vlan", Active: true, Autostart: true, Method: "static", CIDR: "198.51.100.5/24",
			VLANID: &vlanID, VLANRawDevice: "bond0", Digest: digest},
		{Name: "vmbr0", Type: "bridge", Active: true, Autostart: true, Method6: "static", CIDR6: "2001:db8::10/64",
			Options6: []string{"accept_ra 2"}, Comments: "Management", BridgePorts: []string{"bond0"},
			BridgeVLANAware: &vlanAware, Digest: digest},
	}
	if !reflect.DeepEqual(interfaces, want) {
		t.Errorf("NetworkInterfaces() = %+v, want %+v", interfaces, want)
	}
	// PBS refuses any parameter but the node, which is in the path.
	if call := fake.lastCall(t, route); len(call.query) != 0 {
		t.Errorf("query = %v, want none", call.query)
	}
}

// Without pending changes PBS sends nothing next to data.
func TestNetworkInterfacesWithoutChanges(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/network", http.StatusOK, `{"data":[]}`)
	c := fake.client(t)

	interfaces, changes, err := c.NetworkInterfaces(context.Background(), c.Node())
	if err != nil || len(interfaces) != 0 || changes != "" {
		t.Errorf("NetworkInterfaces() = %+v, %q, %v", interfaces, changes, err)
	}
}

func TestNetworkInterfacesReportsErrors(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/network", http.StatusBadRequest, "line 12: unknown iface option auto")
	c := fake.client(t)

	interfaces, changes, err := c.NetworkInterfaces(context.Background(), c.Node())
	if err == nil || interfaces != nil || changes != "" {
		t.Fatalf("NetworkInterfaces() = %+v, %q, %v, want an error", interfaces, changes, err)
	}
	if apiErr, ok := asError(err); !ok || apiErr.StatusCode != http.StatusBadRequest || apiErr.Message != "line 12: unknown iface option auto" {
		t.Errorf("err = %v", err)
	}
}

// GET of one interface sends the digest inside data.
func TestNetworkInterfaceReadsOneWithItsDigest(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/network/vmbr1", http.StatusOK, `{"data":{"active":false,"autostart":true,
	 "bridge_ports":[],"digest":"ab12","method":"manual","method6":"manual","name":"vmbr1","type":"bridge"}}`)
	c := fake.client(t)

	iface, err := c.NetworkInterface(context.Background(), "localhost", "vmbr1")
	if err != nil {
		t.Fatal(err)
	}
	if iface.Name != "vmbr1" || iface.Digest != "ab12" || !iface.Autostart || iface.BridgePorts == nil || len(iface.BridgePorts) != 0 {
		t.Errorf("NetworkInterface() = %+v", iface)
	}

	fake.reply("GET /nodes/localhost/network/vmbr9", http.StatusBadRequest, "interface 'vmbr9' does not exist.")
	if _, err := c.NetworkInterface(context.Background(), "localhost", "vmbr9"); !IsNotFound(err) {
		t.Errorf("err = %v, want IsNotFound", err)
	}
}

func TestNetworkInterfaceWrites(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /nodes/localhost/network", http.StatusOK, `{"data":null}`)
	fake.reply("PUT /nodes/localhost/network/vmbr1", http.StatusOK, `{"data":null}`)
	fake.reply("DELETE /nodes/localhost/network/vmbr1", http.StatusOK, `{"data":null}`)
	fake.reply("DELETE /nodes/localhost/network", http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	if err := c.CreateNetworkInterface(ctx, "localhost", url.Values{"iface": {"vmbr1"}, "type": {"bridge"}}); err != nil {
		t.Fatal(err)
	}
	if form := fake.lastCall(t, "POST /nodes/localhost/network").form; form.Get("iface") != "vmbr1" || form.Get("type") != "bridge" {
		t.Errorf("POST form = %v", form)
	}
	if err := c.UpdateNetworkInterface(ctx, "localhost", "vmbr1", url.Values{"comments": {"a"}, "digest": {"ab12"}}); err != nil {
		t.Fatal(err)
	}
	if form := fake.lastCall(t, "PUT /nodes/localhost/network/vmbr1").form; form.Get("comments") != "a" || form.Get("digest") != "ab12" {
		t.Errorf("PUT form = %v", form)
	}
	if err := c.DeleteNetworkInterface(ctx, "localhost", "vmbr1", "ab12"); err != nil {
		t.Fatal(err)
	}
	if query := fake.lastCall(t, "DELETE /nodes/localhost/network/vmbr1").query; query.Get("digest") != "ab12" {
		t.Errorf("DELETE query = %v", query)
	}
	if err := c.RevertNetwork(ctx, "localhost"); err != nil {
		t.Fatal(err)
	}
}

func TestReloadNetworkReturnsTheTask(t *testing.T) {
	const upid = "UPID:pbs1:000004D2:00000162:00000003:6AE11CDF:srvreload:networking:root@pam:"
	fake := newFakePBS()
	fake.reply("PUT /nodes/localhost/network", http.StatusOK, `{"data":"`+upid+`"}`)
	c := fake.client(t)

	got, err := c.ReloadNetwork(context.Background(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if got.Raw != upid || got.WorkerType != "srvreload" || got.Node != "pbs1" {
		t.Errorf("ReloadNetwork() = %+v", got)
	}

	fake.reply("PUT /nodes/localhost/network", http.StatusOK, `{"data":null}`)
	if _, err := c.ReloadNetwork(context.Background(), "localhost"); err == nil || !strings.Contains(err.Error(), "instead of the task ID") {
		t.Errorf("err = %v", err)
	}

	fake.reply("PUT /nodes/localhost/network", http.StatusBadRequest, "ifupdown2 is not installed.")
	if _, err := c.ReloadNetwork(context.Background(), "localhost"); !IsIfupdown2Missing(err) {
		t.Errorf("err = %v, want IsIfupdown2Missing", err)
	}
}

func TestNetworkErrorClassifiers(t *testing.T) {
	apiErr := func(status int, message string) error {
		return &Error{Method: "PUT", Path: "/nodes/localhost/network/vmbr1", StatusCode: status, Message: message}
	}
	if !IsDuplicateGateway(apiErr(400, "Default IPv4 gateway already exists on interface 'vmbr0'")) ||
		IsDuplicateGateway(apiErr(400, "interface 'vmbr1' already exists")) {
		t.Error("IsDuplicateGateway")
	}
	if IsAlreadyExists(apiErr(400, "Default IPv6 gateway already exists on interface 'vmbr0'")) ||
		!IsAlreadyExists(apiErr(400, "interface 'vmbr1' already exists")) {
		t.Error("IsAlreadyExists and gateways")
	}
	if !IsNetworkDiffFailed(apiErr(400, "diff failed: status code: 2 - diff: /etc/network/interfaces: No such file or directory")) ||
		IsNetworkDiffFailed(apiErr(400, "line 3: unknown iface option auto")) {
		t.Error("IsNetworkDiffFailed")
	}
	transport := fmt.Errorf("GET /x: %w", &url.Error{Op: "Get", URL: "https://pbs:8007", Err: errors.New("connection refused")})
	if !IsTransportError(transport) || IsTransportError(apiErr(400, "x")) || IsTransportError(nil) ||
		IsTransportError(fmt.Errorf("x: %w", &url.Error{Op: "Get", URL: "https://pbs:8007", Err: context.Canceled})) {
		t.Error("IsTransportError")
	}
}

// A reload that makes PBS unreachable for a while — here behind a proxy
// that answers 502 — is waited out, until the grace runs out.
func TestWaitTaskThroughOutages(t *testing.T) {
	const upid = "UPID:pbs1:000004D2:00000162:00000003:6AE11CDF:srvreload:networking:root@pam:"
	route := "GET /nodes/pbs1/tasks/" + upid + "/status"
	fake := newFakePBS()
	polls := 0
	fake.handle(route, func(w http.ResponseWriter, _ *http.Request) {
		polls++
		if polls <= 2 {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("Bad Gateway"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
	})
	c := fake.client(t)
	parsed, err := ParseUPID(upid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WaitTaskThroughOutages(context.Background(), parsed, time.Hour); err != nil || polls != 3 {
		t.Fatalf("WaitTaskThroughOutages() = %v after %d polls", err, polls)
	}

	polls = 0
	_, err = c.WaitTaskThroughOutages(context.Background(), parsed, 0)
	if !IsUnreachable(err) || polls != 1 {
		t.Fatalf("WaitTaskThroughOutages() = %v after %d polls, want the 502", err, polls)
	}
}

// pollTransport fails the first polls of a task as if the node were out of
// reach, then holds every request until its context ends.
type pollTransport struct{ unreachable int }

func (p *pollTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if p.unreachable > 0 {
		p.unreachable--
		return nil, errors.New("connect: no route to host")
	}
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// The task timeout ending a poll is a timeout — or, after the node stopped
// answering, the outage.
func TestWaitTaskThroughOutagesTimeout(t *testing.T) {
	parsed, err := ParseUPID("UPID:pbs1:000004D2:00000162:00000003:6AE11CDF:srvreload:networking:root@pam:")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		unreachable int
		want        func(error) bool
	}{
		{0, func(err error) bool { return errors.Is(err, ErrTaskTimeout) }},
		{1, func(err error) bool { return IsUnreachable(err) && strings.Contains(err.Error(), "no route to host") }},
	} {
		c, err := New(Options{Endpoint: "https://pbs.test:8007", APIToken: fakeAPIToken, TaskTimeout: 50 * time.Millisecond,
			Transport: &pollTransport{unreachable: tc.unreachable}})
		if err != nil {
			t.Fatal(err)
		}
		c.sleep = noSleep
		if _, err := c.WaitTaskThroughOutages(context.Background(), parsed, time.Hour); !tc.want(err) {
			t.Errorf("after %d unreachable polls: err = %v", tc.unreachable, err)
		}
	}
}
