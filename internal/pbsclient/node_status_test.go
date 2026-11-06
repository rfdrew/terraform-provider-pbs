package pbsclient

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

// testNodeStatusJSON is what PBS 4.2.8 answers on an EFI host: every field,
// fractions as numbers from 0 to 1, figures in bytes, the fingerprint as
// colon-separated lower-case hex pairs.
const testNodeStatusJSON = `{"data":{"boot-info":{"mode":"efi","secureboot":false},"cpu":0.0213,
"cpuinfo":{"cpus":8,"model":"Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz","sockets":1},
"current-kernel":{"machine":"x86_64","release":"6.14.11-4-pve","sysname":"Linux","version":"#1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (2025-10-10T08:04Z)"},
"info":{"fingerprint":"2f:f2:f7:e9:8b:a5:62:fe:bb:6d:63:40:33:8b:4a:97:e6:d4:80:5d:f9:96:b9:63:ee:4c:08:31:c2:d0:00:5c"},
"kversion":"Linux 6.14.11-4-pve #1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (2025-10-10T08:04Z)",
"loadavg":[0.12,0.08,0.05],"memory":{"free":12884901888,"total":33395372032,"used":4294967296},
"root":{"avail":90194313216,"total":100861726720,"used":5523898368},
"swap":{"free":8589930496,"total":8589930496,"used":0},"uptime":1234567,"wait":0.0012}}`

func TestNodeStatusDecodesTheAnswer(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/pbs1/status", http.StatusOK, testNodeStatusJSON)
	status, err := fake.client(t).NodeStatus(context.Background(), "pbs1")
	if err != nil {
		t.Fatal(err)
	}
	cpu, wait := 0.0213, 0.0012
	want := NodeStatus{
		Memory:   NodeStatusMemory{Total: 33395372032, Used: 4294967296, Free: 12884901888},
		Swap:     NodeStatusMemory{Total: 8589930496, Used: 0, Free: 8589930496},
		Root:     NodeStatusRoot{Total: 100861726720, Used: 5523898368, Avail: 90194313216},
		Uptime:   1234567,
		LoadAvg:  []float64{0.12, 0.08, 0.05},
		CPU:      &cpu,
		Wait:     &wait,
		KVersion: "Linux 6.14.11-4-pve #1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (2025-10-10T08:04Z)",
		CurrentKernel: NodeStatusKernel{Sysname: "Linux", Release: "6.14.11-4-pve",
			Version: "#1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (2025-10-10T08:04Z)", Machine: "x86_64"},
		CPUInfo:  NodeStatusCPUInfo{Model: "Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz", Sockets: 1, CPUs: 8},
		Info:     NodeStatusInfo{Fingerprint: "2f:f2:f7:e9:8b:a5:62:fe:bb:6d:63:40:33:8b:4a:97:e6:d4:80:5d:f9:96:b9:63:ee:4c:08:31:c2:d0:00:5c"},
		BootInfo: NodeStatusBootInfo{Mode: "efi"},
	}
	if !reflect.DeepEqual(status, want) {
		t.Fatalf("NodeStatus() = %+v,\nwant %+v", status, want)
	}
}

// A fraction PBS cannot compute, NaN, is serialised as null.
func TestNodeStatusTakesNullFractions(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/status", http.StatusOK, `{"data":{"cpu":null,"wait":null,"loadavg":[0,0,0],
		"boot-info":{"mode":"legacy-bios","secureboot":false}}}`)
	status, err := fake.client(t).NodeStatus(context.Background(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if status.CPU != nil || status.Wait != nil || status.BootInfo.Mode != "legacy-bios" || len(status.LoadAvg) != 3 {
		t.Fatalf("NodeStatus() = %+v", status)
	}
}

func TestNodeStatusReportsAPIErrors(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/status", http.StatusForbidden, "permission check failed")
	if _, err := fake.client(t).NodeStatus(context.Background(), "localhost"); !IsForbidden(err) {
		t.Fatalf("err = %v, want a 403", err)
	}
}
