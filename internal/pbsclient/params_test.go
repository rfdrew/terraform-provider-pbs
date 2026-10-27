package pbsclient

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAddDeleteRepeatsTheKey(t *testing.T) {
	params := url.Values{"comment": {"x"}}
	AddDelete(params, "port", "fingerprint")
	if got := params.Encode(); got != "comment=x&delete=fingerprint&delete=port" {
		t.Fatalf("Encode() = %q", got)
	}
	if FormatBool(true) != "true" || FormatBool(false) != "false" {
		t.Fatal("FormatBool")
	}
}

func TestParsePropertyString(t *testing.T) {
	tests := []struct {
		in         string
		defaultKey string
		want       PropertyString
	}{
		{"chunk-order=inode,sync-level=filesystem", "", PropertyString{"chunk-order": "inode", "sync-level": "filesystem"}},
		{" type = s3 , client=minio,bucket=pbs ", "", PropertyString{"type": "s3", "client": "minio", "bucket": "pbs"}},
		{`type=read-only,message="moving disks, back soon"`, "", PropertyString{"type": "read-only", "message": "moving disks, back soon"}},
		{`message="say \"hi\" \\ bye"`, "", PropertyString{"message": `say "hi" \ bye`}},
		{"pbs.example.com,alias=_acme.example.com", "domain", PropertyString{"domain": "pbs.example.com", "alias": "_acme.example.com"}},
		{"", "", PropertyString{}},
	}
	for _, tc := range tests {
		got, err := ParsePropertyString(tc.in, tc.defaultKey)
		if err != nil {
			t.Errorf("ParsePropertyString(%q) error = %v", tc.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParsePropertyString(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	for _, bad := range []string{"bare", "a=1,a=2", `a="open`, `a="x"y`, "=1", `a="x\`} {
		if _, err := ParsePropertyString(bad, ""); err == nil {
			t.Errorf("ParsePropertyString(%q) accepted it", bad)
		}
	}
}

func TestPropertyStringRoundTrip(t *testing.T) {
	p := PropertyString{"type": "read-only", "message": `moving "disks", soon`, "empty": ""}
	formatted := p.Format("")
	if formatted != `empty="",message="moving \"disks\", soon",type=read-only` {
		t.Fatalf("Format() = %q", formatted)
	}
	back, err := ParsePropertyString(formatted, "")
	if err != nil || !reflect.DeepEqual(back, p) {
		t.Fatalf("round trip = %v, %v", back, err)
	}

	withDefault := PropertyString{"domain": "pbs.example.com", "plugin": "cf"}
	if got := withDefault.Format("domain"); got != "pbs.example.com,plugin=cf" {
		t.Fatalf("Format(domain) = %q", got)
	}
}

func TestParseByteSize(t *testing.T) {
	for in, want := range map[string]uint64{
		"500":      500,
		"500B":     500,
		"64KiB":    64 << 10,
		"10MiB":    10 << 20,
		"10 MiB":   10 << 20,
		"10M":      10 << 20,
		"1.5GB":    1_500_000_000,
		"1.5 gib":  3 << 29,
		"2TB":      2e12,
		"0":        0,
		" 1KB ":    1000,
		"0.5 KiB":  512,
		"1048576B": 1 << 20,
	} {
		got, err := ParseByteSize(in)
		if err != nil || got != want {
			t.Errorf("ParseByteSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "MiB", "10 XB", "-1", "1.2.3MB", "ten"} {
		if _, err := ParseByteSize(bad); err == nil {
			t.Errorf("ParseByteSize(%q) accepted it", bad)
		}
	}
	if !SameByteSize("10MiB", "10485760") || !SameByteSize("1 GB", "1000MB") || SameByteSize("1MiB", "1MB") || SameByteSize("x", "y") {
		t.Fatal("SameByteSize")
	}
}

func TestRetryOnDigestConflict(t *testing.T) {
	c := newFakePBS().client(t)
	conflict := apiError(400, "detected modified configuration - file changed by other user? Try again.")

	attempts := 0
	err := c.RetryOnDigestConflict(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return conflict
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("err = %v after %d attempts", err, attempts)
	}

	attempts = 0
	err = c.RetryOnDigestConflict(context.Background(), func() error { attempts++; return conflict })
	if !IsDigestConflict(err) || attempts != digestRetries {
		t.Fatalf("err = %v after %d attempts, want a conflict after %d", err, attempts, digestRetries)
	}

	other := errors.New("other")
	attempts = 0
	err = c.RetryOnDigestConflict(context.Background(), func() error { attempts++; return other })
	if !errors.Is(err, other) || attempts != 1 {
		t.Fatalf("err = %v after %d attempts", err, attempts)
	}
}

func TestWithConfigLockSerialisesOneFile(t *testing.T) {
	c := newFakePBS().client(t)
	var inside, maxInside atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.WithConfigLock(ConfigACL, func() error {
				n := inside.Add(1)
				for {
					m := maxInside.Load()
					if n <= m || maxInside.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				inside.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()
	if maxInside.Load() != 1 {
		t.Fatalf("%d writers held the lock at once", maxInside.Load())
	}

	// Different files do not block each other.
	done := make(chan struct{})
	_ = c.WithConfigLock(ConfigACL, func() error {
		go func() {
			_ = c.WithConfigLock(ConfigRemotes, func() error { return nil })
			close(done)
		}()
		select {
		case <-done:
			return nil
		case <-time.After(5 * time.Second):
			t.Error("a lock on remote.cfg waited for acl.cfg")
			return nil
		}
	})
}
