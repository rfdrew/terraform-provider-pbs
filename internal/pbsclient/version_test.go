package pbsclient

import (
	"context"
	"net/http"
	"testing"
)

func TestVersionComparison(t *testing.T) {
	v := Version{Version: "4.2", Release: "8"}
	for _, tc := range []struct {
		major, minor, release int
		want                  bool
	}{
		{4, 0, 0, true},
		{4, 2, 8, true},
		{4, 2, 9, false},
		{4, 3, 0, false},
		{3, 4, 99, true},
		{5, 0, 0, false},
	} {
		if got := v.AtLeast(tc.major, tc.minor, tc.release); got != tc.want {
			t.Errorf("4.2.8 AtLeast(%d, %d, %d) = %v", tc.major, tc.minor, tc.release, got)
		}
	}

	// An unparsable version counts as new enough.
	if !(Version{Version: "devel"}).AtLeast(9, 9, 9) {
		t.Error("an unparsable version was too old")
	}
	if _, _, _, ok := (Version{Version: "4.x"}).Parts(); ok {
		t.Error("4.x parsed")
	}
	if (Version{Version: "4.0"}).String() != "4.0" {
		t.Error("String() without a release")
	}
}

func TestServerVersion(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /version", http.StatusOK, `{"data":{"release":"21","repoid":"25a5c896","version":"4.0"}}`)
	v, err := fake.client(t).ServerVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.String() != "4.0.21" || v.RepoID != "25a5c896" {
		t.Fatalf("version = %+v", v)
	}

	fake.reply("GET /version", http.StatusOK, `{"data":{}}`)
	if _, err := fake.client(t).ServerVersion(context.Background()); err == nil {
		t.Fatal("an empty version was accepted")
	}
}

func TestProxyCertificate(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, `{"data":[
		{"filename":"proxy.pem","fingerprint":"2f:f2:f7:e9","subject":"CN=pbs-acc","issuer":"CN=pbs-acc","notbefore":1761600000,"notafter":1824672000,"san":["IP:127.0.0.1","DNS:pbs-acc"],"public-key-type":"rsaEncryption","public-key-bits":4096},
		{"filename":"other.pem","fingerprint":"aa"}]}`)
	cert, err := fake.client(t).ProxyCertificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cert.Fingerprint != "2f:f2:f7:e9" || len(cert.SAN) != 2 || cert.PublicKeyBits != 4096 || cert.NotAfter != 1824672000 {
		t.Fatalf("certificate = %+v", cert)
	}

	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, `{"data":[]}`)
	if _, err := fake.client(t).ProxyCertificate(context.Background()); err == nil {
		t.Fatal("a missing proxy.pem was accepted")
	}
}
