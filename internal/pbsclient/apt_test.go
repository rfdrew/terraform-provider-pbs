package pbsclient

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// testAPTRepositoriesJSON is what PBS 4.2.8 answers for a host with Debian's
// sources, the enterprise repository it ships and a disabled no-subscription
// entry: a file's digest is an array of numbers, the files' digest a hex
// string inside data, empty lists and comments are left out, and so is the
// status of a repository the host does not have.
var testAPTRepositoriesJSON = `{"data":{
"errors":[{"path":"/etc/apt/sources.list.d/broken.list","error":"malformed entry on line 1 - unable to parse"}],
"files":[
 {"path":"/etc/apt/sources.list.d/debian.sources","file-type":"sources","digest":[` + strings.Repeat("7,", 31) + `255],
  "repositories":[{"Types":["deb"],"URIs":["http://deb.debian.org/debian"],"Suites":["trixie","trixie-updates"],
   "Components":["main"],"Options":[{"Key":"Signed-By","Values":["/usr/share/keyrings/debian-archive-keyring.pgp"]}],
   "Comment":" http://snapshot.debian.org/archive/debian/20261027T000000Z\n","FileType":"sources","Enabled":true}]},
 {"path":"/etc/apt/sources.list.d/proxmox.sources","file-type":"sources","digest":[` + strings.Repeat("0,", 31) + `1],
  "repositories":[{"Types":["deb"],"URIs":["http://download.proxmox.com/debian/pbs"],"Suites":["trixie"],
   "Components":["pbs-no-subscription"],"Options":[{"Key":"Signed-By","Values":["/usr/share/keyrings/proxmox-archive-keyring.gpg"]},
   {"Key":"Enabled","Values":["false"]}],"FileType":"sources","Enabled":false},
  {"Types":["deb"],"URIs":["http://ftp.example.org/absolute/"],"Suites":["./"],"FileType":"sources","Enabled":true}]}],
"infos":[{"path":"/etc/apt/sources.list.d/debian.sources","index":0,"kind":"origin","message":"Debian"},
 {"path":"/etc/apt/sources.list.d/debian.sources","index":0,"property":"Suites","kind":"warning","message":"old suite"}],
"standard-repos":[{"handle":"enterprise","name":"Enterprise","description":"Stable."},
 {"handle":"no-subscription","status":false,"name":"No-Subscription","description":"Testing."},
 {"handle":"test","name":"Test","description":"Latest."}],
"digest":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}}`

func TestAPTRepositoryCallsHitTheirRoutes(t *testing.T) {
	const route = "/nodes/pbs1/apt/repositories"
	fake := newFakePBS()
	fake.reply("GET "+route, http.StatusOK, testAPTRepositoriesJSON)
	fake.reply("PUT "+route, http.StatusOK, `{"data":null}`)
	fake.reply("POST "+route, http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	repos, err := c.APTRepositories(ctx, "pbs1")
	if err != nil {
		t.Fatal(err)
	}
	if repos.Digest != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" || len(repos.Files) != 2 ||
		len(repos.Errors) != 1 || len(repos.Infos) != 2 || len(repos.StandardRepos) != 3 {
		t.Fatalf("APTRepositories() = %+v", repos)
	}
	if got := repos.Files[0].DigestHex(); got != strings.Repeat("07", 31)+"ff" {
		t.Errorf("file digest = %q", got)
	}
	if (APTRepositoryFile{}).DigestHex() != "" {
		t.Error("a file without a digest has one")
	}
	debian := repos.Files[0].Repositories[0]
	want := APTRepository{Types: []string{"deb"}, URIs: []string{"http://deb.debian.org/debian"},
		Suites: []string{"trixie", "trixie-updates"}, Components: []string{"main"},
		Options:  []APTRepositoryOption{{Key: "Signed-By", Values: []string{"/usr/share/keyrings/debian-archive-keyring.pgp"}}},
		Comment:  " http://snapshot.debian.org/archive/debian/20261027T000000Z\n",
		FileType: "sources", Enabled: true}
	if !reflect.DeepEqual(debian, want) {
		t.Errorf("entry = %+v, want %+v", debian, want)
	}
	if absolute := repos.Files[1].Repositories[1]; absolute.Components != nil || absolute.Comment != "" {
		t.Errorf("absolute entry = %+v", absolute)
	}
	if s, ok := repos.StandardRepository("no-subscription"); !ok || s.Status == nil || *s.Status {
		t.Errorf("no-subscription = %+v", s)
	}
	if s, ok := repos.StandardRepository("test"); !ok || s.Status != nil {
		t.Errorf("test = %+v", s)
	}
	if _, ok := repos.StandardRepository("ceph-squid-test"); ok {
		t.Error("PBS offers no Ceph repository")
	}
	if info := repos.Infos[1]; info.Property != "Suites" || info.Kind != "warning" || info.Index != 0 {
		t.Errorf("info = %+v", info)
	}
	if e, ok := repos.Repository("/etc/apt/sources.list.d/proxmox.sources", 0); !ok || e.Enabled {
		t.Errorf("Repository(proxmox.sources, 0) = %+v, %t", e, ok)
	}
	for _, index := range []int64{-1, 2} {
		if _, ok := repos.Repository("/etc/apt/sources.list.d/proxmox.sources", index); ok {
			t.Errorf("Repository(proxmox.sources, %d) found an entry", index)
		}
	}
	if msg, ok := repos.FileError("/etc/apt/sources.list.d/broken.list"); !ok || !strings.HasPrefix(msg, "malformed entry") {
		t.Errorf("FileError() = %q, %t", msg, ok)
	}

	// Writes send the digest only when they have one.
	if err := c.AddAPTStandardRepository(ctx, "pbs1", "no-subscription", repos.Digest); err != nil {
		t.Fatal(err)
	}
	if form := fake.lastCall(t, "PUT "+route).form; form.Get("handle") != "no-subscription" || form.Get(DigestParam) != repos.Digest {
		t.Errorf("PUT form = %v", form)
	}
	if err := c.AddAPTStandardRepository(ctx, "pbs1", "test", ""); err != nil {
		t.Fatal(err)
	}
	if form := fake.lastCall(t, "PUT "+route).form; form.Has(DigestParam) {
		t.Errorf("PUT form = %v", form)
	}
	if err := c.SetAPTRepositoryEnabled(ctx, "pbs1", "/etc/apt/sources.list.d/proxmox.sources", 1, false, repos.Digest); err != nil {
		t.Fatal(err)
	}
	form := fake.lastCall(t, "POST "+route).form
	if form.Get("path") != "/etc/apt/sources.list.d/proxmox.sources" || form.Get("index") != "1" ||
		form.Get("enabled") != "false" || form.Get(DigestParam) != repos.Digest {
		t.Errorf("POST form = %v", form)
	}
}

// How standard repositories are told apart, as proxmox-apt does it.
func TestAPTMatcherReferences(t *testing.T) {
	entry := func(uri, suite string, components ...string) APTRepository {
		return APTRepository{Types: []string{"deb"}, URIs: []string{uri}, Suites: []string{suite}, Components: components}
	}
	const download, enterprise = "http://download.proxmox.com/debian/pbs", "https://enterprise.proxmox.com/debian/pbs"
	current := APTMatcher{Suite: "trixie", TestComponents: []string{"pbs-test", "pbstest"}}
	older := APTMatcher{Suite: "trixie", TestComponents: []string{"pbs-test"}}
	pbs3 := APTMatcher{Suite: "bookworm", TestComponents: []string{"pbstest"}}
	for _, tc := range []struct {
		name    string
		matcher APTMatcher
		entry   APTRepository
		want    string
	}{
		{"enterprise", current, entry(enterprise, "trixie", "pbs-enterprise"), APTHandleEnterprise},
		{"no-subscription with a trailing slash", current, entry(download+"/", "trixie", "pbs-no-subscription"), APTHandleNoSubscription},
		{"test", current, entry(download, "trixie", "pbs-test"), APTHandleTest},
		{"legacy test component from 4.2.1", current, entry(download, "trixie", "pbstest"), APTHandleTest},
		{"legacy test component before 4.2.1", older, entry(download, "trixie", "pbstest"), ""},
		{"PBS 3 test component", pbs3, entry(download, "bookworm", "pbstest"), APTHandleTest},
		{"PBS 4 test component on PBS 3", pbs3, entry(download, "bookworm", "pbs-test"), ""},
		{"another suite", current, entry(download, "bookworm", "pbs-no-subscription"), ""},
		{"any suite when unknown", APTMatcher{}, entry(download, "duke", "pbs-no-subscription"), APTHandleNoSubscription},
		{"https for the download server", current, entry("https://download.proxmox.com/debian/pbs", "trixie", "pbs-no-subscription"), ""},
		{"a mirror", current, entry("http://mirror.example.org/debian/pbs", "trixie", "pbs-no-subscription"), ""},
		{"enterprise component on the download server", current, entry(download, "trixie", "pbs-enterprise"), ""},
		{"Proxmox VE", current, entry("http://download.proxmox.com/debian/pve", "trixie", "pve-no-subscription"), ""},
		{"Debian", current, entry("http://deb.debian.org/debian", "trixie", "main"), ""},
		{"source packages", current, APTRepository{Types: []string{"deb-src"}, URIs: []string{download}, Suites: []string{"trixie"},
			Components: []string{"pbs-no-subscription"}}, ""},
		{"one of several components and suites", current, APTRepository{Types: []string{"deb-src", "deb"}, URIs: []string{download},
			Suites: []string{"trixie-updates", "trixie"}, Components: []string{"main", "pbs-test"}}, APTHandleTest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.matcher.Handle(tc.entry); got != tc.want {
				t.Errorf("Handle(%+v) = %q, want %q", tc.entry, got, tc.want)
			}
		})
	}
	if current.References(entry(download, "trixie", "pbs-test"), "ceph-squid-test") {
		t.Error("a Ceph handle matched")
	}
}

func TestNewAPTMatcher(t *testing.T) {
	both := []string{"pbs-test", "pbstest"}
	for _, tc := range []struct {
		version Version
		want    APTMatcher
	}{
		{Version{Version: "4.2", Release: "8"}, APTMatcher{Suite: "trixie", TestComponents: both}},
		{Version{Version: "4.2", Release: "1"}, APTMatcher{Suite: "trixie", TestComponents: both}},
		{Version{Version: "4.2", Release: "0"}, APTMatcher{Suite: "trixie", TestComponents: []string{"pbs-test"}}},
		{Version{Version: "4.0", Release: "22"}, APTMatcher{Suite: "trixie", TestComponents: []string{"pbs-test"}}},
		{Version{Version: "3.4", Release: "9"}, APTMatcher{Suite: "bookworm", TestComponents: []string{"pbstest"}}},
		{Version{Version: "5.0", Release: "1"}, APTMatcher{Suite: "forky", TestComponents: both}},
		{Version{Version: "6.0", Release: "1"}, APTMatcher{TestComponents: both}},
		{Version{Version: "next"}, APTMatcher{TestComponents: both}},
	} {
		if got := NewAPTMatcher(tc.version); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("NewAPTMatcher(%s) = %+v, want %+v", tc.version, got, tc.want)
		}
	}
}

// The first entry in PBS's order is the one PUT enables; enabledOnly skips
// disabled ones.
func TestFindStandardRepository(t *testing.T) {
	entry := func(enabled bool) APTRepository {
		return APTRepository{Types: []string{"deb"}, URIs: []string{"http://download.proxmox.com/debian/pbs"},
			Suites: []string{"trixie"}, Components: []string{"pbs-no-subscription"}, Enabled: enabled}
	}
	repos := APTRepositories{Files: []APTRepositoryFile{
		{Path: "/etc/apt/sources.list.d/debian.sources", Repositories: []APTRepository{{Types: []string{"deb"}}}},
		{Path: "/etc/apt/sources.list.d/proxmox.sources", Repositories: []APTRepository{entry(false), entry(true)}},
	}}
	m := APTMatcher{Suite: "trixie", TestComponents: []string{"pbs-test"}}
	if path, index, ok := repos.FindStandardRepository(m, APTHandleNoSubscription, false); !ok ||
		path != "/etc/apt/sources.list.d/proxmox.sources" || index != 0 {
		t.Errorf("FindStandardRepository() = %q, %d, %t", path, index, ok)
	}
	if _, index, ok := repos.FindStandardRepository(m, APTHandleNoSubscription, true); !ok || index != 1 {
		t.Errorf("FindStandardRepository(enabled only) = %d, %t", index, ok)
	}
	if _, _, ok := repos.FindStandardRepository(m, APTHandleTest, false); ok {
		t.Error("found an entry of the test repository")
	}
}
