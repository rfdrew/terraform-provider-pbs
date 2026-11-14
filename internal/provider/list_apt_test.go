package provider

import (
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// listedAPTEntries returns the identities of listed APT entries as
// "<file_path>:<index>".
func listedAPTEntries(t *testing.T, results []listedResult) []string {
	t.Helper()
	var entries []string
	for _, result := range results {
		entries = append(entries, fmt.Sprintf("%s:%d", stringAt(t, result.identity, "file_path"), int64At(t, result.identity, "index")))
	}
	return entries
}

// fakeAPTListEntry is an entry of a one-line .list file.
func fakeAPTListEntry(uri, suite string, enabled bool, components ...string) pbsclient.APTRepository {
	return pbsclient.APTRepository{Types: []string{"deb"}, URIs: []string{uri}, Suites: []string{suite},
		Components: components, FileType: "list", Enabled: enabled}
}

// newAPTListHarness serves the files of newAPTHarness, Proxmox's sources
// with the no-subscription repository enabled and the test repository
// disabled, a sources.list of twelve entries — more than ten, which text
// would order 0, 1, 10, 11, 2 — and a file PBS cannot parse.
func newAPTListHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeAPT) {
	t.Helper()
	h, fake, apt := newAPTHarness(t, false)
	apt.addFile(testProxmoxSources, "sources",
		fakeAPTEntry(testDownloadURI, "trixie", true, "pbs-no-subscription"),
		fakeAPTEntry(testDownloadURI, "trixie", false, "pbs-test"))
	var mirrors []pbsclient.APTRepository
	for i := range 12 {
		mirrors = append(mirrors, fakeAPTListEntry(fmt.Sprintf("http://mirror%d.example.org/debian", i), "trixie", i%2 == 0, "main"))
	}
	apt.addFile(fakeAPTSourcesList, "list", mirrors...)
	apt.addError("/etc/apt/sources.list.d/broken.list", "malformed entry on line 1")
	return h, fake, apt
}

func TestAPTRepositoryListResource(t *testing.T) {
	h, fake, _ := newAPTListHarness(t)

	// Every entry of every file PBS parses, ordered by file and then by
	// index, as numbers.
	all := h.listResources(t, "pbs_apt_repository", listRequest{})
	var results []listedResult
	warned := false
	for _, result := range all {
		requireNoProtocolErrors(t, result.diagnostics)
		if result.identity.IsNull() {
			requireProtocolWarningContaining(t, result.diagnostics, "Left out APT source files PBS cannot read")
			requireProtocolWarningContaining(t, result.diagnostics, "/etc/apt/sources.list.d/broken.list (malformed entry on line 1)")
			warned = true
			continue
		}
		results = append(results, result)
	}
	var want []string
	for i := range 12 {
		want = append(want, fmt.Sprintf("%s:%d", fakeAPTSourcesList, i))
	}
	want = append(want, testDebianSources+":0", testDebianSources+":1", testEnterpriseSources+":0",
		testProxmoxSources+":0", testProxmoxSources+":1")
	if got := listedAPTEntries(t, results); !warned || !slices.Equal(got, want) {
		t.Fatalf("listed %q, warned %v; want %q", got, warned, want)
	}
	for _, result := range results {
		if node := stringAt(t, result.identity, "node"); node != "localhost" {
			t.Fatalf("listed node %q", node)
		}
	}
	for i, wantName := range map[int]string{
		0:  "/etc/apt/sources.list:0 — deb http://mirror0.example.org/debian trixie main",
		11: "/etc/apt/sources.list:11 — deb http://mirror11.example.org/debian trixie main (disabled)",
		12: testDebianSources + ":0 — deb http://deb.debian.org/debian trixie trixie-updates main",
		16: testProxmoxSources + ":1 — deb " + testDownloadURI + " trixie pbs-test (disabled)",
	} {
		if results[i].displayName != wantName {
			t.Errorf("display name %q, want %q", results[i].displayName, wantName)
		}
	}
	reads := fake.count("GET /nodes/localhost/apt/repositories")

	// With resources, each is what importing it gives, and the generated
	// configuration plans nothing.
	results = h.listedObjects(t, "pbs_apt_repository", listRequest{includeResource: true})
	if got := listedAPTEntries(t, results); !slices.Equal(got, want) {
		t.Fatalf("listed %q with resources", got)
	}
	if fake.count("GET /nodes/localhost/apt/repositories") != reads+1+len(want) {
		t.Fatalf("a list with resources read the files %d times", fake.count("GET /nodes/localhost/apt/repositories")-reads)
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_apt_repository", result)
	}
	if boolAt(t, results[16].resource, "enabled") || stringAt(t, results[16].resource, "components", 0) != "pbs-test" ||
		stringAt(t, results[11].resource, "file_type") != "list" || !isNullAt(t, results[0].resource, "comment") ||
		stringAt(t, results[12].resource, "comment") != " http://snapshot.debian.org/archive/debian/20261027T000000Z" {
		t.Fatalf("listed states: %s, %s, %s", results[16].resource, results[11].resource, results[12].resource)
	}

	if got := h.listedObjects(t, "pbs_apt_repository", listRequest{limit: 13}); len(got) != 13 || stringAt(t, got[12].identity, "file_path") != testDebianSources {
		t.Fatalf("a limit of 13 listed %q", listedAPTEntries(t, got))
	}
}

// node selects the node, which the results name as given; entries that
// disappear between the listing and their read are left out; a failed
// listing fails the list block.
func TestAPTRepositoryListResourceNodeAndErrors(t *testing.T) {
	h, fake, apt := newAPTHarness(t, false)
	apt.addFile(testProxmoxSources, "sources", fakeAPTEntry(testDownloadURI, "trixie", true, "pbs-no-subscription"))
	listed := false
	fake.handle("GET /nodes/pbs1/apt/repositories", func(w http.ResponseWriter, req *http.Request) {
		apt.list(w, req)
		if !listed {
			listed = true
			apt.removeFile(testProxmoxSources)
		}
	})

	results := h.listedObjects(t, "pbs_apt_repository", listRequest{config: map[string]any{"node": "pbs1"}, includeResource: true})
	want := []string{testDebianSources + ":0", testDebianSources + ":1", testEnterpriseSources + ":0"}
	if got := listedAPTEntries(t, results); !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	for _, result := range results {
		if node := stringAt(t, result.identity, "node"); node != "pbs1" {
			t.Fatalf("listed node %q", node)
		}
		h.requireListedLikeImport(t, "pbs_apt_repository", result)
	}

	fake.reply("GET /nodes/localhost/apt/repositories", http.StatusForbidden, "permission check failed")
	all := h.listResources(t, "pbs_apt_repository", listRequest{})
	if len(all) != 1 {
		t.Fatalf("got %d results", len(all))
	}
	requireProtocolErrorContaining(t, all[0].diagnostics, "Unable to read the PBS APT repositories")
	requireProtocolErrorContaining(t, all[0].diagnostics, aptReadPrivilege)
}

func TestAPTStandardRepositoryListResource(t *testing.T) {
	h, _, _ := newAPTListHarness(t)

	// The standard repositories an entry references, enabled or not.
	results := h.listedObjects(t, "pbs_apt_standard_repository", listRequest{})
	if got, want := listedIdentities(t, results, "handle"), []string{"enterprise", "no-subscription", "test"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	for i, want := range []string{"enterprise — Enterprise, enabled", "no-subscription — No-Subscription, enabled", "test — Test, disabled"} {
		if results[i].displayName != want {
			t.Errorf("display name %q, want %q", results[i].displayName, want)
		}
		if node := stringAt(t, results[i].identity, "node"); node != "localhost" {
			t.Fatalf("listed node %q", node)
		}
	}

	results = h.listedObjects(t, "pbs_apt_standard_repository", listRequest{includeResource: true})
	if len(results) != 3 {
		t.Fatalf("listed %d standard repositories with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_apt_standard_repository", result)
	}
	if boolAt(t, results[2].resource, "enabled") || stringAt(t, results[2].resource, "file_path") != testProxmoxSources ||
		int64At(t, results[2].resource, "index") != 1 {
		t.Fatalf("listed test repository: %s", results[2].resource)
	}

	// A repository no entry references is not listed.
	h, _, _ = newAPTHarness(t, false)
	results = h.listedObjects(t, "pbs_apt_standard_repository", listRequest{includeResource: true})
	if got := listedIdentities(t, results, "handle"); !slices.Equal(got, []string{"enterprise"}) {
		t.Fatalf("listed %q", got)
	}
	h.requireListedLikeImport(t, "pbs_apt_standard_repository", results[0])
}

// node selects the node; a failed listing fails the list block.
func TestAPTStandardRepositoryListResourceNodeAndErrors(t *testing.T) {
	h, fake, apt := newAPTHarness(t, false)
	fake.handle("GET /nodes/pbs1/apt/repositories", apt.list)
	results := h.listedObjects(t, "pbs_apt_standard_repository", listRequest{config: map[string]any{"node": "pbs1"}, includeResource: true})
	if len(results) != 1 || stringAt(t, results[0].identity, "node") != "pbs1" || stringAt(t, results[0].identity, "handle") != "enterprise" {
		t.Fatalf("listed %v", results)
	}
	h.requireListedLikeImport(t, "pbs_apt_standard_repository", results[0])

	fake.reply("GET /nodes/localhost/apt/repositories", http.StatusForbidden, "permission check failed")
	all := h.listResources(t, "pbs_apt_standard_repository", listRequest{})
	if len(all) != 1 {
		t.Fatalf("got %d results", len(all))
	}
	requireProtocolErrorContaining(t, all[0].diagnostics, "Unable to read the PBS APT repositories")
	requireProtocolErrorContaining(t, all[0].diagnostics, aptReadPrivilege)
}
