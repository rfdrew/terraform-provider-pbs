package provider

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// The files of a PBS 4 host as installed from the ISO, or from packages on
// Debian trixie: Debian's own sources, with a stanza of two suites, and the
// enterprise repository the package ships.
const (
	testDebianSources     = "/etc/apt/sources.list.d/debian.sources"
	testEnterpriseSources = "/etc/apt/sources.list.d/pbs-enterprise.sources"
	testProxmoxSources    = "/etc/apt/sources.list.d/proxmox.sources"
	testEnterpriseURI     = "https://enterprise.proxmox.com/debian/pbs"
	testDownloadURI       = "http://download.proxmox.com/debian/pbs"
)

// fakeVersion420JSON is what PBS 4.2.0 answers GET /version with: the last
// release before proxmox-apt 1.0.
const fakeVersion420JSON = `{"data":{"release":"0","repoid":"035c44989","version":"4.2"}}`

// newAPTHarness serves a PBS 4.2.8 host with Debian's sources and the
// enterprise repository; legacyRelease serves PBS 4.2.0 instead.
func newAPTHarness(t *testing.T, legacyRelease bool) (*protocolHarness, *fakePBS, *fakeAPT) {
	t.Helper()
	fake := newFakePBS()
	if legacyRelease {
		fake.reply("GET /version", http.StatusOK, fakeVersion420JSON)
	}
	apt := newFakeAPT(fake, !legacyRelease)
	debian := fakeAPTEntry("http://deb.debian.org/debian", "trixie", true, "main")
	debian.Suites = []string{"trixie", "trixie-updates"}
	debian.Comment = " http://snapshot.debian.org/archive/debian/20261027T000000Z\n"
	apt.addFile(testDebianSources, "sources", debian, fakeAPTEntry("http://deb.debian.org/debian-security", "trixie-security", true, "main"))
	apt.addFile(testEnterpriseSources, "sources", fakeAPTEntry(testEnterpriseURI, "trixie", true, "pbs-enterprise"))
	return newProtocolHarness(t, fake), fake, apt
}

func aptRepositoryConfig(t *testing.T, h *protocolHarness, filePath string, index int, enabled bool) tftypes.Value {
	t.Helper()
	return h.resourceValue(t, "pbs_apt_repository", map[string]any{"file_path": filePath, "index": index, "enabled": enabled})
}

func aptStandardConfig(t *testing.T, h *protocolHarness, handle string) tftypes.Value {
	t.Helper()
	return h.resourceValue(t, "pbs_apt_standard_repository", map[string]any{"handle": handle})
}

func TestAPTSchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, NewAPTRepositoryResource())
	requireValidResourceSchema(t, NewAPTStandardRepositoryResource())
	requireValidDataSourceSchema(t, NewAPTRepositoriesDataSource())
}

// The requester's case: the enterprise repository off on a host without a
// subscription, then on again, a change outside Terraform, a conflict, and
// a destroy that leaves the entry alone.
func TestAPTRepositoryResourceLifecycle(t *testing.T) {
	h, fake, apt := newAPTHarness(t, false)
	const post = "POST /nodes/localhost/apt/repositories"

	config := aptRepositoryConfig(t, h, testEnterpriseSources, 0, false)
	planned := h.plan(t, "pbs_apt_repository", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	plannedState := h.decodeResource(t, "pbs_apt_repository", planned.PlannedState)
	if got := stringAt(t, plannedState, "id"); got != "localhost,"+testEnterpriseSources+",0" {
		t.Fatalf("planned id = %q", got)
	}
	inst := h.create(t, "pbs_apt_repository", config)
	if e, _ := apt.entry(testEnterpriseSources, 0); e.Enabled {
		t.Fatal("the enterprise entry is still enabled")
	}
	call := fake.lastCall(t, post)
	if call.form.Get("path") != testEnterpriseSources || call.form.Get("index") != "0" ||
		call.form.Get("enabled") != "false" || len(call.form.Get("digest")) != 64 {
		t.Fatalf("POST form = %v", call.form)
	}
	if boolAt(t, inst.state, "enabled") || stringAt(t, inst.state, "file_type") != "sources" ||
		stringAt(t, inst.state, "uris", 0) != testEnterpriseURI || stringAt(t, inst.state, "suites", 0) != "trixie" ||
		stringAt(t, inst.state, "components", 0) != "pbs-enterprise" || stringAt(t, inst.state, "package_types", 0) != "deb" ||
		!isNullAt(t, inst.state, "comment") || stringAt(t, inst.state, "node") != "localhost" {
		t.Fatalf("state = %s", inst.state)
	}
	identity := h.identityValue(t, "pbs_apt_repository", inst.identity)
	if stringAt(t, identity, "node") != "localhost" || stringAt(t, identity, "file_path") != testEnterpriseSources ||
		int64At(t, identity, "index") != 0 {
		t.Fatalf("identity = %s", identity)
	}
	requireEmptyPlan(t, h, inst, config)

	// On again: one POST.
	posts := fake.count(post)
	config = aptRepositoryConfig(t, h, testEnterpriseSources, 0, true)
	inst = h.update(t, inst, config)
	if e, _ := apt.entry(testEnterpriseSources, 0); !e.Enabled || fake.count(post) != posts+1 {
		t.Fatalf("entry = %+v after %d POSTs", e, fake.count(post)-posts)
	}
	requireEmptyPlan(t, h, inst, config)

	// Disabled outside Terraform: the refresh shows it, and the next apply
	// enables it again, past a digest conflict.
	apt.setEnabled(testEnterpriseSources, 0, false)
	inst = h.refresh(t, inst)
	if boolAt(t, inst.state, "enabled") {
		t.Fatal("the refresh missed the change")
	}
	apt.staleWrites = 1
	inst = h.update(t, inst, config)
	if e, _ := apt.entry(testEnterpriseSources, 0); !e.Enabled {
		t.Fatal("the conflict was not retried")
	}

	// Destroy changes nothing.
	posts = fake.count(post)
	h.destroy(t, inst)
	if e, _ := apt.entry(testEnterpriseSources, 0); !e.Enabled || fake.count(post) != posts {
		t.Fatal("destroy changed the entry")
	}
}

// An entry that is as the configuration wants it already is taken over
// without a write.
func TestAPTRepositoryResourceTakesOverWithoutWrite(t *testing.T) {
	h, fake, _ := newAPTHarness(t, false)
	inst := h.create(t, "pbs_apt_repository", aptRepositoryConfig(t, h, testDebianSources, 0, true))
	if fake.count("POST /nodes/localhost/apt/repositories") != 0 {
		t.Fatal("taking over an enabled entry wrote it")
	}
	if lengthAt(t, inst.state, "suites") != 2 || stringAt(t, inst.state, "suites", 1) != "trixie-updates" ||
		stringAt(t, inst.state, "comment") != " http://snapshot.debian.org/archive/debian/20261027T000000Z" {
		t.Fatalf("state = %s", inst.state)
	}
}

// Someone adds an entry above the managed one. Between plan and apply, the
// update refuses to change the entry the index points to now. A refresh
// warns, says where the managed entry went and keeps it in state, so that
// a plain apply — which refreshes first — refuses too. Setting index to the
// new position replaces the resource, which takes the entry over again.
func TestAPTRepositoryResourceIndexShift(t *testing.T) {
	h, fake, apt := newAPTHarness(t, false)
	const post = "POST /nodes/localhost/apt/repositories"
	apt.addFile(testProxmoxSources, "sources",
		fakeAPTEntry(testDownloadURI, "trixie", true, "pbs-no-subscription"),
		fakeAPTEntry(testDownloadURI, "trixie", false, "pbs-test"))
	inst := h.create(t, "pbs_apt_repository", aptRepositoryConfig(t, h, testProxmoxSources, 1, false))

	apt.insert(testProxmoxSources, 0, fakeAPTEntry("http://mirror.example.org/pbs", "trixie", true, "pbs-no-subscription"))
	config := aptRepositoryConfig(t, h, testProxmoxSources, 1, true)
	planned := h.plan(t, "pbs_apt_repository", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, "pbs_apt_repository", inst, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "PBS APT repository moved")
	requireProtocolErrorContaining(t, applied.Diagnostics, "That entry is at index 2 now")

	resp := h.read(t, inst)
	requireNoProtocolErrors(t, resp.Diagnostics)
	requireProtocolWarningContaining(t, resp.Diagnostics, "The state keeps the entry it records")
	inst = &resourceInstance{typeName: inst.typeName, state: h.decodeResource(t, inst.typeName, resp.NewState), identity: resp.NewIdentity}
	if stringAt(t, inst.state, "components", 0) != "pbs-test" || boolAt(t, inst.state, "enabled") {
		t.Fatalf("refreshed state = %s", inst.state)
	}
	planned = h.plan(t, "pbs_apt_repository", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied = h.apply(t, "pbs_apt_repository", inst, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "PBS APT repository moved")
	if fake.count(post) != 0 {
		t.Fatal("an update changed the entry the index points to now")
	}
	if e, _ := apt.entry(testProxmoxSources, 1); !e.Enabled || e.Components[0] != "pbs-no-subscription" {
		t.Fatalf("entry 1 = %+v", e)
	}

	config = aptRepositoryConfig(t, h, testProxmoxSources, 2, true)
	if planned := h.plan(t, "pbs_apt_repository", inst, config); len(planned.RequiresReplace) != 1 {
		t.Fatalf("requires replace = %v", planned.RequiresReplace)
	}
	h.destroy(t, inst)
	inst = h.create(t, "pbs_apt_repository", config)
	if e, _ := apt.entry(testProxmoxSources, 2); !e.Enabled || e.Components[0] != "pbs-test" {
		t.Fatalf("entry 2 = %+v", e)
	}
	requireEmptyPlan(t, h, inst, config)
}

// What PBS changes in an entry on its own does not count as another entry:
// the comment, which it reformats when it rewrites a file, and pbstest,
// which PBS 4.2.1 and later rewrite to pbs-test.
func TestAPTRepositoryResourceSameEntryAfterRewrite(t *testing.T) {
	h, fake, apt := newAPTHarness(t, false)
	legacy := fakeAPTEntry(testDownloadURI, "trixie", false, "pbstest")
	legacy.Comment = " test # since PBS 3\n"
	apt.addFile(testProxmoxSources, "sources", legacy)
	inst := h.create(t, "pbs_apt_repository", aptRepositoryConfig(t, h, testProxmoxSources, 0, false))

	rewritten := fakeAPTEntry(testDownloadURI, "trixie", false, "pbs-test")
	rewritten.Comment = " since PBS 3\n test # since PBS 3\n"
	apt.setEntry(testProxmoxSources, 0, rewritten)
	inst = h.refresh(t, inst)
	if stringAt(t, inst.state, "components", 0) != "pbs-test" {
		t.Fatalf("refreshed state = %s", inst.state)
	}
	apt.setEntry(testProxmoxSources, 0, legacy)
	inst = h.update(t, inst, aptRepositoryConfig(t, h, testProxmoxSources, 0, true))
	if e, _ := apt.entry(testProxmoxSources, 0); !e.Enabled || fake.count("POST /nodes/localhost/apt/repositories") != 1 {
		t.Fatalf("entry = %+v", e)
	}
}

// When reading the entry back after a write fails, the change is recorded
// with a warning: it took effect.
func TestAPTRepositoryResourceReadBackFails(t *testing.T) {
	h, _, apt := newAPTHarness(t, false)
	apt.failReadAfterWrite = true
	config := aptRepositoryConfig(t, h, testEnterpriseSources, 0, false)
	planned := h.plan(t, "pbs_apt_repository", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, "pbs_apt_repository", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "reading it back failed")
	state := h.decodeResource(t, "pbs_apt_repository", applied.NewState)
	if boolAt(t, state, "enabled") || stringAt(t, state, "components", 0) != "pbs-enterprise" {
		t.Fatalf("state = %s", state)
	}
	if e, _ := apt.entry(testEnterpriseSources, 0); e.Enabled {
		t.Fatal("the entry is still enabled")
	}
}

// An entry that is not there fails the create with what is there instead;
// one that goes away is removed from the state; a file PBS cannot parse is
// an error.
func TestAPTRepositoryResourceMissingEntry(t *testing.T) {
	h, _, apt := newAPTHarness(t, false)
	for _, tc := range []struct {
		filePath string
		index    int
		want     string
	}{
		{testEnterpriseSources, 3, "has no entry at index 3: its entries are at indexes 0 to 0"},
		{testProxmoxSources, 0, "has no APT source file " + testProxmoxSources},
	} {
		config := aptRepositoryConfig(t, h, tc.filePath, tc.index, false)
		planned := h.plan(t, "pbs_apt_repository", nil, config)
		requireNoProtocolErrors(t, planned.Diagnostics)
		applied := h.apply(t, "pbs_apt_repository", nil, config, planned)
		requireProtocolErrorContaining(t, applied.Diagnostics, tc.want)
	}

	inst := h.create(t, "pbs_apt_repository", aptRepositoryConfig(t, h, testEnterpriseSources, 0, false))
	apt.removeFile(testEnterpriseSources)
	resp := h.read(t, inst)
	requireNoProtocolErrors(t, resp.Diagnostics)
	requireProtocolWarningContaining(t, resp.Diagnostics, "It is removed from the state")
	if !h.decodeResource(t, "pbs_apt_repository", resp.NewState).IsNull() {
		t.Fatal("the gone entry stayed in state")
	}

	apt.addError(testEnterpriseSources, "malformed entry in stanza 1 - missing URI(s)")
	resp = h.read(t, inst)
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS cannot parse "+testEnterpriseSources)
}

func TestAPTRepositoryResourceImport(t *testing.T) {
	h, _, apt := newAPTHarness(t, false)
	apt.setEnabled(testEnterpriseSources, 0, false)

	inst := h.importByID(t, "pbs_apt_repository", "localhost,"+testEnterpriseSources+",0")
	if boolAt(t, inst.state, "enabled") || stringAt(t, inst.state, "components", 0) != "pbs-enterprise" ||
		stringAt(t, inst.state, "id") != "localhost,"+testEnterpriseSources+",0" {
		t.Fatalf("imported state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, aptRepositoryConfig(t, h, testEnterpriseSources, 0, false))

	inst = h.importByIdentity(t, "pbs_apt_repository", map[string]any{"node": "localhost", "file_path": testDebianSources, "index": 1})
	if stringAt(t, inst.state, "uris", 0) != "http://deb.debian.org/debian-security" {
		t.Fatalf("imported state = %s", inst.state)
	}

	for _, id := range []string{testEnterpriseSources + ",0", "localhost," + testEnterpriseSources + ",-1",
		"localhost,/etc/apt/other.list,0", "localhost," + testEnterpriseSources + ",first"} {
		resp := h.importResource(t, "pbs_apt_repository", id, nil)
		requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS APT repository by <node>,<file path>,<index>")
	}
	identity := &tfprotov6.ResourceIdentityData{IdentityData: dynamicValue(t, tfValue(t, h.identityType(t, "pbs_apt_repository"),
		map[string]any{"node": "localhost", "file_path": "/etc/apt/other.list", "index": 0}))}
	resp := h.importResource(t, "pbs_apt_repository", "", identity)
	requireProtocolErrorContaining(t, resp.Diagnostics, `got "localhost,/etc/apt/other.list,0"`)
}

func TestAPTResourceValidation(t *testing.T) {
	h, _, _ := newAPTHarness(t, false)
	for _, filePath := range []string{"/etc/apt/sources.list.d/pbs.conf", "/etc/apt/preferences", "sources.list",
		"/etc/apt/sources.list.d/.hidden.list", "/etc/apt/sources.list.d/sub/x.list"} {
		requireProtocolErrorContaining(t, h.validateResource(t, "pbs_apt_repository",
			aptRepositoryConfig(t, h, filePath, 0, true)), "must be /etc/apt/sources.list or a .list or .sources file")
	}
	for _, filePath := range []string{"/etc/apt/sources.list", testEnterpriseSources, "/etc/apt/sources.list.d/my_mirror-1.list"} {
		requireNoProtocolErrors(t, h.validateResource(t, "pbs_apt_repository", aptRepositoryConfig(t, h, filePath, 0, true)))
	}
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_apt_repository",
		aptRepositoryConfig(t, h, testEnterpriseSources, -1, true)), "at least 0")
	for _, handle := range []string{"ceph-squid-enterprise", "pbs-no-subscription", "No-Subscription"} {
		requireProtocolErrorContaining(t, h.validateResource(t, "pbs_apt_standard_repository",
			aptStandardConfig(t, h, handle)), "value must be one of")
	}
}

// A standard repository the host does not have: PBS appends its entry, and
// the resource tells where, for a pbs_apt_repository that disables it.
// Destroying it disables the entry, which stays.
func TestAPTStandardRepositoryResourceLifecycle(t *testing.T) {
	h, fake, apt := newAPTHarness(t, false)
	const put = "PUT /nodes/localhost/apt/repositories"

	config := aptStandardConfig(t, h, "no-subscription")
	inst := h.create(t, "pbs_apt_standard_repository", config)
	if call := fake.lastCall(t, put); call.form.Get("handle") != "no-subscription" || len(call.form.Get("digest")) != 64 {
		t.Fatalf("PUT form = %v", call.form)
	}
	if e, ok := apt.entry(testProxmoxSources, 0); !ok || !e.Enabled || e.Components[0] != "pbs-no-subscription" {
		t.Fatalf("entry = %+v, %t", e, ok)
	}
	if stringAt(t, inst.state, "id") != "localhost,no-subscription" || stringAt(t, inst.state, "file_path") != testProxmoxSources ||
		int64At(t, inst.state, "index") != 0 || !boolAt(t, inst.state, "enabled") ||
		stringAt(t, inst.state, "name") != "No-Subscription" || stringAt(t, inst.state, "description") == "" {
		t.Fatalf("state = %s", inst.state)
	}
	identity := h.identityValue(t, "pbs_apt_standard_repository", inst.identity)
	if stringAt(t, identity, "node") != "localhost" || stringAt(t, identity, "handle") != "no-subscription" {
		t.Fatalf("identity = %s", identity)
	}
	requireEmptyPlan(t, h, inst, config)

	// A pbs_apt_repository disables the entry by the standard repository's
	// file_path and index; the standard repository stays, disabled.
	repo := h.create(t, "pbs_apt_repository", aptRepositoryConfig(t, h, testProxmoxSources, 0, false))
	if boolAt(t, repo.state, "enabled") {
		t.Fatalf("repository state = %s", repo.state)
	}
	inst = h.refresh(t, inst)
	if boolAt(t, inst.state, "enabled") || stringAt(t, inst.state, "file_path") != testProxmoxSources {
		t.Fatalf("refreshed state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)

	// Creating it again while its entry is disabled enables that entry
	// rather than adding another.
	h.destroy(t, inst)
	inst = h.create(t, "pbs_apt_standard_repository", config)
	if apt.entries(testProxmoxSources) != 1 || !boolAt(t, inst.state, "enabled") {
		t.Fatalf("%d entries, state = %s", apt.entries(testProxmoxSources), inst.state)
	}

	// Destroying it disables the entry, with the digest.
	h.destroy(t, inst)
	if e, _ := apt.entry(testProxmoxSources, 0); e.Enabled {
		t.Fatal("destroy left the repository enabled")
	}
	if len(fake.lastCall(t, "POST /nodes/localhost/apt/repositories").form.Get("digest")) != 64 {
		t.Fatal("the POST carried no digest")
	}

	// An entry that goes away takes the resource out of the state.
	inst = h.create(t, "pbs_apt_standard_repository", config)
	apt.removeFile(testProxmoxSources)
	resp := h.read(t, inst)
	requireNoProtocolErrors(t, resp.Diagnostics)
	requireProtocolWarningContaining(t, resp.Diagnostics, "the next apply adds it again")
	if !h.decodeResource(t, "pbs_apt_standard_repository", resp.NewState).IsNull() {
		t.Fatal("the gone repository stayed in state")
	}
}

// The enterprise repository is there and enabled: creating the resource
// takes it over and writes nothing new.
func TestAPTStandardRepositoryResourceTakesOver(t *testing.T) {
	h, _, apt := newAPTHarness(t, false)
	inst := h.create(t, "pbs_apt_standard_repository", aptStandardConfig(t, h, "enterprise"))
	if apt.entries(testEnterpriseSources) != 1 || stringAt(t, inst.state, "file_path") != testEnterpriseSources ||
		int64At(t, inst.state, "index") != 0 || !boolAt(t, inst.state, "enabled") {
		t.Fatalf("state = %s", inst.state)
	}
}

// Changing the handle replaces the resource: the old repository is
// disabled, the new one added.
func TestAPTStandardRepositoryResourceReplace(t *testing.T) {
	h, _, apt := newAPTHarness(t, false)
	inst := h.create(t, "pbs_apt_standard_repository", aptStandardConfig(t, h, "test"))
	config := aptStandardConfig(t, h, "no-subscription")
	planned := h.plan(t, "pbs_apt_standard_repository", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 1 || planned.RequiresReplace[0].String() != tftypes.NewAttributePath().WithAttributeName("handle").String() {
		t.Fatalf("requires replace = %v", planned.RequiresReplace)
	}
	// Terraform destroys, then creates.
	h.destroy(t, inst)
	inst = h.create(t, "pbs_apt_standard_repository", config)
	test, _ := apt.entry(testProxmoxSources, 0)
	noSubscription, _ := apt.entry(testProxmoxSources, 1)
	if test.Enabled || test.Components[0] != "pbs-test" || !noSubscription.Enabled || int64At(t, inst.state, "index") != 1 {
		t.Fatalf("test = %+v, no-subscription = %+v, state = %s", test, noSubscription, inst.state)
	}
}

// Destroying disables every enabled entry of the repository, and leaves
// the others alone.
func TestAPTStandardRepositoryResourceDestroyDisablesEveryEntry(t *testing.T) {
	h, fake, apt := newAPTHarness(t, false)
	list := fakeAPTEntry(testDownloadURI+"/", "trixie", true, "pbs-no-subscription")
	list.FileType = "list"
	apt.addFile("/etc/apt/sources.list", "list", list)
	apt.addFile(testProxmoxSources, "sources",
		fakeAPTEntry(testDownloadURI, "trixie", true, "pbs-no-subscription"),
		fakeAPTEntry(testDownloadURI, "bookworm", true, "pbs-no-subscription"))
	inst := h.create(t, "pbs_apt_standard_repository", aptStandardConfig(t, h, "no-subscription"))
	if stringAt(t, inst.state, "file_path") != "/etc/apt/sources.list" {
		t.Fatalf("state = %s", inst.state)
	}
	h.destroy(t, inst)
	first, _ := apt.entry("/etc/apt/sources.list", 0)
	second, _ := apt.entry(testProxmoxSources, 0)
	bookworm, _ := apt.entry(testProxmoxSources, 1)
	if first.Enabled || second.Enabled || !bookworm.Enabled || fake.count("POST /nodes/localhost/apt/repositories") != 2 {
		t.Fatalf("entries = %+v, %+v, %+v", first, second, bookworm)
	}
}

// When reading the repository back after PUT fails, it is recorded with a
// warning: where its entry is when PBS enabled one it had, null when PBS
// appended one; the next refresh fills it in.
func TestAPTStandardRepositoryResourceReadBackFails(t *testing.T) {
	h, _, apt := newAPTHarness(t, false)
	for _, tc := range []struct {
		handle, filePath string
	}{
		{"enterprise", testEnterpriseSources},
		{"no-subscription", ""},
	} {
		apt.failReadAfterWrite = true
		config := aptStandardConfig(t, h, tc.handle)
		planned := h.plan(t, "pbs_apt_standard_repository", nil, config)
		requireNoProtocolErrors(t, planned.Diagnostics)
		applied := h.apply(t, "pbs_apt_standard_repository", nil, config, planned)
		requireNoProtocolErrors(t, applied.Diagnostics)
		requireProtocolWarningContaining(t, applied.Diagnostics, "reading it back failed")
		inst := &resourceInstance{typeName: "pbs_apt_standard_repository",
			state: h.decodeResource(t, "pbs_apt_standard_repository", applied.NewState), identity: applied.NewIdentity}
		if !boolAt(t, inst.state, "enabled") || stringAt(t, inst.state, "name") == "" {
			t.Fatalf("%s: state = %s", tc.handle, inst.state)
		}
		if tc.filePath == "" {
			if !isNullAt(t, inst.state, "file_path") || !isNullAt(t, inst.state, "index") {
				t.Fatalf("%s: state = %s", tc.handle, inst.state)
			}
			inst = h.refresh(t, inst)
			if stringAt(t, inst.state, "file_path") != testProxmoxSources || int64At(t, inst.state, "index") != 0 {
				t.Fatalf("%s: refreshed state = %s", tc.handle, inst.state)
			}
		} else if stringAt(t, inst.state, "file_path") != tc.filePath || int64At(t, inst.state, "index") != 0 {
			t.Fatalf("%s: state = %s", tc.handle, inst.state)
		}
	}
}

// PBS 3 wrote the test repository's component as pbstest. PBS 4.2.1 and
// later count such an entry as the test repository and enable it; older
// releases do not and append an entry of their own, which the resource
// points to.
func TestAPTStandardRepositoryResourceLegacyComponent(t *testing.T) {
	for _, tc := range []struct {
		name          string
		legacyRelease bool
		wantIndex     int64
		wantEntries   int
	}{
		{"4.2.8", false, 0, 1},
		{"4.2.0", true, 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, apt := newAPTHarness(t, tc.legacyRelease)
			apt.addFile(testProxmoxSources, "sources", fakeAPTEntry(testDownloadURI, "trixie", false, "pbstest"))
			inst := h.create(t, "pbs_apt_standard_repository", aptStandardConfig(t, h, "test"))
			if int64At(t, inst.state, "index") != tc.wantIndex || apt.entries(testProxmoxSources) != tc.wantEntries {
				t.Fatalf("%d entries, state = %s", apt.entries(testProxmoxSources), inst.state)
			}
			e, _ := apt.entry(testProxmoxSources, int(tc.wantIndex))
			if !e.Enabled {
				t.Fatalf("entry %d = %+v", tc.wantIndex, e)
			}
		})
	}
}

func TestAPTStandardRepositoryResourceImport(t *testing.T) {
	h, _, apt := newAPTHarness(t, false)
	inst := h.importByID(t, "pbs_apt_standard_repository", "localhost,enterprise")
	if stringAt(t, inst.state, "file_path") != testEnterpriseSources || !boolAt(t, inst.state, "enabled") ||
		stringAt(t, inst.state, "name") != "Enterprise" {
		t.Fatalf("imported state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, aptStandardConfig(t, h, "enterprise"))

	apt.setEnabled(testEnterpriseSources, 0, false)
	inst = h.importByIdentity(t, "pbs_apt_standard_repository", map[string]any{"node": "localhost", "handle": "enterprise"})
	if boolAt(t, inst.state, "enabled") {
		t.Fatalf("imported state = %s", inst.state)
	}

	// A repository the host does not have is not there to import.
	if inst := h.importByID(t, "pbs_apt_standard_repository", "localhost,test"); !inst.state.IsNull() {
		t.Fatalf("imported state = %s", inst.state)
	}

	for _, id := range []string{"enterprise", "localhost,ceph-squid-enterprise", "local host,test"} {
		resp := h.importResource(t, "pbs_apt_standard_repository", id, nil)
		requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS APT standard repository by <node>,<handle>")
	}
}

func TestAPTRepositoriesDataSource(t *testing.T) {
	h, _, apt := newAPTHarness(t, false)
	disabled := fakeAPTEntry(testDownloadURI, "trixie", false, "pbs-no-subscription")
	disabled.FileType = "list"
	disabled.Options = nil
	disabled.Comment = " no-subscription, for later\n"
	debianList := fakeAPTEntry("http://deb.debian.org/debian", "trixie", true, "main", "contrib")
	debianList.FileType = "list"
	apt.addFile("/etc/apt/sources.list", "list", debianList, disabled)
	apt.addError("/etc/apt/sources.list.d/broken.list", "malformed entry on line 1 - unable to parse")

	state := h.readDataSource(t, "pbs_apt_repositories", h.dataSourceValue(t, "pbs_apt_repositories", nil))
	if stringAt(t, state, "node") != "localhost" || len(stringAt(t, state, "digest")) != 64 {
		t.Fatalf("state = %s", state)
	}
	// PBS lists /etc/apt/sources.list first.
	if lengthAt(t, state, "files") != 3 || stringAt(t, state, "files", 0, "path") != "/etc/apt/sources.list" ||
		stringAt(t, state, "files", 0, "file_type") != "list" || len(stringAt(t, state, "files", 1, "digest")) != 64 {
		t.Fatalf("files = %s", valueAt(t, state, "files"))
	}

	// Every entry, file by file, with the standard repository it is.
	if lengthAt(t, state, "repositories") != 5 {
		t.Fatalf("repositories = %s", valueAt(t, state, "repositories"))
	}
	enterprise := valueAt(t, state, "repositories", 4)
	if stringAt(t, enterprise, "file_path") != testEnterpriseSources || int64At(t, enterprise, "index") != 0 ||
		stringAt(t, enterprise, "handle") != "enterprise" || !boolAt(t, enterprise, "enabled") {
		t.Fatalf("enterprise = %s", enterprise)
	}
	if !isNullAt(t, state, "repositories", 2, "handle") || lengthAt(t, state, "repositories", 2, "suites") != 2 {
		t.Fatalf("debian = %s", valueAt(t, state, "repositories", 2))
	}
	noSubscription := valueAt(t, state, "repositories", 1)
	if stringAt(t, noSubscription, "handle") != "no-subscription" || boolAt(t, noSubscription, "enabled") ||
		int64At(t, noSubscription, "index") != 1 || stringAt(t, noSubscription, "comment") != " no-subscription, for later" ||
		stringAt(t, noSubscription, "file_type") != "list" || lengthAt(t, noSubscription, "components") != 1 {
		t.Fatalf("no-subscription = %s", noSubscription)
	}

	// The standard repositories, with where their entries are.
	want := []struct {
		handle              string
		configured, enabled bool
		filePath            string
		index               int64
	}{
		{"enterprise", true, true, testEnterpriseSources, 0},
		{"no-subscription", true, false, "/etc/apt/sources.list", 1},
		{"test", false, false, "", 0},
	}
	if lengthAt(t, state, "standard_repositories") != len(want) {
		t.Fatalf("standard repositories = %s", valueAt(t, state, "standard_repositories"))
	}
	for i, w := range want {
		s := valueAt(t, state, "standard_repositories", i)
		if stringAt(t, s, "handle") != w.handle || boolAt(t, s, "configured") != w.configured || boolAt(t, s, "enabled") != w.enabled {
			t.Fatalf("standard repository %d = %s", i, s)
		}
		if w.filePath == "" {
			if !isNullAt(t, s, "file_path") || !isNullAt(t, s, "index") {
				t.Fatalf("standard repository %d = %s", i, s)
			}
		} else if stringAt(t, s, "file_path") != w.filePath || int64At(t, s, "index") != w.index {
			t.Fatalf("standard repository %d = %s", i, s)
		}
	}

	if lengthAt(t, state, "errors") != 1 || !strings.Contains(stringAt(t, state, "errors", 0, "error"), "malformed entry") {
		t.Fatalf("errors = %s", valueAt(t, state, "errors"))
	}
	if lengthAt(t, state, "infos") != 5 || stringAt(t, state, "infos", 4, "message") != "Proxmox" ||
		stringAt(t, state, "infos", 4, "kind") != "origin" || !isNullAt(t, state, "infos", 4, "property") ||
		stringAt(t, state, "infos", 4, "path") != testEnterpriseSources {
		t.Fatalf("infos = %s", valueAt(t, state, "infos"))
	}
}

// A digest that never matches because PBS cannot read a file when it lists
// them is explained.
func TestAPTWriteExplainsPermanentDigestConflict(t *testing.T) {
	h, _, apt := newAPTHarness(t, false)
	apt.addError("/etc/apt/sources.list.d/private.sources", "Permission denied (os error 13)")
	apt.staleWrites = 100
	config := aptRepositoryConfig(t, h, testEnterpriseSources, 0, false)
	planned := h.plan(t, "pbs_apt_repository", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, "pbs_apt_repository", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "make them readable to the user backup")
	requireProtocolErrorContaining(t, applied.Diagnostics, "private.sources (Permission denied (os error 13))")
}
