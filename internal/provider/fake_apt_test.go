package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeAPT keeps a node's APT source files in memory and serves PBS's API for
// them through a fakePBS, with the behaviour read in PBS 4's source (see
// internal/pbsclient/apt.go):
//
//   - GET lists /etc/apt/sources.list first and then the other files in the
//     order they were added, each with its entries, disabled ones included, the standard repositories with their status — null
//     without an entry, true with an enabled one, false otherwise —, notes on
//     the entries' origin, and a digest inside data that covers every file;
//   - PUT adds the standard repository of a handle, appending its entry to
//     pbs-enterprise.sources or proxmox.sources, or enables its first entry
//     when it has one; a handle outside the enumeration fails;
//   - POST enables or disables the entry at a path and index, rewriting the
//     file, and fails for a path or an index PBS does not have;
//   - both writes check the digest when they carry one.
//
// An entry is of a standard repository when it is of type deb and names the
// suite, the repository's component and its URI; legacy also recognises
// pbstest, as PBS 4.2.1 and later do. Tests set up the files with addFile
// and change them behind the provider's back with setEnabled, insert and
// removeFile.
type fakeAPT struct {
	fake *fakePBS

	mu     sync.Mutex
	files  []*fakeAPTFile
	errors []pbsclient.APTRepositoryFileError
	suite  string
	legacy bool
	// staleWrites is how many writes from now on fail with a digest
	// conflict, as when someone else changed a file meanwhile.
	staleWrites int
	// failReadAfterWrite has the first read after the next write fail, as
	// when the connection drops.
	failReadAfterWrite bool
	failNextRead       bool
}

type fakeAPTFile struct {
	path     string
	fileType string
	entries  []pbsclient.APTRepository
	gen      int
}

// fakeAPTStandardRepo is a standard repository of PBS as the fake knows it.
type fakeAPTStandardRepo struct {
	handle, name, uri, component, legacyComponent, file string
}

var fakeAPTStandard = []fakeAPTStandardRepo{
	{"enterprise", "Enterprise", "https://enterprise.proxmox.com/debian/pbs", "pbs-enterprise", "", "/etc/apt/sources.list.d/pbs-enterprise.sources"},
	{"no-subscription", "No-Subscription", "http://download.proxmox.com/debian/pbs", "pbs-no-subscription", "", "/etc/apt/sources.list.d/proxmox.sources"},
	{"test", "Test", "http://download.proxmox.com/debian/pbs", "pbs-test", "pbstest", "/etc/apt/sources.list.d/proxmox.sources"},
}

const fakeAPTKeyring = "/usr/share/keyrings/proxmox-archive-keyring.gpg"

// newFakeAPT serves the APT repositories of node localhost from fake, for a
// PBS 4 server, on Debian trixie, that recognises legacy components when
// legacy is set.
func newFakeAPT(fake *fakePBS, legacy bool) *fakeAPT {
	a := &fakeAPT{fake: fake, suite: "trixie", legacy: legacy}
	const route = " /nodes/localhost/apt/repositories"
	fake.handle(http.MethodGet+route, a.list)
	fake.handle(http.MethodPut+route, a.add)
	fake.handle(http.MethodPost+route, a.change)
	return a
}

// fakeAPTEntry is an entry of a deb822 file.
func fakeAPTEntry(uri, suite string, enabled bool, components ...string) pbsclient.APTRepository {
	e := pbsclient.APTRepository{Types: []string{"deb"}, URIs: []string{uri}, Suites: []string{suite},
		Components: components, FileType: "sources", Enabled: true}
	if !enabled {
		e.Options = []pbsclient.APTRepositoryOption{{Key: "Enabled", Values: []string{"false"}}}
		e.Enabled = false
	}
	return e
}

// --- test helpers -------------------------------------------------------------

// fakeAPTSourcesList is the one file PBS lists before the others.
const fakeAPTSourcesList = "/etc/apt/sources.list"

func (a *fakeAPT) addFile(path, fileType string, entries ...pbsclient.APTRepository) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := &fakeAPTFile{path: path, fileType: fileType, entries: entries}
	if path == fakeAPTSourcesList {
		a.files = slices.Insert(a.files, 0, f)
		return
	}
	a.files = append(a.files, f)
}

func (a *fakeAPT) addError(path, message string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.errors = append(a.errors, pbsclient.APTRepositoryFileError{Path: path, Error: message})
}

func (a *fakeAPT) fileLocked(path string) *fakeAPTFile {
	for _, f := range a.files {
		if f.path == path {
			return f
		}
	}
	return nil
}

// entry returns the entry at index of the file at path.
func (a *fakeAPT) entry(path string, index int) (pbsclient.APTRepository, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fileLocked(path)
	if f == nil || index >= len(f.entries) {
		return pbsclient.APTRepository{}, false
	}
	return f.entries[index], true
}

// entries returns how many entries the file at path has.
func (a *fakeAPT) entries(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if f := a.fileLocked(path); f != nil {
		return len(f.entries)
	}
	return 0
}

// setEnabled enables or disables an entry behind the provider's back.
func (a *fakeAPT) setEnabled(path string, index int, enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fileLocked(path)
	setFakeAPTEnabled(&f.entries[index], enabled)
	f.gen++
}

// insert adds an entry at index behind the provider's back, moving the
// entries from there down.
func (a *fakeAPT) insert(path string, index int, e pbsclient.APTRepository) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fileLocked(path)
	f.entries = slices.Insert(f.entries, index, e)
	f.gen++
}

// setEntry replaces an entry behind the provider's back, as when PBS
// rewrites a file or someone edits it.
func (a *fakeAPT) setEntry(path string, index int, e pbsclient.APTRepository) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fileLocked(path)
	f.entries[index] = e
	f.gen++
}

func (a *fakeAPT) removeFile(path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.files = slices.DeleteFunc(a.files, func(f *fakeAPTFile) bool { return f.path == path })
}

// --- serving ------------------------------------------------------------------

// setFakeAPTEnabled enables or disables an entry the way proxmox-apt does:
// a deb822 entry gets an Enabled option.
func setFakeAPTEnabled(e *pbsclient.APTRepository, enabled bool) {
	e.Enabled = enabled
	if e.FileType != "sources" {
		return
	}
	value := []string{strconv.FormatBool(enabled)}
	for i, o := range e.Options {
		if o.Key == "Enabled" {
			e.Options[i].Values = value
			return
		}
	}
	e.Options = append(e.Options, pbsclient.APTRepositoryOption{Key: "Enabled", Values: value})
}

func (f *fakeAPTFile) digest() []byte {
	content, _ := json.Marshal(f.entries)
	sum := sha256.Sum256([]byte(f.path + strconv.Itoa(f.gen) + string(content)))
	return sum[:]
}

// digestLocked is the digest of every file, over their digests in path
// order, as proxmox-apt computes it.
func (a *fakeAPT) digestLocked() string {
	files := slices.Clone(a.files)
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	var digests []byte
	for _, f := range files {
		digests = append(digests, f.digest()...)
	}
	sum := sha256.Sum256(digests)
	return hex.EncodeToString(sum[:])
}

// referencesLocked reports whether e is an entry of the standard repository
// at s in fakeAPTStandard.
func (a *fakeAPT) referencesLocked(e pbsclient.APTRepository, s int) bool {
	std := fakeAPTStandard[s]
	componentOK := slices.ContainsFunc(e.Components, func(c string) bool {
		return c == std.component || (a.legacy && std.legacyComponent != "" && c == std.legacyComponent)
	})
	uriOK := slices.ContainsFunc(e.URIs, func(u string) bool { return strings.TrimRight(u, "/") == std.uri })
	return slices.Contains(e.Types, "deb") && slices.Contains(e.Suites, a.suite) && componentOK && uriOK
}

func (a *fakeAPT) list(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failNextRead {
		a.failNextRead = false
		writeFakeResponse(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	files := []map[string]any{}
	infos := []map[string]any{}
	for _, f := range a.files {
		digest := []int{}
		for _, b := range f.digest() {
			digest = append(digest, int(b))
		}
		files = append(files, map[string]any{"path": f.path, "file-type": f.fileType, "repositories": f.entries, "digest": digest})
		for i, e := range f.entries {
			origin := "Debian"
			if strings.Contains(strings.Join(e.URIs, " "), "proxmox.com") {
				origin = "Proxmox"
			}
			infos = append(infos, map[string]any{"path": f.path, "index": i, "kind": "origin", "message": origin})
		}
	}
	standard := []map[string]any{}
	for s, std := range fakeAPTStandard {
		entry := map[string]any{"handle": std.handle, "name": std.name, "description": "The " + std.name + " repository."}
		var status *bool
		for _, f := range a.files {
			for _, e := range f.entries {
				if (status == nil || !*status) && a.referencesLocked(e, s) {
					enabled := e.Enabled
					status = &enabled
				}
			}
		}
		if status != nil {
			entry["status"] = *status
		}
		standard = append(standard, entry)
	}
	errors := a.errors
	if errors == nil {
		errors = []pbsclient.APTRepositoryFileError{}
	}
	writeData(w, map[string]any{"files": files, "errors": errors, "infos": infos, "standard-repos": standard,
		"digest": a.digestLocked()}, "")
}

// checkWriteLocked fails a write like PBS when its digest is stale, or when
// the test has it fail with a conflict.
func (a *fakeAPT) checkWriteLocked(w http.ResponseWriter, digest string) bool {
	if a.staleWrites > 0 {
		a.staleWrites--
		writeError(w, fakeDigestConflict)
		return false
	}
	if digest != "" && digest != a.digestLocked() {
		writeError(w, fakeDigestConflict)
		return false
	}
	return true
}

func (a *fakeAPT) add(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	handle := params.Get("handle")
	a.mu.Lock()
	defer a.mu.Unlock()
	s := slices.IndexFunc(fakeAPTStandard, func(std fakeAPTStandardRepo) bool { return std.handle == handle })
	if s < 0 {
		writeError(w, "parameter verification failed - 'handle': value '%s' is not defined in the enumeration.", handle)
		return
	}
	if !a.checkWriteLocked(w, params.Get(pbsclient.DigestParam)) {
		return
	}
	for _, f := range a.files {
		for i := range f.entries {
			if a.referencesLocked(f.entries[i], s) {
				if !f.entries[i].Enabled {
					setFakeAPTEnabled(&f.entries[i], true)
					f.gen++
				}
				a.wroteLocked()
				writeData(w, nil, "")
				return
			}
		}
	}
	std := fakeAPTStandard[s]
	e := fakeAPTEntry(std.uri, a.suite, true, std.component)
	e.Options = []pbsclient.APTRepositoryOption{{Key: "Signed-By", Values: []string{fakeAPTKeyring}}}
	f := a.fileLocked(std.file)
	if f == nil {
		f = &fakeAPTFile{path: std.file, fileType: "sources"}
		a.files = append(a.files, f)
	}
	f.entries = append(f.entries, e)
	f.gen++
	a.wroteLocked()
	writeData(w, nil, "")
}

func (a *fakeAPT) change(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	path := params.Get("path")
	a.mu.Lock()
	defer a.mu.Unlock()
	index, err := strconv.Atoi(params.Get("index"))
	if err != nil || index < 0 {
		writeError(w, "parameter verification failed - 'index': expected integer")
		return
	}
	if !a.checkWriteLocked(w, params.Get(pbsclient.DigestParam)) {
		return
	}
	for _, e := range a.errors {
		if e.Path == path {
			writeError(w, "unable to parse file %s - %s", e.Path, e.Error)
			return
		}
	}
	f := a.fileLocked(path)
	if f == nil {
		writeError(w, "invalid path - %s", path)
		return
	}
	if index >= len(f.entries) {
		writeError(w, "invalid index - %d", index)
		return
	}
	if enabled, ok := params["enabled"]; ok {
		setFakeAPTEnabled(&f.entries[index], fakeBool(enabled[0]))
	}
	f.gen++
	a.wroteLocked()
	writeData(w, nil, "")
}

// wroteLocked arms the failed read failReadAfterWrite asks for.
func (a *fakeAPT) wroteLocked() {
	if a.failReadAfterWrite {
		a.failReadAfterWrite, a.failNextRead = false, true
	}
}
