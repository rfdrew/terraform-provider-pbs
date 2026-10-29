package pbsclient

import (
	"context"
	"encoding/hex"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// APT repositories are the entries of the node's APT source files,
// /etc/apt/sources.list and the *.list and *.sources files in
// /etc/apt/sources.list.d. What PBS 4 does with them, read in its source
// (src/api2/node/apt.rs) and in the proxmox-apt crates it uses
// (proxmox-apt/src/api.rs, proxmox-apt/src/repositories/*.rs,
// proxmox-apt-api-types):
//
//   - GET /nodes/{node}/apt/repositories parses every file and lists its
//     entries, disabled ones included: a commented-out line of a .list file,
//     a stanza of a .sources file with "Enabled: false". An entry is
//     addressed by its file's path and its index within the file, from 0;
//     a stanza with several URIs or suites is one entry. A file that does
//     not parse is listed under errors, not under files.
//   - The digest — unlike other objects', inside data — is the SHA-256 of
//     the files' own digests, ordered by path: changing any file changes it.
//     Both writes check it when they carry one, with the usual "detected
//     modified configuration" error.
//   - PUT adds the standard repository of a handle: "enterprise",
//     "no-subscription" or "test" on PBS. When an entry of it exists
//     already, the first one in the order GET lists them is enabled, or left
//     alone when it is — except that PBS 4.2.1 and later rewrite the test
//     repository's component pbstest to pbs-test; otherwise a new entry,
//     enabled, is appended to the repository's file — on Debian trixie, PBS
//     4's base, pbs-enterprise.sources for the enterprise repository and
//     proxmox.sources for the others, in deb822 format. Entries are never
//     removed or renumbered.
//   - POST enables or disables the entry at a path and index, rewriting its
//     file: a .list entry is commented out, a .sources stanza gets
//     "Enabled: false". There is no way to remove an entry.
//   - Standard repositories report status null when no entry references
//     them, true when an enabled one does, false otherwise. An entry
//     references one when it is of type deb, lists the current Debian
//     release among its suites, the repository's component — such as
//     pbs-no-subscription — among its components, and the repository's URI
//     among its URIs; APTMatcher does the same. From PBS 4.2.1, which moved
//     to proxmox-apt 1.0, PBS also recognises the test repository's
//     component as PBS 3 wrote it, pbstest, and — once apt has fetched it —
//     an entry with another URI by the key that signs its InRelease file:
//     a local mirror, or the download server over https. APTMatcher does not
//     see those.
//   - The answer has the same shape on every PBS 4 release. PUT took only
//     the handles of its enumeration before 4.2.1 — ceph-squid-* included,
//     which PBS 4.2.1 refuses — and any lower-case word since, failing for
//     one it does not know.
//   - Errors are 400 with plain text, such as "invalid path - <path>",
//     "invalid index - <index>" and, for an unknown handle, "no standard
//     repository for handle ..." or a parameter verification failure.

// APTRepositories is what GET /nodes/{node}/apt/repositories reports.
type APTRepositories struct {
	Files  []APTRepositoryFile      `json:"files"`
	Errors []APTRepositoryFileError `json:"errors"`
	// Infos are notes on entries: their origin, suites to upgrade from.
	Infos         []APTRepositoryInfo     `json:"infos"`
	StandardRepos []APTStandardRepository `json:"standard-repos"`
	// Digest covers every file that parsed. PBS sends it inside data, not
	// next to it.
	Digest string `json:"digest"`
}

// APTRepositoryFile is one source file and its entries, in file order.
type APTRepositoryFile struct {
	Path string `json:"path"`
	// FileType is "list" for the one-line format, "sources" for deb822.
	FileType     string          `json:"file-type"`
	Repositories []APTRepository `json:"repositories"`
	// Digest is the SHA-256 of the file's content; PBS sends it as an
	// array of numbers.
	Digest []byte `json:"digest,omitempty"`
}

// DigestHex returns the file's digest in hexadecimal, or "" without one.
func (f APTRepositoryFile) DigestHex() string {
	if len(f.Digest) == 0 {
		return ""
	}
	return hex.EncodeToString(f.Digest)
}

// APTRepository is one entry of a source file. PBS leaves out the lists
// that are empty and an empty comment.
type APTRepository struct {
	// Types are the package types, "deb" and "deb-src".
	Types      []string              `json:"Types,omitempty"`
	URIs       []string              `json:"URIs,omitempty"`
	Suites     []string              `json:"Suites,omitempty"`
	Components []string              `json:"Components,omitempty"`
	Options    []APTRepositoryOption `json:"Options,omitempty"`
	// Comment is the comment lines above the entry, without their #.
	Comment  string `json:"Comment,omitempty"`
	FileType string `json:"FileType"`
	Enabled  bool   `json:"Enabled"`
}

// APTRepositoryOption is an option of an entry, such as Signed-By.
type APTRepositoryOption struct {
	Key    string   `json:"Key"`
	Values []string `json:"Values"`
}

// APTRepositoryFileError is a file PBS could not read or parse.
type APTRepositoryFileError struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// APTRepositoryInfo is a note on an entry, such as its origin.
type APTRepositoryInfo struct {
	Path  string `json:"path"`
	Index int64  `json:"index"`
	// Property is the property the note is about, such as "Suites".
	Property string `json:"property,omitempty"`
	// Kind is "origin", "warning", "ignore-pre-upgrade-warning" or "badge".
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// APTStandardRepository is a standard repository PBS offers, and whether
// the node has it.
type APTStandardRepository struct {
	Handle string `json:"handle"`
	// Status is nil when no entry references the repository, true when an
	// enabled one does, and false when only disabled ones do.
	Status      *bool  `json:"status,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// The standard repositories PBS offers, by handle.
const (
	APTHandleEnterprise     = "enterprise"
	APTHandleNoSubscription = "no-subscription"
	APTHandleTest           = "test"
)

// aptRepositoriesPath is the API path of a node's APT repositories.
func aptRepositoriesPath(node string) string {
	return Path("nodes", node, "apt", "repositories")
}

// APTRepositories reads a node's APT source files. It needs Sys.Audit on
// /.
func (c *Client) APTRepositories(ctx context.Context, node string) (APTRepositories, error) {
	var repos APTRepositories
	_, err := c.Get(ctx, aptRepositoriesPath(node), nil, &repos)
	return repos, err
}

// AddAPTStandardRepository adds the standard repository of handle to a
// node, or enables its first entry when it has one, provided the source
// files still have digest, when one is given. It needs Sys.Modify on /.
// Callers hold WithConfigLock(ConfigAPTSources).
func (c *Client) AddAPTStandardRepository(ctx context.Context, node, handle, digest string) error {
	params := url.Values{"handle": {handle}}
	if digest != "" {
		params.Set(DigestParam, digest)
	}
	_, err := c.Put(ctx, aptRepositoriesPath(node), params, nil)
	return err
}

// SetAPTRepositoryEnabled enables or disables the entry at index of the
// file at path, provided the source files still have digest, when one is
// given. It needs Sys.Modify on /. Callers hold
// WithConfigLock(ConfigAPTSources).
func (c *Client) SetAPTRepositoryEnabled(ctx context.Context, node, path string, index int64, enabled bool, digest string) error {
	params := url.Values{
		"path":    {path},
		"index":   {strconv.FormatInt(index, 10)},
		"enabled": {FormatBool(enabled)},
	}
	if digest != "" {
		params.Set(DigestParam, digest)
	}
	_, err := c.Post(ctx, aptRepositoriesPath(node), params, nil)
	return err
}

// File returns the file at path.
func (r APTRepositories) File(path string) (APTRepositoryFile, bool) {
	for _, f := range r.Files {
		if f.Path == path {
			return f, true
		}
	}
	return APTRepositoryFile{}, false
}

// FileError returns why the file at path did not parse, if it did not.
func (r APTRepositories) FileError(path string) (string, bool) {
	for _, e := range r.Errors {
		if e.Path == path {
			return e.Error, true
		}
	}
	return "", false
}

// Repository returns the entry at index of the file at path.
func (r APTRepositories) Repository(path string, index int64) (APTRepository, bool) {
	f, ok := r.File(path)
	if !ok || index < 0 || index >= int64(len(f.Repositories)) {
		return APTRepository{}, false
	}
	return f.Repositories[index], true
}

// StandardRepository returns the standard repository of handle, if PBS
// offers it.
func (r APTRepositories) StandardRepository(handle string) (APTStandardRepository, bool) {
	for _, s := range r.StandardRepos {
		if s.Handle == handle {
			return s, true
		}
	}
	return APTStandardRepository{}, false
}

// aptStandardEntry is what makes an entry one of a standard repository of
// PBS: proxmox-apt's table of standard repositories, for the host product
// pbs. The test repository's component depends on the release; see
// APTMatcher.
type aptStandardEntry struct {
	uri       string
	component string
}

var aptStandardEntries = map[string]aptStandardEntry{
	APTHandleEnterprise:     {uri: "https://enterprise.proxmox.com/debian/pbs", component: "pbs-enterprise"},
	APTHandleNoSubscription: {uri: "http://download.proxmox.com/debian/pbs", component: "pbs-no-subscription"},
	APTHandleTest:           {uri: "http://download.proxmox.com/debian/pbs"},
}

// APTMatcher tells the entries of standard repositories apart, as a given
// PBS release does.
type APTMatcher struct {
	// Suite is the Debian release the node runs, which an entry of a
	// standard repository must name; empty matches any suite.
	Suite string
	// TestComponents are the components of the test repository the release
	// recognises: pbstest up to PBS 3, pbs-test from PBS 4.0, and both from
	// PBS 4.2.1, which moved to proxmox-apt 1.0.
	TestComponents []string
}

// NewAPTMatcher returns the matcher of the PBS release v: the suite of its
// Debian base — trixie for PBS 4 — and the components of its test
// repository. For a release line this client does not know, any suite
// matches.
func NewAPTMatcher(v Version) APTMatcher {
	m := APTMatcher{TestComponents: []string{"pbs-test"}}
	major, _, _, ok := v.Parts()
	switch {
	case ok && major <= 3:
		m.TestComponents = []string{"pbstest"}
	case v.AtLeast(4, 2, 1):
		m.TestComponents = []string{"pbs-test", "pbstest"}
	}
	if ok {
		m.Suite = map[int]string{2: "bullseye", 3: "bookworm", 4: "trixie", 5: "forky"}[major]
	}
	return m
}

// components returns the components that make an entry one of the
// standard repository of handle.
func (m APTMatcher) components(handle string) []string {
	if handle == APTHandleTest {
		return m.TestComponents
	}
	return []string{aptStandardEntries[handle].component}
}

// References reports whether e is an entry of the standard repository of
// handle: of type deb, with the suite, one of the repository's components
// among its components and the repository's URI, without a trailing slash,
// among its URIs. An entry PBS 4.2.1 and later recognise by the key that
// signs it — a local mirror, the download server over https — is not
// recognised here.
func (m APTMatcher) References(e APTRepository, handle string) bool {
	standard, ok := aptStandardEntries[handle]
	if !ok {
		return false
	}
	components := m.components(handle)
	return slices.Contains(e.Types, "deb") &&
		(m.Suite == "" || slices.Contains(e.Suites, m.Suite)) &&
		slices.ContainsFunc(e.Components, func(c string) bool { return slices.Contains(components, c) }) &&
		slices.ContainsFunc(e.URIs, func(u string) bool { return strings.TrimRight(u, "/") == standard.uri })
}

// Handle returns the handle of the first standard repository — in the
// order enterprise, no-subscription, test — e is an entry of, or "".
func (m APTMatcher) Handle(e APTRepository) string {
	for _, handle := range []string{APTHandleEnterprise, APTHandleNoSubscription, APTHandleTest} {
		if m.References(e, handle) {
			return handle
		}
	}
	return ""
}

// FindStandardRepository returns where the first entry of the standard
// repository of handle is, in the order PBS lists files and entries: the
// entry PUT enables when the repository is there already. With enabledOnly,
// it looks for the first enabled one.
func (r APTRepositories) FindStandardRepository(m APTMatcher, handle string, enabledOnly bool) (path string, index int64, ok bool) {
	for _, f := range r.Files {
		for i, e := range f.Repositories {
			if (e.Enabled || !enabledOnly) && m.References(e, handle) {
				return f.Path, int64(i), true
			}
		}
	}
	return "", 0, false
}
