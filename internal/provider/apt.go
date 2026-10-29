package provider

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// APT repositories are entries of the node's APT source files; see
// internal/pbsclient/apt.go for what PBS does with them. PBS can add the
// entry of a standard repository and enable or disable any entry, but not
// remove one, so pbs_apt_repository manages whether an existing entry is
// enabled, and pbs_apt_standard_repository makes sure a standard repository
// is there.

// Reading the APT source files needs Sys.Audit on /, changing them
// Sys.Modify on /.
const (
	aptReadPrivilege   = "Sys.Audit on /"
	aptModifyPrivilege = "Sys.Modify on /"
)

// aptFilePathPattern is a file PBS reads APT repositories from:
// /etc/apt/sources.list, or a .list or .sources file in
// /etc/apt/sources.list.d whose name PBS accepts. PBS ignores hidden files.
var aptFilePathPattern = regexp.MustCompile(`^/etc/apt/sources\.list$|^/etc/apt/sources\.list\.d/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(list|sources)$`)

// aptIDSeparator separates the parts of the IDs of APT resources, as in
// bpg/proxmox: no node name, file path or handle contains a comma.
const aptIDSeparator = ","

// aptRepositoryID is the ID of an entry: <node>,<file path>,<index>.
func aptRepositoryID(node, path string, index int64) string {
	return strings.Join([]string{node, path, strconv.FormatInt(index, 10)}, aptIDSeparator)
}

// aptStandardRepositoryID is the ID of a standard repository:
// <node>,<handle>.
func aptStandardRepositoryID(node, handle string) string {
	return node + aptIDSeparator + handle
}

// aptStandardHandles are the handles of PBS's standard repositories.
var aptStandardHandles = []string{pbsclient.APTHandleEnterprise, pbsclient.APTHandleNoSubscription, pbsclient.APTHandleTest}

// aptMatcher tells the entries of standard repositories apart as the
// server's release does.
func (d *providerData) aptMatcher() pbsclient.APTMatcher {
	return pbsclient.NewAPTMatcher(d.version)
}

// aptNodeAttribute is the node attribute of the APT resources, of which a
// configuration has many.
func aptNodeAttribute() schema.StringAttribute {
	return nodeAttributeDescribed("Node whose APT source files to manage: `localhost`, which every PBS answers to, or " +
		"the node's host name. Defaults to the provider's `node`. PBS is a single node, so both name the same " +
		"files: do not manage one entry or repository under both. Changing it replaces the resource.")
}

// stringListOf maps a list PBS answers to a list, the empty list included.
func stringListOf(values []string, diags *diag.Diagnostics) types.List {
	elements := make([]attr.Value, len(values))
	for i, v := range values {
		elements[i] = types.StringValue(v)
	}
	list, d := types.ListValue(types.StringType, elements)
	diags.Append(d...)
	return list
}

// aptEntryDetails are the attributes that describe an entry, which
// pbs_apt_repository and pbs_apt_repositories share.
type aptEntryDetails struct {
	FileType     types.String
	PackageTypes types.List
	URIs         types.List
	Suites       types.List
	Components   types.List
	Comment      types.String
}

func newAPTEntryDetails(file pbsclient.APTRepositoryFile, e pbsclient.APTRepository, diags *diag.Diagnostics) aptEntryDetails {
	fileType := e.FileType
	if fileType == "" {
		fileType = file.FileType
	}
	return aptEntryDetails{
		FileType:     types.StringValue(fileType),
		PackageTypes: stringListOf(e.Types, diags),
		URIs:         stringListOf(e.URIs, diags),
		Suites:       stringListOf(e.Suites, diags),
		Components:   stringListOf(e.Components, diags),
		Comment:      stringOrNull(strings.TrimRight(e.Comment, "\n")),
	}
}

// sameEntry reports whether two entries' details are those of one entry:
// whether an index still points to the entry it pointed to. The comment
// does not count — PBS reformats it when it rewrites a file —, and neither
// does the test repository's component as PBS 3 wrote it, pbstest, which
// PBS 4.2.1 and later rewrite to pbs-test.
func (a aptEntryDetails) sameEntry(b aptEntryDetails) bool {
	return a.FileType.Equal(b.FileType) && a.PackageTypes.Equal(b.PackageTypes) && a.URIs.Equal(b.URIs) &&
		a.Suites.Equal(b.Suites) && canonicalComponents(a.Components).Equal(canonicalComponents(b.Components))
}

// canonicalComponents is components with pbstest spelt pbs-test.
func canonicalComponents(components types.List) types.List {
	elements := components.Elements()
	canonical := make([]attr.Value, len(elements))
	for i, e := range elements {
		canonical[i] = e
		if e.Equal(types.StringValue("pbstest")) {
			canonical[i] = types.StringValue("pbs-test")
		}
	}
	list, _ := types.ListValue(types.StringType, canonical)
	return list
}

// describe is the entry in one line, as a .list file would have it.
func (a aptEntryDetails) describe(ctx context.Context) string {
	parts := []string{}
	for _, l := range []types.List{a.PackageTypes, a.URIs, a.Suites, a.Components} {
		var values []string
		_ = l.ElementsAs(ctx, &values, false)
		parts = append(parts, strings.Join(values, " "))
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// findEntry returns the index of the first entry of the file at path whose
// details are those of want.
func findEntry(repos pbsclient.APTRepositories, path string, want aptEntryDetails, diags *diag.Diagnostics) (int64, bool) {
	file, _ := repos.File(path)
	for i, e := range file.Repositories {
		if newAPTEntryDetails(file, e, diags).sameEntry(want) {
			return int64(i), true
		}
	}
	return 0, false
}

// aptMovedEntryDetail explains that the entry at index of the file at path
// is current, not prior, and where prior is now, if anywhere in the file.
func aptMovedEntryDetail(ctx context.Context, repos pbsclient.APTRepositories, node, path string, index int64, prior, current aptEntryDetails, diags *diag.Diagnostics) string {
	detail := fmt.Sprintf("The entry at index %d of %s on node %s is \"%s\" now, not \"%s\": entries before it were "+
		"added or removed, or the entry was edited, outside Terraform.", index, path, node, current.describe(ctx), prior.describe(ctx))
	if moved, found := findEntry(repos, path, prior, diags); found {
		detail += fmt.Sprintf(" That entry is at index %d now; set index to %d to manage it again.", moved, moved)
	}
	return detail + " To manage the entry that is at index " + strconv.FormatInt(index, 10) + " now instead, replace " +
		"the resource, with terraform apply -replace."
}

// aptMissingEntryDetail explains why the node has no entry at index of the
// file at path.
func aptMissingEntryDetail(repos pbsclient.APTRepositories, node, path string, index int64) string {
	if msg, failed := repos.FileError(path); failed {
		return fmt.Sprintf("PBS cannot parse %s on node %s: %s", path, node, msg)
	}
	file, ok := repos.File(path)
	if !ok {
		var paths []string
		for _, f := range repos.Files {
			paths = append(paths, f.Path)
		}
		return fmt.Sprintf("Node %s has no APT source file %s. Its source files are: %s.", node, path, strings.Join(paths, ", "))
	}
	if len(file.Repositories) == 0 {
		return fmt.Sprintf("%s on node %s has no entries.", path, node)
	}
	return fmt.Sprintf("%s on node %s has no entry at index %d: its entries are at indexes 0 to %d.",
		path, node, index, len(file.Repositories)-1)
}

// aptWriteErrorDetail explains a failed write. repos is what the write was
// based on, as far as it got. A digest that never matches, after every
// retry, can come from a source file PBS cannot read when it lists them —
// it reads them as the unprivileged user backup then, and as root when it
// writes, so the digests differ.
func aptWriteErrorDetail(client *pbsclient.Client, repos pbsclient.APTRepositories, err error) string {
	detail := apiErrorDetail(client, aptModifyPrivilege, err)
	if !pbsclient.IsDigestConflict(err) || len(repos.Errors) == 0 {
		return detail
	}
	var files []string
	for _, e := range repos.Errors {
		files = append(files, e.Path+" ("+e.Error+")")
	}
	return detail + " PBS lists source files it cannot read or parse: " + strings.Join(files, ", ") + ". When it " +
		"reads them as root to write, they count towards the digest it checks, which then never matches the one it " +
		"listed; make them readable to the user backup, or fix them."
}
