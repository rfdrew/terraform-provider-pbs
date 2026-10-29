package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

// The provider supports PBS 4.0 and newer, and some attributes map to
// properties later releases added. An older server would refuse such a
// property with a terse "parameter verification failed", or — inside a
// property string — not at all, so a resource checks the attributes it sets
// against the version Configure read, in ModifyPlan, and the plan fails with
// the attribute and the release it needs. The thresholds are the releases
// that introduced each property, from PBS's changelog and roadmap; the
// no-subscription packages get some properties a little earlier.

// pbsRelease is a PBS release an attribute needs.
type pbsRelease struct {
	major, minor, release int
}

// pbs41 is what verify job thread counts and the datastore's defaults for
// them need.
var pbs41 = pbsRelease{4, 1, 0}

// pbs416 is what an S3 endpoint's provider quirk
// delete-objects-via-delete-object needs.
var pbs416 = pbsRelease{4, 1, 6}

// pbs42 is what running garbage collection before unmounting a removable
// datastore, sync job worker threads and a remote's use of the node's proxy
// need.
var pbs42 = pbsRelease{4, 2, 0}

// pbs421 is what the extra audiences of an OpenID realm need.
var pbs421 = pbsRelease{4, 2, 1}

// pbs424 is what the request limits of an S3 endpoint and its use of the
// node's proxy need.
var pbs424 = pbsRelease{4, 2, 4}

func (r pbsRelease) String() string {
	if r.release == 0 {
		return fmt.Sprintf("%d.%d", r.major, r.minor)
	}
	return fmt.Sprintf("%d.%d.%d", r.major, r.minor, r.release)
}

// requireRelease fails the plan when it sets the attribute at p, which needs
// release r, and the server is older. An unknown value counts as set. d is
// nil while the provider is not configured yet, and nothing is checked then.
func (d *providerData) requireRelease(diags *diag.Diagnostics, p path.Path, value attr.Value, r pbsRelease) {
	if d == nil || value.IsNull() || d.version.AtLeast(r.major, r.minor, r.release) {
		return
	}
	diags.AddAttributeError(p, "Attribute needs a newer PBS",
		fmt.Sprintf("%s needs PBS %s or newer, but the server at %s runs PBS %s. Remove it, or upgrade the server first.",
			p, r, d.client.BaseURL(), d.version))
}
