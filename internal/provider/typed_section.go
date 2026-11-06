package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Some PBS configuration files keep objects of several types in one
// namespace, keyed by name: realms of every type in domains.cfg, InfluxDB
// HTTP and UDP metric servers in metricserver.cfg. PBS answers a GET or PUT
// of a name that an object of another type holds with 400 "got unexpected
// type …" (pbsclient.IsOfOtherType), but its DELETE removes the object of
// that name whatever its type. So the resources of such objects never delete
// by name alone: they read the object as their own type first, and delete it
// with the digest of that read, so that nothing replaces it in between. A
// refresh that finds the name taken by another type drops the resource from
// state, and leaves the other object alone.

// sectionKind is a type of object in such a file, as a resource manages it.
type sectionKind struct {
	// object is what the objects of the file are called in messages, such
	// as "realm" or "metric server".
	object string
	// typ is PBS's name of the type, such as ldap or influxdb-http.
	typ string
	// name is the type's name in messages, such as "LDAP" or "InfluxDB
	// HTTP".
	name string
	// file is the configuration file, for WithConfigLock.
	file string
}

// readSectionFailed handles a failed read of the object in Read: one that is
// gone, or whose name an object of another type holds now, leaves state.
// privilege is what reading needs, for the error.
func readSectionFailed(ctx context.Context, resp *resource.ReadResponse, client *pbsclient.Client, kind sectionKind, name, privilege string, err error) {
	switch {
	case pbsclient.IsNotFound(err):
		resp.State.RemoveResource(ctx)
	case pbsclient.IsOfOtherType(err):
		resp.Diagnostics.AddWarning(fmt.Sprintf("PBS %s is no %s %s", kind.object, kind.name, kind.object),
			fmt.Sprintf("PBS has a %s %q, but not of type %s: it was replaced outside Terraform. It is removed from "+
				"state, and Terraform leaves it alone; creating the %s %s again fails while it exists. %s",
				kind.object, name, kind.typ, kind.name, kind.object, err))
		resp.State.RemoveResource(ctx)
	default:
		resp.Diagnostics.AddError(fmt.Sprintf("Unable to read PBS %s %s", kind.name, kind.object),
			apiErrorDetail(client, privilege, err))
	}
}

// deleteSection deletes the object; one already gone is not an error.
// digest reads the object as the resource's type, failing with
// pbsclient.IsOfOtherType when its name belongs to another type, and returns
// the digest of the file; del deletes it, provided the file still has that
// digest. Both run under the provider's lock of the file, again when another
// writer changed the file in between. privilege is what deleting needs, for
// the error.
func deleteSection(ctx context.Context, client *pbsclient.Client, kind sectionKind, name, privilege string,
	digest func() (string, error), del func(digest string) error, diags *diag.Diagnostics) {
	err := client.WithConfigLock(kind.file, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			d, err := digest()
			if err != nil {
				return err
			}
			return del(d)
		})
	})
	switch {
	case err == nil || pbsclient.IsNotFound(err):
	case pbsclient.IsOfOtherType(err):
		diags.AddWarning(fmt.Sprintf("PBS %s is no %s %s", kind.object, kind.name, kind.object),
			fmt.Sprintf("PBS has a %s %q, but not of type %s: it was replaced outside Terraform, so it was not "+
				"deleted. %s", kind.object, name, kind.typ, err))
	default:
		diags.AddError(fmt.Sprintf("Unable to delete PBS %s %s", kind.name, kind.object), apiErrorDetail(client, privilege, err))
	}
}
