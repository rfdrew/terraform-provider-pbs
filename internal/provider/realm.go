package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// What the realm resources — pbs_realm_openid, pbs_realm_ldap and
// pbs_realm_ad — share. Realms of every type live in domains.cfg and share
// one namespace and one digest, and PBS handles them alike:
//
//   - default = true takes the flag from every other realm, and an update
//     that does not send default = true clears the realm's own. A realm with
//     default = true therefore sends it with every update, and every write is
//     read back under the provider's lock of domains.cfg, so that no other
//     realm of this provider takes the flag in between.
//   - A realm of another type answers GET and PUT with "got unexpected type",
//     but DELETE removes a realm of any type: Delete reads the realm first,
//     and deletes it with the digest of that read, only while it still has
//     the resource's type.

// Privileges the realm resources need, for error messages.
const (
	realmReadPrivilege   = "Sys.Audit on /access/domains"
	realmModifyPrivilege = "Realm.Allocate on /access/domains"
)

// minRealmLength is the shortest realm name PBS allows.
const minRealmLength = 2

// realmKind is a type of realm a resource manages: the type PBS names it
// by, and the name messages give it, such as "Active Directory".
type realmKind struct {
	typ  string
	name string
}

var (
	openIDRealmKind = realmKind{typ: pbsclient.RealmTypeOpenID, name: "OpenID"}
	ldapRealmKind   = realmKind{typ: pbsclient.RealmTypeLDAP, name: "LDAP"}
	adRealmKind     = realmKind{typ: pbsclient.RealmTypeAD, name: "Active Directory"}
)

// realmValidators check the name of a realm a resource creates: not one of
// the built-in realms, which PBS refuses as existing, so that the plan says
// so already.
func realmValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(minRealmLength, maxSafeIDLength),
		stringvalidator.RegexMatches(realmPattern, "must start with a letter, a digit or an underscore, followed by letters, digits, underscores, dots and hyphens"),
		stringvalidator.NoneOf(pbsclient.RealmTypePAM, pbsclient.RealmTypePBS),
	}
}

// writeRealm runs write and then read under the provider's lock of
// domains.cfg, so that no other realm of this provider takes the default
// flag between the two. It returns the error of write; read is not run when
// write fails, and keeps its own error.
func writeRealm(client *pbsclient.Client, write, read func() error) (readErr, err error) {
	err = client.WithConfigLock(pbsclient.ConfigDomains, func() error {
		if err := write(); err != nil {
			return err
		}
		readErr = read()
		return nil
	})
	return readErr, err
}

// addRealmExistsError explains a create PBS refused because the name is
// taken, by a realm of any type.
func addRealmExistsError(diags *diag.Diagnostics, kind realmKind, name string, err error) {
	diags.AddAttributeError(path.Root("realm"), "PBS realm already exists",
		fmt.Sprintf("PBS already has a realm %q; realms of every type share one namespace. If it is an %s "+
			"realm, import it to manage it with Terraform, with an import block whose id is %q or with "+
			"`terraform import`; otherwise choose another name. %s", name, kind.name, name, err))
}

// readRealmFailed handles a failed read of the realm in Read: a realm that is
// gone, or that has another type now, leaves state.
func readRealmFailed(ctx context.Context, resp *resource.ReadResponse, client *pbsclient.Client, kind realmKind, name string, err error) {
	switch {
	case pbsclient.IsNotFound(err):
		resp.State.RemoveResource(ctx)
	case pbsclient.IsRealmOfOtherType(err):
		resp.Diagnostics.AddWarning("PBS realm is no "+kind.name+" realm",
			fmt.Sprintf("PBS has a realm %q, but not of type %s: it was replaced outside Terraform. It is "+
				"removed from state, and Terraform leaves it alone; creating the %s realm again fails while "+
				"it exists. %s", name, kind.typ, kind.name, err))
		resp.State.RemoveResource(ctx)
	default:
		resp.Diagnostics.AddError("Unable to read PBS "+kind.name+" realm", apiErrorDetail(client, realmReadPrivilege, err))
	}
}

// deleteRealm deletes the realm; one already gone is not an error. PBS's
// delete removes a realm of any type, so the realm is read first, and
// deleted only while it still has the resource's type — with the digest of
// that read, so that nothing replaces it in between.
func deleteRealm(ctx context.Context, client *pbsclient.Client, kind realmKind, name string, diags *diag.Diagnostics) {
	err := client.WithConfigLock(pbsclient.ConfigDomains, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			digest, err := client.RealmDigest(ctx, kind.typ, name)
			if err != nil {
				return err
			}
			return client.DeleteRealm(ctx, kind.typ, name, digest)
		})
	})
	switch {
	case err == nil || pbsclient.IsNotFound(err):
	case pbsclient.IsRealmOfOtherType(err):
		diags.AddWarning("PBS realm is no "+kind.name+" realm",
			fmt.Sprintf("PBS has a realm %q, but not of type %s: it was replaced outside Terraform, so it was not "+
				"deleted. %s", name, kind.typ, err))
	default:
		diags.AddError("Unable to delete PBS "+kind.name+" realm", apiErrorDetail(client, realmModifyPrivilege, err))
	}
}
