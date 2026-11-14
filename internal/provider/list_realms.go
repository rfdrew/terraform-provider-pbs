package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// The list resources of the realms: pbs_realm_ldap, pbs_realm_ad and
// pbs_realm_openid. Each names the realms of its type from /access/domains,
// which lists every realm, of every type, to anyone — the sign-in form needs
// it (src/api2/access/domain.rs, list_domains). PBS's lists of one type,
// GET /config/access/{ldap,ad,openid}, need Realm.Allocate on
// /access/domains (src/api2/config/access/{ldap,ad,openid}.rs), more than
// reading a realm does, Sys.Audit there; the resources' Read needs only the
// latter. The built-in pam and pbs have types of their own, and no resource.

// realmListKind is a type of realm a list resource names, and what its
// description says about the configuration generated for one.
type realmListKind struct {
	kind realmKind
	// title is how descriptions call the realms, such as "OpenID
	// Connect".
	title string
	// secrets says what the generated configuration cannot know.
	secrets string
}

var (
	ldapRealmListKind = realmListKind{kind: ldapRealmKind, title: "LDAP", secrets: directoryRealmListSecrets}
	adRealmListKind   = realmListKind{kind: adRealmKind, title: "Active Directory", secrets: directoryRealmListSecrets}

	openIDRealmListKind = realmListKind{
		kind: openIDRealmKind, title: "OpenID Connect",
		secrets: "The client key is not imported, though PBS returns it: the generated configuration has " +
			"`client_key = null # sensitive`, `client_key_wo = null # sensitive` and `client_key_wo_version = " +
			"null`, which plans no change, and the realm keeps the key PBS has. Set `client_key`, or " +
			"`client_key_wo` with `client_key_wo_version`, to manage the key with Terraform; a change of `realm` " +
			"or `username_claim`, which replaces the realm, loses the key otherwise.",
	}
)

// directoryRealmListSecrets is what the generated configuration of an LDAP or
// Active Directory realm lacks.
const directoryRealmListSecrets = "The bind password is write-only and never read: the generated configuration " +
	"has `password_wo = null # sensitive` and `password_wo_version = null`, which plans no change, and the realm " +
	"keeps the password PBS has. A realm with a `bind_dn` needs both filled in only to be created again, when a " +
	"change of `realm` or `capath` replaces it: the plan fails without them then."

// NewLDAPRealmListResource returns the pbs_realm_ldap list resource.
func NewLDAPRealmListResource() list.ListResource {
	return newRealmList(NewLDAPRealmResource, ldapRealmListKind)
}

// NewADRealmListResource returns the pbs_realm_ad list resource.
func NewADRealmListResource() list.ListResource {
	return newRealmList(NewADRealmResource, adRealmListKind)
}

// NewOpenIDRealmListResource returns the pbs_realm_openid list resource.
func NewOpenIDRealmListResource() list.ListResource {
	return newRealmList(NewOpenIDRealmResource, openIDRealmListKind)
}

// newRealmList returns the list resource of the realms of one type, which
// newResource manages.
func newRealmList(newResource func() resource.Resource, kind realmListKind) list.ListResource {
	return &importedList{
		newResource:   newResource,
		identityOrder: []string{"realm"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the " + kind.title + " realms of a Proxmox Backup Server, for `terraform " +
				"query`, to import them as `pbs_realm_" + kind.kind.typ + "` resources. Realms of other types have " +
				"list resources of their own; the built-in `pam` and `pbs` have none.\n\n" + kind.secrets + "\n\n" +
				"PBS names its realms to anyone, as its sign-in form needs them, so listing them needs no " +
				"privilege. Including the resources, as `include_resource` and `-generate-config-out` do, reads each " +
				"realm, which needs `" + realmReadPrivilege + "`: without it, every realm is left out with a " +
				"warning.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{},
		},
		enumerate: func(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
			return listRealms(ctx, data, kind.kind, diags)
		},
	}
}

// listRealms names the realms of kind's type.
func listRealms(ctx context.Context, data *providerData, kind realmKind, diags *diag.Diagnostics) []listedObject {
	realms, err := data.client.ListRealms(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS "+kind.name+" realms", apiErrorDetail(data.client, realmReadPrivilege, err))
		return nil
	}
	var objects []listedObject
	for _, realm := range realms {
		if realm.Type != kind.typ {
			continue
		}
		objects = append(objects, listedObject{
			identity:    map[string]any{"realm": realm.Realm},
			displayName: displayNameWithComment(realm.Realm, realm.Comment),
		})
	}
	return objects
}
