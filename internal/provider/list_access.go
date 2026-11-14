package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// List resources of the access layer: API tokens and ACL entries. Users are
// in list_user.go.

// NewAPITokenListResource returns the pbs_api_token list resource.
func NewAPITokenListResource() list.ListResource {
	return &importedList{
		newResource:   NewAPITokenResource,
		identityOrder: []string{"tokenid"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the API tokens of a Proxmox Backup Server's users, for `terraform query`, to " +
				"import them as `pbs_api_token` resources: the tokens of every user, or with `userid` those of one " +
				"user.\n\n" +
				"Needs `" + userReadPrivilege + "`; without it, PBS lists only the tokens of the user the provider " +
				"signs in as — the token's owner, when it signs in with an API token — and lets only that user, " +
				"signed in with its password, read them or list them with `userid`. An API token without the " +
				"privilege lists its owner's tokens only without `userid`, which fails with a 403 otherwise, and " +
				"cannot read them: with resources included, each is left out with a warning.\n\n" +
				"A token's secret, `value`, is never known: PBS shows it only when it creates the token or " +
				"regenerates its secret, so it is null in the results, as after any import. Change `regenerate` " +
				"in the generated configuration to have PBS generate a new secret.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{
				"userid": listschema.StringAttribute{
					Optional:            true,
					MarkdownDescription: "List only the tokens of this user, such as `alice@pbs`.",
					Validators:          userIDValidators(),
				},
			},
		},
		enumerate: listAPITokens,
	}
}

type apiTokenListModel struct {
	UserID types.String `tfsdk:"userid"`
}

// listAPITokens lists one user's tokens with GET
// /access/users/{userid}/token, or every user's with GET /access/users and
// include_tokens: PBS reads both from user.cfg (src/api2/access/user.rs,
// list_tokens and list_users). The first lists nothing for a user that does
// not exist rather than failing, and a "no such user" is taken the same way.
func listAPITokens(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	var filter apiTokenListModel
	diags.Append(config.Get(ctx, &filter)...)
	if diags.HasError() {
		return nil
	}
	var tokens []pbsclient.APIToken
	if !filter.UserID.IsNull() {
		var err error
		tokens, err = data.client.ListAPITokens(ctx, filter.UserID.ValueString())
		if err != nil && !pbsclient.IsNotFound(err) {
			diags.AddError("Unable to list PBS API tokens", apiErrorDetail(data.client, userReadPrivilege, err))
			return nil
		}
	} else {
		users, err := data.client.ListUsers(ctx, true)
		if err != nil {
			diags.AddError("Unable to list PBS API tokens", apiErrorDetail(data.client, userReadPrivilege, err))
			return nil
		}
		for _, user := range users {
			tokens = append(tokens, user.Tokens...)
		}
	}
	objects := make([]listedObject, 0, len(tokens))
	for _, token := range tokens {
		objects = append(objects, listedObject{
			identity:    map[string]any{"tokenid": token.TokenID},
			displayName: displayNameWithComment(token.TokenID, token.Comment),
		})
	}
	return objects
}

// NewACLListResource returns the pbs_acl list resource.
func NewACLListResource() list.ListResource {
	return &importedList{
		newResource:   NewACLResource,
		identityOrder: []string{"path", "auth_id", "role"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the entries of a Proxmox Backup Server's access control list, for " +
				"`terraform query`, to import them as `pbs_acl` resources: one result for each role of a user or " +
				"API token on a path, as `pbs_acl` manages them. `path` and `auth_id` select the entries on one " +
				"path or of one user or token.\n\n" +
				"Needs `" + aclReadPrivilege + "`; without it, PBS shows a user signed in with its password only the " +
				"entries of its own API tokens, and an API token none at all. Entries of groups, which PBS's API " +
				"cannot create but `/etc/proxmox-backup/acl.cfg` may hold, are left out: `pbs_acl` manages those " +
				"of users and tokens only.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{
				"path": listschema.StringAttribute{
					Optional: true,
					MarkdownDescription: "List only the entries on this ACL path, such as `/datastore/store1`; not " +
						"those below it.",
					Validators: aclPathValidators(),
				},
				"auth_id": listschema.StringAttribute{
					Optional: true,
					MarkdownDescription: "List only the entries of this user, such as `alice@pbs`, or API token, such " +
						"as `alice@pbs!ci`. A user's entries are not its tokens'.",
					Validators: authIDValidators(),
				},
			},
		},
		enumerate: listACLEntries,
	}
}

type aclListModel struct {
	Path   types.String `tfsdk:"path"`
	AuthID types.String `tfsdk:"auth_id"`
}

// listACLEntries lists the entries with GET /access/acl: every entry, or
// with a path those on exactly that path. PBS lists one item for each role
// of a user, token or group on a path, with ugid_type "user" for users and
// tokens alike and "group" for groups, and leaves out, without an error,
// those a caller without Sys.Audit on /access/acl may not see
// (src/api2/access/acl.rs, read_acl and extract_acl_node_data).
func listACLEntries(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	var filter aclListModel
	diags.Append(config.Get(ctx, &filter)...)
	if diags.HasError() {
		return nil
	}
	entries, _, err := data.client.ListACL(ctx, filter.Path.ValueString(), !filter.Path.IsNull())
	if err != nil {
		// PBS lets everyone read the ACL and leaves out what a caller may not
		// see, so a failure is not about privileges.
		diags.AddError("Unable to list PBS ACL entries", err.Error())
		return nil
	}
	var objects []listedObject
	for _, entry := range entries {
		if entry.UGIDType == "group" || !filter.AuthID.IsNull() && entry.UGID != filter.AuthID.ValueString() {
			continue
		}
		objects = append(objects, listedObject{
			identity:    map[string]any{"path": entry.Path, "auth_id": entry.UGID, "role": entry.RoleID},
			displayName: entry.RoleID + " on " + entry.Path + " for " + entry.UGID,
		})
	}
	return objects
}
