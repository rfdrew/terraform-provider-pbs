package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// NewUserListResource returns the pbs_user list resource.
func NewUserListResource() list.ListResource {
	return &importedList{
		newResource:   NewUserResource,
		identityOrder: []string{"userid"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the users of a Proxmox Backup Server, for `terraform query`, to import them " +
				"as `pbs_user` resources. Every user PBS has is listed, `root@pam` and the users of other realms " +
				"included, unless `realm` selects one realm.\n\n" +
				"Needs `" + userReadPrivilege + "`; without it, PBS lists only the user the provider signs in as. " +
				"A user's password is write-only and never read: the generated configuration has `password_wo = null " +
				"# sensitive` and `password_wo_version = null`, which plans no change, and the user keeps its " +
				"password. Fill in both only to change the password of a `pbs` user with Terraform, as `pbs_user` " +
				"describes.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{
				"realm": listschema.StringAttribute{
					Optional:            true,
					MarkdownDescription: "List only the users of this realm, such as `pbs`.",
					Validators:          []validator.String{stringvalidator.RegexMatches(realmPattern, "must be a realm name such as pbs or pam")},
				},
			},
		},
		enumerate: listUsers,
	}
}

type userListModel struct {
	Realm types.String `tfsdk:"realm"`
}

func listUsers(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	var filter userListModel
	diags.Append(config.Get(ctx, &filter)...)
	if diags.HasError() {
		return nil
	}
	users, err := data.client.ListUsers(ctx, false)
	if err != nil {
		diags.AddError("Unable to list PBS users", apiErrorDetail(data.client, userReadPrivilege, err))
		return nil
	}
	var objects []listedObject
	for _, user := range users {
		if !filter.Realm.IsNull() && !strings.HasSuffix(user.UserID, "@"+filter.Realm.ValueString()) {
			continue
		}
		objects = append(objects, listedObject{
			identity:    map[string]any{"userid": user.UserID},
			displayName: displayNameWithComment(user.UserID, user.Comment),
		})
	}
	return objects
}

// displayNameWithComment is an object's name followed by its comment, if it
// has one: what Terraform shows next to each result.
func displayNameWithComment(name, comment string) string {
	if comment == "" {
		return name
	}
	return name + " — " + comment
}
