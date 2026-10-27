package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Resource identity is the small object Terraform 1.12 and later store next to
// a resource's state to say which remote object it is, and accept in an import
// block's `identity` argument instead of an import id. Every resource here is
// identified by strings that never change while the object exists and that
// Read always knows, because they are what Read looks up:
//
//   - pbs_user by its user ID, such as `alice@pbs`;
//   - pbs_api_token by its token ID, such as `alice@pbs!ci`;
//   - pbs_acl by its path, user or token ID and role together.
//
// The framework requires an identity after every successful create, read and
// update of a resource that declares one, whether or not Terraform supports
// identities. Older Terraform neither sends nor stores it and is otherwise
// unaffected.

// identityAttribute is one string attribute of an identity.
type identityAttribute struct {
	name        string
	description string
}

// stringIdentitySchema is the identity of a resource identified by one or
// more strings, all required to import it.
func stringIdentitySchema(attributes ...identityAttribute) identityschema.Schema {
	s := identityschema.Schema{Attributes: map[string]identityschema.Attribute{}}
	for _, a := range attributes {
		s.Attributes[a.name] = identityschema.StringAttribute{
			RequiredForImport: true,
			Description:       a.description,
		}
	}
	return s
}

// setIdentity records value as the identity attribute of the given name.
// identity is nil only when a method is called directly rather than through
// the framework, and an empty value has nothing to record.
//
// Read calls it with the values from state before looking the object up. A
// refresh that finds the object gone drops it from state without an error,
// and the framework still requires an identity then whenever state had none
// yet — state written by Terraform before 1.12 — failing the refresh with
// "Missing Resource Identity After Read" otherwise.
func setIdentity(ctx context.Context, identity *tfsdk.ResourceIdentity, attribute, value string, diags *diag.Diagnostics) {
	if identity == nil || value == "" {
		return
	}
	diags.Append(identity.SetAttribute(ctx, path.Root(attribute), value)...)
}

// importedID returns what an import names the resource by: the import id, in
// whatever form the resource accepts, or — for an import block that used
// `identity` — the identity attributes of the given names, in that order.
// byIdentity tells the two apart; for an import id, values is nil.
func importedID(ctx context.Context, req resource.ImportStateRequest, diags *diag.Diagnostics, attributes ...string) (id string, values []string, byIdentity bool) {
	if req.ID != "" || req.Identity == nil {
		return req.ID, nil, false
	}
	var missing []string
	for _, attribute := range attributes {
		var value types.String
		diags.Append(req.Identity.GetAttribute(ctx, path.Root(attribute), &value)...)
		if value.ValueString() == "" {
			missing = append(missing, "`"+attribute+"`")
		}
		values = append(values, value.ValueString())
	}
	if diags.HasError() {
		return "", nil, true
	}
	if len(missing) > 0 {
		diags.AddError(
			"Missing import identity",
			"The import block's identity must set "+strings.Join(missing, " and ")+" to name the PBS object to import.",
		)
		return "", nil, true
	}
	return "", values, true
}
