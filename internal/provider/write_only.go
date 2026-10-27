package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Secrets that PBS accepts but never returns — a user's password, a remote's
// password, an SMTP password — are write-only attributes, in pairs:
//
//   - <name>_wo, WriteOnly and Sensitive: Terraform hands it to the provider
//     in the configuration of every plan and apply, and stores it nowhere,
//     neither in the plan nor in state. It may be an ephemeral value.
//   - <name>_wo_version, an Int64 Terraform does store. The provider sends the
//     secret when the object is created and whenever the version changes, and
//     at no other time: it cannot tell whether the secret itself changed.
//
// Each requires the other, so that a secret cannot be given without a way to
// change it, or a version without a secret to send. Removing both leaves the
// secret on the server as it is. Write-only attributes need Terraform or
// OpenTofu 1.11 or later; older releases are refused by the framework with
// "WriteOnly Attribute Not Allowed".

// writeOnlySecretAttributes returns the pair of attributes for the secret
// called name: name_wo, described by secretDescription and checked by
// validators, and name_wo_version.
func writeOnlySecretAttributes(name, secretDescription string, validators ...validator.String) (secret schema.StringAttribute, version schema.Int64Attribute) {
	secretAttr, versionAttr := name+"_wo", name+"_wo_version"
	secret = schema.StringAttribute{
		Optional:  true,
		WriteOnly: true,
		Sensitive: true,
		MarkdownDescription: secretDescription + " Write-only: Terraform passes it to PBS without storing it in the " +
			"plan or state, and PBS never returns it, so a change made outside Terraform goes unnoticed. PBS " +
			"receives it when the object is created and whenever `" + versionAttr + "` changes. Requires `" +
			versionAttr + "`, and Terraform or OpenTofu 1.11 or later.",
		Validators: append([]validator.String{
			stringvalidator.AlsoRequires(path.MatchRoot(versionAttr)),
		}, validators...),
	}
	version = schema.Int64Attribute{
		Optional: true,
		MarkdownDescription: "Version of `" + secretAttr + "`, which Terraform stores in its place. Change it — " +
			"increment it, say — to send a new `" + secretAttr + "`; removing it, with `" + secretAttr + "`, " +
			"leaves the value on the server as it is. Requires `" + secretAttr + "`.",
		Validators: []validator.Int64{
			int64validator.AlsoRequires(path.MatchRoot(secretAttr)),
		},
	}
	return secret, version
}

// writeOnlySecret returns the value of name_wo. Write-only values reach the
// provider only in the configuration, so it is read from there; ok is false
// when it is null or unknown.
func writeOnlySecret(ctx context.Context, config tfsdk.Config, name string, diags *diag.Diagnostics) (value string, ok bool) {
	var secret types.String
	diags.Append(config.GetAttribute(ctx, path.Root(name+"_wo"), &secret)...)
	if secret.IsNull() || secret.IsUnknown() {
		return "", false
	}
	return secret.ValueString(), true
}

// writeOnlyChanged reports whether a plan sends a write-only secret: its
// version is set and differs from the prior one, which is null for a create.
// A version that is still unknown counts as changed.
func writeOnlyChanged(plan, prior types.Int64) bool {
	return !plan.IsNull() && !plan.Equal(prior)
}
