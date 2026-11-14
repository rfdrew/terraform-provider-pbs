package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// List resources answer `terraform query` (Terraform 1.14 and later), which
// lists the objects of a managed resource type that a `list` block in a
// .tfquery.hcl file selects, and with -generate-config-out writes an import
// block and a resource block for each. OpenTofu has no list resources
// (opentofu/opentofu#3787); it and older Terraform never ask for them.
//
// Each result carries the resource's identity, which the generated import
// block imports by, and — when the list block sets include_resource, which
// -generate-config-out does by itself — the resource's state, which the
// configuration is generated from: by Terraform itself, as framework 1.19
// does not announce its GenerateResourceConfig to Terraform, with the same
// rules (computed-only attributes, sensitive ones and empty optional strings
// left out). That state has to be what importing the
// object gives: `terraform plan` on the generated files imports the object
// (ImportState, then Read) and compares the result with the configuration,
// so any difference is a change in the first plan. importedList therefore
// does not map PBS objects to states itself: it names the objects, and for
// each runs the resource's own ImportState and Read in process, as Terraform
// would. A list block that does not include resources costs one call; one
// that does, one more per object, as many as importing them.
//
// Two adjustments: sensitive attributes are null in the results, because
// `terraform query -json` prints results without redacting anything (the
// generated configuration writes them as `null # sensitive` either way), and
// an object that fails to read is left out with a warning rather than
// failing the whole list block, which an error would.

// listRequirementNote ends the description of every list resource.
const listRequirementNote = "-> List resources need Terraform 1.14 or later; OpenTofu and older Terraform " +
	"releases do not support them. Declare `list` blocks in a `.tfquery.hcl` " +
	"file and run `terraform query`; `terraform query -generate-config-out=generated.tf` writes an `import` " +
	"block and a `resource` block for each object, which `terraform plan` then imports. Sensitive attributes " +
	"are null in the results and in the generated configuration, and write-only ones are never read, so they " +
	"are null there too; the text above says which of them, if any, the generated configuration needs filled in."

// listedObject is one object an enumeration found: the values of the
// resource's identity attributes — strings, or an int64 for the index of
// pbs_apt_repository — and the name Terraform shows next to it.
type listedObject struct {
	identity    map[string]any
	displayName string
}

// sortKey orders objects by their identity: strings as text, numbers by
// value.
func (o listedObject) sortKey(attributes []string) string {
	var b strings.Builder
	for _, name := range attributes {
		switch v := o.identity[name].(type) {
		case int64:
			// Offset to keep negative numbers before positive ones, padded so
			// that text order is number order.
			fmt.Fprintf(&b, "%020d\x00", uint64(v)^(1<<63))
		default:
			fmt.Fprintf(&b, "%v\x00", v)
		}
	}
	return b.String()
}

// importedList lists the objects of a managed resource, as the package
// comment above describes.
type importedList struct {
	// newResource returns the managed resource the list is of; the list
	// takes its name, and imports and reads its objects through it.
	newResource func() resource.Resource
	// schema is the configuration schema of the list block.
	schema listschema.Schema
	// enumerate finds the objects the configuration selects. config is the
	// list block's configuration; an error in diags ends the list.
	enumerate func(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject
	// identityOrder names the identity attributes in the order results are
	// sorted by.
	identityOrder []string

	data *providerData
}

var _ list.ListResourceWithConfigure = &importedList{}

func (l *importedList) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	l.newResource().Metadata(ctx, req, resp)
}

func (l *importedList) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	l.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (l *importedList) ListResourceConfigSchema(_ context.Context, _ list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = l.schema
}

func (l *importedList) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	stream.Results = func(push func(list.ListResult) bool) {
		var diags diag.Diagnostics
		if l.data == nil {
			diags.AddError("Unconfigured PBS provider",
				"The list resource was asked for results before the provider was configured. This is a bug in the provider.")
			push(list.ListResult{Diagnostics: diags})
			return
		}
		objects := l.enumerate(ctx, l.data, req.Config, &diags)
		if len(diags) > 0 {
			if !push(list.ListResult{Diagnostics: diags}) || diags.HasError() {
				return
			}
		}
		slices.SortStableFunc(objects, func(a, b listedObject) int {
			return strings.Compare(a.sortKey(l.identityOrder), b.sortKey(l.identityOrder))
		})

		var r resource.Resource
		if req.IncludeResource {
			r = l.newResource()
			if configurable, ok := r.(resource.ResourceWithConfigure); ok {
				var configured resource.ConfigureResponse
				configurable.Configure(ctx, resource.ConfigureRequest{ProviderData: l.data}, &configured)
				if configured.Diagnostics.HasError() {
					push(list.ListResult{Diagnostics: configured.Diagnostics})
					return
				}
			}
		}

		var listed int64
		for _, object := range objects {
			if ctx.Err() != nil || req.Limit > 0 && listed >= req.Limit {
				return
			}
			result := req.NewListResult(ctx)
			result.DisplayName = object.displayName
			for name, value := range object.identity {
				result.Diagnostics.Append(result.Identity.SetAttribute(ctx, path.Root(name), identityValue(value))...)
			}
			if result.Diagnostics.HasError() {
				push(result)
				return
			}

			if req.IncludeResource {
				state, identity, readDiags := importAndRead(ctx, r, req, result.Identity)
				switch {
				case readDiags.HasError():
					// One object PBS will not show does not void the others.
					var warnings diag.Diagnostics
					for _, d := range readDiags {
						warnings.AddWarning("Left out "+object.displayName+": "+d.Summary(), d.Detail())
					}
					if !push(list.ListResult{Diagnostics: warnings}) {
						return
					}
					continue
				case state == nil:
					// Gone between the listing and the read.
					continue
				}
				result.Resource, result.Identity = state, identity
				result.Diagnostics.Append(readDiags...)
			}

			if !push(result) {
				return
			}
			listed++
		}
	}
}

// identityValue wraps a value of an identity attribute.
func identityValue(value any) attr.Value {
	switch v := value.(type) {
	case int64:
		return types.Int64Value(v)
	case string:
		return types.StringValue(v)
	}
	panic(fmt.Sprintf("unexpected identity value %T", value))
}

// importAndRead imports the object identity names and reads it, as
// Terraform does for an import block, and returns the state Read stored,
// with sensitive values null, and the identity Read recorded. A nil state
// means Read found no such object.
func importAndRead(ctx context.Context, r resource.Resource, req list.ListRequest, identity *tfsdk.ResourceIdentity) (*tfsdk.Resource, *tfsdk.ResourceIdentity, diag.Diagnostics) {
	var diags diag.Diagnostics
	importer, ok := r.(resource.ResourceWithImportState)
	if !ok {
		diags.AddError("Resource cannot be imported", "The list resource lists a resource that has no import. This is a bug in the provider.")
		return nil, nil, diags
	}
	empty := tftypes.NewValue(req.ResourceSchema.Type().TerraformType(ctx), nil)

	imported := resource.ImportStateResponse{
		State:    tfsdk.State{Schema: req.ResourceSchema, Raw: empty},
		Identity: copyIdentity(identity),
	}
	importer.ImportState(ctx, resource.ImportStateRequest{Identity: copyIdentity(identity)}, &imported)
	diags.Append(imported.Diagnostics...)
	if diags.HasError() {
		return nil, nil, diags
	}

	read := resource.ReadResponse{
		State:    tfsdk.State{Schema: req.ResourceSchema, Raw: imported.State.Raw.Copy()},
		Identity: copyIdentity(imported.Identity),
	}
	r.Read(ctx, resource.ReadRequest{State: imported.State, Identity: copyIdentity(imported.Identity)}, &read)
	diags.Append(read.Diagnostics...)
	if diags.HasError() || read.State.Raw.IsNull() {
		return nil, nil, diags
	}

	raw, err := tftypes.Transform(read.State.Raw, func(p *tftypes.AttributePath, v tftypes.Value) (tftypes.Value, error) {
		if v.IsNull() || len(p.Steps()) == 0 {
			return v, nil
		}
		attribute, err := req.ResourceSchema.AttributeAtTerraformPath(ctx, p)
		if err != nil || !attribute.IsSensitive() {
			// Not an attribute: an element of a collection, or an object
			// of a nested attribute, which its own attributes decide.
			return v, nil
		}
		return tftypes.NewValue(v.Type(), nil), nil
	})
	if err != nil {
		diags.AddError("Unable to hide sensitive values", "Removing the sensitive values of the listed object failed. "+
			"This is a bug in the provider: "+err.Error())
		return nil, nil, diags
	}
	return &tfsdk.Resource{Schema: req.ResourceSchema, Raw: raw}, read.Identity, diags
}

// copyIdentity copies an identity, so that a resource's method cannot change
// what its caller holds.
func copyIdentity(identity *tfsdk.ResourceIdentity) *tfsdk.ResourceIdentity {
	if identity == nil {
		return nil
	}
	return &tfsdk.ResourceIdentity{Schema: identity.Schema, Raw: identity.Raw.Copy()}
}
