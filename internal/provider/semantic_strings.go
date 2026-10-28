package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Some PBS properties take one value in several spellings and store another
// than they were given: a rate limit of "10MiB" reads back as "10 MiB", and a
// certificate fingerprint may be written in upper case or without colons.
// Attributes for them are strings of a custom type with semantic equality:
// when what PBS reports stands for the same value as the configuration, the
// framework keeps the configuration's spelling in state — after a create or
// update, the planned value; after a refresh, the prior state — so neither
// the plan nor the apply shows a difference. The framework compares no
// values while it plans, and the attributes are not computed, so a plan
// shows a new spelling, and an import, which has no prior spelling to keep,
// PBS's; the resources then send nothing for it.

// stringSemantics says when two spellings of a property stand for the same
// value.
type stringSemantics interface {
	// equal reports whether a and b stand for the same value.
	equal(a, b string) bool
	// typeName names the attribute type, for messages.
	typeName() string
}

// byteSizeSemantics compares byte sizes, such as rate and burst limits, by
// the number of bytes they stand for.
type byteSizeSemantics struct{}

func (byteSizeSemantics) equal(a, b string) bool { return pbsclient.SameByteSize(a, b) }
func (byteSizeSemantics) typeName() string       { return "byteSizeType" }

// fingerprintSemantics compares SHA-256 certificate fingerprints whatever
// their case and separators.
type fingerprintSemantics struct{}

func (fingerprintSemantics) equal(a, b string) bool {
	if a == b {
		return true
	}
	x, errA := pbsclient.NormaliseFingerprint(a)
	y, errB := pbsclient.NormaliseFingerprint(b)
	return errA == nil && errB == nil && x == y
}
func (fingerprintSemantics) typeName() string { return "fingerprintType" }

// semanticStringType is a string attribute type whose values compare as S
// says.
type semanticStringType[S stringSemantics] struct {
	basetypes.StringType
}

// semanticStringValue is a value of semanticStringType.
type semanticStringValue[S stringSemantics] struct {
	basetypes.StringValue
}

// The two kinds the provider uses.
type (
	byteSizeType     = semanticStringType[byteSizeSemantics]
	byteSizeValue    = semanticStringValue[byteSizeSemantics]
	fingerprintType  = semanticStringType[fingerprintSemantics]
	fingerprintValue = semanticStringValue[fingerprintSemantics]
)

var (
	_ basetypes.StringTypable                    = byteSizeType{}
	_ basetypes.StringValuableWithSemanticEquals = byteSizeValue{}
	_ basetypes.StringTypable                    = fingerprintType{}
	_ basetypes.StringValuableWithSemanticEquals = fingerprintValue{}
)

func (t semanticStringType[S]) Equal(o attr.Type) bool {
	_, ok := o.(semanticStringType[S])
	return ok
}

func (t semanticStringType[S]) String() string {
	var s S
	return s.typeName()
}

func (t semanticStringType[S]) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return semanticStringValue[S]{StringValue: in}, nil
}

func (t semanticStringType[S]) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	value, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	stringValue, ok := value.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T", value)
	}
	return semanticStringValue[S]{StringValue: stringValue}, nil
}

func (t semanticStringType[S]) ValueType(_ context.Context) attr.Value {
	return semanticStringValue[S]{}
}

func (v semanticStringValue[S]) Equal(o attr.Value) bool {
	other, ok := o.(semanticStringValue[S])
	return ok && v.StringValue.Equal(other.StringValue)
}

func (v semanticStringValue[S]) Type(_ context.Context) attr.Type {
	return semanticStringType[S]{}
}

// StringSemanticEquals reports whether the new value stands for the same as
// v. The framework calls it with known values only.
func (v semanticStringValue[S]) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	newValue, ok := newValuable.(semanticStringValue[S])
	if !ok {
		diags.AddError("Semantic equality check error",
			fmt.Sprintf("Expected a value of type %T, got %T. This is a bug in the provider.", v, newValuable))
		return false, diags
	}
	var s S
	return s.equal(v.ValueString(), newValue.ValueString()), diags
}

// byteSizeOrNull is the byte size PBS reports, null when it leaves the
// property out.
func byteSizeOrNull(s string) byteSizeValue {
	return byteSizeValue{StringValue: stringOrNull(s)}
}

// fingerprintOrNull is the fingerprint PBS reports, null when it leaves the
// property out.
func fingerprintOrNull(s string) fingerprintValue {
	return fingerprintValue{StringValue: stringOrNull(s)}
}
