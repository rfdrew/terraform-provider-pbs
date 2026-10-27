package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestPropertyChanges(t *testing.T) {
	var diags diag.Diagnostics
	c := newPropertyChanges(&diags, "comment", "email")
	c.String("comment", types.StringNull(), types.StringValue("old"))  // deleted
	c.String("email", types.StringNull(), types.StringValue("a@b"))    // deleted
	c.String("firstname", types.StringValue("Al"), types.StringNull()) // set
	c.String("lastname", types.StringValue("Same"), types.StringValue("Same"))
	c.Bool("enable", types.BoolValue(false), types.BoolValue(true))
	c.Int64("expire", types.Int64Value(0), types.Int64Value(1700000000))
	requireNoErrors(t, diags)

	values := c.Values()
	want := map[string][]string{
		"delete":    {"comment", "email"},
		"firstname": {"Al"},
		"enable":    {"false"},
		"expire":    {"0"},
	}
	if len(values) != len(want) {
		t.Fatalf("values = %v, want %v", values, want)
	}
	for name, v := range want {
		if got := values[name]; len(got) != len(v) || got[0] != v[0] || (len(v) > 1 && got[1] != v[1]) {
			t.Errorf("%s = %v, want %v", name, got, v)
		}
	}
	if c.Empty() {
		t.Error("Empty() with changes")
	}

	// Values hands out a copy.
	values.Set("firstname", "changed")
	if c.Values().Get("firstname") != "Al" {
		t.Error("Values() shares its map")
	}
}

func TestPropertyChangesWithoutChanges(t *testing.T) {
	var diags diag.Diagnostics
	c := newPropertyChanges(&diags)
	c.String("comment", types.StringNull(), types.StringNull())
	c.Bool("enable", types.BoolValue(true), types.BoolValue(true))
	requireNoErrors(t, diags)
	if !c.Empty() || len(c.Values()) != 0 {
		t.Errorf("values = %v, want none", c.Values())
	}
}

// Unsetting a property PBS cannot delete, or sending one that is still
// unknown, is a bug in the provider, and says so.
func TestPropertyChangesRefusesWhatPBSCannotDo(t *testing.T) {
	var diags diag.Diagnostics
	c := newPropertyChanges(&diags, "comment")
	c.Int64("expire", types.Int64Null(), types.Int64Value(5))
	requireErrorContaining(t, diags, `PBS cannot delete the property "expire"`)

	diags = nil
	c = newPropertyChanges(&diags)
	c.String("comment", types.StringUnknown(), types.StringNull())
	requireErrorContaining(t, diags, `"comment" was still unknown`)
}

func TestWriteOnlyChanged(t *testing.T) {
	for _, tc := range []struct {
		plan, prior types.Int64
		want        bool
	}{
		{types.Int64Null(), types.Int64Null(), false},
		{types.Int64Null(), types.Int64Value(1), false},
		{types.Int64Value(1), types.Int64Value(1), false},
		{types.Int64Value(1), types.Int64Null(), true},
		{types.Int64Value(2), types.Int64Value(1), true},
		{types.Int64Unknown(), types.Int64Value(1), true},
	} {
		if got := writeOnlyChanged(tc.plan, tc.prior); got != tc.want {
			t.Errorf("writeOnlyChanged(%s, %s) = %v, want %v", tc.plan, tc.prior, got, tc.want)
		}
	}
}

// The pair of attributes is write-only, sensitive and not stored on one side,
// stored on the other, and each requires the other.
func TestWriteOnlySecretAttributes(t *testing.T) {
	secret, version := writeOnlySecretAttributes("password", "The password.")
	if !secret.WriteOnly || !secret.Sensitive || secret.Computed || version.Computed || version.WriteOnly {
		t.Errorf("secret = %+v, version = %+v", secret, version)
	}
	if len(secret.Validators) != 1 || len(version.Validators) != 1 {
		t.Errorf("validators: %d and %d, want AlsoRequires on each", len(secret.Validators), len(version.Validators))
	}

	s := schema.Schema{Attributes: map[string]schema.Attribute{"password_wo": secret, "password_wo_version": version}}
	typ := s.Type().TerraformType(context.Background())
	config := tfsdk.Config{Schema: s, Raw: tfValue(t, typ, map[string]any{"password_wo": "hunter22", "password_wo_version": 1})}
	var diags diag.Diagnostics
	if got, ok := writeOnlySecret(context.Background(), config, "password", &diags); !ok || got != "hunter22" {
		t.Errorf("writeOnlySecret() = %q, %v", got, ok)
	}
	requireNoErrors(t, diags)

	config.Raw = tfValue(t, typ, map[string]any{"password_wo": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)})
	if _, ok := writeOnlySecret(context.Background(), config, "password", &diags); ok {
		t.Error("writeOnlySecret() reports an unknown value as set")
	}
}
