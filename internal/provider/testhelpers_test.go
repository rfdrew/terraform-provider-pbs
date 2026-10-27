package provider

import (
	"context"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test helpers shared by the provider's unit tests, taken from
// terraform-provider-kopia's harness and cut down to what the provider uses
// so far.
//
// tfValue builds a tftypes.Value of a schema's type from plain Go values:
// nil for null, tfUnknown for unknown, strings, bools, numbers, slices for
// lists and sets, and map[string]any for objects, where attributes left out
// are null. dataSourceValue and providerConfigValue build whole objects of a
// data source's or the provider's schema; readDataSource and
// configureProvider run them.
//
// requireNoErrors, requireErrorContaining, requireWarningContaining,
// requireNoWarnings and requireAttributeError check framework diagnostics.

// --- values -----------------------------------------------------------------

// unknownValue is the type of tfUnknown.
type unknownValue struct{}

// tfUnknown marks a value as unknown wherever tfValue accepts a value.
var tfUnknown = unknownValue{}

// tfValue converts a Go value into a tftypes.Value of typ; see the package
// comment above for what it accepts.
func tfValue(t *testing.T, typ tftypes.Type, v any) tftypes.Value {
	t.Helper()
	value, err := toTFValue(typ, v)
	if err != nil {
		t.Fatalf("building a %s value: %v", typ, err)
	}
	return value
}

func toTFValue(typ tftypes.Type, v any) (tftypes.Value, error) {
	switch v := v.(type) {
	case nil:
		return tftypes.NewValue(typ, nil), nil
	case unknownValue:
		return tftypes.NewValue(typ, tftypes.UnknownValue), nil
	case tftypes.Value:
		if !v.Type().Equal(typ) {
			return tftypes.Value{}, fmt.Errorf("value of type %s where %s was expected", v.Type(), typ)
		}
		return v, nil
	}

	switch typ := typ.(type) {
	case tftypes.List:
		elements, err := toTFElements(typ.ElementType, v)
		if err != nil {
			return tftypes.Value{}, err
		}
		return tftypes.NewValue(typ, elements), nil
	case tftypes.Set:
		elements, err := toTFElements(typ.ElementType, v)
		if err != nil {
			return tftypes.Value{}, err
		}
		return tftypes.NewValue(typ, elements), nil
	case tftypes.Map:
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
			return tftypes.Value{}, fmt.Errorf("want a map with string keys for %s, got %T", typ, v)
		}
		elements := make(map[string]tftypes.Value, rv.Len())
		for _, key := range rv.MapKeys() {
			element, err := toTFValue(typ.ElementType, rv.MapIndex(key).Interface())
			if err != nil {
				return tftypes.Value{}, fmt.Errorf("[%q]: %w", key.String(), err)
			}
			elements[key.String()] = element
		}
		return tftypes.NewValue(typ, elements), nil
	case tftypes.Object:
		attrs, ok := v.(map[string]any)
		if !ok {
			return tftypes.Value{}, fmt.Errorf("want map[string]any for an object, got %T", v)
		}
		for name := range attrs {
			if _, ok := typ.AttributeTypes[name]; !ok {
				return tftypes.Value{}, fmt.Errorf("the object has no attribute %q (it has %s)", name, strings.Join(harnessSortedKeys(typ.AttributeTypes), ", "))
			}
		}
		values := make(map[string]tftypes.Value, len(typ.AttributeTypes))
		for name, attrType := range typ.AttributeTypes {
			value, err := toTFValue(attrType, attrs[name])
			if err != nil {
				return tftypes.Value{}, fmt.Errorf(".%s: %w", name, err)
			}
			values[name] = value
		}
		return tftypes.NewValue(typ, values), nil
	}

	switch {
	case typ.Is(tftypes.String):
		s, ok := v.(string)
		if !ok {
			return tftypes.Value{}, fmt.Errorf("want a string, got %T", v)
		}
		return tftypes.NewValue(typ, s), nil
	case typ.Is(tftypes.Bool):
		b, ok := v.(bool)
		if !ok {
			return tftypes.Value{}, fmt.Errorf("want a bool, got %T", v)
		}
		return tftypes.NewValue(typ, b), nil
	case typ.Is(tftypes.Number):
		n, err := toBigFloat(v)
		if err != nil {
			return tftypes.Value{}, err
		}
		return tftypes.NewValue(typ, n), nil
	}
	return tftypes.Value{}, fmt.Errorf("type %s is not supported", typ)
}

func toTFElements(elementType tftypes.Type, v any) ([]tftypes.Value, error) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice {
		return nil, fmt.Errorf("want a slice for a list or set, got %T", v)
	}
	elements := make([]tftypes.Value, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		element, err := toTFValue(elementType, rv.Index(i).Interface())
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		elements = append(elements, element)
	}
	return elements, nil
}

func toBigFloat(v any) (*big.Float, error) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return new(big.Float).SetInt64(rv.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return new(big.Float).SetUint64(rv.Uint()), nil
	case reflect.Float32, reflect.Float64:
		return big.NewFloat(rv.Float()), nil
	}
	if f, ok := v.(*big.Float); ok {
		return f, nil
	}
	return nil, fmt.Errorf("want a number, got %T", v)
}

func harnessSortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// dataSourceSchema returns d's schema, failing the test on a schema error.
func dataSourceSchema(t *testing.T, d datasource.DataSource) datasourceschema.Schema {
	t.Helper()
	var resp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &resp)
	requireNoErrors(t, resp.Diagnostics)
	return resp.Schema
}

// requireValidDataSourceSchema fails the test when d's schema breaks one of the
// framework's rules, which the framework would otherwise only report when
// Terraform first asks for the schema.
func requireValidDataSourceSchema(t *testing.T, d datasource.DataSource) {
	t.Helper()
	requireNoErrors(t, dataSourceSchema(t, d).ValidateImplementation(context.Background()))
}

// dataSourceType is the object type of d's schema.
func dataSourceType(t *testing.T, d datasource.DataSource) tftypes.Type {
	t.Helper()
	return dataSourceSchema(t, d).Type().TerraformType(context.Background())
}

// dataSourceValue builds an object of d's schema; attributes attrs leaves out
// are null.
func dataSourceValue(t *testing.T, d datasource.DataSource, attrs map[string]any) tftypes.Value {
	t.Helper()
	return tfValue(t, dataSourceType(t, d), attrs)
}

// readDataSource runs d.Read with config.
func readDataSource(t *testing.T, d datasource.DataSource, config tftypes.Value) datasource.ReadResponse {
	t.Helper()
	s := dataSourceSchema(t, d)
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: s, Raw: config.Copy()}}
	d.Read(context.Background(), datasource.ReadRequest{Config: tfsdk.Config{Schema: s, Raw: config}}, &resp)
	return resp
}

// providerSchema returns the provider's schema.
func providerSchema(t *testing.T) fwprovider.SchemaResponse {
	t.Helper()
	var resp fwprovider.SchemaResponse
	(&pbsProvider{}).Schema(context.Background(), fwprovider.SchemaRequest{}, &resp)
	requireNoErrors(t, resp.Diagnostics)
	return resp
}

// providerConfigValue builds an object of the provider's schema; attributes
// attrs leaves out are null.
func providerConfigValue(t *testing.T, attrs map[string]any) tftypes.Value {
	t.Helper()
	return tfValue(t, providerSchema(t).Schema.Type().TerraformType(context.Background()), attrs)
}

// configureProvider runs p.Configure with attrs as the provider block.
func configureProvider(t *testing.T, p *pbsProvider, attrs map[string]any) fwprovider.ConfigureResponse {
	t.Helper()
	s := providerSchema(t).Schema
	var resp fwprovider.ConfigureResponse
	p.Configure(context.Background(), fwprovider.ConfigureRequest{
		Config: tfsdk.Config{Schema: s, Raw: providerConfigValue(t, attrs)},
	}, &resp)
	return resp
}

// --- diagnostics ------------------------------------------------------------

func requireNoErrors(t *testing.T, diags diag.Diagnostics) {
	t.Helper()
	if diags.HasError() {
		t.Fatalf("unexpected errors: %v", diags)
	}
}

func requireErrorContaining(t *testing.T, diags diag.Diagnostics, want string) {
	t.Helper()
	for _, d := range diags.Errors() {
		if strings.Contains(d.Detail(), want) || strings.Contains(d.Summary(), want) {
			return
		}
	}
	t.Fatalf("expected an error containing %q, got %v", want, diags)
}

func requireWarningContaining(t *testing.T, diags diag.Diagnostics, want string) {
	t.Helper()
	for _, d := range diags.Warnings() {
		if strings.Contains(d.Detail(), want) || strings.Contains(d.Summary(), want) {
			return
		}
	}
	t.Fatalf("expected a warning containing %q, got %v", want, diags)
}

func requireNoWarnings(t *testing.T, diags diag.Diagnostics) {
	t.Helper()
	if n := diags.WarningsCount(); n != 0 {
		t.Fatalf("unexpected warnings: %v", diags.Warnings())
	}
}

// requireAttributeError fails the test unless an error is attached to the
// attribute at attributePath, written as "a.b.c".
func requireAttributeError(t *testing.T, diags diag.Diagnostics, attributePath string) {
	t.Helper()
	requireAttributeDiagnostic(t, diags.Errors(), attributePath, "error")
}

func requireAttributeDiagnostic(t *testing.T, diags diag.Diagnostics, attributePath, kind string) {
	t.Helper()
	for _, d := range diags {
		if withPath, ok := d.(diag.DiagnosticWithPath); ok && withPath.Path().String() == attributePath {
			return
		}
	}
	t.Fatalf("expected an %s on %s, got %v", kind, attributePath, diags)
}
