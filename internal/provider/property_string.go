package provider

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Some PBS properties nest options in one parameter, as a property string
// (see pbsclient.PropertyString): a datastore's notify, tuning and
// maintenance-mode, for instance. The schema shows each as a single nested
// attribute with one attribute per key, and a propertyStringFormat converts
// between the two. A null nested attribute is the property left out; a key
// left out of the string is a null attribute.
//
// The provider writes the whole string: keys it does not know, set outside
// Terraform or by a newer PBS, are not kept when it changes the property.

// propertyStringKey is one key of a property string and the attribute of the
// nested object that holds it.
type propertyStringKey struct {
	attribute string
	key       string
	// typ is types.StringType, types.Int64Type, types.BoolType or
	// propertyStringListType.
	typ attr.Type
}

// propertyStringListType is the type of a key that holds a list, such as
// remove-vanished in a realm's sync-defaults-options: a set of strings,
// which the property string separates by semicolons, as commas separate its
// keys. PBS splits such a list at semicolons, commas and white space.
var propertyStringListType = types.SetType{ElemType: types.StringType}

// propertyStringFormat is the set of keys of one property string.
type propertyStringFormat struct {
	// defaultKey is the key a bare value belongs to, when the format has
	// one, such as type in maintenance-mode's "read-only,message=...".
	defaultKey string
	keys       []propertyStringKey
}

// attributeTypes is the type of the nested object, for types.Object values.
func (f propertyStringFormat) attributeTypes() map[string]attr.Type {
	attributeTypes := make(map[string]attr.Type, len(f.keys))
	for _, k := range f.keys {
		attributeTypes[k.attribute] = k.typ
	}
	return attributeTypes
}

// object parses a property string as PBS sends it into the nested object.
// The empty string, a property PBS leaves out, is null, and so is a string
// that holds none of the format's keys.
func (f propertyStringFormat) object(name, s string, diags *diag.Diagnostics) types.Object {
	if strings.TrimSpace(s) == "" {
		return types.ObjectNull(f.attributeTypes())
	}
	parsed, err := pbsclient.ParsePropertyString(s, f.defaultKey)
	if err != nil {
		diags.AddError("Unexpected PBS property string",
			fmt.Sprintf("PBS answered a %s the provider cannot read: %s", name, err))
		return types.ObjectNull(f.attributeTypes())
	}
	values := make(map[string]attr.Value, len(f.keys))
	found := false
	for _, k := range f.keys {
		raw, ok := parsed[k.key]
		values[k.attribute] = propertyValue(k.typ, raw, ok, func(err error) {
			diags.AddError("Unexpected PBS property string",
				fmt.Sprintf("PBS answered a %s whose %s the provider cannot read, %q: %s", name, k.key, raw, err))
		})
		found = found || ok
	}
	if diags.HasError() || !found {
		return types.ObjectNull(f.attributeTypes())
	}
	object, d := types.ObjectValue(f.attributeTypes(), values)
	diags.Append(d...)
	return object
}

// propertyValue converts one value of a property string; ok is false for a
// key the string leaves out.
func propertyValue(typ attr.Type, raw string, ok bool, fail func(error)) attr.Value {
	switch typ {
	case propertyStringListType:
		if !ok {
			return types.SetNull(types.StringType)
		}
		var d diag.Diagnostics
		set := stringSetOrNull(uniqueStrings(pbsclient.SplitList(raw)), &d)
		if d.HasError() {
			fail(fmt.Errorf("%q is not a list", raw))
		}
		return set
	case types.Int64Type:
		if !ok {
			return types.Int64Null()
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			fail(err)
			return types.Int64Null()
		}
		return types.Int64Value(n)
	case byteSizeType{}:
		return byteSizeValue{StringValue: stringOrNull(raw)}
	case types.BoolType:
		if !ok {
			return types.BoolNull()
		}
		b, err := parsePBSBool(raw)
		if err != nil {
			fail(err)
			return types.BoolNull()
		}
		return types.BoolValue(b)
	default:
		if !ok {
			return types.StringNull()
		}
		return types.StringValue(raw)
	}
}

// parsePBSBool reads a boolean the way PBS's schema parser does.
func parsePBSBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%q is not a boolean", s)
}

// format writes a known, non-null nested object as a property string, as PBS
// writes it: the default key's value first and bare, then the other keys,
// sorted, each with its name.
func (f propertyStringFormat) format(object types.Object) (string, error) {
	attributes := object.Attributes()
	p := pbsclient.PropertyString{}
	for _, k := range f.keys {
		value, ok := attributes[k.attribute]
		if !ok || value.IsNull() {
			continue
		}
		if value.IsUnknown() {
			return "", fmt.Errorf("%s is still unknown", k.attribute)
		}
		switch v := value.(type) {
		case types.String:
			p[k.key] = v.ValueString()
		case byteSizeValue:
			p[k.key] = v.ValueString()
		case types.Int64:
			p[k.key] = strconv.FormatInt(v.ValueInt64(), 10)
		case types.Bool:
			p[k.key] = pbsclient.FormatBool(v.ValueBool())
		case types.Set:
			p[k.key] = strings.Join(sortedStrings(v.Elements()), ";")
		default:
			return "", fmt.Errorf("%s has the unexpected type %T", k.attribute, value)
		}
	}
	return p.Format(f.defaultKey), nil
}

// sortedStrings returns the elements of a known set or list of strings,
// sorted, so that a request is the same from one run to the next.
func sortedStrings(elements []attr.Value) []string {
	out := make([]string, 0, len(elements))
	for _, e := range elements {
		if s, ok := e.(types.String); ok && !s.IsNull() && !s.IsUnknown() {
			out = append(out, s.ValueString())
		}
	}
	sort.Strings(out)
	return out
}

// stringSetOrNull maps a list PBS answers to a set, the empty list — a
// property PBS leaves out — to null. PBS keeps an element given twice, which
// a set cannot hold: it is read once, and the next change that sends the set
// writes it once.
func stringSetOrNull(values []string, diags *diag.Diagnostics) types.Set {
	if len(values) == 0 {
		return types.SetNull(types.StringType)
	}
	elements := make([]attr.Value, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			elements = append(elements, types.StringValue(v))
		}
	}
	set, d := types.SetValue(types.StringType, elements)
	diags.Append(d...)
	return set
}
