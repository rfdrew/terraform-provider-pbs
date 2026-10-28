package provider

import "github.com/hashicorp/terraform-plugin-framework/types"

// stringOrNull maps the empty string, which is how PBS's answers leave out a
// property, to null, which is how a configuration leaves it out.
func stringOrNull(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// stringOr is s, or def when PBS leaves the property out.
func stringOr(s, def string) types.String {
	if s == "" {
		return types.StringValue(def)
	}
	return types.StringValue(s)
}

// boolOr is *b, or def when PBS leaves the property out.
func boolOr(b *bool, def bool) types.Bool {
	if b == nil {
		return types.BoolValue(def)
	}
	return types.BoolValue(*b)
}

// int64OrNull is *n, or null when PBS leaves the property out.
func int64OrNull(n *int64) types.Int64 {
	if n == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*n)
}

// int64Or is *n, or def when PBS leaves the property out.
func int64Or(n *int64, def int64) types.Int64 {
	if n == nil {
		return types.Int64Value(def)
	}
	return types.Int64Value(*n)
}
