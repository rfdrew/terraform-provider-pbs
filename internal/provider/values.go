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
