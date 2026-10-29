package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestPropertyStringFormat(t *testing.T) {
	format := propertyStringFormat{defaultKey: "type", keys: []propertyStringKey{
		{"type", "type", types.StringType},
		{"message", "message", types.StringType},
		{"cutoff", "gc-atime-cutoff", types.Int64Type},
		{"check", "gc-atime-safety-check", types.BoolType},
	}}

	for input, want := range map[string]map[string]attr.Value{
		// PBS writes the default key bare and quotes only what needs it.
		"read-only,message=moving disks": {
			"type": types.StringValue("read-only"), "message": types.StringValue("moving disks"),
			"cutoff": types.Int64Null(), "check": types.BoolNull(),
		},
		`type=offline,message="say \"hi\""`: {
			"type": types.StringValue("offline"), "message": types.StringValue(`say "hi"`),
			"cutoff": types.Int64Null(), "check": types.BoolNull(),
		},
		// Booleans in any spelling PBS accepts; keys the format does not
		// know are ignored.
		"gc-atime-cutoff=60,gc-atime-safety-check=0,future-option=1": {
			"type": types.StringNull(), "message": types.StringNull(),
			"cutoff": types.Int64Value(60), "check": types.BoolValue(false),
		},
	} {
		var diags diag.Diagnostics
		got := format.object("test", input, &diags)
		requireNoErrors(t, diags)
		if want := types.ObjectValueMust(format.attributeTypes(), want); !got.Equal(want) {
			t.Errorf("object(%q) = %s, want %s", input, got, want)
		}
	}

	// Nothing, or nothing the format knows, is null.
	for _, input := range []string{"", "  ", "future-option=1"} {
		var diags diag.Diagnostics
		if got := format.object("test", input, &diags); !got.IsNull() || diags.HasError() {
			t.Errorf("object(%q) = %s, %v, want null", input, got, diags)
		}
	}

	// What PBS sends that cannot be read is an error.
	for _, input := range []string{"gc-atime-cutoff=soon", "gc-atime-safety-check=maybe", `message="unterminated`} {
		var diags diag.Diagnostics
		format.object("tuning", input, &diags)
		requireErrorContaining(t, diags, "PBS answered a tuning")
	}

	// format writes the default key's value first and bare, as PBS does, then
	// every other key with its name, sorted, quoting what needs it.
	object := types.ObjectValueMust(format.attributeTypes(), map[string]attr.Value{
		"type": types.StringValue("read-only"), "message": types.StringValue("moving disks"),
		"cutoff": types.Int64Value(1445), "check": types.BoolValue(true),
	})
	got, err := format.format(object)
	if err != nil || got != `read-only,gc-atime-cutoff=1445,gc-atime-safety-check=true,message="moving disks"` {
		t.Errorf("format() = %q, %v", got, err)
	}
	var diags diag.Diagnostics
	if back := format.object("test", got, &diags); !back.Equal(object) || diags.HasError() {
		t.Errorf("object(format()) = %s, %v, want %s", back, diags, object)
	}
}

func TestStringSetOrNull(t *testing.T) {
	var diags diag.Diagnostics
	if got := stringSetOrNull(nil, &diags); !got.IsNull() {
		t.Errorf("stringSetOrNull(nil) = %s", got)
	}
	got := stringSetOrNull([]string{"b", "a"}, &diags)
	requireNoErrors(t, diags)
	if strings := sortedStrings(got.Elements()); len(strings) != 2 || strings[0] != "a" || strings[1] != "b" {
		t.Errorf("elements = %v", strings)
	}
}

// A key that holds a list, such as remove-vanished in a realm's
// sync-defaults-options, is a set: PBS's list in any order, split at
// semicolons, commas and white space, reads as the same set, and the
// provider writes it sorted and separated by semicolons, which need no
// quoting in a property string.
func TestPropertyStringListKey(t *testing.T) {
	format := propertyStringFormat{keys: []propertyStringKey{
		{"enable_new", "enable-new", types.BoolType},
		{"remove_vanished", "remove-vanished", propertyStringListType},
	}}
	set := func(values ...string) types.Set {
		elements := make([]attr.Value, len(values))
		for i, v := range values {
			elements[i] = types.StringValue(v)
		}
		return types.SetValueMust(types.StringType, elements)
	}
	aclAndEntry := types.ObjectValueMust(format.attributeTypes(), map[string]attr.Value{
		"enable_new": types.BoolValue(true), "remove_vanished": set("acl", "entry"),
	})

	for _, input := range []string{
		"enable-new=1,remove-vanished=acl;entry",
		"remove-vanished=entry;acl;entry,enable-new=true",
		`enable-new=yes,remove-vanished="entry, acl"`,
		"enable-new=on,remove-vanished=entry;;acl",
	} {
		var diags diag.Diagnostics
		got := format.object("sync-defaults-options", input, &diags)
		requireNoErrors(t, diags)
		if !got.Equal(aclAndEntry) {
			t.Errorf("object(%q) = %s, want %s", input, got, aclAndEntry)
		}
	}

	var diags diag.Diagnostics
	onlyFlag := format.object("sync-defaults-options", "enable-new=false", &diags)
	requireNoErrors(t, diags)
	if want := types.ObjectValueMust(format.attributeTypes(), map[string]attr.Value{
		"enable_new": types.BoolValue(false), "remove_vanished": types.SetNull(types.StringType),
	}); !onlyFlag.Equal(want) {
		t.Errorf("object(enable-new=false) = %s, want %s", onlyFlag, want)
	}

	for _, tc := range []struct {
		object types.Object
		want   string
	}{
		{aclAndEntry, "enable-new=true,remove-vanished=acl;entry"},
		{types.ObjectValueMust(format.attributeTypes(), map[string]attr.Value{
			"enable_new": types.BoolNull(), "remove_vanished": set("properties", "entry", "acl"),
		}), "remove-vanished=acl;entry;properties"},
	} {
		got, err := format.format(tc.object)
		if err != nil || got != tc.want {
			t.Errorf("format(%s) = %q, %v, want %q", tc.object, got, err, tc.want)
		}
		var diags diag.Diagnostics
		if back := format.object("sync-defaults-options", got, &diags); !back.Equal(tc.object) || diags.HasError() {
			t.Errorf("object(%q) = %s, %v, want %s", got, back, diags, tc.object)
		}
	}

	// A list still unknown cannot be written.
	partlyUnknown := types.ObjectValueMust(format.attributeTypes(), map[string]attr.Value{
		"enable_new": types.BoolNull(), "remove_vanished": types.SetUnknown(types.StringType),
	})
	if _, err := format.format(partlyUnknown); err == nil {
		t.Error("format() wrote an unknown list")
	}
}
