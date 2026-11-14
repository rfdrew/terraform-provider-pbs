package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestSameJSONDocument(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{`{"text": "{{ escape title }}"}`, `{"text":"{{ escape title }}"}`, true},
		{"{\n  \"b\": 1,\n  \"a\": \"x & y\"\n}", `{"a":"x & y","b":1}`, true},
		{`[1.0, 2e0]`, `[1,2]`, true},
		{`{"a": 1}`, `{"a": "1"}`, false},
		{`{"a": 1}`, `{"a": 2}`, false},
		{`{"a": 1}`, `{"a": 1, "b": null}`, false},
		// Templates that are not JSON yet, and JSON scalars, are compared as
		// text by the caller.
		{`{"n": {{ count }}}`, `{"n":{{ count }}}`, false},
		{`"x"`, `"x"`, false},
		{`{"a": 1} trailing`, `{"a":1}`, false},
		{`{"a":1}}`, `{"a":1}`, false},
		{`[1]]`, `[1]`, false},
	} {
		if got := sameJSONDocument(tc.a, tc.b); got != tc.same {
			t.Errorf("sameJSONDocument(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}

func TestKeepSameJSON(t *testing.T) {
	prior := types.StringValue("{\n  \"b\": [1, 2],\n  \"a\": \"x\"\n}")
	for _, tc := range []struct {
		prior types.String
		read  string
		want  types.String
	}{
		{prior, `{"a":"x","b":[1,2]}`, prior},
		{prior, `{"a":"x","b":[2,1]}`, types.StringValue(`{"a":"x","b":[2,1]}`)},
		{prior, "", types.StringNull()},
		{types.StringNull(), `{"a":"x"}`, types.StringValue(`{"a":"x"}`)},
		{types.StringUnknown(), `{"a":"x"}`, types.StringValue(`{"a":"x"}`)},
	} {
		if got := keepSameJSON(tc.prior, tc.read); !got.Equal(tc.want) {
			t.Errorf("keepSameJSON(%s, %q) = %s, want %s", tc.prior, tc.read, got, tc.want)
		}
	}
}
