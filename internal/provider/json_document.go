package provider

import (
	"context"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// String attributes that hold a JSON document — a webhook's body, a
// matcher's expression — compare by the document, not by its text: the
// same document written another way is no change.
//
//   - Terraform generates the configuration of an imported or listed object
//     with a JSON object or array in a string attribute written as
//     `jsonencode(…)`, which gives the document compacted, its keys sorted
//     and <, > and & escaped (hashicorp/terraform
//     internal/genconfig/generate_config.go), so the attribute would change
//     on the first apply of such a configuration, to the same document.
//   - PBS rewrites some documents it stores, such as a matcher's expression,
//     which it decodes and encodes again, compacted and with its keys in the
//     order of its own types, so what it reads back differs from what it
//     was sent.
//
// sameJSONKeepsPrior plans the prior value for the first case, and
// keepSameJSON keeps the prior value in state for the second. Terraform
// accepts the prior value as the plan of an attribute that is not
// computed, which is what semantic equality amounts to; the framework does
// not consult semantic equality while planning.

// sameJSONKeepsPrior plans the prior value of a string attribute when the
// configuration holds the same JSON document written another way.
type sameJSONKeepsPrior struct{}

func (sameJSONKeepsPrior) Description(context.Context) string {
	return "A JSON document written another way is no change."
}

func (m sameJSONKeepsPrior) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (sameJSONKeepsPrior) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.StateValue.IsNull() || req.StateValue.IsUnknown() || req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() ||
		req.ConfigValue.Equal(req.StateValue) {
		return
	}
	if sameJSONDocument(req.ConfigValue.ValueString(), req.StateValue.ValueString()) {
		resp.PlanValue = req.StateValue
	}
}

// keepSameJSON returns what to record for a string attribute that PBS
// reports as read, empty when PBS has none: prior, the value the plan or
// the state holds, when it is the same JSON document, and otherwise read.
func keepSameJSON(prior types.String, read string) types.String {
	switch {
	case read == "":
		return types.StringNull()
	case !prior.IsNull() && !prior.IsUnknown() && sameJSONDocument(prior.ValueString(), read):
		return prior
	default:
		return types.StringValue(read)
	}
}

// sameJSONDocument reports whether a and b are JSON objects or arrays with
// the same contents, numbers compared by value, as jsonencode writes 1.0 as
// 1.
func sameJSONDocument(a, b string) bool {
	decode := func(s string) (any, bool) {
		trimmed := strings.TrimSpace(s)
		// One document and nothing else: the decoder alone would take a
		// stray closing bracket after it.
		if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') || !json.Valid([]byte(trimmed)) {
			return nil, false
		}
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		decoder.UseNumber()
		var v any
		if decoder.Decode(&v) != nil || decoder.More() {
			return nil, false
		}
		return canonicalJSONNumbers(v), true
	}
	va, okA := decode(a)
	vb, okB := decode(b)
	return okA && okB && reflect.DeepEqual(va, vb)
}

// jsonNumberValue is a JSON number by its exact value.
type jsonNumberValue string

// canonicalJSONNumbers replaces the numbers of a decoded JSON document by
// their exact values, so that 1, 1.0 and 1e0 compare equal.
func canonicalJSONNumbers(v any) any {
	switch v := v.(type) {
	case json.Number:
		// A type of its own, so that the number 1 and the string "1" stay
		// apart.
		if r, ok := new(big.Rat).SetString(v.String()); ok {
			return jsonNumberValue(r.RatString())
		}
		return jsonNumberValue(v.String())
	case map[string]any:
		for k, e := range v {
			v[k] = canonicalJSONNumbers(e)
		}
	case []any:
		for i, e := range v {
			v[i] = canonicalJSONNumbers(e)
		}
	}
	return v
}
