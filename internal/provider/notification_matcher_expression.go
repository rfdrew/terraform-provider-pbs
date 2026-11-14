package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// A matcher's expression, from PBS 4.2.10 (proxmox-notify 2.0), is one JSON
// rule tree, read in proxmox-match-expression's lib.rs (Expression) and
// proxmox-notify's matcher/mod.rs (ensure_valid), expression.rs, field.rs,
// severity.rs and calendar.rs:
//
//   - a rule is an object with one key: all-of, any-of or one-of with a list
//     of rules, not with a rule, constant with true or false, or match with
//     a test of the notification, tagged by its type;
//   - PBS refuses an all-of, any-of or one-of without rules, a field test
//     without values, a severity test without severities, a field name
//     that is not a safe ID, and a field test with both values and regex;
//   - a key PBS does not know is refused in a rule, in its list and in a
//     field test, but dropped silently from a severity or calendar test;
//     an object with a key twice is refused, and so is an escape of half a
//     UTF-16 surrogate pair, such as \ud800, which encoding/json reads as
//     U+FFFD;
//   - PBS stores the expression as serde_json writes it, which escapes
//     U+0000 to U+001F but not U+007F to U+009F, and the section config
//     refuses a line with a control character ("detected unexpected
//     control character"), so a string holding one of those fails;
//   - serde_json, which PBS parses the expression with, refuses objects and
//     lists nested more than matchExpressionMaxDepth deep (its recursion
//     limit of 128, which PBS leaves on);
//   - PBS stores the tree compacted, with the keys in the order of its own
//     types, such as {"match":{"type":"field","field":"type","values":[…]}},
//     and an all-of, any-of or one-of keeps its rules in their order;
//   - an expression is mutually exclusive with match-field, match-severity,
//     match-calendar, mode and invert-match, the last two even at their
//     defaults: a create or update that leaves both fails with 400 "invalid
//     matcher config: 'expression' property is mutually exclusive with: …".
//     An update applies its delete first, so one update switches between
//     the two.
//
// matchExpressionValidator refuses at plan time what PBS would refuse, and
// what it would drop silently, as that would change the expression on every
// plan. It does not check regular expressions, which PBS compiles with Rust's
// regex crate, nor schedules, which it parses as calendar events.

// The keys of a rule and the types of a match test, as PBS names them.
var (
	matchExpressionRuleKeys   = []string{"all-of", "any-of", "one-of", "not", "constant", "match"}
	matchExpressionMatchTypes = []string{"field", "severity", "calendar"}
	matchExpressionSeverities = []string{"info", "notice", "warning", "error", "unknown"}
)

// matchExpressionMaxDepth is how deep objects and lists nest at most in an
// expression PBS reads: serde_json counts down from 128 on entering each and
// fails when it reaches 0.
const matchExpressionMaxDepth = 127

// matchExpressionValidator checks a matcher's expression.
type matchExpressionValidator struct{}

func (matchExpressionValidator) Description(context.Context) string {
	return "must be a match expression: a JSON rule tree as PBS stores it"
}

func (v matchExpressionValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (matchExpressionValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if err := checkMatchExpression(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid match expression",
			fmt.Sprintf("%s. A rule is an object with one key: all-of, any-of or one-of with a list of rules, not "+
				"with a rule, constant with true or false, or match with a test such as {\"type\": \"severity\", "+
				"\"severities\": [\"error\"]}; see the resource's documentation.", err))
	}
}

// checkMatchExpression reports what is wrong with expression, or nil.
func checkMatchExpression(expression string) error {
	if !json.Valid([]byte(expression)) {
		return errors.New("the expression is not valid JSON")
	}
	if hasLoneSurrogateEscape(expression) {
		return errors.New(`the expression escapes half of a UTF-16 surrogate pair without the other half, such as "\ud800", which PBS refuses`)
	}
	decoder := json.NewDecoder(strings.NewReader(expression))
	decoder.UseNumber()
	tree, err := decodeJSONNoDuplicates(decoder, "", 0)
	if err != nil {
		return err
	}
	return checkMatchRule(tree, "")
}

// decodeJSONNoDuplicates decodes the next JSON value of decoder, refusing an
// object with a key twice, which encoding/json would take the last of, and
// objects and lists nested deeper than PBS reads. at is where the value is,
// for the error, and depth how many objects and lists it is inside.
func decodeJSONNoDuplicates(decoder *json.Decoder, at string, depth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if (token == json.Delim('{') || token == json.Delim('[')) && depth == matchExpressionMaxDepth {
		return nil, fmt.Errorf("%s nests objects and lists more than %d deep, more than PBS reads", matchExpressionPlace(at),
			matchExpressionMaxDepth)
	}
	switch token {
	case json.Delim('{'):
		object := map[string]any{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			name, _ := key.(string)
			if _, twice := object[name]; twice {
				return nil, fmt.Errorf("%s has the key %q twice", matchExpressionPlace(at), name)
			}
			if object[name], err = decodeJSONNoDuplicates(decoder, matchExpressionPath(at, name), depth+1); err != nil {
				return nil, err
			}
		}
		_, err = decoder.Token()
		return object, err
	case json.Delim('['):
		list := []any{}
		for decoder.More() {
			value, err := decodeJSONNoDuplicates(decoder, fmt.Sprintf("%s[%d]", at, len(list)), depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, value)
		}
		_, err = decoder.Token()
		return list, err
	default:
		if s, ok := token.(string); ok && strings.ContainsFunc(s, isUnescapedControl) {
			return nil, fmt.Errorf("%s holds a control character from U+007F to U+009F, which PBS cannot store",
				matchExpressionPlace(at))
		}
		return token, nil
	}
}

// checkMatchRule checks the rule v at at.
func checkMatchRule(v any, at string) error {
	rule, ok := v.(map[string]any)
	if !ok || len(rule) != 1 {
		return fmt.Errorf("%s must be an object with exactly one key: %s", matchExpressionPlace(at),
			strings.Join(matchExpressionRuleKeys, ", "))
	}
	for key, value := range rule {
		inner := matchExpressionPath(at, key)
		switch key {
		case "all-of", "any-of", "one-of":
			rules, ok := value.([]any)
			if !ok || len(rules) == 0 {
				return fmt.Errorf("%s must be a list of at least one rule", matchExpressionPlace(inner))
			}
			for i, r := range rules {
				if err := checkMatchRule(r, fmt.Sprintf("%s[%d]", inner, i)); err != nil {
					return err
				}
			}
		case "not":
			return checkMatchRule(value, inner)
		case "constant":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%s must be true or false", matchExpressionPlace(inner))
			}
		case "match":
			return checkMatchTest(value, inner)
		default:
			return fmt.Errorf("%s is not a rule PBS knows; a rule is one of %s", matchExpressionPlace(inner),
				strings.Join(matchExpressionRuleKeys, ", "))
		}
	}
	return nil
}

// checkMatchTest checks the test of a match rule, v at at.
func checkMatchTest(v any, at string) error {
	test, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be an object with a type: %s", matchExpressionPlace(at),
			strings.Join(matchExpressionMatchTypes, ", "))
	}
	kind, _ := test["type"].(string)
	var keys []string
	switch kind {
	case "field":
		field, ok := test["field"].(string)
		if !ok || !safeIDPattern.MatchString(field) {
			return fmt.Errorf("%s must be the name of a notification field, such as \"type\" or \"job-id\": letters, "+
				"digits, _, . and -, not starting with . or -", matchExpressionPlace(matchExpressionPath(at, "field")))
		}
		values, hasValues := test["values"]
		regex, hasRegex := test["regex"]
		switch {
		case hasValues == hasRegex:
			return fmt.Errorf("%s must have either values or regex", matchExpressionPlace(at))
		case hasValues:
			keys = []string{"type", "field", "values"}
			if !isNonEmptyStringList(values, nil) {
				return fmt.Errorf("%s must be a list of at least one string", matchExpressionPlace(matchExpressionPath(at, "values")))
			}
		default:
			keys = []string{"type", "field", "regex"}
			if _, ok := regex.(string); !ok {
				return fmt.Errorf("%s must be a regular expression, as a string", matchExpressionPlace(matchExpressionPath(at, "regex")))
			}
		}
	case "severity":
		keys = []string{"type", "severities"}
		if !isNonEmptyStringList(test["severities"], matchExpressionSeverities) {
			return fmt.Errorf("%s must be a list of at least one severity: %s", matchExpressionPlace(matchExpressionPath(at, "severities")),
				strings.Join(matchExpressionSeverities, ", "))
		}
	case "calendar":
		keys = []string{"type", "schedule"}
		if schedule, ok := test["schedule"].(string); !ok || strings.TrimSpace(schedule) == "" {
			return fmt.Errorf("%s must be a time range with optional days, such as \"mon..fri 8-17\"",
				matchExpressionPlace(matchExpressionPath(at, "schedule")))
		}
	default:
		return fmt.Errorf("%s must be %s", matchExpressionPlace(matchExpressionPath(at, "type")),
			strings.Join(matchExpressionMatchTypes, ", "))
	}
	var unknown []string
	for key := range test {
		if !slices.Contains(keys, key) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("%s has %s, which a %s test does not take; it takes %s", matchExpressionPlace(at),
			strings.Join(unknown, ", "), kind, strings.Join(keys, ", "))
	}
	return nil
}

// isNonEmptyStringList reports whether v is a list of at least one string,
// each one of allowed unless that is nil.
func isNonEmptyStringList(v any, allowed []string) bool {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return false
	}
	for _, e := range list {
		s, ok := e.(string)
		if !ok || (allowed != nil && !slices.Contains(allowed, s)) {
			return false
		}
	}
	return true
}

// matchExpressionPath is the path of key inside the value at at, such as
// all-of[0].match.
func matchExpressionPath(at, key string) string {
	if at == "" {
		return key
	}
	return at + "." + key
}

// matchExpressionPlace names the value at at in an error.
func matchExpressionPlace(at string) string {
	if at == "" {
		return "the expression"
	}
	return "`" + at + "`"
}

// hasLoneSurrogateEscape reports whether the JSON text s, which must be
// valid, escapes half of a UTF-16 surrogate pair without the other half, as
// "\ud800" or "\udc00" alone does.
func hasLoneSurrogateEscape(s string) bool {
	hex := func(i int) uint64 {
		n, _ := strconv.ParseUint(s[i:i+4], 16, 16)
		return n
	}
	inString := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '"':
			inString = !inString
		case s[i] == '\\' && inString:
			i++
			if s[i] != 'u' {
				continue
			}
			r := hex(i + 1)
			i += 4
			switch {
			case r >= 0xd800 && r <= 0xdbff:
				// A high half needs a low one next.
				if i+6 < len(s) && s[i+1] == '\\' && s[i+2] == 'u' {
					if low := hex(i + 3); low >= 0xdc00 && low <= 0xdfff {
						i += 6
						continue
					}
				}
				return true
			case r >= 0xdc00 && r <= 0xdfff:
				return true
			}
		}
	}
	return false
}

// isUnescapedControl reports whether r is a control character serde_json
// writes as it is: DEL and the C1 controls.
func isUnescapedControl(r rune) bool {
	return r >= 0x7f && r <= 0x9f
}
