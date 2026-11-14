package provider

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// testMatcherExpression is a matcher's rules as PBS 4.2.10 and later store
// them: one rule tree, compacted, with each match test's type first, here
// matching notifications of severity error (proxmox-match-expression's
// Expression and proxmox-notify's matcher/expression.rs,
// NotificationMatcher).
const testMatcherExpression = `{"all-of":[{"match":{"type":"severity","severities":["error"]}}]}`

// The example of PBS's documentation (docs/notifications.rst, Match
// Expression Reference), written by hand with its keys in another order,
// and as PBS stores it.
const (
	testMatcherExpressionPretty = `{
  "all-of": [
    {
      "any-of": [
        {"match": {"schedule": "mon..fri 09:00-17:00", "type": "calendar"}},
        {"match": {"severities": ["warning", "error"], "type": "severity"}}
      ]
    },
    {"match": {"values": ["gc"], "field": "type", "type": "field"}}
  ]
}`
	testMatcherExpressionStored = `{"all-of":[{"any-of":[{"match":{"type":"calendar","schedule":"mon..fri 09:00-17:00"}},` +
		`{"match":{"type":"severity","severities":["warning","error"]}}]},{"match":{"type":"field","field":"type","values":["gc"]}}]}`
	// testMatcherExpressionEncoded is the same document as jsonencode writes
	// it: compacted, with its keys sorted.
	testMatcherExpressionEncoded = `{"all-of":[{"any-of":[{"match":{"schedule":"mon..fri 09:00-17:00","type":"calendar"}},` +
		`{"match":{"severities":["warning","error"],"type":"severity"}}]},{"match":{"field":"type","type":"field","values":["gc"]}}]}`
)

func TestCheckMatchExpression(t *testing.T) {
	for _, valid := range []string{
		testMatcherExpression,
		testMatcherExpressionPretty,
		testMatcherExpressionStored,
		`{"constant":true}`,
		`{"not":{"match":{"type":"field","field":"job-id","regex":"^daily-"}}}`,
		`{"one-of":[{"match":{"type":"calendar","schedule":"sat,sun 10-14"}},{"constant":false}]}`,
		`{"match":{"type":"field","field":"some.field_1","values":["a & b", ""]}}`,
		`{"match":{"type":"severity","severities":["info","notice","warning","error","unknown"]}}`,
		// A surrogate pair, and text that only looks like an escape.
		`{"match":{"type":"field","field":"type","values":["\ud83d\ude00","\\ud800"]}}`,
		// Controls serde_json escapes, which PBS stores.
		`{"match":{"type":"field","field":"type","values":["a\nb\u0001","\u2028"]}}`,
		nestedMatchExpression(matchExpressionMaxDepth),
	} {
		if err := checkMatchExpression(valid); err != nil {
			t.Errorf("checkMatchExpression(%s) = %v, want nil", valid, err)
		}
	}

	for expression, want := range map[string]string{
		`not json`:                       "not valid JSON",
		`{"constant":true} {}`:           "not valid JSON",
		`[]`:                             "the expression must be an object with exactly one key",
		`{}`:                             "the expression must be an object with exactly one key",
		`{"constant":true,"not":{}}`:     "the expression must be an object with exactly one key",
		`{"all-of":[]}`:                  "`all-of` must be a list of at least one rule",
		`{"any-of":{"constant":true}}`:   "`any-of` must be a list of at least one rule",
		`{"constant":"yes"}`:             "`constant` must be true or false",
		`{"nor":[{"constant":true}]}`:    "`nor` is not a rule PBS knows",
		`{"not":[{"constant":true}]}`:    "`not` must be an object with exactly one key",
		`{"match":"severity"}`:           "`match` must be an object with a type",
		`{"match":{"type":"hostname"}}`:  "`match.type` must be field, severity, calendar",
		`{"match":{"severities":["x"]}}`: "`match.type` must be field, severity, calendar",
		`{"match":{"type":"severity","severities":[]}}`:                                             "`match.severities` must be a list of at least one severity",
		`{"match":{"type":"severity","severities":["warn"]}}`:                                       "`match.severities` must be a list of at least one severity",
		`{"match":{"type":"severity","severities":"error"}}`:                                        "`match.severities` must be a list of at least one severity",
		`{"match":{"type":"severity","severities":["error"],"invert":true}}`:                        "`match` has invert, which a severity test does not take; it takes type, severities",
		`{"match":{"type":"field","field":"-type","values":["gc"]}}`:                                "`match.field` must be the name of a notification field",
		`{"match":{"type":"field","values":["gc"]}}`:                                                "`match.field` must be the name of a notification field",
		`{"match":{"type":"field","field":"type"}}`:                                                 "`match` must have either values or regex",
		`{"match":{"type":"field","field":"type","values":["a"],"regex":"b"}}`:                      "`match` must have either values or regex",
		`{"match":{"type":"field","field":"type","values":[]}}`:                                     "`match.values` must be a list of at least one string",
		`{"match":{"type":"field","field":"type","values":[1]}}`:                                    "`match.values` must be a list of at least one string",
		`{"match":{"type":"field","field":"type","regex":true}}`:                                    "`match.regex` must be a regular expression",
		`{"match":{"type":"field","field":"type","regex":"^g","flags":"i"}}`:                        "`match` has flags, which a field test does not take; it takes type, field, regex",
		`{"match":{"type":"calendar","schedule":" "}}`:                                              "`match.schedule` must be a time range",
		`{"match":{"type":"calendar","schedule":"8-17","days":"mon"}}`:                              "`match` has days, which a calendar test does not take",
		`{"match":{"type":"severity","type":"field"}}`:                                              "`match` has the key \"type\" twice",
		`{"all-of":[{"constant":true},{"not":{"match":{"type":"severity","severities":["bad"]}}}]}`: "`all-of[1].not.match.severities` must be",
		`{"match":{"type":"field","field":"type","values":["\ud800"]}}`:                             "half of a UTF-16 surrogate pair",
		`{"match":{"type":"field","field":"type","values":["\udc00\ud800"]}}`:                       "half of a UTF-16 surrogate pair",
		`{"match":{"type":"field","field":"type","values":["\ud800\u0041"]}}`:                       "half of a UTF-16 surrogate pair",
		`{"match":{"type":"field","field":"type\ud800","values":["gc"]}}`:                           "half of a UTF-16 surrogate pair",
		nestedMatchExpression(matchExpressionMaxDepth + 1):                                          "nests objects and lists more than 127 deep",
		`{"match":{"type":"field","field":"type","values":["gc\u0085"]}}`:                           "`match.values[0]` holds a control character from U+007F to U+009F",
		"{\"match\":{\"type\":\"field\",\"field\":\"type\",\"regex\":\"^g\x7f\"}}":                  "`match.regex` holds a control character",
		`{"match":{"type":"calendar","schedule":"8-17\u009f"}}`:                                     "`match.schedule` holds a control character",
	} {
		err := checkMatchExpression(expression)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("checkMatchExpression(%s) = %v, want an error containing %q", expression, err, want)
		}
	}
}

// nestedMatchExpression is an expression with objects nested depth deep:
// nots around a constant.
func nestedMatchExpression(depth int) string {
	return strings.Repeat(`{"not":`, depth-1) + `{"constant":true}` + strings.Repeat("}", depth-1)
}

// matcherConfig is the configuration of matcher "gc-alerts", sending to the
// SMTP endpoint "mail", with attrs on top.
func matcherConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"name": "gc-alerts", "target": []any{"mail"}}
	for k, v := range attrs {
		config[k] = v
	}
	return h.resourceValue(t, matcherType, config)
}

// requirePlansNoChange fails the test when config plans a change of inst.
func requirePlansNoChange(t *testing.T, h *protocolHarness, inst *resourceInstance, config tftypes.Value) {
	t.Helper()
	requireNoProtocolErrors(t, h.validateResource(t, inst.typeName, config))
	planned := h.plan(t, inst.typeName, inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if got := h.decodeResource(t, inst.typeName, planned.PlannedState); !got.Equal(inst.state) {
		t.Fatalf("planned a change\nstate:   %s\nplanned: %s", inst.state, got)
	}
}

// A matcher with an expression keeps the expression as the configuration
// writes it, while PBS stores it rewritten, and the same rules written
// another way — as jsonencode writes them — are no change. One update each
// switches between an expression and match_* rules.
func TestNotificationMatcherExpressionLifecycle(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"}}, "")

	config := matcherConfig(t, h, map[string]any{"expression": testMatcherExpressionPretty})
	inst := h.create(t, matcherType, config)
	if got := fake.lastCall(t, "POST /config/notifications/matchers").form; got.Get("expression") != testMatcherExpressionPretty ||
		got.Has("mode") || got.Has("invert-match") {
		t.Fatalf("POST form = %v", got)
	}
	if got := stringAt(t, inst.state, "expression"); got != testMatcherExpressionPretty {
		t.Fatalf("state expression = %s", got)
	}
	if stringAt(t, inst.state, "mode") != matcherModeAll || boolAt(t, inst.state, "invert_match") || !isNullAt(t, inst.state, "match_severity") {
		t.Fatalf("state = %s", inst.state)
	}
	stored, _ := notifications.entry("gc-alerts")
	if stored["expression"] != testMatcherExpressionStored {
		t.Fatalf("PBS stored %v", stored["expression"])
	}

	inst = h.refresh(t, inst)
	if got := stringAt(t, inst.state, "expression"); got != testMatcherExpressionPretty {
		t.Fatalf("refreshed expression = %s", got)
	}
	requirePlansNoChange(t, h, inst, config)
	requirePlansNoChange(t, h, inst, matcherConfig(t, h, map[string]any{"expression": testMatcherExpressionEncoded}))
	requirePlansNoChange(t, h, inst, matcherConfig(t, h, map[string]any{"expression": testMatcherExpressionStored}))

	// Other rules are a change.
	inst = h.update(t, inst, matcherConfig(t, h, map[string]any{"expression": testMatcherExpression}))
	// PBS refuses an expression next to mode or invert-match even at their
	// defaults, which the state cannot tell from absent ones.
	if got := fake.lastCall(t, "PUT /config/notifications/matchers/gc-alerts").form; got.Get("expression") != testMatcherExpression ||
		strings.Join(got["delete"], ",") != "invert-match,mode" {
		t.Fatalf("PUT form = %v", got)
	}
	if got := stringAt(t, inst.state, "expression"); got != testMatcherExpression {
		t.Fatalf("state expression = %s", got)
	}

	// From an expression to match_* rules, in one update.
	legacy := matcherConfig(t, h, map[string]any{"match_severity": []any{"error"}, "mode": "any", "invert_match": true})
	inst = h.update(t, inst, legacy)
	updated := fake.lastCall(t, "PUT /config/notifications/matchers/gc-alerts")
	if got := strings.Join(updated.form["delete"], ","); got != "expression" || updated.form.Get("match-severity") != "error" ||
		updated.form.Get("mode") != "any" || updated.form.Get("invert-match") != "true" {
		t.Fatalf("PUT form = %v", updated.form)
	}
	if !isNullAt(t, inst.state, "expression") || stringAt(t, inst.state, "match_severity", 0) != "error" {
		t.Fatalf("state = %s", inst.state)
	}
	if stored, _ := notifications.entry("gc-alerts"); stored["expression"] != nil {
		t.Fatalf("PBS kept the expression: %v", stored)
	}
	requirePlansNoChange(t, h, inst, legacy)

	// And back: mode and invert_match return to PBS's defaults, which
	// deletes them.
	inst = h.update(t, inst, config)
	updated = fake.lastCall(t, "PUT /config/notifications/matchers/gc-alerts")
	if got := strings.Join(updated.form["delete"], ","); got != "invert-match,match-severity,mode" ||
		updated.form.Get("expression") != testMatcherExpressionPretty {
		t.Fatalf("PUT form = %v", updated.form)
	}
	requirePlansNoChange(t, h, h.refresh(t, inst), config)

	h.destroy(t, inst)
	if _, exists := notifications.entry("gc-alerts"); exists {
		t.Fatal("the matcher still exists")
	}
}

// Editing a matcher in the web interface of PBS 4.2.10 or later turns its
// match_* rules into an expression. A matcher managed with match_* rules
// then reads with the expression and without them, and the next apply
// restores its rules, deleting the expression in the same update. The
// expression of a matcher managed with one is drift like any other.
func TestNotificationMatcherExpressionEditedInWebInterface(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"}}, "")

	legacy := matcherConfig(t, h, map[string]any{"match_severity": []any{"error"}, "mode": "any"})
	inst := h.create(t, matcherType, legacy)
	// What the editor stores: the same rules, as an expression.
	notifications.addMatcher("gc-alerts", fakeProperties{"expression": `{"any-of":[{"match":{"type":"severity","severities":["error"]}}]}`, "target": []string{"mail"}})
	inst = h.refresh(t, inst)
	if !isNullAt(t, inst.state, "match_severity") || stringAt(t, inst.state, "mode") != matcherModeAll ||
		stringAt(t, inst.state, "expression") != `{"any-of":[{"match":{"type":"severity","severities":["error"]}}]}` {
		t.Fatalf("refreshed %s", inst.state)
	}
	inst = h.update(t, inst, legacy)
	updated := fake.lastCall(t, "PUT /config/notifications/matchers/gc-alerts")
	if got := strings.Join(updated.form["delete"], ","); got != "expression" || updated.form.Get("match-severity") != "error" ||
		updated.form.Get("mode") != "any" {
		t.Fatalf("PUT form = %v", updated.form)
	}
	requirePlansNoChange(t, h, h.refresh(t, inst), legacy)

	config := matcherConfig(t, h, map[string]any{"expression": testMatcherExpressionPretty})
	inst = h.update(t, inst, config)
	notifications.addMatcher("gc-alerts", fakeProperties{"expression": testMatcherExpression, "target": []string{"mail"}})
	inst = h.refresh(t, inst)
	if got := stringAt(t, inst.state, "expression"); got != testMatcherExpression {
		t.Fatalf("refreshed expression = %s", got)
	}
	inst = h.update(t, inst, config)
	if got := fake.lastCall(t, "PUT /config/notifications/matchers/gc-alerts").form.Get("expression"); got != testMatcherExpressionPretty {
		t.Fatalf("PUT expression = %s", got)
	}
	if stored, _ := notifications.entry("gc-alerts"); stored["expression"] != testMatcherExpressionStored {
		t.Fatalf("PBS stored %v", stored["expression"])
	}
	if got := stringAt(t, inst.state, "expression"); got != testMatcherExpressionPretty {
		t.Fatalf("state expression = %s", got)
	}
}

// An imported matcher with an expression holds it as PBS stores it, and a
// configuration with the same rules written another way plans no change.
func TestNotificationMatcherExpressionImport(t *testing.T) {
	h, _, notifications := newNotificationsHarness(t)
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"}}, "")
	notifications.addMatcher("gc-alerts", fakeProperties{"expression": testMatcherExpressionStored, "target": []string{"mail"}})

	inst := h.importByID(t, matcherType, "gc-alerts")
	if got := stringAt(t, inst.state, "expression"); got != testMatcherExpressionStored {
		t.Fatalf("imported expression = %s", got)
	}
	requirePlansNoChange(t, h, inst, matcherConfig(t, h, map[string]any{"expression": testMatcherExpressionPretty}))
	requirePlansNoChange(t, h, inst, matcherConfig(t, h, map[string]any{"expression": testMatcherExpressionEncoded}))

	// default-matcher, which a change turns from builtin into
	// modified-builtin, plans its origin unknown for a change only.
	notifications.addMatcher(defaultMatcher, fakeProperties{"expression": testMatcherExpressionStored, "target": []string{"mail"}})
	inst = h.importByID(t, matcherType, defaultMatcher)
	if got := stringAt(t, inst.state, "origin"); got != "modified-builtin" {
		t.Fatalf("imported origin %s", got)
	}
	config := map[string]any{"name": defaultMatcher, "target": []any{"mail"}, "expression": testMatcherExpressionEncoded}
	requirePlansNoChange(t, h, inst, h.resourceValue(t, matcherType, config))
	config["comment"] = "GC alerts"
	planned := h.plan(t, matcherType, inst, h.resourceValue(t, matcherType, config))
	requireNoProtocolErrors(t, planned.Diagnostics)
	plannedState := h.decodeResource(t, matcherType, planned.PlannedState)
	if !isUnknownAt(t, plannedState, "origin") || stringAt(t, plannedState, "expression") != testMatcherExpressionStored {
		t.Fatalf("planned %s", plannedState)
	}
}

// The configuration is checked before PBS is asked: the expression's rules,
// and that it stands alone. Mode all and invert_match false, PBS's
// defaults, which Terraform writes into the configuration it generates,
// are no conflict.
func TestNotificationMatcherExpressionValidation(t *testing.T) {
	h, _, _ := newNotificationsHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"invalid":        {map[string]any{"expression": `{"all-of":[]}`}, "`all-of` must be a list of at least one rule"},
		"not JSON":       {map[string]any{"expression": `all-of`}, "not valid JSON"},
		"match_severity": {map[string]any{"expression": testMatcherExpression, "match_severity": []any{"error"}}, "match_severity cannot be set next to expression"},
		"match_field":    {map[string]any{"expression": testMatcherExpression, "match_field": []any{"exact:type=gc"}}, "match_field cannot be set next to expression"},
		"match_calendar": {map[string]any{"expression": testMatcherExpression, "match_calendar": []any{"8-17"}}, "match_calendar cannot be set next to expression"},
		"mode any":       {map[string]any{"expression": testMatcherExpression, "mode": "any"}, `mode = "any" cannot be set next to expression`},
		"invert_match":   {map[string]any{"expression": testMatcherExpression, "invert_match": true}, "invert_match = true cannot be set next to expression"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, matcherType, matcherConfig(t, h, tc.attrs)), tc.want)
		})
	}
	requireNoProtocolErrors(t, h.validateResource(t, matcherType, matcherConfig(t, h, map[string]any{
		"expression": testMatcherExpression, "mode": "all", "invert_match": false,
	})))
	// An unknown expression, such as a variable in the validation Terraform
	// runs before planning, may turn out null.
	requireNoProtocolErrors(t, h.validateResource(t, matcherType, matcherConfig(t, h, map[string]any{
		"expression": tfUnknown, "match_severity": []any{"error"}, "mode": "any", "invert_match": true,
	})))
}

// A matcher that stores mode or invert-match at their defaults — the
// built-in default-matcher has mode all — switches to an expression: PBS
// refuses either next to one, so the update deletes both.
func TestNotificationMatcherExpressionReplacesStoredDefaults(t *testing.T) {
	h, fake, notifications := newNotificationsHarness(t)
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"}}, "")
	notifications.addMatcher("gc-alerts", fakeProperties{"mode": "all", "invert-match": false, "match-severity": []string{"error"}, "target": []string{"mail"}})

	for _, name := range []string{defaultMatcher, "gc-alerts"} {
		inst := h.importByID(t, matcherType, name)
		config := map[string]any{"name": name, "target": []any{"mail"}, "expression": testMatcherExpressionPretty}
		inst = h.update(t, inst, h.resourceValue(t, matcherType, config))
		updated := fake.lastCall(t, "PUT /config/notifications/matchers/"+name)
		if got := updated.form["delete"]; !slices.Contains(got, "mode") || !slices.Contains(got, "invert-match") {
			t.Fatalf("%s: PUT form = %v", name, updated.form)
		}
		stored, _ := notifications.entry(name)
		if stored["expression"] != testMatcherExpressionStored || stored["mode"] != nil || stored["invert-match"] != nil {
			t.Fatalf("%s: PBS stored %v", name, stored)
		}
		requirePlansNoChange(t, h, h.refresh(t, inst), h.resourceValue(t, matcherType, config))
	}
}

// PBS before 4.2.10 does not know the property: the plan fails with the
// release it needs, and a matcher without one plans as before.
func TestNotificationMatcherExpressionNeedsPBS4210(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /version", http.StatusOK, fakeVersionJSON)
	notifications := newFakeNotifications(fake)
	h := newProtocolHarness(t, fake)
	notifications.addSMTP("mail", fakeProperties{"server": "smtp.example.com", "from-address": "pbs@example.com", "mailto": []string{"ops@example.com"}}, "")

	planned := h.plan(t, matcherType, nil, matcherConfig(t, h, map[string]any{"expression": testMatcherExpression}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "expression needs PBS 4.2.10 or newer, but the server at")
	requireProtocolErrorContaining(t, planned.Diagnostics, "runs PBS 4.2.8")
	h.create(t, matcherType, matcherConfig(t, h, map[string]any{"match_severity": []any{"error"}}))
}

// The fake PBS writes strings as serde_json does: the quote, the backslash
// and U+0000 to U+001F escaped, everything else as it is.
func TestFakeStoredExpressionStrings(t *testing.T) {
	expression := `{"match":{"values":["\\u2028","\u2028","a\"b\\c\n\u0001<&>\u00e9"],"type":"field","field":"type"}}`
	stored, err := fakeStoredExpression(expression)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"match":{"type":"field","field":"type","values":["\\u2028","` + "\u2028" + `","a\"b\\c\n\u0001<&>` + "\u00e9" + `"]}}`
	if stored != want {
		t.Fatalf("stored %s\nwant   %s", stored, want)
	}
	if !sameJSONDocument(stored, expression) {
		t.Fatalf("stored %s is not the document %s", stored, expression)
	}
}
