package provider

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestTrafficControlRuleResourceSchemaIsValid(t *testing.T) {
	requireValidResourceSchema(t, &trafficControlRuleResource{})
}

// newTrafficControlHarness is a fake PBS with the traffic control API and a
// provider signed in to it. version, when set, is what GET /version answers.
func newTrafficControlHarness(t *testing.T, version ...string) (*protocolHarness, *fakePBS, *fakeTrafficControl) {
	t.Helper()
	fake := newFakePBS()
	if len(version) > 0 {
		fake.reply("GET /version", http.StatusOK, version[0])
	}
	rules := newFakeTrafficControl(fake)
	return newProtocolHarness(t, fake), fake, rules
}

// trafficControlRuleConfig is the configuration of a rule "office", with
// attrs on top of what it needs; a nil value leaves an attribute out.
func trafficControlRuleConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"name": "office", "network": []any{"192.0.2.0/24"}}
	for k, v := range attrs {
		config[k] = v
	}
	return h.resourceValue(t, "pbs_traffic_control_rule", config)
}

// trafficControlStringsAt returns the elements of the set of strings at
// steps, sorted and joined by commas.
func trafficControlStringsAt(t *testing.T, v tftypes.Value, steps ...any) string {
	t.Helper()
	var elements []tftypes.Value
	if err := knownAt(t, v, steps...).As(&elements); err != nil {
		t.Fatalf("%v: %v", steps, err)
	}
	out := make([]string, 0, len(elements))
	for _, e := range elements {
		var s string
		if err := e.As(&s); err != nil {
			t.Fatalf("%v: %v", steps, err)
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestTrafficControlRuleResourceLifecycle(t *testing.T) {
	h, fake, rules := newTrafficControlHarness(t)
	const putRoute = "PUT /config/traffic-control/office"

	// The sets go out sorted, each as its key repeated, and nothing that is
	// not set goes out.
	attrs := map[string]any{
		"network":   []any{"192.0.2.0/24", "10.0.0.1/8", "2001:db8::/32"},
		"timeframe": []any{"mon..fri 8-12", "mon..fri 14:30-18"},
		"users":     []any{"bob@pbs", "alice@pbs"},
		"rate_in":   "100MB",
		"burst_in":  "200MB",
		"rate_out":  "10MiB",
		"comment":   "Office hours",
	}
	full := trafficControlRuleConfig(t, h, attrs)
	inst := h.create(t, "pbs_traffic_control_rule", full)
	created := fake.lastCall(t, "POST /config/traffic-control")
	for name, want := range map[string]string{
		"name":      "office",
		"network":   "10.0.0.1/8,192.0.2.0/24,2001:db8::/32",
		"timeframe": "mon..fri 14:30-18,mon..fri 8-12",
		"users":     "alice@pbs,bob@pbs",
		"rate-in":   "100MB",
		"burst-in":  "200MB",
		"rate-out":  "10MiB",
		"comment":   "Office hours",
	} {
		if got := strings.Join(created.form[name], ","); got != want {
			t.Errorf("POST %s = %q, want %q", name, got, want)
		}
	}
	if len(created.form) != 8 {
		t.Errorf("POST form = %v, want only what is set", created.form)
	}
	// PBS keeps the arrays in the order sent and writes sizes its own way,
	// which state does not show.
	if stored, _ := rules.rule("office"); fakeTrafficControlJoined(stored, "network") != "10.0.0.1/8,192.0.2.0/24,2001:db8::/32" ||
		stored["rate-in"] != "100 MB" || stored["rate-out"] != "10 MiB" || stored["burst-out"] != nil {
		t.Errorf("stored rule = %v", stored)
	}
	if stringAt(t, inst.state, "id") != "office" || stringAt(t, inst.state, "rate_in") != "100MB" ||
		stringAt(t, inst.state, "rate_out") != "10MiB" || !isNullAt(t, inst.state, "burst_out") ||
		trafficControlStringsAt(t, inst.state, "network") != "10.0.0.1/8,192.0.2.0/24,2001:db8::/32" ||
		trafficControlStringsAt(t, inst.state, "users") != "alice@pbs,bob@pbs" ||
		stringAt(t, inst.state, "comment") != "Office hours" {
		t.Errorf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_traffic_control_rule", inst.identity), "name"); got != "office" {
		t.Errorf("identity name = %q", got)
	}
	replan := h.plan(t, "pbs_traffic_control_rule", inst, full)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_traffic_control_rule", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}
	if refreshed := h.refresh(t, inst); !refreshed.state.Equal(inst.state) {
		diffs, _ := refreshed.state.Diff(inst.state)
		t.Errorf("refresh changes %v", diffs)
	}

	// Another spelling of the same sizes sends nothing.
	respelt := map[string]any{"rate_in": "100 MB", "burst_in": "200000000", "rate_out": "10 MiB"}
	for k, v := range respelt {
		attrs[k] = v
	}
	inst = h.update(t, inst, trafficControlRuleConfig(t, h, attrs))
	if fake.count(putRoute) != 0 {
		t.Errorf("a new spelling of the same sizes was sent: %v", fake.lastCall(t, putRoute).form)
	}

	// A changed set goes out whole, and replaces what PBS has.
	attrs["network"] = []any{"10.0.0.1/8", "::/0", "0.0.0.0/0"}
	attrs["timeframe"] = []any{"sat,sun 10:00-14:30"}
	attrs["users"] = []any{"alice@pbs"}
	attrs["burst_out"] = "20MiB"
	inst = h.update(t, inst, trafficControlRuleConfig(t, h, attrs))
	updated := fake.lastCall(t, putRoute)
	for name, want := range map[string]string{
		"network":   "0.0.0.0/0,10.0.0.1/8,::/0",
		"timeframe": "sat,sun 10:00-14:30",
		"users":     "alice@pbs",
		"burst-out": "20MiB",
	} {
		if got := strings.Join(updated.form[name], ","); got != want {
			t.Errorf("PUT %s = %q, want %q", name, got, want)
		}
	}
	if len(updated.form) != 4 {
		t.Errorf("PUT form = %v, want only what changed", updated.form)
	}
	if stored, _ := rules.rule("office"); fakeTrafficControlJoined(stored, "network") != "0.0.0.0/0,10.0.0.1/8,::/0" ||
		fakeTrafficControlJoined(stored, "users") != "alice@pbs" ||
		fakeTrafficControlJoined(stored, "timeframe") != "sat,sun 10:00-14:30" {
		t.Errorf("stored rule = %v, want the new arrays alone", stored)
	}

	// What the configuration drops is deleted; network stays, as it must.
	inst = h.update(t, inst, trafficControlRuleConfig(t, h, map[string]any{
		"network": []any{"10.0.0.1/8", "::/0", "0.0.0.0/0"}, "rate_in": "100MB", "rate_out": "10MiB",
	}))
	updated = fake.lastCall(t, putRoute)
	if got := strings.Join(updated.form["delete"], ","); got != "burst-in,burst-out,comment,timeframe,users" {
		t.Errorf("delete = %q", got)
	}
	if len(updated.form) != 1 {
		t.Errorf("PUT form = %v, want only deletions", updated.form)
	}
	if stored, _ := rules.rule("office"); len(stored) != 4 || stored["rate-in"] != "100 MB" {
		t.Errorf("stored rule = %v, want name, network, rate-in and rate-out", stored)
	}
	for _, name := range []string{"timeframe", "users", "burst_in", "burst_out", "comment"} {
		if !isNullAt(t, inst.state, name) {
			t.Errorf("%s = %s after it was removed", name, valueAt(t, inst.state, name))
		}
	}

	// A rule without rates exempts its clients from broader rules.
	inst = h.update(t, inst, trafficControlRuleConfig(t, h, map[string]any{"network": []any{"10.0.0.1/8"}}))
	updated = fake.lastCall(t, putRoute)
	if got := strings.Join(updated.form["delete"], ","); got != "rate-in,rate-out" || updated.form.Get("network") != "10.0.0.1/8" {
		t.Errorf("PUT form = %v", updated.form)
	}
	if stored, _ := rules.rule("office"); len(stored) != 2 {
		t.Errorf("stored rule = %v, want name and network", stored)
	}

	// A rule deleted outside Terraform is gone from state, and destroying it
	// is no error.
	rules.mu.Lock()
	delete(rules.rules, "office")
	rules.mu.Unlock()
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept a deleted rule: %s", refreshed.state)
	}
	h.destroy(t, inst)
	if fake.count("DELETE /config/traffic-control/office") != 1 {
		t.Errorf("routes = %v", fake.routes())
	}
}

func TestTrafficControlRuleResourceImport(t *testing.T) {
	h, fake, rules := newTrafficControlHarness(t)
	rules.addRule("lab", fakeProperties{"network": []string{"192.0.2.0/24", "2001:db8::/32"}, "users": []string{"alice@pbs"},
		"timeframe": []string{"mon..fri 8-17"}, "rate-in": "10 MiB", "burst-in": "20 MiB", "comment": "Lab"})

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_traffic_control_rule", "lab"),
		"identity": h.importByIdentity(t, "pbs_traffic_control_rule", map[string]any{"name": "lab"}),
	} {
		if stringAt(t, inst.state, "id") != "lab" || stringAt(t, inst.state, "name") != "lab" ||
			trafficControlStringsAt(t, inst.state, "network") != "192.0.2.0/24,2001:db8::/32" ||
			trafficControlStringsAt(t, inst.state, "users") != "alice@pbs" ||
			trafficControlStringsAt(t, inst.state, "timeframe") != "mon..fri 8-17" ||
			stringAt(t, inst.state, "rate_in") != "10 MiB" || stringAt(t, inst.state, "burst_in") != "20 MiB" ||
			!isNullAt(t, inst.state, "rate_out") || !isNullAt(t, inst.state, "burst_out") ||
			stringAt(t, inst.state, "comment") != "Lab" {
			t.Errorf("import by %s = %s", name, inst.state)
		}
		if got := stringAt(t, h.identityValue(t, "pbs_traffic_control_rule", inst.identity), "name"); got != "lab" {
			t.Errorf("import by %s: identity name = %q", name, got)
		}
	}

	// The configuration's spelling of the sizes PBS has sends nothing.
	inst := h.importByID(t, "pbs_traffic_control_rule", "lab")
	inst = h.update(t, inst, h.resourceValue(t, "pbs_traffic_control_rule", map[string]any{
		"name": "lab", "network": []any{"2001:db8::/32", "192.0.2.0/24"}, "users": []any{"alice@pbs"},
		"timeframe": []any{"mon..fri 8-17"}, "rate_in": "10MiB", "burst_in": "20mib", "comment": "Lab",
	}))
	if fake.count("PUT /config/traffic-control/lab") != 0 {
		t.Errorf("an imported rule was changed: %v", fake.lastCall(t, "PUT /config/traffic-control/lab").form)
	}
	h.destroy(t, inst)
	if _, exists := rules.rule("lab"); exists {
		t.Error("the rule still exists")
	}

	// A rule that does not exist imports as nothing, which Terraform reports.
	resp := h.importResource(t, "pbs_traffic_control_rule", "missing", nil)
	requireNoProtocolErrors(t, resp.Diagnostics)
	imported := resp.ImportedResources[0]
	read := h.read(t, &resourceInstance{typeName: "pbs_traffic_control_rule",
		state: h.decodeResource(t, "pbs_traffic_control_rule", imported.State), identity: imported.Identity})
	requireNoProtocolErrors(t, read.Diagnostics)
	if state := h.decodeResource(t, "pbs_traffic_control_rule", read.NewState); !state.IsNull() {
		t.Errorf("import of a missing rule = %s", state)
	}

	// An import id that cannot be a rule name is refused.
	resp = h.importResource(t, "pbs_traffic_control_rule", "lab/1", nil)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS traffic control rule by its name")
}

// A rule that exists is imported, not created; a create whose read-back
// fails keeps the rule in state, and a refused update says what it needs.
func TestTrafficControlRuleResourceErrors(t *testing.T) {
	h, fake, rules := newTrafficControlHarness(t)
	rules.addRule("taken", fakeProperties{"network": []string{"10.0.0.0/8"}})

	config := trafficControlRuleConfig(t, h, map[string]any{"name": "taken"})
	planned := h.plan(t, "pbs_traffic_control_rule", nil, config)
	applied := h.apply(t, "pbs_traffic_control_rule", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "import it")
	requireProtocolErrorOn(t, applied.Diagnostics, tftypes.NewAttributePath().WithAttributeName("name"))
	if stored, _ := rules.rule("taken"); fakeTrafficControlJoined(stored, "network") != "10.0.0.0/8" {
		t.Errorf("stored rule = %v", stored)
	}

	fake.reply("GET /config/traffic-control/office", http.StatusForbidden, "permission check failed")
	config = trafficControlRuleConfig(t, h, map[string]any{"rate_in": "10MiB"})
	planned = h.plan(t, "pbs_traffic_control_rule", nil, config)
	applied = h.apply(t, "pbs_traffic_control_rule", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "it is marked tainted")
	requireProtocolErrorContaining(t, applied.Diagnostics, "Sys.Audit on /")
	state := h.decodeResource(t, "pbs_traffic_control_rule", applied.NewState)
	if state.IsNull() || stringAt(t, state, "id") != "office" || stringAt(t, state, "rate_in") != "10MiB" {
		t.Errorf("state = %s, want the rule as planned", state)
	}
	if _, exists := rules.rule("office"); !exists {
		t.Error("the rule was not created")
	}

	fake.reply("PUT /config/traffic-control/taken", http.StatusForbidden, "permission check failed")
	inst := h.importByID(t, "pbs_traffic_control_rule", "taken")
	config = h.resourceValue(t, "pbs_traffic_control_rule", map[string]any{"name": "taken", "network": []any{"10.0.0.0/16"}})
	planned = h.plan(t, "pbs_traffic_control_rule", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied = h.apply(t, "pbs_traffic_control_rule", inst, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to update PBS traffic control rule")
	requireProtocolErrorContaining(t, applied.Diagnostics, "Sys.Modify on /")
}

func TestTrafficControlRuleResourceValidation(t *testing.T) {
	h, _, _ := newTrafficControlHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"IPv4 prefix too long": {map[string]any{"network": []any{"10.0.0.0/33"}}, "CIDR notation"},
		"IPv6 prefix too long": {map[string]any{"network": []any{"::/129"}}, "CIDR notation"},
		"bare address":         {map[string]any{"network": []any{"10.0.0.1"}}, "CIDR notation"},
		"zone":                 {map[string]any{"network": []any{"fe80::1%eth0/64"}}, "CIDR notation"},
		"leading zero":         {map[string]any{"network": []any{"010.0.0.0/8"}}, "CIDR notation"},
		"padded prefix length": {map[string]any{"network": []any{"10.0.0.0/08"}}, "CIDR notation"},
		"padded network":       {map[string]any{"network": []any{" 10.0.0.0/8"}}, "CIDR notation"},
		"44 characters":        {map[string]any{"network": []any{"0000:0000:0000:0000:0000:ffff:10.10.10.1/128"}}, "CIDR notation"},
		"no networks":          {map[string]any{"network": []any{}}, "network"},
		"network left out":     {map[string]any{"network": nil}, "network"},
		"night":                {map[string]any{"timeframe": []any{"22-6"}}, "time range"},
		"no time frames":       {map[string]any{"timeframe": []any{}}, "timeframe"},
		"token":                {map[string]any{"users": []any{"alice@pbs!tok"}}, "must be a user ID"},
		"no realm":             {map[string]any{"users": []any{"alice"}}, "must be a user ID"},
		"no users":             {map[string]any{"users": []any{}}, "users"},
		"rate 0":               {map[string]any{"rate_in": "0"}, "at least 1 byte"},
		"rate 0B":              {map[string]any{"rate_out": "0B"}, "at least 1 byte"},
		"half a byte":          {map[string]any{"rate_in": "0.5"}, "at least 1 byte"},
		"under a byte":         {map[string]any{"rate_out": "0.999 B"}, "at least 1 byte"},
		"burst 0":              {map[string]any{"rate_in": "1", "burst_in": "0"}, "at least 1 byte"},
		"four decimals":        {map[string]any{"rate_in": "0.0001"}, "three decimals"},
		"bad size":             {map[string]any{"rate_in": "10MIB"}, "rate_in"},
		"burst_in alone":       {map[string]any{"burst_in": "1MiB"}, `"rate_in" must be specified`},
		"burst_out alone":      {map[string]any{"rate_in": "1MiB", "burst_out": "1MiB"}, `"rate_out" must be specified`},
		"short name":           {map[string]any{"name": "ab"}, "name"},
		"padded comment":       {map[string]any{"comment": "Office "}, "white space"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_traffic_control_rule", trafficControlRuleConfig(t, h, tc.attrs)), tc.want)
		})
	}
	for name, attrs := range map[string]map[string]any{
		"networks": {"network": []any{"10.0.0.0/8", "10.0.0.1/8", "2001:db8::/32", "0.0.0.0/0", "::/0",
			"2001:0db8:0000:0000:0000:0000:0000:0001/128"}},
		"time frames": {"timeframe": []any{"8-17", "mon..fri 8:00-18:00", "sat,sun 10:00-14:30"}},
		"users":       {"users": []any{"alice@pbs", "root@pam"}},
		"sizes":       {"rate_in": "1", "burst_in": "1.5", "rate_out": "0.001K", "burst_out": "10 MiB"},
		"no rates":    {},
	} {
		t.Run("valid "+name, func(t *testing.T) {
			diags := h.validateResource(t, "pbs_traffic_control_rule", trafficControlRuleConfig(t, h, attrs))
			requireNoProtocolErrors(t, diags)
			if len(diags) != 0 {
				t.Errorf("diagnostics = %v", diags)
			}
		})
	}
}

// PBS takes an IPv4 client connecting over IPv6 for an IPv4 one, so an
// IPv4-mapped network matches no client.
func TestTrafficControlRuleResourceWarnsAboutIPv4MappedNetworks(t *testing.T) {
	h, _, _ := newTrafficControlHarness(t)
	diags := h.validateResource(t, "pbs_traffic_control_rule", trafficControlRuleConfig(t, h, map[string]any{
		"network": []any{"10.0.0.0/8", "::ffff:10.0.0.0/104"},
	}))
	requireNoProtocolErrors(t, diags)
	requireProtocolWarningContaining(t, diags, "::ffff:10.0.0.0/104 is an IPv4-mapped IPv6 network")
	if len(diags) != 1 {
		t.Errorf("diagnostics = %v, want one warning", diags)
	}

	// Networks known only at apply are not checked.
	diags = h.validateResource(t, "pbs_traffic_control_rule", trafficControlRuleConfig(t, h, map[string]any{"network": tfUnknown}))
	if len(diags) != 0 {
		t.Errorf("diagnostics = %v", diags)
	}
}

// users needs PBS 4.1; a rule without it plans on PBS 4.0.
func TestTrafficControlRuleResourceUsersNeedPBS41(t *testing.T) {
	h, fake, _ := newTrafficControlHarness(t, fakeVersion40)
	for _, users := range []any{[]any{"alice@pbs"}, tfUnknown} {
		planned := h.plan(t, "pbs_traffic_control_rule", nil, trafficControlRuleConfig(t, h, map[string]any{"users": users}))
		requireProtocolErrorContaining(t, planned.Diagnostics, "users needs PBS 4.1 or newer")
		requireProtocolErrorOn(t, planned.Diagnostics, tftypes.NewAttributePath().WithAttributeName("users"))
	}
	inst := h.create(t, "pbs_traffic_control_rule", trafficControlRuleConfig(t, h, map[string]any{"rate_in": "10MiB"}))
	if _, sent := fake.lastCall(t, "POST /config/traffic-control").form["users"]; sent {
		t.Error("users was sent to PBS 4.0")
	}
	h.destroy(t, inst)
}

func TestIsDailyDuration(t *testing.T) {
	for _, s := range []string{
		"8-12", "8:05 - 12:20", "8:0-12:0", "8:00-12:00", "8:5-9", "08:00-09:00", "0-23:59", "8-8",
		"mon 8-12", "tue..fri 8-12", "sat,tue..thu,fri 8-12", "fri..mon 0-6", "Monday 8-9", "MON..FRI 8-17",
		"mon..wed 8:00-16:30", "sat,sun 10:00-14:30", "mon8-12",
	} {
		if !isDailyDuration(s) {
			t.Errorf("isDailyDuration(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"12-8", "8-24", "8-25", "8:60-9", " 8-12", "8-12 ", "22-6", "xyz 8-9", "mon, tue 8-12", "mon.fri 8-12",
		"sat,sun", "mon..fri", "8-", "-12", "8", "", "8:-9", "24:00-24:00", "99999999999999999999-1",
	} {
		if isDailyDuration(s) {
			t.Errorf("isDailyDuration(%q) = true, want false", s)
		}
	}
}

// PBS multiplies a size's number by its unit and truncates the bytes.
func TestWholeBytes(t *testing.T) {
	for s, want := range map[string]uint64{
		"0": 0, "0.5": 0, "0.999 B": 0, "1": 1, "1.5": 1, "0.001K": 1, "0.001Ki": 1, "1.001K": 1000,
		"10MiB": 10 << 20, "10 MiB": 10 << 20, "20mib": 20 << 20, "100MB": 100e6, "1.5GB": 1.5e9,
	} {
		if n, ok := wholeBytes(s); !ok || n != want {
			t.Errorf("wholeBytes(%q) = %d, %v, want %d", s, n, ok, want)
		}
	}
	for _, s := range []string{"", "10MIB", "10i", "1e3", "-1", "B"} {
		if n, ok := wholeBytes(s); ok {
			t.Errorf("wholeBytes(%q) = %d, want no size", s, n)
		}
	}
}

// PBS keeps an array element given twice, which a set cannot hold: the rule
// reads it once, and so does the list.
func TestTrafficControlRuleDuplicateElements(t *testing.T) {
	h, _, rules := newTrafficControlHarness(t)
	rules.addRule("dup", fakeProperties{"network": []string{"10.0.0.0/8", "10.0.0.0/8"}, "rate-in": "10 MiB"})
	inst := h.importByID(t, "pbs_traffic_control_rule", "dup")
	if lengthAt(t, inst.state, "network") != 1 {
		t.Errorf("state = %s", inst.state)
	}
	list := h.readDataSource(t, "pbs_traffic_control_rules", h.dataSourceValue(t, "pbs_traffic_control_rules", nil))
	if lengthAt(t, list, "rules", 0, "network") != 1 {
		t.Errorf("list = %s", list)
	}
}
