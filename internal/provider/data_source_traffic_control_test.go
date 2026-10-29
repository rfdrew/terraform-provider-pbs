package provider

import (
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestTrafficControlDataSourceSchemasAreValid(t *testing.T) {
	requireValidDataSourceSchema(t, &trafficControlRuleDataSource{})
	requireValidDataSourceSchema(t, &trafficControlRulesDataSource{})
}

// The rule data source reports a rule as PBS has it, sizes in its spelling,
// and what is not set as null.
func TestTrafficControlRuleDataSource(t *testing.T) {
	h, _, rules := newTrafficControlHarness(t)
	rules.addRule("office", fakeProperties{"network": []string{"192.0.2.0/24", "::/0"}, "timeframe": []string{"mon..fri 8-12"},
		"users": []string{"alice@pbs"}, "rate-in": "100 MB", "burst-in": "200 MB", "rate-out": "10 MiB", "burst-out": "20 MiB",
		"comment": "Office hours"})
	rules.addRule("minimal", fakeProperties{"network": []string{"10.0.0.0/8"}})

	rule := h.readDataSource(t, "pbs_traffic_control_rule", h.dataSourceValue(t, "pbs_traffic_control_rule", map[string]any{"name": "office"}))
	if stringAt(t, rule, "name") != "office" || trafficControlStringsAt(t, rule, "network") != "192.0.2.0/24,::/0" ||
		trafficControlStringsAt(t, rule, "timeframe") != "mon..fri 8-12" || trafficControlStringsAt(t, rule, "users") != "alice@pbs" ||
		stringAt(t, rule, "rate_in") != "100 MB" || stringAt(t, rule, "burst_in") != "200 MB" ||
		stringAt(t, rule, "rate_out") != "10 MiB" || stringAt(t, rule, "burst_out") != "20 MiB" ||
		stringAt(t, rule, "comment") != "Office hours" {
		t.Errorf("pbs_traffic_control_rule = %s", rule)
	}

	minimal := h.readDataSource(t, "pbs_traffic_control_rule", h.dataSourceValue(t, "pbs_traffic_control_rule", map[string]any{"name": "minimal"}))
	if trafficControlStringsAt(t, minimal, "network") != "10.0.0.0/8" {
		t.Errorf("pbs_traffic_control_rule = %s", minimal)
	}
	for _, name := range []string{"timeframe", "users", "rate_in", "burst_in", "rate_out", "burst_out", "comment"} {
		if !isNullAt(t, minimal, name) {
			t.Errorf("%s = %s, want null", name, valueAt(t, minimal, name))
		}
	}

	resp := h.readDataSourceResponse(t, "pbs_traffic_control_rule", h.dataSourceValue(t, "pbs_traffic_control_rule", map[string]any{"name": "missing"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS has no traffic control rule "missing"`)
	requireProtocolErrorOn(t, resp.Diagnostics, tftypes.NewAttributePath().WithAttributeName("name"))
}

// The list reads /admin/traffic-control, which needs only Sys.Audit, and
// sorts the rules by name, with the rates their connections reach now.
func TestTrafficControlRulesDataSource(t *testing.T) {
	h, fake, rules := newTrafficControlHarness(t)
	config := h.dataSourceValue(t, "pbs_traffic_control_rules", map[string]any{})

	if empty := h.readDataSource(t, "pbs_traffic_control_rules", config); lengthAt(t, empty, "rules") != 0 {
		t.Errorf("pbs_traffic_control_rules = %s, want no rules", empty)
	}

	rules.addRule("office", fakeProperties{"network": []string{"192.0.2.0/24"}, "users": []string{"alice@pbs", "bob@pbs"},
		"rate-in": "100 MB", "rate-out": "10 MiB"})
	rules.addRule("lab", fakeProperties{"network": []string{"10.0.0.0/8", "2001:db8::/32"}, "comment": "Lab"})
	rules.addRule("backup", fakeProperties{"network": []string{"0.0.0.0/0", "::/0"}, "timeframe": []string{"0-6"},
		"rate-in": "1 GiB", "burst-in": "2 GiB"})
	rules.setCurrentRates("office", 1048576, 524288)
	rules.setCurrentRates("backup", 734003200, 0)

	list := h.readDataSource(t, "pbs_traffic_control_rules", config)
	if lengthAt(t, list, "rules") != 3 || stringAt(t, list, "rules", 0, "name") != "backup" ||
		stringAt(t, list, "rules", 1, "name") != "lab" || stringAt(t, list, "rules", 2, "name") != "office" {
		t.Fatalf("pbs_traffic_control_rules = %s, want backup, lab and office", list)
	}
	if trafficControlStringsAt(t, list, "rules", 0, "network") != "0.0.0.0/0,::/0" ||
		trafficControlStringsAt(t, list, "rules", 0, "timeframe") != "0-6" ||
		stringAt(t, list, "rules", 0, "rate_in") != "1 GiB" || stringAt(t, list, "rules", 0, "burst_in") != "2 GiB" ||
		!isNullAt(t, list, "rules", 0, "rate_out") || !isNullAt(t, list, "rules", 0, "users") ||
		int64At(t, list, "rules", 0, "current_rate_in") != 734003200 || int64At(t, list, "rules", 0, "current_rate_out") != 0 {
		t.Errorf("backup = %s", valueAt(t, list, "rules", 0))
	}
	if stringAt(t, list, "rules", 1, "comment") != "Lab" || !isNullAt(t, list, "rules", 1, "rate_in") ||
		!isNullAt(t, list, "rules", 1, "timeframe") ||
		int64At(t, list, "rules", 1, "current_rate_in") != 0 || int64At(t, list, "rules", 1, "current_rate_out") != 0 {
		t.Errorf("lab = %s", valueAt(t, list, "rules", 1))
	}
	if trafficControlStringsAt(t, list, "rules", 2, "users") != "alice@pbs,bob@pbs" ||
		stringAt(t, list, "rules", 2, "rate_in") != "100 MB" || stringAt(t, list, "rules", 2, "rate_out") != "10 MiB" ||
		!isNullAt(t, list, "rules", 2, "comment") ||
		int64At(t, list, "rules", 2, "current_rate_in") != 1048576 || int64At(t, list, "rules", 2, "current_rate_out") != 524288 {
		t.Errorf("office = %s", valueAt(t, list, "rules", 2))
	}
	if fake.count("GET /admin/traffic-control") != 2 || fake.count("GET /config/traffic-control") != 0 {
		t.Errorf("routes = %v, want the rates read twice and the configuration never", fake.routes())
	}

	fake.reply("GET /admin/traffic-control", http.StatusForbidden, "permission check failed")
	resp := h.readDataSourceResponse(t, "pbs_traffic_control_rules", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS traffic control rules")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /")
}
