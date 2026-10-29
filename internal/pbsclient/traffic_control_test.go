package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

// GET /admin/traffic-control answers each rule with its current rates in the
// same object, which decode into the embedded rule and the two rates.
func TestListTrafficControlRatesDecodesTheRates(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /admin/traffic-control", http.StatusOK, `{"data":[`+
		`{"name":"office","comment":"Office hours","network":["192.0.2.0/24","::/0"],"timeframe":["mon..fri 8-12"],`+
		`"users":["alice@pbs"],"rate-in":"100 MB","burst-in":"200 MB","rate-out":"10 MiB","burst-out":"20 MiB",`+
		`"cur-rate-in":1048576,"cur-rate-out":524288},`+
		`{"name":"lab","network":["10.0.0.0/8"],"cur-rate-in":0,"cur-rate-out":0}],"digest":"9f86d081884c7d65"}`)

	rates, err := fake.client(t).ListTrafficControlRates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []TrafficControlRuleRates{
		{
			TrafficControlRule: TrafficControlRule{Name: "office", Comment: "Office hours", Network: []string{"192.0.2.0/24", "::/0"},
				Timeframe: []string{"mon..fri 8-12"}, Users: []string{"alice@pbs"}, RateIn: "100 MB", BurstIn: "200 MB",
				RateOut: "10 MiB", BurstOut: "20 MiB"},
			CurrentRateIn:  1048576,
			CurrentRateOut: 524288,
		},
		{TrafficControlRule: TrafficControlRule{Name: "lab", Network: []string{"10.0.0.0/8"}}},
	}
	if !reflect.DeepEqual(rates, want) {
		t.Fatalf("ListTrafficControlRates() = %+v, want %+v", rates, want)
	}
	if got := fake.routes(); !reflect.DeepEqual(got, []string{"GET /admin/traffic-control"}) {
		t.Fatalf("routes = %v", got)
	}
}

// The writes send the caller's params as the form, arrays as the key
// repeated; the reads decode what PBS leaves out as empty; the delete names
// the rule in its path and sends nothing else.
func TestTrafficControlCallsHitTheirRoutes(t *testing.T) {
	const (
		listRoute   = "GET /config/traffic-control"
		createRoute = "POST /config/traffic-control"
		getRoute    = "GET /config/traffic-control/office"
		updateRoute = "PUT /config/traffic-control/office"
		deleteRoute = "DELETE /config/traffic-control/office"
	)
	fake := newFakePBS()
	fake.reply(listRoute, http.StatusOK, `{"data":[{"name":"office","network":["192.0.2.0/24"],"rate-in":"10 MiB"},`+
		`{"name":"lab","network":["10.0.0.0/8","2001:db8::/32"],"users":["alice@pbs"]}],"digest":"9f86d081884c7d65"}`)
	fake.reply(createRoute, http.StatusOK, `{"data":null}`)
	fake.reply(getRoute, http.StatusOK, `{"data":{"name":"office","network":["192.0.2.0/24","10.0.0.1/8"],`+
		`"timeframe":["mon..fri 8-12","mon..fri 14:30-18"],"rate-out":"1.5 GB","comment":"Office"},"digest":"9f86d081884c7d65"}`)
	fake.reply(updateRoute, http.StatusOK, `{"data":null}`)
	fake.reply(deleteRoute, http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	rules, err := c.ListTrafficControlRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantRules := []TrafficControlRule{
		{Name: "office", Network: []string{"192.0.2.0/24"}, RateIn: "10 MiB"},
		{Name: "lab", Network: []string{"10.0.0.0/8", "2001:db8::/32"}, Users: []string{"alice@pbs"}},
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Fatalf("ListTrafficControlRules() = %+v, want %+v", rules, wantRules)
	}

	create := url.Values{"name": {"office"}, "network": {"10.0.0.1/8", "192.0.2.0/24"}, "users": {"alice@pbs", "bob@pbs"},
		"rate-in": {"10MiB"}}
	if err := c.CreateTrafficControlRule(ctx, create); err != nil {
		t.Fatalf("CreateTrafficControlRule() = %v", err)
	}
	rule, err := c.GetTrafficControlRule(ctx, "office")
	if err != nil {
		t.Fatal(err)
	}
	wantRule := TrafficControlRule{Name: "office", Network: []string{"192.0.2.0/24", "10.0.0.1/8"},
		Timeframe: []string{"mon..fri 8-12", "mon..fri 14:30-18"}, RateOut: "1.5 GB", Comment: "Office"}
	if !reflect.DeepEqual(rule, wantRule) {
		t.Fatalf("GetTrafficControlRule() = %+v, want %+v", rule, wantRule)
	}
	update := url.Values{"timeframe": {"8-12", "14-16"}, "delete": {"burst-in", "comment", "users"}}
	if err := c.UpdateTrafficControlRule(ctx, "office", update); err != nil {
		t.Fatalf("UpdateTrafficControlRule() = %v", err)
	}
	if err := c.DeleteTrafficControlRule(ctx, "office"); err != nil {
		t.Fatalf("DeleteTrafficControlRule() = %v", err)
	}

	want := []string{listRoute, createRoute, getRoute, updateRoute, deleteRoute}
	if got := fake.routes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if call := fake.lastCall(t, createRoute); !reflect.DeepEqual(call.form, create) {
		t.Errorf("CreateTrafficControlRule form = %v, want %v", call.form, create)
	}
	if call := fake.lastCall(t, updateRoute); !reflect.DeepEqual(call.form, update) {
		t.Errorf("UpdateTrafficControlRule form = %v, want %v", call.form, update)
	}
	for _, route := range []string{getRoute, deleteRoute} {
		if call := fake.lastCall(t, route); len(call.query) != 0 || len(call.form) != 0 {
			t.Errorf("%s query = %v, form = %v, want neither", route, call.query, call.form)
		}
	}
}

// A missing rule is a 400 on read and update and a 404 on delete, all of them
// not found; a taken name is a 400 the provider tells apart, and a missing
// network neither.
func TestTrafficControlErrorsAreRecognised(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/traffic-control/missing", http.StatusBadRequest, "no such rule 'missing'")
	fake.reply("PUT /config/traffic-control/missing", http.StatusBadRequest, "no such rule 'missing'")
	fake.reply("DELETE /config/traffic-control/missing", http.StatusNotFound, "traffic control rule 'missing' does not exist.")
	fake.replies("POST /config/traffic-control", http.StatusBadRequest,
		"parameter verification failed - 'name': traffic control rule 'taken' already exists.",
		"parameter verification failed - 'network': parameter is missing and it is not optional.")
	c := fake.client(t)
	ctx := context.Background()

	if rule, err := c.GetTrafficControlRule(ctx, "missing"); !IsNotFound(err) || IsAlreadyExists(err) || !reflect.DeepEqual(rule, TrafficControlRule{}) {
		t.Errorf("GetTrafficControlRule() = %+v, %v, want only a not-found error", rule, err)
	}
	if err := c.UpdateTrafficControlRule(ctx, "missing", url.Values{"comment": {"x"}}); !IsNotFound(err) {
		t.Errorf("UpdateTrafficControlRule() = %v, want a not-found error", err)
	}
	if err := c.DeleteTrafficControlRule(ctx, "missing"); !IsNotFound(err) || IsEndpointMissing(err) {
		t.Errorf("DeleteTrafficControlRule() = %v, want a not-found error", err)
	}
	if err := c.CreateTrafficControlRule(ctx, url.Values{"name": {"taken"}, "network": {"10.0.0.0/8"}}); !IsAlreadyExists(err) || IsNotFound(err) {
		t.Errorf("CreateTrafficControlRule(taken) = %v, want an already-exists error", err)
	}
	if err := c.CreateTrafficControlRule(ctx, url.Values{"name": {"office"}}); err == nil || IsAlreadyExists(err) || IsNotFound(err) {
		t.Errorf("CreateTrafficControlRule(no network) = %v, want a plain 400", err)
	}
}
