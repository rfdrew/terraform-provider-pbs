package pbsclient

import (
	"context"
	"net/url"
)

// Traffic control rules limit the bandwidth of the connections PBS accepts,
// by the client's network, and optionally by user and time of day; they live
// in traffic-control.cfg. What PBS 4.2 does, read in its source
// (src/api2/config/traffic_control.rs, pbs-api-types traffic_control.rs):
//
//   - Every call needs Sys.Modify on /, listing the rules too, except
//     reading one rule and GET /admin/traffic-control, which lists them with
//     their current rates: those need Sys.Audit on /.
//   - A read leaves out what is not set; networks, time frames and users are
//     JSON arrays, and the limits byte sizes in PBS's spelling.
//   - A duplicate name is 400 "parameter verification failed - 'name':
//     traffic control rule 'x' already exists.". A missing rule is 400 "no
//     such rule 'x'" on GET and PUT, and 404 "traffic control rule 'x' does
//     not exist." on DELETE; IsNotFound covers both.

// ConfigTrafficControl is the configuration file of traffic control rules,
// as a name for WithConfigLock.
const ConfigTrafficControl = "traffic-control.cfg"

// TrafficControlRule is a traffic control rule as PBS reports it.
type TrafficControlRule struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
	// Network holds the client networks the rule applies to, in CIDR
	// notation.
	Network []string `json:"network"`
	// Timeframe holds the times of day the rule applies at, as PBS daily
	// durations such as "mon..fri 8:00-18:00"; always when empty.
	Timeframe []string `json:"timeframe,omitempty"`
	// Users holds the users the rule applies to; everybody when empty.
	Users []string `json:"users,omitempty"`
	// RateIn, BurstIn, RateOut and BurstOut are byte sizes, in the spelling
	// PBS stores them in; SameByteSize compares them.
	RateIn   string `json:"rate-in,omitempty"`
	BurstIn  string `json:"burst-in,omitempty"`
	RateOut  string `json:"rate-out,omitempty"`
	BurstOut string `json:"burst-out,omitempty"`
}

// TrafficControlRuleRates is a traffic control rule with the rates its
// connections reach now, in bytes per second: always 0 for a direction the
// rule sets no rate for, and for a rule the proxy has not loaded yet.
type TrafficControlRuleRates struct {
	TrafficControlRule
	CurrentRateIn  int64 `json:"cur-rate-in"`
	CurrentRateOut int64 `json:"cur-rate-out"`
}

// ListTrafficControlRates lists the traffic control rules with their current
// rates, which needs only Sys.Audit.
func (c *Client) ListTrafficControlRates(ctx context.Context) ([]TrafficControlRuleRates, error) {
	var rules []TrafficControlRuleRates
	_, err := c.Get(ctx, "/admin/traffic-control", nil, &rules)
	return rules, err
}

// ListTrafficControlRules lists the traffic control rules.
func (c *Client) ListTrafficControlRules(ctx context.Context) ([]TrafficControlRule, error) {
	var rules []TrafficControlRule
	_, err := c.Get(ctx, "/config/traffic-control", nil, &rules)
	return rules, err
}

// GetTrafficControlRule reads one traffic control rule.
func (c *Client) GetTrafficControlRule(ctx context.Context, name string) (TrafficControlRule, error) {
	var rule TrafficControlRule
	_, err := c.Get(ctx, Path("config", "traffic-control", name), nil, &rule)
	return rule, err
}

// CreateTrafficControlRule creates a traffic control rule from params, which
// must hold "name" and "network".
func (c *Client) CreateTrafficControlRule(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/traffic-control", params, nil)
	return err
}

// UpdateTrafficControlRule changes the properties params carries, and
// deletes those named in its delete parameter.
func (c *Client) UpdateTrafficControlRule(ctx context.Context, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "traffic-control", name), params, nil)
	return err
}

// DeleteTrafficControlRule deletes a traffic control rule.
func (c *Client) DeleteTrafficControlRule(ctx context.Context, name string) error {
	_, err := c.Delete(ctx, Path("config", "traffic-control", name), nil, nil)
	return err
}
