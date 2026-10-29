package provider

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeTrafficControl keeps traffic control rules in memory and serves PBS's
// API for them through a fakePBS, with the behaviour read in PBS 4.2's source
// (see internal/pbsclient/traffic_control.go):
//
//   - network, timeframe and users are JSON arrays in the order sent; network
//     is always there, every other property only when set;
//   - rates and bursts read back in PBS's spelling, such as "10 MiB";
//   - creating a rule needs name and network, and refuses a taken name;
//   - an update's delete accepts only the names PBS accepts, network not
//     among them, and PBS applies the deletions before the values; an array
//     an update carries replaces the stored one whole; the comment is
//     trimmed, and an empty one deleted;
//   - a missing rule is 400 "no such rule 'x'" on GET and PUT, and 404
//     "traffic control rule 'x' does not exist." on DELETE; PUT and DELETE
//     refuse a stale digest, which covers every rule;
//   - GET /admin/traffic-control lists the rules with their current rates,
//     0 until a test sets them;
//   - both lists answer in reverse name order: PBS answers in no particular
//     one, and the data sources must sort.
//
// Tests set up state with addRule and setCurrentRates, and look at it with
// rule.
type fakeTrafficControl struct {
	fake *fakePBS

	mu    sync.Mutex
	rules map[string]fakeProperties
	// rates are the current rates of each rule, in and out, in bytes per
	// second.
	rates map[string][2]int64
	// gen counts the changes to traffic-control.cfg, for its digest.
	gen int
}

// What PBS keeps of a rule as arrays, and what an update may delete.
var (
	fakeTrafficControlArrays    = []string{"network", "timeframe", "users"}
	fakeTrafficControlDeletable = []string{"rate-in", "burst-in", "rate-out", "burst-out", "comment", "timeframe", "users"}
)

// fakeCIDRPattern is the shape of PBS's CIDR notation: an address and a
// prefix length, whose range PBS does not check.
var fakeCIDRPattern = regexp.MustCompile(`^([0-9.]+/[0-9]{1,2}|[0-9A-Fa-f:.]+/[0-9]{1,3})$`)

// newFakeTrafficControl serves the traffic control API from fake.
func newFakeTrafficControl(fake *fakePBS) *fakeTrafficControl {
	c := &fakeTrafficControl{fake: fake, rules: map[string]fakeProperties{}, rates: map[string][2]int64{}}
	fake.handle("GET /config/traffic-control", c.listRules)
	fake.handle("POST /config/traffic-control", c.createRule)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /config/traffic-control/", c.serveRule)
	}
	fake.handle("GET /admin/traffic-control", c.listCurrentRates)
	return c
}

// --- test helpers -------------------------------------------------------------

func (c *fakeTrafficControl) addRule(name string, props fakeProperties) {
	c.mu.Lock()
	defer c.mu.Unlock()
	props = cloneProperties(props)
	props["name"] = name
	c.rules[name] = props
	c.gen++
}

// setCurrentRates sets what GET /admin/traffic-control reports a rule's
// connections reach now.
func (c *fakeTrafficControl) setCurrentRates(name string, in, out int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rates[name] = [2]int64{in, out}
}

func (c *fakeTrafficControl) rule(name string) (fakeProperties, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	props, ok := c.rules[name]
	return cloneProperties(props), ok
}

// fakeTrafficControlJoined is an array property of a stored rule, its
// elements joined by commas in their stored order; "" when it is not set.
func fakeTrafficControlJoined(props fakeProperties, key string) string {
	values, _ := props[key].([]string)
	return strings.Join(values, ",")
}

// --- serving ------------------------------------------------------------------

// rulesLocked returns the rules in reverse name order; the caller holds the
// lock.
func (c *fakeTrafficControl) rulesLocked() []fakeProperties {
	names := make([]string, 0, len(c.rules))
	for name := range c.rules {
		names = append(names, name)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	list := make([]fakeProperties, 0, len(names))
	for _, name := range names {
		list = append(list, c.rules[name])
	}
	return list
}

func (c *fakeTrafficControl) digestLocked() string {
	return fakeDigest(pbsclient.ConfigTrafficControl, c.gen)
}

func (c *fakeTrafficControl) listRules(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	writeData(w, c.rulesLocked(), c.digestLocked())
}

// listCurrentRates serves GET /admin/traffic-control: every rule, with the
// rates of its connections.
func (c *fakeTrafficControl) listCurrentRates(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := []fakeProperties{}
	for _, rule := range c.rulesLocked() {
		withRates := cloneProperties(rule)
		rates := c.rates[rule["name"].(string)]
		withRates["cur-rate-in"], withRates["cur-rate-out"] = rates[0], rates[1]
		list = append(list, withRates)
	}
	writeData(w, list, c.digestLocked())
}

// checkTrafficControlForm fails like PBS on a network not in CIDR notation.
func checkTrafficControlForm(w http.ResponseWriter, params url.Values) bool {
	for _, network := range params["network"] {
		if !fakeCIDRPattern.MatchString(network) {
			writeError(w, "parameter verification failed - 'network': value does not match the regex pattern")
			return false
		}
	}
	return true
}

// applyTrafficControlForm sets the properties a form carries, as PBS stores
// them: arrays in the order sent, replacing what was there, and sizes in its
// own spelling.
func applyTrafficControlForm(props fakeProperties, params url.Values) {
	applyFakeForm(props, params, nil, nil, slices.Concat(fakeTrafficControlArrays, fakeByteSizes)...)
	for _, key := range fakeTrafficControlArrays {
		if values, ok := params[key]; ok {
			props[key] = slices.Clone(values)
		}
	}
	for _, key := range fakeByteSizes {
		if v, ok := params[key]; ok {
			props[key] = fakeHumanByte(v[0])
		}
	}
}

func (c *fakeTrafficControl) createRule(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "name", "network") || !checkTrafficControlForm(w, params) {
		return
	}
	name := params.Get("name")
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.rules[name]; exists {
		writeError(w, "parameter verification failed - 'name': traffic control rule '%s' already exists.", name)
		return
	}
	props := fakeProperties{}
	applyTrafficControlForm(props, params)
	c.rules[name] = props
	c.gen++
	writeData(w, nil, "")
}

// serveRule serves /config/traffic-control/{name}.
func (c *fakeTrafficControl) serveRule(w http.ResponseWriter, req *http.Request) {
	name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/traffic-control/")
	params := form(req)
	c.mu.Lock()
	defer c.mu.Unlock()
	props, exists := c.rules[name]

	switch req.Method {
	case http.MethodGet:
		if !exists {
			writeError(w, "no such rule '%s'", name)
			return
		}
		writeData(w, props, c.digestLocked())
	case http.MethodPut:
		if !checkDelete(w, params, fakeTrafficControlDeletable...) || !checkTrafficControlForm(w, params) {
			return
		}
		if staleDigest(params, c.digestLocked()) {
			writeError(w, fakeDigestConflict)
			return
		}
		if !exists {
			writeError(w, "no such rule '%s'", name)
			return
		}
		updated := cloneProperties(props)
		for _, key := range params[pbsclient.DeleteParam] {
			delete(updated, key)
		}
		applyTrafficControlForm(updated, params)
		if comment, ok := updated["comment"].(string); ok && comment == "" {
			delete(updated, "comment")
		}
		c.rules[name] = updated
		c.gen++
		writeData(w, nil, "")
	case http.MethodDelete:
		if staleDigest(params, c.digestLocked()) {
			writeError(w, fakeDigestConflict)
			return
		}
		if !exists {
			writeFakeResponse(w, http.StatusNotFound, fmt.Sprintf("traffic control rule '%s' does not exist.", name))
			return
		}
		delete(c.rules, name)
		delete(c.rates, name)
		c.gen++
		writeData(w, nil, "")
	}
}
