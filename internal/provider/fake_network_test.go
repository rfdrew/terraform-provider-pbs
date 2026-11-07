package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeNetwork serves a node's network configuration as PBS 4 does
// (src/api2/node/network.rs, proxmox-network-api's parser and writer), from
// what the handlers do rather than from the provider's client:
//
//   - the running configuration, /etc/network/interfaces, and the pending
//     one, interfaces.new; reads and writes use the pending one when it
//     exists. The node's physical NICs, as `ip link` reports them, are added
//     to whichever is read, as type eth, method manual, without autostart.
//   - the digest is the SHA-256 of the file as PBS writes it, which this
//     fake renders; GET of an interface sends it inside data, the list on
//     every interface, with the diff next to data while changes are
//     pending.
//   - POST creates bridges, bonds and VLAN interfaces, for root@pam signed
//     in with a password only — anyone else gets 403, as the server checks
//     the permission with the name from the path a create does not have.
//   - PUT sets the IPv4 method from the address and gateway, whatever it
//     was; the IPv6 method too, except that from 4.1.7 one without an
//     address is kept (keepMethod6).
//   - every write checks the whole configuration as PBS's writer does: ports
//     and slaves used once, bond slaves physical and existing, bridge ports
//     existing, a child's MTU at most its parent's.
//   - what PBS writes and reads back: a bond's primary only in
//     active-backup and its hash policy only in 802.3ad and balance-xor
//     mode, VLAN awareness only when on, comments trimmed line by line, an
//     inet6 stanza only when the method is not manual or it has comments or
//     options.
//   - PUT /nodes/{node}/network applies the pending file in a task, which
//     fails without ifupdown2 or as reloadError says; DELETE drops it.
type fakeNetwork struct {
	mu   sync.Mutex
	fake *fakePBS
	node string

	running []*fakeIface
	pending []*fakeIface
	// hasPending says whether interfaces.new exists; hasRunningFile whether
	// /etc/network/interfaces does.
	hasPending     bool
	hasRunningFile bool
	// physical are the NICs `ip link` reports, and up those it reports up.
	physical []string
	up       map[string]bool

	ifupdown2   bool
	keepMethod6 bool
	reloadError string
	reloads     int

	taskGen int
	tasks   map[string]func() string
}

// fakeIface is one interface as PBS's Interface struct holds it.
type fakeIface struct {
	Name               string   `json:"name"`
	Type               string   `json:"type"`
	Autostart          bool     `json:"autostart"`
	Active             bool     `json:"active"`
	Method             string   `json:"method,omitempty"`
	Method6            string   `json:"method6,omitempty"`
	CIDR               string   `json:"cidr,omitempty"`
	Gateway            string   `json:"gateway,omitempty"`
	CIDR6              string   `json:"cidr6,omitempty"`
	Gateway6           string   `json:"gateway6,omitempty"`
	Options            []string `json:"options,omitempty"`
	Options6           []string `json:"options6,omitempty"`
	Comments           string   `json:"comments,omitempty"`
	Comments6          string   `json:"comments6,omitempty"`
	MTU                *int64   `json:"mtu,omitempty"`
	BridgePorts        []string `json:"bridge_ports,omitempty"`
	BridgeVLANAware    *bool    `json:"bridge_vlan_aware,omitempty"`
	VLANID             *int64   `json:"vlan-id,omitempty"`
	VLANRawDevice      string   `json:"vlan-raw-device,omitempty"`
	Slaves             []string `json:"slaves,omitempty"`
	BondMode           string   `json:"bond_mode,omitempty"`
	BondPrimary        string   `json:"bond-primary,omitempty"`
	BondXmitHashPolicy string   `json:"bond_xmit_hash_policy,omitempty"`
}

func (i *fakeIface) clone() *fakeIface {
	c := *i
	c.Options = slices.Clone(i.Options)
	c.Options6 = slices.Clone(i.Options6)
	c.BridgePorts = slices.Clone(i.BridgePorts)
	c.Slaves = slices.Clone(i.Slaves)
	if i.MTU != nil {
		n := *i.MTU
		c.MTU = &n
	}
	if i.VLANID != nil {
		n := *i.VLANID
		c.VLANID = &n
	}
	if i.BridgeVLANAware != nil {
		b := *i.BridgeVLANAware
		c.BridgeVLANAware = &b
	}
	return &c
}

// newFakeNetwork serves the network API of node from fake. The node starts
// with the physical NICs given, nothing in its configuration but lo, and
// ifupdown2.
func newFakeNetwork(fake *fakePBS, node string, physical ...string) *fakeNetwork {
	n := &fakeNetwork{
		fake:           fake,
		node:           node,
		running:        []*fakeIface{{Name: "lo", Type: "loopback", Autostart: true, Method: "loopback"}},
		hasRunningFile: true,
		physical:       physical,
		up:             map[string]bool{},
		ifupdown2:      true,
		keepMethod6:    true,
		tasks:          map[string]func() string{},
	}
	for _, nic := range physical {
		n.up[nic] = true
	}
	base := "/nodes/" + node + "/network"
	fake.handle("GET "+base, n.list)
	fake.handle("POST "+base, n.create)
	fake.handle("PUT "+base, n.reload)
	fake.handle("DELETE "+base, n.revert)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" "+base+"/", n.serveInterface(base+"/"))
	}
	fake.handlePrefix("GET /nodes/"+node+"/tasks/", n.taskStatus(node))
	return n
}

// --- test helpers -------------------------------------------------------------

// add puts an interface into the running configuration, as if the file had
// it.
func (n *fakeNetwork) add(iface *fakeIface) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.running = append(n.running, iface)
}

// get returns a copy of an interface of the configuration PBS reads, or nil.
func (n *fakeNetwork) get(name string) *fakeIface {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, i := range n.configLocked() {
		if i.Name == name {
			return i.clone()
		}
	}
	return nil
}

// runningInterface returns a copy of an interface of the running
// configuration, or nil.
func (n *fakeNetwork) runningInterface(name string) *fakeIface {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, i := range n.running {
		if i.Name == name {
			return i.clone()
		}
	}
	return nil
}

// pendingChanges reports whether changes are pending.
func (n *fakeNetwork) pendingChanges() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.hasPending && n.renderLocked(n.pending) != n.renderLocked(n.running)
}

// edit changes an interface of the pending configuration — as the web
// interface would —, creating the pending file when there is none.
func (n *fakeNetwork) edit(name string, change func(*fakeIface)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	config := n.configLocked()
	for _, i := range config {
		if i.Name == name {
			change(i)
		}
	}
	n.pending, n.hasPending = config, true
}

// --- the configuration ----------------------------------------------------------

// configLocked returns a copy of the configuration PBS parses — the
// pending file, or the running one — with the physical NICs the file does
// not name.
func (n *fakeNetwork) configLocked() []*fakeIface {
	source := n.running
	if n.hasPending {
		source = n.pending
	}
	var config []*fakeIface
	named := map[string]bool{}
	for _, i := range source {
		c := i.clone()
		c.Active = n.up[c.Name]
		config = append(config, c)
		named[c.Name] = true
	}
	for _, nic := range n.physical {
		if !named[nic] {
			config = append(config, &fakeIface{Name: nic, Type: "eth", Method: "manual", Active: n.up[nic]})
		}
	}
	return config
}

// renderLocked writes a configuration as PBS's writer does, which is what
// its digest covers; interfaces without a method are left out.
func (n *fakeNetwork) renderLocked(config []*fakeIface) string {
	var b strings.Builder
	for _, i := range config {
		if i.Method == "" && i.Method6 == "" {
			continue
		}
		if i.Autostart {
			fmt.Fprintf(&b, "auto %s\n", i.Name)
		}
		common := func() {
			switch i.Type {
			case "bridge":
				if i.BridgeVLANAware != nil && *i.BridgeVLANAware {
					b.WriteString("\tbridge-vlan-aware yes\n")
				}
				ports := "none"
				if len(i.BridgePorts) > 0 {
					ports = strings.Join(i.BridgePorts, " ")
				}
				fmt.Fprintf(&b, "\tbridge-ports %s\n", ports)
			case "bond":
				mode := i.BondMode
				if mode == "" {
					mode = defaultBondMode
				}
				fmt.Fprintf(&b, "\tbond-mode %s\n", mode)
				if i.BondPrimary != "" && mode == "active-backup" {
					fmt.Fprintf(&b, "\tbond-primary %s\n", i.BondPrimary)
				}
				if i.BondXmitHashPolicy != "" && (mode == "802.3ad" || mode == "balance-xor") {
					fmt.Fprintf(&b, "\tbond_xmit_hash_policy %s\n", i.BondXmitHashPolicy)
				}
				slaves := "none"
				if len(i.Slaves) > 0 {
					slaves = strings.Join(i.Slaves, " ")
				}
				fmt.Fprintf(&b, "\tbond-slaves %s\n", slaves)
			case "vlan":
				if i.VLANID != nil {
					fmt.Fprintf(&b, "\tvlan-id %d\n", *i.VLANID)
				}
				if i.VLANRawDevice != "" {
					fmt.Fprintf(&b, "\tvlan-raw-device %s\n", i.VLANRawDevice)
				}
			}
			if i.MTU != nil {
				fmt.Fprintf(&b, "\tmtu %d\n", *i.MTU)
			}
		}
		family := func(method, cidr, gateway string, options []string, comments string) {
			if method == "static" {
				if cidr != "" {
					fmt.Fprintf(&b, "\taddress %s\n", cidr)
				}
				if gateway != "" {
					fmt.Fprintf(&b, "\tgateway %s\n", gateway)
				}
			}
			for _, o := range options {
				fmt.Fprintf(&b, "\t%s\n", o)
			}
			if comments != "" {
				for _, line := range strings.Split(comments, "\n") {
					fmt.Fprintf(&b, "#%s\n", line)
				}
			}
		}
		if i.Method != "" {
			fmt.Fprintf(&b, "iface %s inet %s\n", i.Name, i.Method)
			family(i.Method, i.CIDR, i.Gateway, i.Options, i.Comments)
			common()
			b.WriteString("\n")
		}
		skipV6 := i.Method != "" && i.Method6 == "manual" && i.Comments6 == "" && len(i.Options6) == 0
		if i.Method6 != "" && !skipV6 {
			fmt.Fprintf(&b, "iface %s inet6 %s\n", i.Name, i.Method6)
			family(i.Method6, i.CIDR6, i.Gateway6, i.Options6, i.Comments6)
			if i.Method == "" {
				common()
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// fakeReadBack is what PBS reads from what it wrote of an interface: the
// writer leaves things out and the parser trims comments.
func fakeReadBack(i *fakeIface) *fakeIface {
	c := i.clone()
	trim := func(comments string) string {
		var lines []string
		for _, line := range strings.Split(comments, "\n") {
			line = strings.TrimSpace(line)
			if len(lines) == 0 && line == "" {
				continue
			}
			lines = append(lines, line)
		}
		return strings.Join(lines, "\n")
	}
	c.Comments = trim(c.Comments)
	c.Comments6 = trim(c.Comments6)
	if c.Type == "bond" {
		if c.BondMode == "" {
			c.BondMode = defaultBondMode
		}
		if c.BondMode != "active-backup" {
			c.BondPrimary = ""
		}
		if c.BondMode != "802.3ad" && c.BondMode != "balance-xor" {
			c.BondXmitHashPolicy = ""
		}
	}
	if c.BridgeVLANAware != nil && !*c.BridgeVLANAware {
		c.BridgeVLANAware = nil
	}
	if c.Method == "static" || c.Method == "" {
		// Addresses are written only for static.
	} else {
		c.CIDR, c.Gateway = "", ""
	}
	if c.Method6 != "static" {
		c.CIDR6, c.Gateway6 = "", ""
	}
	if c.Method != "" && c.Method6 == "manual" && c.Comments6 == "" && len(c.Options6) == 0 {
		c.Method6 = ""
	}
	return c
}

func (n *fakeNetwork) digestLocked() string {
	source := n.running
	if n.hasPending {
		source = n.pending
	}
	sum := sha256.Sum256([]byte(n.renderLocked(source)))
	return hex.EncodeToString(sum[:])
}

// saveLocked checks a configuration as PBS's writer does and makes it the
// pending one. It answers the error and returns false when PBS would.
func (n *fakeNetwork) saveLocked(w http.ResponseWriter, config []*fakeIface) bool {
	byName := map[string]*fakeIface{}
	for _, i := range config {
		byName[i.Name] = i
	}
	used := map[string]string{}
	for _, i := range config {
		for _, port := range append(slices.Clone(i.BridgePorts), i.Slaves...) {
			if prev, ok := used[port]; ok {
				writeError(w, "iface '%s' port '%s' is already used on interface '%s'", i.Name, port, prev)
				return false
			}
			used[port] = i.Name
		}
	}
	mtu := func(parent, child *fakeIface) bool {
		if child.MTU == nil {
			return true
		}
		parentMTU := int64(1500)
		if parent.MTU != nil {
			parentMTU = *parent.MTU
		} else if parent.Type == "bond" {
			parentMTU = *child.MTU
		}
		if parentMTU < *child.MTU {
			writeError(w, "interface '%s' - mtu %d is lower than '%s' - mtu %d\n", parent.Name, parentMTU, child.Name, *child.MTU)
			return false
		}
		return true
	}
	for _, i := range config {
		for _, slave := range i.Slaves {
			s := byName[slave]
			if s == nil {
				writeError(w, "bond '%s' - unable to find slave '%s'", i.Name, slave)
				return false
			}
			if s.Type != "eth" {
				writeError(w, "bond '%s' - wrong interface type on slave '%s' (%s != Eth)", i.Name, slave, fakeTypeName(s.Type))
				return false
			}
			if !mtu(i, s) {
				return false
			}
		}
	}
	for _, i := range config {
		for _, port := range i.BridgePorts {
			name := port
			if dev, _, ok := strings.Cut(port, "."); ok && dev != "" {
				if _, err := strconv.Atoi(port[len(dev)+1:]); err == nil {
					name = dev
				}
			}
			p := byName[name]
			if p == nil {
				writeError(w, "bridge '%s' - unable to find port '%s'", i.Name, name)
				return false
			}
			if !mtu(i, p) {
				return false
			}
		}
	}
	// The file keeps the physical NICs PBS added while parsing, as
	// "iface <nic> inet manual".
	var saved []*fakeIface
	for _, i := range config {
		c := i.clone()
		c.Active = false
		saved = append(saved, c)
	}
	n.pending, n.hasPending = saved, true
	return true
}

// fakeTypeName is the Debug name PBS prints for an interface type.
func fakeTypeName(t string) string {
	if t == "" {
		return "Unknown"
	}
	return strings.ToUpper(t[:1]) + t[1:]
}

// --- serving ------------------------------------------------------------------

// fakeIsRoot reports whether the request comes from root@pam signed in with
// a password: an API token never is.
func (n *fakeNetwork) fakeIsRoot(req *http.Request) bool {
	if req.Header.Get("Authorization") != "" {
		return false
	}
	n.fake.mu.Lock()
	defer n.fake.mu.Unlock()
	return n.fake.username == "root@pam"
}

func (n *fakeNetwork) list(w http.ResponseWriter, _ *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	digest := n.digestLocked()
	var items []map[string]any
	config := n.configLocked()
	sort.Slice(config, func(a, b int) bool { return config[a].Name < config[b].Name })
	for _, i := range config {
		if i.Name == "lo" {
			continue
		}
		items = append(items, n.itemLocked(i, digest))
	}
	envelope := map[string]any{"data": items}
	if n.hasPending {
		if !n.hasRunningFile {
			writeError(w, "diff failed: status code: 2 - diff: /etc/network/interfaces: No such file or directory\n")
			return
		}
		if diff := n.diffLocked(); diff != "" {
			envelope["changes"] = diff
		}
	}
	writeJSON(w, envelope)
}

// itemLocked is an interface as PBS sends it.
func (n *fakeNetwork) itemLocked(i *fakeIface, digest string) map[string]any {
	c := fakeReadBack(i)
	c.Active = n.up[c.Name]
	item := map[string]any{}
	raw := mustJSON(c)
	for k, v := range raw {
		item[k] = v
	}
	item["active"] = c.Active
	item["autostart"] = c.Autostart
	item["digest"] = digest
	item["iface"] = c.Name
	// PBS sends an empty list for a bridge or bond without ports or
	// slaves: bridge-ports none reads as Some([]).
	if c.Type == "bridge" && c.BridgePorts == nil {
		item["bridge_ports"] = []string{}
	}
	if c.Type == "bond" && c.Slaves == nil {
		item["slaves"] = []string{}
	}
	return item
}

// diffLocked is a line diff of the running and the pending file, enough to
// show something; PBS runs diff -b -u.
func (n *fakeNetwork) diffLocked() string {
	before, after := n.renderLocked(n.running), n.renderLocked(n.pending)
	if before == after {
		return ""
	}
	var b strings.Builder
	b.WriteString("--- /etc/network/interfaces\n+++ /etc/network/interfaces.new\n")
	old := map[string]bool{}
	for _, line := range strings.Split(before, "\n") {
		old[line] = true
	}
	nw := map[string]bool{}
	for _, line := range strings.Split(after, "\n") {
		nw[line] = true
		if !old[line] {
			b.WriteString("+" + line + "\n")
		}
	}
	for _, line := range strings.Split(before, "\n") {
		if !nw[line] {
			b.WriteString("-" + line + "\n")
		}
	}
	return b.String()
}

func (n *fakeNetwork) serveInterface(prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+prefix)
		switch req.Method {
		case http.MethodGet:
			n.mu.Lock()
			defer n.mu.Unlock()
			for _, i := range n.configLocked() {
				if i.Name == name {
					writeData(w, n.itemLocked(i, n.digestLocked()), "")
					return
				}
			}
			writeError(w, "interface '%s' does not exist.", name)
		case http.MethodPut:
			n.update(w, req, name)
		case http.MethodDelete:
			n.deleteInterface(w, req, name)
		}
	}
}

// fakeNetworkDeletable are the names PUT takes in delete.
var fakeNetworkDeletable = []string{"cidr", "cidr6", "gateway", "gateway6", "method", "method6", "comments",
	"comments6", "mtu", "autostart", "bridge_ports", "bridge_vlan_aware", "slaves", "bond-primary",
	"bond_xmit_hash_policy"}

var fakeNetworkMethods = []string{"manual", "static", "dhcp", "loopback", "auto"}

// checkNetworkParams fails like PBS's schema does.
func checkNetworkParams(w http.ResponseWriter, params url.Values) bool {
	for _, key := range []string{"method", "method6"} {
		if v := params.Get(key); v != "" && !slices.Contains(fakeNetworkMethods, v) {
			writeError(w, "parameter verification failed - '%s': value '%s' is not defined in the enumeration.", key, v)
			return false
		}
	}
	if v := params.Get("mtu"); v != "" {
		if mtu, err := strconv.Atoi(v); err != nil || mtu < 46 || mtu > 65535 {
			writeError(w, "parameter verification failed - 'mtu': value must have a minimum value of 46")
			return false
		}
	}
	for _, d := range params[pbsclient.DeleteParam] {
		if !slices.Contains(fakeNetworkDeletable, d) {
			writeError(w, "parameter verification failed - 'delete': value '%s' is not defined in the enumeration.", d)
			return false
		}
	}
	return true
}

func splitFakeList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
}

func (n *fakeNetwork) create(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !n.fakeIsRoot(req) {
		writeFakeResponse(w, http.StatusForbidden, "permission check failed")
		return
	}
	if !checkRequired(w, params, "iface") || !checkNetworkParams(w, params) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	name, typ := params.Get("iface"), params.Get("type")
	if typ == "" {
		writeError(w, "parameter 'type' is missing")
		return
	}
	config := n.configLocked()
	for _, i := range config {
		if i.Name == name {
			writeError(w, "interface '%s' already exists", name)
			return
		}
	}
	iface := &fakeIface{Name: name, Type: typ}
	if v, ok := params["autostart"]; ok {
		iface.Autostart = fakeBool(v[0])
	}
	iface.Method, iface.Method6 = params.Get("method"), params.Get("method6")
	n.setCommonLocked(iface, params)
	if v := params.Get("cidr"); v != "" {
		iface.CIDR = v
	}
	if v := params.Get("cidr6"); v != "" {
		iface.CIDR6 = v
	}
	if !n.setGatewaysLocked(w, config, iface, params) {
		return
	}
	switch typ {
	case "bridge":
		if v, ok := params["bridge_ports"]; ok {
			iface.BridgePorts = splitFakeList(v[0])
		}
		if v, ok := params["bridge_vlan_aware"]; ok {
			b := fakeBool(v[0])
			iface.BridgeVLANAware = &b
		}
	case "bond":
		if mode := params.Get("bond_mode"); mode != "" {
			iface.BondMode = mode
			if p := params.Get("bond-primary"); p != "" {
				if mode != "active-backup" {
					writeError(w, "bond-primary is only valid with Active/Backup mode")
					return
				}
				iface.BondPrimary = p
			}
			if p := params.Get("bond_xmit_hash_policy"); p != "" {
				if mode != "802.3ad" && mode != "balance-xor" {
					writeError(w, "bond_xmit_hash_policy is only valid with LACP(802.3ad) or balance-xor mode")
					return
				}
				iface.BondXmitHashPolicy = p
			}
		}
		if v, ok := params["slaves"]; ok {
			iface.Slaves = splitFakeList(v[0])
		}
	case "vlan":
		device, _, hasTag := vlanFromName(name)
		if params.Get("vlan-id") == "" && !hasTag {
			writeError(w, "vlan-id must be set")
			return
		}
		if v := params.Get("vlan-id"); v != "" {
			id, _ := strconv.ParseInt(v, 10, 64)
			iface.VLANID = &id
		}
		dev := params.Get("vlan-raw-device")
		if dev == "" {
			dev = device
		}
		if dev == "" {
			writeError(w, "vlan-raw-device must be set")
			return
		}
		if !slices.ContainsFunc(config, func(i *fakeIface) bool { return i.Name == dev }) {
			writeError(w, "vlan-raw-device %s does not exist", dev)
			return
		}
		iface.VLANRawDevice = params.Get("vlan-raw-device")
	default:
		writeError(w, "creating network interface type '%s' is not supported", fakeTypeName(typ))
		return
	}
	if iface.CIDR != "" || iface.Gateway != "" {
		iface.Method = "static"
	} else if iface.Method == "" {
		iface.Method = "manual"
	}
	if iface.CIDR6 != "" || iface.Gateway6 != "" {
		iface.Method6 = "static"
	} else if iface.Method6 == "" {
		iface.Method6 = "manual"
	}
	if n.saveLocked(w, append(config, iface)) {
		writeData(w, nil, "")
	}
}

// setCommonLocked sets what create and update set alike.
func (n *fakeNetwork) setCommonLocked(iface *fakeIface, params url.Values) {
	if v := params.Get("mtu"); v != "" {
		mtu, _ := strconv.ParseInt(v, 10, 64)
		iface.MTU = &mtu
	}
	if v, ok := params["comments"]; ok {
		iface.Comments = v[0]
	}
	if v, ok := params["comments6"]; ok {
		iface.Comments6 = v[0]
	}
}

// setGatewaysLocked sets the gateways, refusing a second one of a family
// as PBS does.
func (n *fakeNetwork) setGatewaysLocked(w http.ResponseWriter, config []*fakeIface, iface *fakeIface, params url.Values) bool {
	for _, family := range []struct {
		param, label string
		get          func(*fakeIface) string
		set          func(string)
	}{
		{"gateway", "IPv4", func(i *fakeIface) string { return i.Gateway }, func(s string) { iface.Gateway = s }},
		{"gateway6", "IPv6", func(i *fakeIface) string { return i.Gateway6 }, func(s string) { iface.Gateway6 = s }},
	} {
		v := params.Get(family.param)
		if v == "" {
			continue
		}
		for _, other := range config {
			if other.Name != iface.Name && family.get(other) != "" {
				writeError(w, "Default %s gateway already exists on interface '%s'", family.label, other.Name)
				return false
			}
		}
		family.set(v)
	}
	return true
}

func (n *fakeNetwork) update(w http.ResponseWriter, req *http.Request, name string) {
	params := form(req)
	if !checkNetworkParams(w, params) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if staleDigest(params, n.digestLocked()) {
		writeError(w, fakeDigestConflict)
		return
	}
	config := n.configLocked()
	var iface *fakeIface
	for _, i := range config {
		if i.Name == name {
			iface = i
		}
	}
	// Before it looks the interface up, PBS checks that the VLAN device —
	// the one the call names, or else the one the name gives — exists, on
	// every change of an interface. (It checks the gateways there too; this
	// fake checks them with the other properties, below.)
	dev := params.Get("vlan-raw-device")
	if dev == "" {
		dev, _, _ = vlanFromName(name)
	}
	if dev != "" && !slices.ContainsFunc(config, func(i *fakeIface) bool { return i.Name == dev }) {
		writeError(w, "vlan-raw-device %s does not exist", dev)
		return
	}
	if iface == nil {
		writeError(w, "interface '%s' does not exist.", name)
		return
	}
	if t := params.Get("type"); t != "" && t != iface.Type {
		writeError(w, "got unexpected interface type (%s != %s)", fakeTypeName(t), fakeTypeName(iface.Type))
		return
	}
	for _, d := range params[pbsclient.DeleteParam] {
		switch d {
		case "cidr":
			iface.CIDR = ""
		case "cidr6":
			iface.CIDR6 = ""
		case "gateway":
			iface.Gateway = ""
		case "gateway6":
			iface.Gateway6 = ""
		case "method":
			iface.Method = ""
		case "method6":
			iface.Method6 = ""
		case "comments":
			iface.Comments = ""
		case "comments6":
			iface.Comments6 = ""
		case "mtu":
			iface.MTU = nil
		case "autostart":
			iface.Autostart = false
		case "bridge_ports":
			if iface.Type != "bridge" {
				writeError(w, "interface '%s' is no bridge (type is %s)", name, fakeTypeName(iface.Type))
				return
			}
			iface.BridgePorts = []string{}
		case "bridge_vlan_aware":
			iface.BridgeVLANAware = nil
		case "slaves":
			if iface.Type != "bond" {
				writeError(w, "interface '%s' is no bond (type is %s)", name, fakeTypeName(iface.Type))
				return
			}
			iface.Slaves = []string{}
		case "bond-primary":
			iface.BondPrimary = ""
		case "bond_xmit_hash_policy":
			iface.BondXmitHashPolicy = ""
		}
	}
	if v, ok := params["autostart"]; ok {
		iface.Autostart = fakeBool(v[0])
	}
	if v := params.Get("method"); v != "" {
		iface.Method = v
	}
	if v := params.Get("method6"); v != "" {
		iface.Method6 = v
	}
	n.setCommonLocked(iface, params)
	if v, ok := params["bridge_ports"]; ok {
		if iface.Type != "bridge" {
			writeError(w, "interface '%s' is no bridge (type is %s)", name, fakeTypeName(iface.Type))
			return
		}
		iface.BridgePorts = splitFakeList(v[0])
	}
	if v, ok := params["bridge_vlan_aware"]; ok {
		b := fakeBool(v[0])
		iface.BridgeVLANAware = &b
	}
	if v, ok := params["slaves"]; ok {
		if iface.Type != "bond" {
			writeError(w, "interface '%s' is no bond (type is %s)", name, fakeTypeName(iface.Type))
			return
		}
		iface.Slaves = splitFakeList(v[0])
	}
	if mode := params.Get("bond_mode"); mode != "" {
		iface.BondMode = mode
		if p := params.Get("bond-primary"); p != "" {
			if mode != "active-backup" {
				writeError(w, "bond-primary is only valid with Active/Backup mode")
				return
			}
			iface.BondPrimary = p
		}
		if p := params.Get("bond_xmit_hash_policy"); p != "" {
			if mode != "802.3ad" && mode != "balance-xor" {
				writeError(w, "bond_xmit_hash_policy is only valid with LACP(802.3ad) or balance-xor mode")
				return
			}
			iface.BondXmitHashPolicy = p
		}
	}
	if v := params.Get("cidr"); v != "" {
		iface.CIDR = v
	}
	if v := params.Get("cidr6"); v != "" {
		iface.CIDR6 = v
	}
	if !n.setGatewaysLocked(w, config, iface, params) {
		return
	}
	if iface.CIDR != "" || iface.Gateway != "" {
		iface.Method = "static"
	} else {
		iface.Method = "manual"
	}
	switch {
	case iface.CIDR6 != "" || iface.Gateway6 != "":
		iface.Method6 = "static"
	case iface.Method6 == "" || !n.keepMethod6:
		iface.Method6 = "manual"
	}
	if v := params.Get("vlan-id"); v != "" {
		id, _ := strconv.ParseInt(v, 10, 64)
		iface.VLANID = &id
	}
	if v := params.Get("vlan-raw-device"); v != "" {
		iface.VLANRawDevice = v
	}
	if n.saveLocked(w, config) {
		writeData(w, nil, "")
	}
}

func (n *fakeNetwork) deleteInterface(w http.ResponseWriter, req *http.Request, name string) {
	params := form(req)
	n.mu.Lock()
	defer n.mu.Unlock()
	if staleDigest(params, n.digestLocked()) {
		writeError(w, fakeDigestConflict)
		return
	}
	config := n.configLocked()
	index := slices.IndexFunc(config, func(i *fakeIface) bool { return i.Name == name })
	if index < 0 {
		writeError(w, "interface '%s' does not exist.", name)
		return
	}
	if n.saveLocked(w, slices.Delete(config, index, index+1)) {
		writeData(w, nil, "")
	}
}

func (n *fakeNetwork) reload(w http.ResponseWriter, _ *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.ifupdown2 {
		writeError(w, "ifupdown2 is not installed.")
		return
	}
	n.taskGen++
	upid := fmt.Sprintf("UPID:%s:00000003:00000003:%08X:6AE11CDF:srvreload:networking:%s:", n.node, n.taskGen, fakeTokenID)
	n.tasks[upid] = func() string {
		n.reloads++
		if n.hasPending {
			n.running, n.pending, n.hasPending = n.pending, nil, false
			n.hasRunningFile = true
		}
		if n.reloadError != "" {
			return "ifreload failed: status code: 1 - " + n.reloadError
		}
		for _, i := range n.running {
			if i.Autostart {
				n.up[i.Name] = true
			}
		}
		return "OK"
	}
	writeData(w, upid, "")
}

func (n *fakeNetwork) revert(w http.ResponseWriter, _ *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pending, n.hasPending = nil, false
	writeData(w, nil, "")
}

func (n *fakeNetwork) taskStatus(node string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		rest := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/nodes/"+node+"/tasks/")
		upid, ok := strings.CutSuffix(rest, "/status")
		if !ok {
			writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		exit := "unknown"
		if run, ok := n.tasks[upid]; ok {
			exit = run()
			delete(n.tasks, upid)
		}
		writeData(w, map[string]any{"status": "stopped", "exitstatus": exit, "upid": upid}, "")
	}
}

// writeJSON answers v, a whole envelope, with 200.
func writeJSON(w http.ResponseWriter, v any) {
	body, _ := json.Marshal(v)
	writeFakeResponse(w, http.StatusOK, string(body))
}

// mustJSON is v as the JSON object it marshals to.
func mustJSON(v any) map[string]any {
	raw, _ := json.Marshal(v)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}
