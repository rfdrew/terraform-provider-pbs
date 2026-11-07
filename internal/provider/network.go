package provider

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// What pbs_network_interface and pbs_network_apply share: the names PBS
// takes for interfaces, the way it reads a VLAN interface's tag and device
// from its name, and checks of addresses and comments that make what PBS
// writes into /etc/network/interfaces read back the same.

// Privileges of the network calls. Reading and changing an interface is
// checked on its own path; creating one is open to root@pam only (see
// pbsclient's network.go); applying the pending changes is checked on the
// parent path.
const (
	networkInterfaceReadPrivilege   = "Sys.Audit on /system/network/interfaces/<name>"
	networkInterfaceModifyPrivilege = "Sys.Modify on /system/network/interfaces/<name>"
	networkApplyPrivilege           = "Sys.Modify on /system/network/interfaces"
)

// maxNetworkInterfaceNameLength is the kernel's IFNAMSIZ less the
// terminating zero, which PBS enforces.
const maxNetworkInterfaceNameLength = 15

// networkInterfaceNameValidators check an interface name as PBS does: a safe
// ID of 1 to 15 characters.
func networkInterfaceNameValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(1, maxNetworkInterfaceNameLength),
		stringvalidator.RegexMatches(safeIDPattern, "must be an interface name such as eno1, bond0 or vmbr1: a letter, "+
			"a digit or an underscore, followed by letters, digits, underscores, dots and hyphens"),
	}
}

// pbsVLANNamePattern is the pattern PBS reads a VLAN interface's name with
// (proxmox-network-api's VLAN_INTERFACE_REGEX), unanchored as there: the
// first branch is anchored at the start only, the second at the end only.
// <device>.<tag> names both the device and the tag, vlan<tag> only the tag.
var pbsVLANNamePattern = regexp.MustCompile(`^(?P<device>\S+)\.(?P<tag>\d+)|vlan(?P<tag2>\d+)$`)

// vlanFromName returns what PBS takes from a VLAN interface's name: the
// device it runs on, or "", and its tag, when the name has one PBS can read.
func vlanFromName(name string) (device string, tag int64, hasTag bool) {
	m := pbsVLANNamePattern.FindStringSubmatch(name)
	if m == nil {
		return "", 0, false
	}
	device = m[pbsVLANNamePattern.SubexpIndex("device")]
	text := m[pbsVLANNamePattern.SubexpIndex("tag")]
	if text == "" {
		text = m[pbsVLANNamePattern.SubexpIndex("tag2")]
	}
	// PBS parses the tag as a u16, and takes none from a larger number.
	n, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return device, 0, false
	}
	return device, int64(n), true
}

// looksLikeVLAN reports whether PBS would take name for a VLAN interface.
func looksLikeVLAN(name string) bool {
	return pbsVLANNamePattern.MatchString(name)
}

// interfaceAddressValidator accepts an address with its prefix length of one family,
// such as 192.0.2.10/24 or 2001:db8::10/64, as PBS's CIDR formats do. PBS
// keeps the text as given, so it is not normalised either.
type interfaceAddressValidator struct{ ipv6 bool }

func (v interfaceAddressValidator) family() string {
	if v.ipv6 {
		return "IPv6"
	}
	return "IPv4"
}

func (v interfaceAddressValidator) Description(_ context.Context) string {
	if v.ipv6 {
		return "must be an IPv6 address with its prefix length, such as 2001:db8::10/64"
	}
	return "must be an IPv4 address with its prefix length, such as 192.0.2.10/24"
}

func (v interfaceAddressValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v interfaceAddressValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	s := req.ConfigValue.ValueString()
	prefix, err := netip.ParsePrefix(s)
	// PBS refuses a prefix length of 0, and an IPv4 address written as
	// IPv6 (::ffff:192.0.2.1) is neither family's address to it.
	if err != nil || prefix.Addr().Is6() != v.ipv6 || prefix.Addr().Is4In6() || prefix.Bits() == 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid "+v.family()+" address",
			fmt.Sprintf("Attribute %s %s, and a prefix length of at least 1, got %q.", req.Path, v.Description(ctx), s))
	}
}

// gatewayValidator accepts an address of one family, without a prefix
// length. A link-local IPv6 gateway, such as fe80::1, is fine: ifupdown2
// adds the route through the interface it belongs to.
type gatewayValidator struct{ ipv6 bool }

func (v gatewayValidator) Description(_ context.Context) string {
	if v.ipv6 {
		return "must be an IPv6 address, such as 2001:db8::1 or fe80::1"
	}
	return "must be an IPv4 address, such as 192.0.2.1"
}

func (v gatewayValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v gatewayValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	s := req.ConfigValue.ValueString()
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Is6() != v.ipv6 || addr.Is4In6() || addr.Zone() != "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid gateway",
			fmt.Sprintf("Attribute %s %s, without a prefix length or zone, got %q.", req.Path, v.Description(ctx), s))
	}
}

// networkCommentsCheck accepts comments that read back as written. PBS
// writes each line as a "#" line of the stanza and reads it back trimmed of
// white space, and it drops empty lines at the start and the end; a value
// without any line is no comment at all.
var networkCommentsCheck = stringCheck{
	description: "must not contain control characters other than line breaks, must not begin or end with a line " +
		"break, and no line may begin or end with white space",
	check: func(s string) bool {
		if s == "" || strings.HasPrefix(s, "\n") || strings.HasSuffix(s, "\n") {
			return false
		}
		for _, line := range strings.Split(s, "\n") {
			if strings.ContainsFunc(line, unicode.IsControl) || strings.TrimSpace(line) != line {
				return false
			}
		}
		return true
	},
}
