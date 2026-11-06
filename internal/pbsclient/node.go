package pbsclient

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// The node's own settings. What PBS 4.0 and 4.2 do with them, read in their
// source (src/api2/node/{config,dns}.rs, pbs-config/src/node.rs and
// pbs-api-types/src/node.rs):
//
//   - GET /nodes/{node}/config answers node.cfg, leaving out what is unset,
//     with its digest next to data; PUT changes the properties it carries,
//     deletes those named in delete — every property can be deleted — under
//     node.cfg's lock, and checks a non-empty digest. Deleting applies before
//     setting. The ACME settings live in the same file (see acme.go), so a
//     write of either kind carries the digest and holds
//     WithConfigLock(ConfigNode).
//   - PUT rewrites the APT proxy configuration from http-proxy every time.
//     Nothing else takes effect at once: the proxy reads its ciphers when it
//     starts, so a change waits for its restart.
//   - location is a property string, "latitude=<deg>,longitude=<deg>" and an
//     optional name, which PBS 4.2.1 added.
//   - GET /nodes/{node}/dns reads /etc/resolv.conf: the last search or
//     domain line's first domain as search, the first three nameserver lines
//     as dns1 to dns3, and every other line, comments included, joined as
//     options. The digest, the SHA-256 of the file, is inside data. PUT
//     changes what it carries, deletes the nameservers named in delete —
//     search cannot be deleted — and writes the file anew: search, the
//     nameservers in order, then the options; nameservers past the third
//     are dropped. A nameserver deleted before another one is no gap: the
//     next read numbers them again from dns1. The file is written by
//     renaming a new one over it, which fails with "Atomic rename failed"
//     where /etc/resolv.conf is a mount point, as in a Docker container.

// NodeSettings is a node's configuration, GET /nodes/{node}/config, but for
// its ACME settings, which NodeConfig holds. Empty strings and nil are
// properties PBS leaves out.
type NodeSettings struct {
	HTTPProxy      string `json:"http-proxy,omitempty"`
	EmailFrom      string `json:"email-from,omitempty"`
	CiphersTLS12   string `json:"ciphers-tls-1.2,omitempty"`
	CiphersTLS13   string `json:"ciphers-tls-1.3,omitempty"`
	DefaultLang    string `json:"default-lang,omitempty"`
	Description    string `json:"description,omitempty"`
	TaskLogMaxDays *int64 `json:"task-log-max-days,omitempty"`
	ConsentText    string `json:"consent-text,omitempty"`
	// Location is a property string; see ParseNodeLocation.
	Location string `json:"location,omitempty"`
}

// GetNodeSettings reads a node's settings and the digest of node.cfg. It
// needs Sys.Audit on /system.
func (c *Client) GetNodeSettings(ctx context.Context, node string) (NodeSettings, string, error) {
	var settings NodeSettings
	env, err := c.Get(ctx, Path("nodes", node, "config"), nil, &settings)
	if err != nil {
		return NodeSettings{}, "", err
	}
	return settings, env.Digest, nil
}

// NodeLocation is the location property of a node's settings.
type NodeLocation struct {
	// Name is the location's name, empty when unset.
	Name      string
	Latitude  float64
	Longitude float64
}

// ParseNodeLocation parses a location property.
func ParseNodeLocation(s string) (NodeLocation, error) {
	p, err := ParsePropertyString(s, "")
	if err != nil {
		return NodeLocation{}, err
	}
	location := NodeLocation{Name: p["name"]}
	for key, value := range map[string]*float64{"latitude": &location.Latitude, "longitude": &location.Longitude} {
		raw, ok := p[key]
		if !ok {
			return NodeLocation{}, &missingKeyError{key: key}
		}
		if *value, err = strconv.ParseFloat(raw, 64); err != nil {
			return NodeLocation{}, err
		}
	}
	return location, nil
}

// Format writes the location as PBS reads it.
func (l NodeLocation) Format() string {
	p := PropertyString{
		"latitude":  strconv.FormatFloat(l.Latitude, 'f', -1, 64),
		"longitude": strconv.FormatFloat(l.Longitude, 'f', -1, 64),
	}
	if l.Name != "" {
		p["name"] = l.Name
	}
	return p.Format("")
}

type missingKeyError struct{ key string }

func (e *missingKeyError) Error() string { return "the property string has no " + e.key }

// DNS is a node's DNS settings, GET /nodes/{node}/dns. Empty strings are
// settings the node does not have.
type DNS struct {
	Search string `json:"search,omitempty"`
	DNS1   string `json:"dns1,omitempty"`
	DNS2   string `json:"dns2,omitempty"`
	DNS3   string `json:"dns3,omitempty"`
	// Options are the other lines of /etc/resolv.conf, which PBS keeps.
	Options string `json:"options,omitempty"`
	// Digest is the SHA-256 of /etc/resolv.conf, in hexadecimal.
	Digest string `json:"digest"`
}

// Nameservers returns dns1 to dns3, empty where unset.
func (d DNS) Nameservers() [3]string { return [3]string{d.DNS1, d.DNS2, d.DNS3} }

// ConfigDNS stands for /etc/resolv.conf, for WithConfigLock.
const ConfigDNS = "resolv.conf"

// GetDNS reads a node's DNS settings. It needs Sys.Audit on
// /system/network/dns.
func (c *Client) GetDNS(ctx context.Context, node string) (DNS, error) {
	var dns DNS
	_, err := c.Get(ctx, Path("nodes", node, "dns"), nil, &dns)
	return dns, err
}

// UpdateDNS changes the DNS settings params carries, and deletes the
// nameservers named in its delete parameter. It needs Sys.Modify on
// /system/network/dns. Callers hold WithConfigLock(ConfigDNS) and pass the
// digest they read.
func (c *Client) UpdateDNS(ctx context.Context, node string, params url.Values) error {
	_, err := c.Put(ctx, Path("nodes", node, "dns"), params, nil)
	return err
}

// IsResolvConfMountPoint reports whether PBS failed to write
// /etc/resolv.conf because it cannot rename a file over it: it is a mount
// point, as Docker makes it in a container.
func IsResolvConfMountPoint(err error) bool {
	apiErr, ok := asError(err)
	return ok && strings.Contains(apiErr.Message, "Atomic rename failed")
}

// A node's time, /nodes/{node}/time. What PBS 4.0 and 4.2 do, read in their
// source (src/api2/node/time.rs):
//
//   - GET answers the time zone, the time, and the local time as epoch
//     seconds shifted by the zone's offset. It reads the zone from
//     /etc/timezone, or the target of the /etc/localtime link, before PBS
//     4.2.3, and from timedatectl, or the link, since — with a line break
//     at the end when timedatectl answers.
//   - PUT sets the zone with timedatectl since PBS 4.2.3, falling back to
//     the link as PBS did before, when it also wrote /etc/timezone. A zone
//     without a file under /usr/share/zoneinfo is "No such timezone.".
//     There is no digest: the zone is one value.

// Time is a node's time as GET /nodes/{node}/time reports it.
type Time struct {
	Timezone string `json:"timezone"`
	// Time is the epoch time; LocalTime is it shifted by the zone's
	// current offset from UTC.
	Time      int64 `json:"time"`
	LocalTime int64 `json:"localtime"`
}

// GetTime reads a node's time and time zone, which any user may.
func (c *Client) GetTime(ctx context.Context, node string) (Time, error) {
	var t Time
	if _, err := c.Get(ctx, Path("nodes", node, "time"), nil, &t); err != nil {
		return Time{}, err
	}
	t.Timezone = strings.TrimSpace(t.Timezone)
	return t, nil
}

// SetTimezone sets a node's time zone. It needs Sys.Modify on /system/time.
func (c *Client) SetTimezone(ctx context.Context, node, timezone string) error {
	_, err := c.Put(ctx, Path("nodes", node, "time"), url.Values{"timezone": {timezone}}, nil)
	return err
}
