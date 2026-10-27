package pbsclient

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// DeleteParam is the parameter through which a PUT unsets optional
// properties. PUT changes only the properties it carries; to remove one, its
// name goes into delete. PBS takes the array as the key repeated
// (delete=comment&delete=port) — a comma-separated string is refused with 400
// — and checks every name against a list of its own per object: a name
// outside it, even of an optional property, fails the whole call. When a PUT
// both sets and deletes a property, the deletion happens first and the new
// value stays.
const DeleteParam = "delete"

// DigestParam carries the digest of the configuration file a write is based
// on; PBS refuses the write when the file changed since (IsDigestConflict).
const DigestParam = "digest"

// AddDelete appends names to the delete parameter of params, sorted, so that
// a request is the same from one run to the next.
func AddDelete(params url.Values, names ...string) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	for _, name := range sorted {
		params.Add(DeleteParam, name)
	}
}

// FormatBool writes a boolean the way PBS's own tools send it.
func FormatBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Property strings are PBS's way of nesting options in one parameter:
// comma-separated key=value pairs, such as a datastore's
// "tuning=chunk-order=inode,sync-level=filesystem" or a maintenance mode's
// "type=read-only,message=moving disks". A value that contains a comma, a
// quote, a backslash or white space is double-quoted, with \" and \\ escaped
// inside. Some formats have a default key, whose value may stand alone
// without "key=".

// PropertyString is a parsed property string. The default key's bare value,
// when the string has one, is under "".
type PropertyString map[string]string

// ParsePropertyString parses a property string. defaultKey names the key a
// bare value belongs to; with an empty defaultKey, a bare value is an error.
func ParsePropertyString(s, defaultKey string) (PropertyString, error) {
	out := PropertyString{}
	rest := strings.TrimSpace(s)
	for rest != "" {
		var key, value string
		var err error
		eq := strings.IndexAny(rest, "=,\"")
		if eq >= 0 && rest[eq] == '=' {
			key = strings.TrimSpace(rest[:eq])
			rest = rest[eq+1:]
		} else {
			if defaultKey == "" {
				return nil, fmt.Errorf("property string %q has a value without a key", s)
			}
			key = defaultKey
		}
		if key == "" {
			return nil, fmt.Errorf("property string %q has an empty key", s)
		}
		value, rest, err = parsePropertyValue(rest)
		if err != nil {
			return nil, fmt.Errorf("property string %q: %w", s, err)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("property string %q sets %q twice", s, key)
		}
		out[key] = value
		rest = strings.TrimSpace(rest)
		if rest != "" {
			if rest[0] != ',' {
				return nil, fmt.Errorf("property string %q: expected a comma after %q", s, key)
			}
			rest = strings.TrimSpace(rest[1:])
		}
	}
	return out, nil
}

// parsePropertyValue reads one value, quoted or not, and returns it and what
// follows it.
func parsePropertyValue(s string) (value, rest string, err error) {
	if !strings.HasPrefix(s, `"`) {
		end := strings.IndexByte(s, ',')
		if end < 0 {
			return strings.TrimSpace(s), "", nil
		}
		return strings.TrimSpace(s[:end]), s[end:], nil
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", "", fmt.Errorf("unterminated escape in %q", s)
			}
			i++
			b.WriteByte(s[i])
		case '"':
			return b.String(), s[i+1:], nil
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", fmt.Errorf("unterminated quote in %q", s)
}

// Format writes the property string with its keys sorted, so that the same
// properties always give the same string. The default key's value is written
// first and bare when defaultKey is set and present.
func (p PropertyString) Format(defaultKey string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		if k != "" && k != defaultKey {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var parts []string
	if v, ok := p[defaultKey]; ok && defaultKey != "" {
		parts = append(parts, quotePropertyValue(v))
	} else if v, ok := p[""]; ok {
		parts = append(parts, quotePropertyValue(v))
	}
	for _, k := range keys {
		parts = append(parts, k+"="+quotePropertyValue(p[k]))
	}
	return strings.Join(parts, ",")
}

func quotePropertyValue(v string) string {
	if v != "" && !strings.ContainsAny(v, ",\"\\= \t\n") {
		return v
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		if v[i] == '"' || v[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	b.WriteByte('"')
	return b.String()
}

// Byte sizes — rate and burst limits, cache sizes — are strings with an
// optional unit, such as "10MiB", "1.5 GB" or "500": decimal units (KB, MB,
// GB, TB, PB) and binary ones (KiB … PiB, and K … P without the "iB"), or
// bytes without a unit. PBS may store a size in another spelling than it was
// given, so sizes are compared by their value.

var byteUnits = map[string]float64{
	"": 1, "b": 1,
	"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12, "pb": 1e15,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40, "pib": 1 << 50,
	"k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40, "p": 1 << 50,
}

// ParseByteSize returns the number of bytes a size stands for.
func ParseByteSize(s string) (uint64, error) {
	trimmed := strings.TrimSpace(s)
	split := strings.IndexFunc(trimmed, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	number, unit := trimmed, ""
	if split >= 0 {
		number, unit = trimmed[:split], strings.TrimSpace(trimmed[split:])
	}
	factor, ok := byteUnits[strings.ToLower(unit)]
	if number == "" || !ok {
		return 0, fmt.Errorf("%q is not a byte size such as 500, 64KiB, 10MiB or 1.5GB", s)
	}
	value, err := strconv.ParseFloat(number, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%q is not a byte size such as 500, 64KiB, 10MiB or 1.5GB", s)
	}
	bytes := math.Round(value * factor)
	if bytes > math.MaxUint64 {
		return 0, fmt.Errorf("byte size %q is too large", s)
	}
	return uint64(bytes), nil
}

// SameByteSize reports whether two sizes stand for the same number of bytes.
// A size that does not parse equals only the identical string.
func SameByteSize(a, b string) bool {
	if a == b {
		return true
	}
	x, errA := ParseByteSize(a)
	y, errB := ParseByteSize(b)
	return errA == nil && errB == nil && x == y
}
