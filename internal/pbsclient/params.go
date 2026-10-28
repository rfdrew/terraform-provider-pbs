package pbsclient

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
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

// Byte sizes — rate and burst limits — are strings PBS parses as its
// proxmox-human-byte crate does: a number, optionally followed by white space
// and a unit. The unit is one of the letters K, M, G, T and P, in either case,
// for a power of 1000, or the letter followed by a lower-case "i" for a power
// of 1024, then an optional "B" or "b"; no unit, or "B" alone, means bytes.
// So "10M" and "10MB" are 10,000,000 bytes, "10Mi" and "10MiB" 10,485,760,
// and "10MIB" is no size at all. PBS writes a size back in its own spelling —
// the number, rounded to three decimals, a space and the unit, such as
// "10 MiB" for "10mib" — so sizes are compared by their value.

// byteUnitFactors are the powers of 1000 and of 1024 each unit letter stands
// for.
var byteUnitFactors = map[rune][2]float64{
	'k': {1e3, 1 << 10},
	'm': {1e6, 1 << 20},
	'g': {1e9, 1 << 30},
	't': {1e12, 1 << 40},
	'p': {1e15, 1 << 50},
}

// byteSizeNumber is the number of a byte size: digits, with an optional
// fraction. PBS would take more forms of a floating-point number, such as
// "1e3" or "inf", which no one writes for a size.
var byteSizeNumber = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// ParseByteSize returns the number of bytes a size stands for, rounded to a
// whole byte.
func ParseByteSize(s string) (uint64, error) {
	invalid := fmt.Errorf("%q is not a byte size such as 500, 64KiB, 10MiB or 1.5GB", s)
	rest := s
	if strings.HasSuffix(rest, "B") || strings.HasSuffix(rest, "b") {
		rest = rest[:len(rest)-1]
	}
	binary := strings.HasSuffix(rest, "i")
	if binary {
		rest = rest[:len(rest)-1]
	}
	factor := 1.0
	if rest != "" {
		if factors, ok := byteUnitFactors[unicode.ToLower(rune(rest[len(rest)-1]))]; ok {
			factor = factors[0]
			if binary {
				factor = factors[1]
			}
			rest = rest[:len(rest)-1]
		} else if binary {
			// PBS reads "10i" as 10 bytes; it is a typo rather than a size.
			return 0, invalid
		}
	}
	number := strings.TrimRightFunc(rest, unicode.IsSpace)
	if !byteSizeNumber.MatchString(number) {
		return 0, invalid
	}
	value, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, invalid
	}
	bytes := math.Round(value * factor)
	// float64(math.MaxUint64) rounds up to 2^64, which no uint64 holds.
	if bytes >= math.MaxUint64 {
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
