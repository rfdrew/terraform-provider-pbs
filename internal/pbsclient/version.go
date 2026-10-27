package pbsclient

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Version is what GET /version reports. Every authenticated user may read
// it, an API token without any ACL included.
type Version struct {
	// Version is the release line, e.g. "4.2".
	Version string `json:"version"`
	// Release is the patch level within the line, e.g. "8", without the
	// Debian revision.
	Release string `json:"release"`
	// RepoID is the git commit the release was built from.
	RepoID string `json:"repoid"`
}

// String is the full version, e.g. "4.2.8".
func (v Version) String() string {
	if v.Release == "" {
		return v.Version
	}
	return v.Version + "." + v.Release
}

// Parts returns the version as numbers, the way PBS compares versions
// itself. ok is false when the version does not parse.
func (v Version) Parts() (major, minor, release int, ok bool) {
	line, _, _ := strings.Cut(v.Version, "-")
	majorText, minorText, found := strings.Cut(line, ".")
	if !found {
		return 0, 0, 0, false
	}
	var err error
	if major, err = strconv.Atoi(majorText); err != nil {
		return 0, 0, 0, false
	}
	if minor, err = strconv.Atoi(minorText); err != nil {
		return 0, 0, 0, false
	}
	if v.Release != "" {
		if release, err = strconv.Atoi(v.Release); err != nil {
			return 0, 0, 0, false
		}
	}
	return major, minor, release, true
}

// AtLeast reports whether the version is major.minor.release or newer. A
// version that does not parse counts as new enough: refusing a field on a
// server whose version is unknown would block more than it protects.
func (v Version) AtLeast(major, minor, release int) bool {
	gotMajor, gotMinor, gotRelease, ok := v.Parts()
	if !ok {
		return true
	}
	if gotMajor != major {
		return gotMajor > major
	}
	if gotMinor != minor {
		return gotMinor > minor
	}
	return gotRelease >= release
}

// ServerVersion reads GET /version. It is the cheapest authenticated call, so
// it doubles as the check that the endpoint and the credentials work.
func (c *Client) ServerVersion(ctx context.Context) (Version, error) {
	var v Version
	if _, err := c.Get(ctx, "/version", nil, &v); err != nil {
		return Version{}, err
	}
	if v.Version == "" {
		return Version{}, fmt.Errorf("GET /version answered without a version")
	}
	return v, nil
}
