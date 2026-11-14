package pbsclient

import "context"

// GET /config/notifications/matchers lists every notification matcher, as
// read in PBS 4.2's source (src/api2/config/notifications/matchers.rs,
// list_matchers, and proxmox-notify's api/matcher.rs, get_matchers):
//
//   - It needs Sys.Audit on /system/notifications, as reading one matcher
//     does.
//   - Each entry is the whole matcher, in the shape a single read answers
//     but without the digest, its origin included: the built-in
//     default-matcher is listed too, as builtin or modified-builtin, since
//     proxmox-notify merges the built-in entries into the configuration it
//     reads (lib.rs, Config::new).
//   - PBS 4.2.10 and later may answer an "expression" — the rule tree of the
//     matcher editor of that release — in place of the match-* properties,
//     mode and invert-match, which NotificationMatcher.Expression holds.

// ListNotificationMatchers lists every notification matcher, default-matcher
// included.
func (c *Client) ListNotificationMatchers(ctx context.Context) ([]NotificationMatcher, error) {
	var matchers []NotificationMatcher
	_, err := c.Get(ctx, "/config/notifications/matchers", nil, &matchers)
	return matchers, err
}
