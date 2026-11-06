package pbsclient

import (
	"context"
	"net/url"
	"strings"
)

// The subscription of a node, /nodes/{node}/subscription. What PBS 4.0 and
// 4.2 do, read in their source (src/api2/node/subscription.rs and the
// proxmox-subscription crate):
//
//   - GET reads /etc/proxmox-backup/subscription and never asks Proxmox. It
//     answers status "notfound" and the message "There is no subscription
//     key" without one. With Sys.Audit on / — not /system — it answers the
//     whole record, the key included; without it only status, message and
//     url. A stored active status turns invalid when the record is older
//     than 20 days or the server ID no longer matches.
//   - PUT checks the key's format first, then sends it with the node's
//     server ID to Proxmox's shop, through the node's HTTP proxy, and only
//     then writes the record and APT's credentials for the enterprise
//     repository. Whatever the shop answers is written: an invalid or
//     expired key is no error. A shop PBS cannot reach is "Error checking
//     subscription: client error (Connect)", and nothing is written. PBS
//     sets no timeout for the shop.
//   - DELETE removes the record and APT's credentials, and tells nobody;
//     without a record it fails, "Deleting subscription failed: No such file
//     or directory (os error 2)".
//   - The daily update has PBS check the key again — an active key once its
//     last check is more than five days old, another one every day —, so
//     status, message and checktime change on their own.

// Subscription is the subscription of a node as GET reports it. Fields PBS
// leaves out are empty.
type Subscription struct {
	// Status is new, notfound, active, invalid, expired or suspended.
	Status      string `json:"status"`
	ServerID    string `json:"serverid,omitempty"`
	CheckTime   int64  `json:"checktime,omitempty"`
	Key         string `json:"key,omitempty"`
	Message     string `json:"message,omitempty"`
	ProductName string `json:"productname,omitempty"`
	RegDate     string `json:"regdate,omitempty"`
	NextDueDate string `json:"nextduedate,omitempty"`
	URL         string `json:"url,omitempty"`
	// Signature is set for an offline key.
	Signature string `json:"signature,omitempty"`
}

// SubscriptionNotFound is the status of a node without a subscription.
const SubscriptionNotFound = "notfound"

// GetSubscription reads the subscription of a node.
func (c *Client) GetSubscription(ctx context.Context, node string) (Subscription, error) {
	var subscription Subscription
	_, err := c.Get(ctx, Path("nodes", node, "subscription"), nil, &subscription)
	return subscription, err
}

// SetSubscription has a node check a subscription key with Proxmox and store
// it with Proxmox's verdict. It needs Sys.Modify on /system. The key is kept
// out of any error.
func (c *Client) SetSubscription(ctx context.Context, node, key string) error {
	_, err := c.Put(ctx, Path("nodes", node, "subscription"), url.Values{"key": {key}}, nil)
	return redactAPIError(err, key)
}

// DeleteSubscription removes the subscription of a node, which is no error
// when it has none. It needs Sys.Modify on /system.
func (c *Client) DeleteSubscription(ctx context.Context, node string) error {
	_, err := c.Delete(ctx, Path("nodes", node, "subscription"), nil, nil)
	if apiErr, ok := asError(err); ok && strings.HasPrefix(apiErr.Message, "Deleting subscription failed: No such file or directory") {
		return nil
	}
	return err
}

// IsSubscriptionShopUnreachable reports whether PBS failed to set a
// subscription key because it could not reach Proxmox's shop.
func IsSubscriptionShopUnreachable(err error) bool {
	apiErr, ok := asError(err)
	return ok && strings.HasPrefix(apiErr.Message, "Error checking subscription:")
}
