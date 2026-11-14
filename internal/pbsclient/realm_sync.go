package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// What PBS 4.x does when asked to sync the users of a realm, read in its
// source (src/api2/access/domain.rs sync_realm, src/server/realm_sync_job.rs,
// pbs-api-types ldap.rs; proxmox-backup 7c86c5ad5, after 4.2.11, the same
// since 4.0):
//
//   - POST /access/domains/{realm}/sync needs Permissions.Modify on
//     /access/users and starts task realm-sync, whose worker ID is the
//     realm. It takes dry-run (default false), enable-new and
//     remove-vanished; the last two default to the realm's
//     sync-defaults-options, and to true and nothing without them. A
//     remove-vanished sent replaces the realm's, it does not add to it.
//   - remove-vanished is a list of acl, entry and properties, separated by
//     commas, semicolons or white space, of one element at least: an empty
//     string is a parameter error. entry deletes the users of the realm the
//     directory no longer has, with their API tokens and token secrets; acl
//     deletes their ACL entries and their tokens', but only together with
//     entry, as PBS looks at it only while deleting users — acl alone
//     removes nothing; properties clears the names and email address of the
//     users it finds that the directory has no value for.
//   - A realm that does not exist fails the call: 400 "unable to find realm
//     <realm>". A realm of any type but ldap and ad starts the task all the
//     same, which then fails with "cannot sync realm <realm> of type
//     <type>".
//   - The task searches the directory, then takes the locks of user.cfg and
//     acl.cfg — the ones every user and ACL write takes — and creates,
//     updates and deletes users. It logs one line per user it creates,
//     updates or deletes, nothing for a user that is unchanged, and no
//     totals: "creating user <userid>", "updating user <userid>", "deleting
//     user <userid>", and "could not create/update user: <reason>" for a
//     directory entry it skips, such as one without the user attribute,
//     which counts as information, not as a warning. A dry run logs "this is
//     a DRY RUN - changes will not be persisted" first, the same lines, and
//     saves nothing. Existing users keep their comment, expiry and enabled
//     flag; their names and email address are those of the directory. New
//     users are enabled as enable-new says, and so are existing users that
//     have no enabled flag stored.
//   - Starting a sync holds the realm's job lock only while the task is
//     being started: a second call within those milliseconds waits up to
//     10 s and answers 400 "realm sync already running"
//     (IsTaskAlreadyRunning), but two syncs of the same realm can otherwise
//     run at the same time.
//   - proxmox-ldap's own sync module, which PBS does not use as of 4.2.11,
//     logs "would create user", "would update user" and "would delete
//     user" in a dry run, and "updating user <userid>:" followed by the
//     changes; ParseRealmSyncLog reads both forms.

// RealmSyncOptions are what a sync of a realm does besides the realm's own
// settings.
type RealmSyncOptions struct {
	// DryRun only logs what the sync would do.
	DryRun bool
	// EnableNew, when set, overrides the realm's enable-new.
	EnableNew *bool
	// RemoveVanished, when not nil, replaces the realm's remove-vanished:
	// "acl", "entry" and "properties". An empty, non-nil list removes
	// nothing.
	RemoveVanished []string
}

// StartRealmSync starts a sync of the users of an LDAP or Active Directory
// realm and returns its task.
func (c *Client) StartRealmSync(ctx context.Context, realm string, options RealmSyncOptions) (UPID, error) {
	params := url.Values{}
	if options.DryRun {
		params.Set("dry-run", FormatBool(true))
	}
	if options.EnableNew != nil {
		params.Set("enable-new", FormatBool(*options.EnableNew))
	}
	if options.RemoveVanished != nil {
		values := slices.Sorted(slices.Values(options.RemoveVanished))
		if len(values) == 0 {
			// PBS takes no empty list, and acl alone removes nothing: it is
			// only consulted while deleting users, which needs entry.
			values = []string{"acl"}
		}
		params.Set("remove-vanished", strings.Join(values, ";"))
	}
	return c.StartTask(ctx, http.MethodPost, Path("access", "domains", realm, "sync"), params)
}

// RealmSyncSummary is what a realm sync's log says it did, or would do in a
// dry run.
type RealmSyncSummary struct {
	DryRun bool
	// Created, Updated and Deleted are the user IDs of the users the sync
	// created, changed and deleted, in the order of the log.
	Created []string
	Updated []string
	Deleted []string
	// Skipped are the reasons the sync gave for the directory entries it
	// could not turn into users.
	Skipped []string
}

// ParseRealmSyncLog reads what a realm sync did from its log.
func ParseRealmSyncLog(lines []TaskLogLine) RealmSyncSummary {
	var summary RealmSyncSummary
	userID := func(rest string) string {
		return strings.TrimSuffix(strings.TrimSpace(rest), ":")
	}
	for _, line := range lines {
		message := line.Message()
		switch {
		case strings.HasPrefix(message, "this is a DRY RUN"):
			summary.DryRun = true
		case strings.HasPrefix(message, "creating user "):
			summary.Created = append(summary.Created, userID(strings.TrimPrefix(message, "creating user ")))
		case strings.HasPrefix(message, "would create user "):
			summary.DryRun = true
			summary.Created = append(summary.Created, userID(strings.TrimPrefix(message, "would create user ")))
		case strings.HasPrefix(message, "updating user "):
			summary.Updated = append(summary.Updated, userID(strings.TrimPrefix(message, "updating user ")))
		case strings.HasPrefix(message, "would update user "):
			summary.DryRun = true
			summary.Updated = append(summary.Updated, userID(strings.TrimPrefix(message, "would update user ")))
		case strings.HasPrefix(message, "deleting user "):
			summary.Deleted = append(summary.Deleted, userID(strings.TrimPrefix(message, "deleting user ")))
		case strings.HasPrefix(message, "would delete user "):
			summary.DryRun = true
			summary.Deleted = append(summary.Deleted, userID(strings.TrimPrefix(message, "would delete user ")))
		case strings.HasPrefix(message, "could not create/update user: "):
			summary.Skipped = append(summary.Skipped, strings.TrimPrefix(message, "could not create/update user: "))
		}
	}
	return summary
}

// IsRealmUnknown reports whether PBS refused to sync a realm it does not
// have: 400 "unable to find realm <realm>".
func IsRealmUnknown(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest && strings.HasPrefix(apiErr.Message, "unable to find realm ")
}
