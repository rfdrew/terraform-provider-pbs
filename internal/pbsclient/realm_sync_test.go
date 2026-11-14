package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

const realmSyncRoute = "POST /access/domains/corp/sync"

// The options a sync is started with are sent only when set, so that the
// realm's sync-defaults-options apply otherwise; remove-vanished is sorted,
// and an empty list, which PBS refuses, is sent as acl, which alone removes
// nothing.
func TestStartRealmSync(t *testing.T) {
	enable := false
	for _, tc := range []struct {
		name    string
		options RealmSyncOptions
		want    url.Values
	}{
		{"defaults", RealmSyncOptions{}, url.Values{}},
		{"dry run", RealmSyncOptions{DryRun: true}, url.Values{"dry-run": {"true"}}},
		{"enable-new", RealmSyncOptions{EnableNew: &enable}, url.Values{"enable-new": {"false"}}},
		{"remove-vanished", RealmSyncOptions{RemoveVanished: []string{"properties", "entry", "acl"}},
			url.Values{"remove-vanished": {"acl;entry;properties"}}},
		{"remove nothing", RealmSyncOptions{RemoveVanished: []string{}}, url.Values{"remove-vanished": {"acl"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(realmSyncRoute, http.StatusOK, taskAnswer(sampleUPID))
			upid, err := fake.client(t).StartRealmSync(context.Background(), "corp", tc.options)
			if err != nil {
				t.Fatal(err)
			}
			if upid.Raw != sampleUPID {
				t.Fatalf("upid = %+v", upid)
			}
			if got := fake.lastCall(t, realmSyncRoute).form; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("form = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsRealmUnknown(t *testing.T) {
	fake := newFakePBS()
	fake.reply(realmSyncRoute, http.StatusBadRequest, "unable to find realm corp")
	_, err := fake.client(t).StartRealmSync(context.Background(), "corp", RealmSyncOptions{})
	if !IsRealmUnknown(err) || IsTaskAlreadyRunning(err) {
		t.Fatalf("err = %v", err)
	}
	fake.reply(realmSyncRoute, http.StatusBadRequest, "realm sync already running")
	_, err = fake.client(t).StartRealmSync(context.Background(), "corp", RealmSyncOptions{})
	if IsRealmUnknown(err) || !IsTaskAlreadyRunning(err) {
		t.Fatalf("err = %v", err)
	}
}

// The log of a sync as PBS 4.x writes it, and as proxmox-ldap's own sync
// module would.
func TestParseRealmSyncLog(t *testing.T) {
	log := func(messages ...string) []TaskLogLine {
		lines := make([]TaskLogLine, 0, len(messages))
		for i, message := range messages {
			lines = append(lines, TaskLogLine{N: i + 1, Text: "2026-11-14T10:00:00+01:00: " + message})
		}
		return lines
	}
	for _, tc := range []struct {
		name  string
		lines []TaskLogLine
		want  RealmSyncSummary
	}{
		{
			name: "pbs",
			lines: log("creating user alice@corp", "updating user bob@corp", "creating user carol@corp",
				"could not create/update user: userid attribute `uid` not in LDAP search result",
				"dave@corp: ignoring attribute `email`: value does not match the regex pattern",
				"deleting user eve@corp", "could not delete token for user eve@corp: ENOENT", "TASK OK"),
			want: RealmSyncSummary{
				Created: []string{"alice@corp", "carol@corp"}, Updated: []string{"bob@corp"}, Deleted: []string{"eve@corp"},
				Skipped: []string{"userid attribute `uid` not in LDAP search result"},
			},
		},
		{
			name:  "pbs dry run",
			lines: log("this is a DRY RUN - changes will not be persisted", "creating user alice@corp", "TASK OK"),
			want:  RealmSyncSummary{DryRun: true, Created: []string{"alice@corp"}},
		},
		{
			name: "proxmox-ldap",
			lines: log("this is a DRY RUN. Changes will not be persisted.", "would create user alice@corp",
				"would update user bob@corp:", "  email: bob@old.example -> bob@example.org", "would delete user eve@corp",
				"this was a DRY RUN. Changes were not persisted.", "TASK OK"),
			want: RealmSyncSummary{
				DryRun: true, Created: []string{"alice@corp"}, Updated: []string{"bob@corp"}, Deleted: []string{"eve@corp"},
			},
		},
		{
			name:  "nothing changed",
			lines: log("TASK OK"),
			want:  RealmSyncSummary{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseRealmSyncLog(tc.lines); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("summary = %+v, want %+v", got, tc.want)
			}
		})
	}
}
