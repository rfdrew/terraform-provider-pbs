package pbsclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

const (
	verifyRoute = "POST /admin/datastore/store1/verify"
	pruneRoute  = "POST /admin/datastore/store1/prune-datastore"
)

// A verification sends what is set, under PBS's names, and leaves the rest
// to PBS's defaults.
func TestStartVerify(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	no := false
	for _, tc := range []struct {
		name    string
		options VerifyOptions
		want    url.Values
	}{
		{"datastore", VerifyOptions{}, url.Values{}},
		{"namespace", VerifyOptions{NS: "dept1/hosts", MaxDepth: n(0)}, url.Values{"ns": {"dept1/hosts"}, "max-depth": {"0"}}},
		{"group", VerifyOptions{BackupType: "vm", BackupID: "100"}, url.Values{"backup-type": {"vm"}, "backup-id": {"100"}}},
		{
			"snapshot", VerifyOptions{NS: "dept1", BackupType: "ct", BackupID: "web.1", BackupTime: n(1794621605)},
			url.Values{"ns": {"dept1"}, "backup-type": {"ct"}, "backup-id": {"web.1"}, "backup-time": {"1794621605"}},
		},
		{
			"options", VerifyOptions{IgnoreVerified: &no, OutdatedAfter: n(30), ReadThreads: n(2), VerifyThreads: n(8)},
			url.Values{"ignore-verified": {"false"}, "outdated-after": {"30"}, "read-threads": {"2"}, "verify-threads": {"8"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(verifyRoute, http.StatusOK, taskAnswer(sampleUPID))
			upid, err := fake.client(t).StartVerify(context.Background(), "store1", tc.options)
			if err != nil {
				t.Fatal(err)
			}
			if upid.Raw != sampleUPID {
				t.Fatalf("upid = %+v", upid)
			}
			if got := fake.lastCall(t, verifyRoute).form; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("form = %v, want %v", got, tc.want)
			}
		})
	}
}

// A prune sends the kinds of retention that are set, and dry-run only when
// it is one.
func TestStartPruneDatastore(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	for _, tc := range []struct {
		name    string
		options PruneDatastoreOptions
		want    url.Values
	}{
		{"keep", PruneDatastoreOptions{Keep: KeepOptions{KeepLast: n(2), KeepDaily: n(7)}},
			url.Values{"keep-last": {"2"}, "keep-daily": {"7"}}},
		{
			"every kind", PruneDatastoreOptions{Keep: KeepOptions{
				KeepLast: n(1), KeepHourly: n(2), KeepDaily: n(3), KeepWeekly: n(4), KeepMonthly: n(5), KeepYearly: n(6),
			}},
			url.Values{
				"keep-last": {"1"}, "keep-hourly": {"2"}, "keep-daily": {"3"}, "keep-weekly": {"4"},
				"keep-monthly": {"5"}, "keep-yearly": {"6"},
			},
		},
		{"namespace", PruneDatastoreOptions{NS: "dept1", MaxDepth: n(0), Keep: KeepOptions{KeepLast: n(1)}},
			url.Values{"ns": {"dept1"}, "max-depth": {"0"}, "keep-last": {"1"}}},
		{"dry run", PruneDatastoreOptions{Keep: KeepOptions{KeepYearly: n(3)}, DryRun: true},
			url.Values{"keep-yearly": {"3"}, "dry-run": {"true"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(pruneRoute, http.StatusOK, taskAnswer(sampleUPID))
			upid, err := fake.client(t).StartPruneDatastore(context.Background(), "store1", tc.options)
			if err != nil {
				t.Fatal(err)
			}
			if upid.Raw != sampleUPID {
				t.Fatalf("upid = %+v", upid)
			}
			if got := fake.lastCall(t, pruneRoute).form; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("form = %v, want %v", got, tc.want)
			}
		})
	}
}

// What PBS answers when it refuses to verify a group or a backup the caller
// may not verify, or that does not exist; prune-datastore's refusal is the
// 400 IsPrivilegeMissing reports, verify's a 403.
func TestVerifyAndPruneErrors(t *testing.T) {
	for _, tc := range []struct {
		route        string
		status       int
		body         string
		ownerFailed  bool
		groupMissing bool
		privilege    bool
		forbidden    bool
	}{
		{verifyRoute, 400, "backup owner check failed (tfacc@pbs!acc != root@pam)", true, false, false, false},
		{verifyRoute, 400, `unable to read "/datastore/store1/ns/dept1/vm/999/owner" - No such file or directory (os error 2)`, false, true, false, false},
		// Another file PBS cannot read, or another reason, is something else.
		{verifyRoute, 400, `unable to read "/datastore/store1/vm/100/owner" - Permission denied (os error 13)`, false, false, false, false},
		{verifyRoute, 400, `unable to read "/etc/proxmox-backup/user.cfg" - No such file or directory (os error 2)`, false, false, false, false},
		{verifyRoute, 403, "permission check failed - missing Datastore.Verify|Datastore.Backup on /datastore/store1/dept1", false, false, false, true},
		{pruneRoute, 400, "missing permissions 'Datastore.Modify|Datastore.Prune' on '/datastore/store1/dept1'", false, false, true, false},
	} {
		fake := newFakePBS()
		fake.reply(tc.route, tc.status, tc.body)
		var err error
		if tc.route == verifyRoute {
			_, err = fake.client(t).StartVerify(context.Background(), "store1", VerifyOptions{})
		} else {
			_, err = fake.client(t).StartPruneDatastore(context.Background(), "store1", PruneDatastoreOptions{})
		}
		if err == nil {
			t.Fatalf("%q: no error", tc.body)
		}
		if IsBackupOwnerCheckFailed(err) != tc.ownerFailed || IsBackupGroupMissing(err) != tc.groupMissing ||
			IsPrivilegeMissing(err) != tc.privilege || IsForbidden(err) != tc.forbidden || IsNotFound(err) {
			t.Errorf("%d %q: owner check failed %v, group missing %v, privilege missing %v, forbidden %v, not found %v",
				tc.status, tc.body, IsBackupOwnerCheckFailed(err), IsBackupGroupMissing(err), IsPrivilegeMissing(err),
				IsForbidden(err), IsNotFound(err))
		}
	}
	if IsBackupOwnerCheckFailed(errors.New("backup owner check failed (a != b)")) {
		t.Error("an error that is not PBS's counts as a failed owner check")
	}
}
