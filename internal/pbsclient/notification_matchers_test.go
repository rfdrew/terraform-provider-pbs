package pbsclient

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

// The list in the shape PBS 4.2 sends: whole matchers with their origin, the
// built-in default-matcher among them, and no digest.
func TestListNotificationMatchersDecodesTheList(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/notifications/matchers", http.StatusOK, `{"data":[`+
		`{"name":"default-matcher","mode":"all","invert-match":true,"match-field":["exact:type=prune"],`+
		`"match-severity":["info"],"target":["mail-to-root"],"comment":"Route everything but successful prune job `+
		`notifications to mail-to-root","origin":"builtin"},`+
		`{"name":"ops","target":["ops-mail"],"match-calendar":["mon..fri 8-18"],"disable":true,"origin":"user-created"},`+
		`{"name":"tree","expression":"{\"all-of\":[{\"match\":{\"type\":\"severity\",\"severities\":[\"error\"]}}]}",`+
		`"target":["ops-mail"],"origin":"user-created"}]}`)
	matchers, err := fake.client(t).ListNotificationMatchers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	want := []NotificationMatcher{
		{
			Name: "default-matcher", Mode: "all", InvertMatch: &yes, MatchField: []string{"exact:type=prune"},
			MatchSeverity: []string{"info"}, Target: []string{"mail-to-root"},
			Comment: "Route everything but successful prune job notifications to mail-to-root", Origin: OriginBuiltin,
		},
		{Name: "ops", Target: []string{"ops-mail"}, MatchCalendar: []string{"mon..fri 8-18"}, Disable: &yes, Origin: OriginUserCreated},
		{
			Name: "tree", Expression: `{"all-of":[{"match":{"type":"severity","severities":["error"]}}]}`,
			Target: []string{"ops-mail"}, Origin: OriginUserCreated,
		},
	}
	if !reflect.DeepEqual(matchers, want) {
		t.Fatalf("ListNotificationMatchers() = %+v, want %+v", matchers, want)
	}
}

// Without Sys.Audit on /system/notifications PBS refuses the whole list.
func TestListNotificationMatchersForbidden(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/notifications/matchers", http.StatusForbidden, "permission check failed")
	if _, err := fake.client(t).ListNotificationMatchers(context.Background()); !IsForbidden(err) {
		t.Fatalf("ListNotificationMatchers() = %v, want a 403", err)
	}
}
