package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"testing"
)

// notify is sent only when set: PBS defaults it to false.
func TestStartAPTUpdate(t *testing.T) {
	const route = "POST /nodes/localhost/apt/update"
	for _, notify := range []bool{false, true} {
		t.Run(strconv.FormatBool(notify), func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(route, http.StatusOK, taskAnswer(sampleUPID))
			upid, err := fake.client(t).StartAPTUpdate(context.Background(), "localhost", notify)
			if err != nil {
				t.Fatal(err)
			}
			if upid.Raw != sampleUPID {
				t.Fatalf("upid = %+v", upid)
			}
			want := url.Values{}
			if notify {
				want = url.Values{"notify": {"true"}}
			}
			if got := fake.lastCall(t, route).form; !reflect.DeepEqual(got, want) {
				t.Fatalf("form = %v, want %v", got, want)
			}
		})
	}
}
