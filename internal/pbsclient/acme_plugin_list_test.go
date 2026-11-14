package pbsclient

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

// The plugin list answers whole plugin configurations, settings included,
// as PBS 4.2 does (proxmox-acme-api/src/plugin_api_impl.rs, list_plugins);
// the client keeps everything but the settings.
func TestListACMEPlugins(t *testing.T) {
	const route = "GET /config/acme/plugins"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":[
		{"plugin":"cloudflare","type":"dns","api":"cf","data":"CF_Token=secret\nCF_Zone_ID=zone","validation-delay":120,"disable":true},
		{"plugin":"standalone","type":"standalone"},
		{"plugin":"*Error*","type":"*Error*"}
	],"digest":"0123"}`)
	c := fake.client(t)
	ctx := context.Background()

	plugins, err := c.ListACMEPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delay, disabled := int64(120), true
	want := []ACMEPlugin{
		{ID: "cloudflare", Type: DNSACMEPluginType, API: "cf", ValidationDelay: &delay, Disable: &disabled},
		{ID: StandaloneACMEPlugin, Type: StandaloneACMEPlugin},
		{ID: UnreadableACMEPlugin, Type: UnreadableACMEPlugin},
	}
	if !reflect.DeepEqual(plugins, want) {
		t.Errorf("ListACMEPlugins() = %+v, want %+v", plugins, want)
	}
	if call := fake.lastCall(t, route); len(call.query) != 0 || len(call.form) != 0 {
		t.Errorf("query = %v, form = %v, want neither", call.query, call.form)
	}

	fake.reply(route, http.StatusOK, `{"data":null}`)
	if plugins, err := c.ListACMEPlugins(ctx); err != nil || len(plugins) != 0 {
		t.Errorf("ListACMEPlugins() of no data = %+v, %v, want none", plugins, err)
	}
	fake.reply(route, http.StatusForbidden, "permission check failed")
	if plugins, err := c.ListACMEPlugins(ctx); !IsForbidden(err) || plugins != nil {
		t.Errorf("ListACMEPlugins() = %+v, %v, want a forbidden error", plugins, err)
	}
}
