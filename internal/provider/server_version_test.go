package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestRequireRelease(t *testing.T) {
	client, err := pbsclient.New(pbsclient.Options{Endpoint: "https://pbs.test:8007", APIToken: fakeAPIToken})
	if err != nil {
		t.Fatal(err)
	}
	attribute := path.Root("read_threads")
	for _, tc := range []struct {
		version pbsclient.Version
		value   types.Int64
		fails   bool
	}{
		{pbsclient.Version{Version: "4.0", Release: "22"}, types.Int64Value(2), true},
		{pbsclient.Version{Version: "4.0", Release: "22"}, types.Int64Unknown(), true},
		{pbsclient.Version{Version: "4.0", Release: "22"}, types.Int64Null(), false},
		{pbsclient.Version{Version: "4.1", Release: "0"}, types.Int64Value(2), false},
		{pbsclient.Version{Version: "4.2", Release: "8"}, types.Int64Value(2), false},
		// A version that does not parse counts as new enough.
		{pbsclient.Version{Version: "devel"}, types.Int64Value(2), false},
	} {
		var diags diag.Diagnostics
		(&providerData{client: client, version: tc.version}).requireRelease(&diags, attribute, tc.value, pbs41)
		if diags.HasError() != tc.fails {
			t.Errorf("PBS %s, %s: errors = %v, want failure %v", tc.version, tc.value, diags, tc.fails)
		}
		if tc.fails {
			requireErrorContaining(t, diags, "read_threads needs PBS 4.1 or newer, but the server at https://pbs.test:8007 runs PBS "+tc.version.String())
		}
	}

	// Before Configure there is nothing to check against.
	var diags diag.Diagnostics
	(*providerData)(nil).requireRelease(&diags, attribute, types.Int64Value(2), pbs41)
	requireNoErrors(t, diags)

	if got := (pbsRelease{4, 2, 4}).String(); got != "4.2.4" {
		t.Errorf("String() = %q", got)
	}
}
