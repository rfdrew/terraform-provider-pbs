package provider

import (
	"net/http"
	"os"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestVersionDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &versionDataSource{})
}

func TestVersionDataSourceReadsTheVersion(t *testing.T) {
	fake := newFakePBS()
	d := &versionDataSource{data: fake.configured(t)}
	fake.reply("GET /version", http.StatusOK, `{"data":{"release":"21","repoid":"25a5c896","version":"4.0"}}`)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{"version": "4.0.21", "major": 4, "minor": 0, "release": 21, "repoid": "25a5c896"})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// A version that does not parse is still reported, without its parts.
func TestVersionDataSourceUnparsableVersion(t *testing.T) {
	fake := newFakePBS()
	d := &versionDataSource{data: fake.configured(t)}
	fake.reply("GET /version", http.StatusOK, `{"data":{"release":"","repoid":"abc","version":"devel"}}`)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{"version": "devel", "repoid": "abc"})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

func TestVersionDataSourceReportsErrors(t *testing.T) {
	fake := newFakePBS()
	d := &versionDataSource{data: fake.configured(t)}
	fake.reply("GET /version", http.StatusInternalServerError, "something broke")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, "Unable to read the PBS version")
	requireErrorContaining(t, resp.Diagnostics, "something broke")
}

// --- acceptance --------------------------------------------------------------

func TestAccVersionDataSource(t *testing.T) {
	checks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr("data.pbs_version.this", "major", "4"),
		acc.TestCheckResourceAttrSet("data.pbs_version.this", "minor"),
		acc.TestCheckResourceAttrSet("data.pbs_version.this", "release"),
		acc.TestCheckResourceAttrSet("data.pbs_version.this", "repoid"),
	}
	if version := os.Getenv(envAccVersion); version != "" {
		checks = append(checks, acc.TestCheckResourceAttr("data.pbs_version.this", "version", version))
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				Config: providerConfig + `
data "pbs_version" "this" {}
`,
				Check: acc.ComposeAggregateTestCheckFunc(checks...),
			},
		},
	})
}
