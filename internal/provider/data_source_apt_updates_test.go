package provider

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAPTUpdatesDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &aptUpdatesDataSource{})
}

// What PBS 4.2.8 answers for a node with a pending PBS point release, a
// Debian security update and a new kernel: PascalCase keys in the order of
// APT's cache, with OldVersion left out for the package an upgrade would
// install anew.
const testAPTUpdatesJSON = `{"data":[
 {"Arch":"amd64","Description":"This package contains the Proxmox Backup Server daemons and related tools. This\nincludes a web-based graphical user interface.","OldVersion":"4.2.7","Origin":"Proxmox","Package":"proxmox-backup-server","Priority":"optional","Section":"admin","Title":"Proxmox Backup Server daemon with tools and GUI","Version":"4.2.8"},
 {"Arch":"amd64","Description":"This package is part of the OpenSSL project's implementation of the SSL and TLS\ncryptographic protocols.","OldVersion":"3.5.1-1","Origin":"Debian","Package":"libssl3t64","Priority":"optional","Section":"libs","Title":"Secure Sockets Layer toolkit - shared libraries","Version":"3.5.4-1~deb13u1"},
 {"Arch":"amd64","Description":"","Origin":"Proxmox","Package":"proxmox-kernel-6.17.2-1-pve-signed","Priority":"optional","Section":"kernel","Title":"Proxmox Kernel Image (signed)","Version":"6.17.2-1"},
 {"Arch":"all","Description":"Metapackage depending on the default kernel of Proxmox products.","OldVersion":"2.0.0","Origin":"Proxmox","Package":"proxmox-default-kernel","Priority":"optional","Section":"admin","Title":"Default Proxmox Kernel Image","Version":"2.0.1"}
]}`

func TestAPTUpdatesDataSourceReadsTheUpdates(t *testing.T) {
	fake := newFakePBS()
	d := &aptUpdatesDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/apt/update", http.StatusOK, testAPTUpdatesJSON)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node": "localhost",
		"updates": []map[string]any{
			{
				"package": "libssl3t64", "title": "Secure Sockets Layer toolkit - shared libraries",
				"description": "This package is part of the OpenSSL project's implementation of the SSL and TLS\ncryptographic protocols.",
				"arch":        "amd64", "version": "3.5.4-1~deb13u1", "old_version": "3.5.1-1",
				"origin": "Debian", "priority": "optional", "section": "libs",
			},
			{
				"package": "proxmox-backup-server", "title": "Proxmox Backup Server daemon with tools and GUI",
				"description": "This package contains the Proxmox Backup Server daemons and related tools. This\nincludes a web-based graphical user interface.",
				"arch":        "amd64", "version": "4.2.8", "old_version": "4.2.7",
				"origin": "Proxmox", "priority": "optional", "section": "admin",
			},
			{
				"package": "proxmox-default-kernel", "title": "Default Proxmox Kernel Image",
				"description": "Metapackage depending on the default kernel of Proxmox products.",
				"arch":        "all", "version": "2.0.1", "old_version": "2.0.0",
				"origin": "Proxmox", "priority": "optional", "section": "admin",
			},
			{
				"package": "proxmox-kernel-6.17.2-1-pve-signed", "title": "Proxmox Kernel Image (signed)",
				"description": "", "arch": "amd64", "version": "6.17.2-1", "old_version": nil,
				"origin": "Proxmox", "priority": "optional", "section": "kernel",
			},
		},
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// aptUpdate is an entry of the data source's updates, with the defaults PBS
// fills in for what APT does not know.
func aptUpdate(pkg, arch, version string, oldVersion any) map[string]any {
	return map[string]any{
		"package": pkg, "title": pkg, "description": "", "arch": arch, "version": version, "old_version": oldVersion,
		"origin": "unknown", "priority": "unknown", "section": "unknown",
	}
}

func TestAPTUpdatesDataSourceEdgeCases(t *testing.T) {
	tests := []struct {
		name, node, body string
		want             []map[string]any
	}{
		{"an up-to-date node", "", `{"data":[]}`, []map[string]any{}},
		{"no list at all", "", `{"data":null}`, []map[string]any{}},
		{
			// PBS before 4.0.20 sent "" for a package an upgrade would
			// install anew, later releases leave it out; null is the same.
			// ExtraInfo, which only apt/versions sets, is ignored.
			"no old version", "",
			`{"data":[
			 {"Package":"b","Title":"b","Arch":"amd64","Description":"","Version":"2","OldVersion":"","Origin":"unknown","Priority":"unknown","Section":"unknown"},
			 {"Package":"a","Title":"a","Arch":"amd64","Description":"","Version":"1","OldVersion":null,"Origin":"unknown","Priority":"unknown","Section":"unknown"},
			 {"Package":"c","Title":"c","Arch":"amd64","Description":"","Version":"3","Origin":"unknown","Priority":"unknown","Section":"unknown","ExtraInfo":"running version: 4.2.8"}]}`,
			[]map[string]any{aptUpdate("a", "amd64", "1", nil), aptUpdate("b", "amd64", "2", nil), aptUpdate("c", "amd64", "3", nil)},
		},
		{
			// A node with a foreign architecture may list a package for
			// each; the order of APT's cache is not sorted.
			"unsorted, with two architectures", "pbs1",
			`{"data":[
			 {"Package":"zlib1g","Title":"zlib1g","Arch":"i386","Description":"","Version":"1:1.3.dfsg+really1.3.1-1+b2","OldVersion":"1:1.3.dfsg+really1.3.1-1+b1","Origin":"unknown","Priority":"unknown","Section":"unknown"},
			 {"Package":"libc6","Title":"libc6","Arch":"i386","Description":"","Version":"2.41-12+deb13u1","OldVersion":"2.41-12","Origin":"unknown","Priority":"unknown","Section":"unknown"},
			 {"Package":"zlib1g","Title":"zlib1g","Arch":"amd64","Description":"","Version":"1:1.3.dfsg+really1.3.1-1+b2","OldVersion":"1:1.3.dfsg+really1.3.1-1+b1","Origin":"unknown","Priority":"unknown","Section":"unknown"},
			 {"Package":"libc6","Title":"libc6","Arch":"amd64","Description":"","Version":"2.41-12+deb13u1","OldVersion":"2.41-12","Origin":"unknown","Priority":"unknown","Section":"unknown"}]}`,
			[]map[string]any{
				aptUpdate("libc6", "amd64", "2.41-12+deb13u1", "2.41-12"),
				aptUpdate("libc6", "i386", "2.41-12+deb13u1", "2.41-12"),
				aptUpdate("zlib1g", "amd64", "1:1.3.dfsg+really1.3.1-1+b2", "1:1.3.dfsg+really1.3.1-1+b1"),
				aptUpdate("zlib1g", "i386", "1:1.3.dfsg+really1.3.1-1+b2", "1:1.3.dfsg+really1.3.1-1+b1"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakePBS()
			d := &aptUpdatesDataSource{data: fake.configured(t)}
			config, node := map[string]any{}, "localhost"
			if tt.node != "" {
				config, node = map[string]any{"node": tt.node}, tt.node
			}
			fake.reply("GET /nodes/"+node+"/apt/update", http.StatusOK, tt.body)

			resp := readDataSource(t, d, dataSourceValue(t, d, config))
			requireNoErrors(t, resp.Diagnostics)
			want := dataSourceValue(t, d, map[string]any{"node": node, "updates": tt.want})
			if !resp.State.Raw.Equal(want) {
				t.Errorf("state = %s, want %s", resp.State.Raw, want)
			}
		})
	}
}

// A token without Sys.Audit on / gets 403, and the error says what is
// missing.
func TestAPTUpdatesDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	d := &aptUpdatesDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/apt/update", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, aptReadPrivilege)
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}

// --- acceptance --------------------------------------------------------------

// Whether a stand has updates depends on its package lists — an image that
// removed them has none — and on when apt update last ran, so the test
// checks the shape of whatever the stand lists, not what it lists.
func TestAccAPTUpdatesDataSource(t *testing.T) {
	const name = "data.pbs_apt_updates.this"
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{{
			Config: providerConfig + `data "pbs_apt_updates" "this" {}` + "\n",
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttr(name, "node", "localhost"),
				acc.TestCheckResourceAttrSet(name, "updates.#"),
				testAccCheckAPTUpdates(name),
			),
		}},
	})
}

// testAccCheckAPTUpdates checks that every update names a package, an
// architecture and a new version, that an installed version differs from
// the new one, and that the list is sorted by package and architecture.
func testAccCheckAPTUpdates(name string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s not found in state", name)
		}
		attrs := rs.Primary.Attributes
		count, err := strconv.Atoi(attrs["updates.#"])
		if err != nil {
			return fmt.Errorf("updates.# = %q", attrs["updates.#"])
		}
		var previous string
		for i := range count {
			prefix := "updates." + strconv.Itoa(i) + "."
			for _, attr := range []string{"package", "title", "arch", "version", "origin", "priority", "section"} {
				if attrs[prefix+attr] == "" {
					return fmt.Errorf("%s%s is empty", prefix, attr)
				}
			}
			if old, ok := attrs[prefix+"old_version"]; ok && (old == "" || old == attrs[prefix+"version"]) {
				return fmt.Errorf("%sold_version = %q, version = %q", prefix, old, attrs[prefix+"version"])
			}
			key := attrs[prefix+"package"] + " " + attrs[prefix+"arch"]
			if key < previous {
				return fmt.Errorf("updates are not sorted: %q after %q", key, previous)
			}
			previous = key
		}
		return nil
	}
}
