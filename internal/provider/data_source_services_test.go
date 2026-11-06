package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestServicesDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &servicesDataSource{})
}

// fakeService is a service as the data source's state holds it.
func fakeService(service, name, description, state, unitState string) map[string]any {
	return map[string]any{"service": service, "name": name, "description": description, "state": state, "unit_state": unitState}
}

// A node with systemd: every service, in PBS's order, one of them not
// installed.
func TestServicesDataSourceReadsTheServices(t *testing.T) {
	fake := newFakePBS()
	d := &servicesDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/services", http.StatusOK, `{"data":[
		{"service":"proxmox-backup","name":"proxmox-backup","desc":"Proxmox Backup API Server","state":"running","unit-state":"enabled"},
		{"service":"proxmox-backup-proxy","name":"proxmox-backup-proxy","desc":"Proxmox Backup API Proxy Server","state":"running","unit-state":"enabled"},
		{"service":"sshd","name":"sshd","desc":"OpenBSD Secure Shell server","state":"running","unit-state":"enabled"},
		{"service":"systemd-journald","name":"systemd-journald","desc":"Journal Service","state":"running","unit-state":"static"},
		{"service":"cron","name":"cron","desc":"Regular background program processing daemon","state":"running","unit-state":"enabled"},
		{"service":"postfix","name":"postfix","desc":"Postfix Mail Transport Agent","state":"running","unit-state":"enabled"},
		{"service":"chrony","name":"chrony","desc":"chrony.service","state":"dead","unit-state":"not-found"}]}`)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node": "localhost",
		"services": []any{
			fakeService("proxmox-backup", "proxmox-backup", "Proxmox Backup API Server", "running", "enabled"),
			fakeService("proxmox-backup-proxy", "proxmox-backup-proxy", "Proxmox Backup API Proxy Server", "running", "enabled"),
			fakeService("sshd", "sshd", "OpenBSD Secure Shell server", "running", "enabled"),
			fakeService("systemd-journald", "systemd-journald", "Journal Service", "running", "static"),
			fakeService("cron", "cron", "Regular background program processing daemon", "running", "enabled"),
			fakeService("postfix", "postfix", "Postfix Mail Transport Agent", "running", "enabled"),
			fakeService("chrony", "chrony", "chrony.service", "dead", "not-found"),
		},
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

func TestServicesDataSourceEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name string
		node string
		body string
		want []any
	}{{
		// A node without systemd, such as PBS in a Docker container.
		name: "no services",
		body: `{"data":[]}`,
		want: []any{},
	}, {
		name: "null data",
		body: `{"data":null}`,
		want: []any{},
	}, {
		// PBS fills every property; should one be missing, the provider
		// falls back as PBS does.
		name: "missing and null properties",
		body: `{"data":[
			{"service":"cron","name":null,"desc":"Regular background program processing daemon","state":null},
			{"service":"chrony","desc":null,"state":"","unit-state":""}]}`,
		want: []any{
			fakeService("cron", "cron", "Regular background program processing daemon", "unknown", "unknown"),
			fakeService("chrony", "chrony", "", "unknown", "unknown"),
		},
	}, {
		// The order PBS sends is kept, whatever it is, and so is a oneshot
		// unit's result.
		name: "order kept",
		node: "pbs1",
		body: `{"data":[
			{"service":"sshd","name":"sshd","desc":"OpenBSD Secure Shell server","state":"failed","unit-state":"disabled"},
			{"service":"cron","name":"cron","desc":"Regular background program processing daemon","state":"running","unit-state":"masked"},
			{"service":"chrony","name":"chrony","desc":"chrony, an NTP client/server","state":"exit-code","unit-state":"enabled"}]}`,
		want: []any{
			fakeService("sshd", "sshd", "OpenBSD Secure Shell server", "failed", "disabled"),
			fakeService("cron", "cron", "Regular background program processing daemon", "running", "masked"),
			fakeService("chrony", "chrony", "chrony, an NTP client/server", "exit-code", "enabled"),
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			d := &servicesDataSource{data: fake.configured(t)}
			node := tc.node
			if node == "" {
				node = "localhost"
			}
			fake.reply("GET /nodes/"+node+"/services", http.StatusOK, tc.body)

			config := map[string]any{}
			if tc.node != "" {
				config["node"] = tc.node
			}
			resp := readDataSource(t, d, dataSourceValue(t, d, config))
			requireNoErrors(t, resp.Diagnostics)
			want := dataSourceValue(t, d, map[string]any{"node": node, "services": tc.want})
			if !resp.State.Raw.Equal(want) {
				t.Errorf("state = %s, want %s", resp.State.Raw, want)
			}
		})
	}
}

// A token without Sys.Audit on /system/services gets 403, and the error says
// what is missing.
func TestServicesDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	d := &servicesDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/services", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, servicesPrivilege)
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}

// --- acceptance --------------------------------------------------------------

// servicesOrder is the services PBS reports, in its order.
var servicesOrder = []string{"proxmox-backup", "proxmox-backup-proxy", "sshd", "systemd-journald", "cron", "postfix", "chrony"}

// The services the data source reads are those the client reads, in the same
// order — none on a stand without systemd, such as the Docker image — and
// in the order the documentation gives.
func TestAccServicesDataSource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	testAccPreCheck(t)
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	listed, err := client.Services(context.Background(), client.Node())
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(listed))
	for _, s := range listed {
		ids = append(ids, s.Service)
	}
	if len(ids) == 0 {
		t.Log("the stand lists no services: it runs without systemd")
	}

	const name = "data.pbs_services.this"
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{{
			Config: providerConfig + `data "pbs_services" "this" {}` + "\n",
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttr(name, "node", client.Node()),
				acc.TestCheckResourceAttr(name, "services.#", strconv.Itoa(len(ids))),
				testAccCheckServices(name, ids),
			),
		}},
	})
}

// testAccCheckServices checks that the data source lists the services ids,
// in that order, which must be the documented one, each with a name and
// systemd states.
func testAccCheckServices(resourceName string, ids []string) acc.TestCheckFunc {
	state := regexp.MustCompile(`^[a-z][a-z-]*$`)
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("%s is not in state", resourceName)
		}
		attrs := rs.Primary.Attributes
		next := 0
		for i, id := range ids {
			prefix := "services." + strconv.Itoa(i) + "."
			if got := attrs[prefix+"service"]; got != id {
				return fmt.Errorf("%s: services[%d] is %q, the client read %q", resourceName, i, got, id)
			}
			position := slices.Index(servicesOrder[next:], id)
			if position < 0 {
				return fmt.Errorf("%s: service %q is not one of %v, or out of their order: %v", resourceName, id, servicesOrder, ids)
			}
			next += position + 1
			if attrs[prefix+"name"] == "" {
				return fmt.Errorf("%s: service %q has no name", resourceName, id)
			}
			if _, ok := attrs[prefix+"description"]; !ok {
				return fmt.Errorf("%s: service %q has no description", resourceName, id)
			}
			for _, key := range []string{"state", "unit_state"} {
				if !state.MatchString(attrs[prefix+key]) {
					return fmt.Errorf("%s: service %q has %s %q", resourceName, id, key, attrs[prefix+key])
				}
			}
		}
		return nil
	}
}
