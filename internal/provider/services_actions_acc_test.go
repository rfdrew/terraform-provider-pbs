package provider

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The service actions run on the packages stand, whose PBS runs under
// systemd; the image stand has no systemd, and the actions fail there with
// an explanation. The tests restart and reload a service that does no harm
// — postfix or sshd —, and reload both of PBS's daemons, the proxy last:
// should its reload break the stand, the tests after it fail too.

// testAccServiceStand skips the test without TF_ACC, and returns a client
// and the services the stand lists: none without systemd.
func testAccServiceStand(t *testing.T) (*pbsclient.Client, []pbsclient.Service) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	testAccPreCheck(t)
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	services, err := client.Services(context.Background(), client.Node())
	if err != nil {
		t.Fatal(err)
	}
	return client, services
}

// testAccSystemdStand is testAccServiceStand for a test that needs systemd.
func testAccSystemdStand(t *testing.T) (*pbsclient.Client, []pbsclient.Service) {
	t.Helper()
	client, services := testAccServiceStand(t)
	if len(services) == 0 {
		t.Skip("the stand lists no services: it runs without systemd")
	}
	return client, services
}

// testAccHarmlessService returns a running service a test may restart
// without disturbing the stand.
func testAccHarmlessService(t *testing.T, services []pbsclient.Service) string {
	t.Helper()
	for _, candidate := range []string{"postfix", "sshd"} {
		for _, s := range services {
			if s.Service == candidate && s.Running() && s.UnitState != pbsclient.ServiceNotFound {
				return candidate
			}
		}
	}
	t.Skipf("neither postfix nor sshd runs on the stand: %+v", services)
	return ""
}

// testAccServiceActionConfig invokes an action of type on service whenever
// input changes; extra are further lines of its config block.
func testAccServiceActionConfig(actionType, service, input string, extra ...string) string {
	return providerConfig + fmt.Sprintf(`
action %q "test" {
  config {
    service = %q
    timeout = "5m"
%s  }
}
`, actionType, service, strings.Join(extra, "")) + testAccActionTrigger("action."+actionType+".test", input)
}

// testAccServiceTasks lists the tasks of a worker type that ran on service
// since a time, newest first: pbs_network_reload runs srvreload tasks too,
// for networking.
func testAccServiceTasks(workerType, service string, since time.Time) ([]testAccTask, error) {
	tasks, err := testAccTasksOfType(workerType, since)
	if err != nil {
		return nil, err
	}
	matching := tasks[:0]
	for _, task := range tasks {
		if task.WorkerID == service {
			matching = append(matching, task)
		}
	}
	return matching, nil
}

// testAccCheckServiceTask checks that a task of workerType ran on service
// since a time, at least count of them, and that the newest ended OK.
func testAccCheckServiceTask(workerType, service string, since *time.Time, count int) acc.TestCheckFunc {
	return func(*terraform.State) error {
		tasks, err := testAccServiceTasks(workerType, service, *since)
		switch {
		case err != nil:
			return err
		case len(tasks) < count:
			return fmt.Errorf("PBS ran %d %s tasks for %s since %s, want %d", len(tasks), workerType, service,
				since.Format(time.RFC3339), count)
		case count > 0 && tasks[0].Status != "OK":
			return fmt.Errorf("task %s ended with %q", tasks[0].UPID, tasks[0].Status)
		case count == 0 && len(tasks) > 0:
			return fmt.Errorf("PBS ran %s for %s: %s", workerType, service, tasks[0].UPID)
		}
		return nil
	}
}

// testAccCheckServiceRunning checks that systemd reports service running.
func testAccCheckServiceRunning(service string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		state, ok, err := client.ServiceState(context.Background(), client.Node(), service)
		switch {
		case err != nil:
			return err
		case !ok || !state.Running():
			return fmt.Errorf("service %s is %+v", service, state)
		}
		return nil
	}
}

// testAccCheckProtectedCall checks that PBS's API daemon answers through
// the proxy: GET /nodes/{node}/apt/update is a protected call, which the
// proxy hands to the daemon.
func testAccCheckProtectedCall() acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		if _, err := client.ServerVersion(context.Background()); err != nil {
			return fmt.Errorf("the proxy does not answer: %w", err)
		}
		if _, err := client.APTUpdates(context.Background(), client.Node()); err != nil {
			return fmt.Errorf("the API daemon does not answer through the proxy: %w", err)
		}
		return nil
	}
}

// testAccMainPID returns the main PID systemd reports for unit on the
// stand, or "" when the test cannot look: without the packages stand's
// container or docker.
func testAccMainPID(unit string) (string, error) {
	container := os.Getenv(envAccContainer)
	if container == "" || os.Getenv(envAccVariant) != "packages" {
		return "", nil
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return "", nil
	}
	out, err := exec.Command("docker", "exec", container, "systemctl", "show", "-p", "MainPID", "--value", unit).Output()
	if err != nil {
		return "", fmt.Errorf("reading the main PID of %s: %w", unit, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// testAccRememberMainPID keeps the main PID of unit in pid, for
// testAccCheckMainPID.
func testAccRememberMainPID(t *testing.T, unit string, pid *string) {
	t.Helper()
	var err error
	if *pid, err = testAccMainPID(unit); err != nil {
		t.Fatal(err)
	}
}

// testAccCheckMainPID checks that unit runs as another process than before
// — a restart or a reload of PBS's daemons starts a new one — or, unless
// changed, as the same. It checks nothing when the test could not look
// before, or the unit had no main process.
func testAccCheckMainPID(unit string, before *string, changed bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		if *before == "" || *before == "0" {
			return nil
		}
		// systemd learns the new main process of a daemon of PBS when the
		// process notifies it, which may come just after the task ended.
		var now string
		for deadline := time.Now().Add(10 * time.Second); ; {
			var err error
			if now, err = testAccMainPID(unit); err != nil {
				return err
			}
			if (now != *before) == changed || time.Now().After(deadline) {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		switch {
		case changed && now == *before:
			return fmt.Errorf("%s still runs as process %s", unit, now)
		case !changed && now != *before:
			return fmt.Errorf("%s runs as process %s, not %s any more", unit, now, *before)
		}
		return nil
	}
}

// Restart and reload a service that does no harm.
func TestAccServiceRestartAction(t *testing.T) {
	_, services := testAccSystemdStand(t)
	service := testAccHarmlessService(t, services)
	var start time.Time
	var pid string

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		Steps: []acc.TestStep{
			{
				PreConfig: func() {
					start = time.Now()
					testAccRememberMainPID(t, service, &pid)
				},
				Config: testAccServiceActionConfig("pbs_service_restart", service, "1"),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckServiceTask("srvrestart", service, &start, 1),
					testAccCheckServiceRunning(service),
					testAccCheckMainPID(service, &pid, true),
				),
			},
			{
				PreConfig: func() { start = time.Now() },
				Config:    testAccServiceActionConfig("pbs_service_reload", service, "2"),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckServiceTask("srvreload", service, &start, 1),
					testAccCheckServiceRunning(service),
				),
			},
		},
	})
}

// A service that runs is left alone.
func TestAccServiceStartAction(t *testing.T) {
	_, services := testAccSystemdStand(t)
	service := testAccHarmlessService(t, services)
	var start time.Time
	var pid string

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		Steps: []acc.TestStep{{
			PreConfig: func() {
				start = time.Now()
				testAccRememberMainPID(t, service, &pid)
			},
			Config: testAccServiceActionConfig("pbs_service_start", service, "1"),
			Check: acc.ComposeAggregateTestCheckFunc(
				testAccCheckServiceTask("srvstart", service, &start, 0),
				testAccCheckServiceRunning(service),
				testAccCheckMainPID(service, &pid, false),
			),
		}},
	})
}

// A service the stand does not have — cron or chrony, which the
// proxmox-backup-server package does not depend on — is refused before PBS
// is asked.
func TestAccServiceNotInstalled(t *testing.T) {
	_, services := testAccSystemdStand(t)
	missing := ""
	for _, s := range services {
		if s.UnitState == pbsclient.ServiceNotFound {
			missing = s.Service
			break
		}
	}
	if missing == "" {
		t.Skip("every service PBS lists is installed on the stand")
	}
	var start time.Time

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		Steps: []acc.TestStep{
			{
				PreConfig:   func() { start = time.Now() },
				Config:      testAccServiceActionConfig("pbs_service_restart", missing, "1"),
				ExpectError: regexp.MustCompile(`Service\s+` + missing + `\s+is\s+not\s+installed`),
			},
			{
				Config: providerConfig,
				Check:  testAccCheckServiceTask("srvrestart", missing, &start, 0),
			},
		},
	})
}

// Without systemd, as on the image stand, the action says why it cannot
// control a service.
func TestAccServiceActionsWithoutSystemd(t *testing.T) {
	_, services := testAccServiceStand(t)
	if len(services) > 0 {
		t.Skip("the stand runs systemd")
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		Steps: []acc.TestStep{{
			Config:      testAccServiceActionConfig("pbs_service_restart", "postfix", "1"),
			ExpectError: regexp.MustCompile(`Unable\s+to\s+read\s+the\s+state\s+of\s+service\s+postfix`),
		}},
	})
}

// Restarting PBS's API daemon is refused before PBS is asked, on any stand.
func TestAccServiceRestartAPIDaemonRefused(t *testing.T) {
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		Steps: []acc.TestStep{{
			Config:      testAccServiceActionConfig("pbs_service_restart", pbsclient.ServiceAPI, "1"),
			ExpectError: regexp.MustCompile(`cannot\s+be\s+restarted\s+through\s+its\s+API`),
		}},
	})
}

// A reload of PBS's API daemon starts a new one, which then answers the
// protected calls the proxy hands it.
func TestAccServiceReloadAPIDaemonAction(t *testing.T) {
	testAccSystemdStand(t)
	var start time.Time
	var pid string

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		Steps: []acc.TestStep{{
			PreConfig: func() {
				start = time.Now()
				testAccRememberMainPID(t, pbsclient.ServiceAPI, &pid)
			},
			Config: testAccServiceActionConfig("pbs_service_reload", pbsclient.ServiceAPI, "1"),
			Check: acc.ComposeAggregateTestCheckFunc(
				testAccCheckServiceTask("srvreload", pbsclient.ServiceAPI, &start, 1),
				testAccCheckServiceRunning(pbsclient.ServiceAPI),
				testAccCheckMainPID(pbsclient.ServiceAPI, &pid, true),
				testAccCheckProtectedCall(),
			),
		}},
	})
}

// A reload of the proxy, after the action checked its certificate and
// cipher lists, starts a new proxy, which answers with the same
// certificate; a restart of the proxy is a reload too.
func TestAccServiceReloadProxyAction(t *testing.T) {
	testAccSystemdStand(t)
	var start time.Time
	var pid string

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		Steps: []acc.TestStep{
			{
				PreConfig: func() {
					start = time.Now()
					testAccRememberMainPID(t, pbsclient.ServiceProxy, &pid)
				},
				Config: testAccServiceActionConfig("pbs_service_reload", pbsclient.ServiceProxy, "1"),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckServiceTask("srvreload", pbsclient.ServiceProxy, &start, 1),
					testAccCheckServiceRunning(pbsclient.ServiceProxy),
					testAccCheckMainPID(pbsclient.ServiceProxy, &pid, true),
					testAccCheckProtectedCall(),
				),
			},
			{
				PreConfig: func() {
					start = time.Now()
					testAccRememberMainPID(t, pbsclient.ServiceProxy, &pid)
				},
				Config: testAccServiceActionConfig("pbs_service_restart", pbsclient.ServiceProxy, "2"),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckServiceTask("srvreload", pbsclient.ServiceProxy, &start, 1),
					testAccCheckServiceTask("srvrestart", pbsclient.ServiceProxy, &start, 0),
					testAccCheckMainPID(pbsclient.ServiceProxy, &pid, true),
					testAccCheckProtectedCall(),
				),
			},
		},
	})
}

// PBS stores @SECLEVEL in the TLS 1.3 cipher suites, which OpenSSL skips as
// the name of a suite it does not know (SSL_CTX_set_ciphersuites): the
// action checks the proxy's chain at the level of the TLS 1.2 list, and the
// reloaded proxy starts — with PBS's self-signed RSA-4096 certificate or an
// ACME P-256 one, which level 4 would refuse.
func TestAccServiceReloadProxyIgnoresTLS13SecurityLevel(t *testing.T) {
	testAccSystemdStand(t)
	var start time.Time
	var pid string
	const suites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:@SECLEVEL=4"
	config := providerConfig + fmt.Sprintf(`
resource "pbs_node_config" "this" {
  ciphers_tls_1_3 = %q
}

resource "terraform_data" "proxy_ciphers" {
  input = pbs_node_config.this.ciphers_tls_1_3

  lifecycle {
    action_trigger {
      events  = [after_create, after_update]
      actions = [action.pbs_service_reload.proxy]
    }
  }
}

action "pbs_service_reload" "proxy" {
  config {
    service = %q
    timeout = "5m"
  }
}
`, suites, pbsclient.ServiceProxy)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		CheckDestroy:             testAccCheckNodeSettings(func(s pbsclient.NodeSettings) bool { return s.CiphersTLS13 == "" }),
		Steps: []acc.TestStep{{
			PreConfig: func() {
				start = time.Now()
				testAccRememberMainPID(t, pbsclient.ServiceProxy, &pid)
			},
			Config: config,
			Check: acc.ComposeAggregateTestCheckFunc(
				testAccCheckNodeSettings(func(s pbsclient.NodeSettings) bool { return s.CiphersTLS13 == suites }),
				testAccCheckServiceTask("srvreload", pbsclient.ServiceProxy, &start, 1),
				testAccCheckServiceRunning(pbsclient.ServiceProxy),
				testAccCheckMainPID(pbsclient.ServiceProxy, &pid, true),
				testAccCheckProtectedCall(),
			),
		}},
	})
}
