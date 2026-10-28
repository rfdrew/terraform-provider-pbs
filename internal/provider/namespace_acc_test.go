package provider

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_namespace and pbs_namespaces. Each test creates a
// datastore of its own for its namespaces, as the datastore tests do.

// More facts scripts/bootstrap-test-pbs.sh exports about the stand.
const (
	// envAccContainer is the stand's Docker container, and envAccVariant
	// its kind: packages, with proxmox-backup-client, or image, without.
	envAccContainer = "PBS_ACC_CONTAINER"
	envAccVariant   = "PBS_ACC_VARIANT"
)

// testAccSkipWithoutBackupClient skips a test that writes backups on a stand
// without proxmox-backup-client — the image stand — or without Docker to run
// it in the stand's container.
func testAccSkipWithoutBackupClient(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		return
	}
	if os.Getenv(envAccContainer) == "" || os.Getenv(envAccVariant) != "packages" {
		t.Skipf("writing a backup needs proxmox-backup-client in the packages stand; the stand is %q", os.Getenv(envAccVariant))
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("writing a backup needs docker:", err)
	}
}

// testAccWriteBackup writes a small backup of a directory of the stand into a
// namespace of a datastore, with proxmox-backup-client in the stand's
// container, as the provider's API token. Tests that call it call
// testAccSkipWithoutBackupClient first.
func testAccWriteBackup(t *testing.T, store, ns string) {
	t.Helper()
	container := os.Getenv(envAccContainer)
	tokenID, secret, err := pbsclient.SplitAPIToken(os.Getenv(envAPIToken))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"exec",
		"-e", "PBS_REPOSITORY=" + tokenID + "@localhost:" + store,
		"-e", "PBS_PASSWORD=" + secret,
		"-e", "PBS_FINGERPRINT=" + os.Getenv(envCertFingerprint),
		container, "proxmox-backup-client", "backup", "apt.pxar:/etc/apt",
		"--backup-type", "host", "--backup-id", "tfacc", "--ns", ns,
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("writing a backup to %s:%s failed: %v\n%s", store, ns, err, pbsclient.Redact(string(out), secret))
	}
}

// testAccCheckNamespace checks whether a namespace exists.
func testAccCheckNamespace(store, ns string, want bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		exists, err := client.NamespaceExists(context.Background(), store, ns)
		if err != nil {
			return err
		}
		if exists != want {
			return fmt.Errorf("namespace %s:%s exists = %t, want %t", store, ns, exists, want)
		}
		return nil
	}
}

// testAccNamespaceConfig is a datastore with the given resources after it.
func testAccNamespaceConfig(name, dir, rest string) string {
	return providerConfig + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  destroy_data = true
}
`, name, dir) + rest
}

func TestAccNamespaceResource(t *testing.T) {
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	namespaces := `
resource "pbs_namespace" "parent" {
  store     = pbs_datastore.test.name
  namespace = "dept1"
}

resource "pbs_namespace" "child" {
  store     = pbs_datastore.test.name
  namespace = "${pbs_namespace.parent.namespace}/hosts"
}

data "pbs_namespaces" "all" {
  store      = pbs_datastore.test.name
  depends_on = [pbs_namespace.child]
}

data "pbs_namespaces" "below" {
  store      = pbs_datastore.test.name
  parent     = pbs_namespace.parent.namespace
  max_depth  = 1
  depends_on = [pbs_namespace.child]
}
`
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			{
				Config: testAccNamespaceConfig(name, dir, namespaces),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_namespace.child", "id", name+":dept1/hosts"),
					acc.TestCheckResourceAttr("pbs_namespace.child", "delete_groups", "false"),
					acc.TestCheckResourceAttr("pbs_namespace.child", "error_on_protected", "true"),
					acc.TestCheckResourceAttr("data.pbs_namespaces.all", "namespaces.#", "2"),
					acc.TestCheckResourceAttr("data.pbs_namespaces.all", "namespaces.0", "dept1"),
					acc.TestCheckResourceAttr("data.pbs_namespaces.all", "namespaces.1", "dept1/hosts"),
					acc.TestCheckResourceAttr("data.pbs_namespaces.below", "namespaces.#", "1"),
					acc.TestCheckResourceAttr("data.pbs_namespaces.below", "namespaces.0", "dept1/hosts"),
					testAccCheckNamespace(name, "dept1/hosts", true),
				),
			},
			{
				ResourceName:      "pbs_namespace.child",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Destroying the namespaces, the datastore stays.
				Config: testAccNamespaceConfig(name, dir, ""),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckNamespace(name, "dept1/hosts", false),
					testAccCheckNamespace(name, "dept1", false),
				),
			},
			{
				// PBS creates a namespace only below one that exists.
				Config: testAccNamespaceConfig(name, dir, `
resource "pbs_namespace" "orphan" {
  store     = pbs_datastore.test.name
  namespace = "missing/child"
}
`),
				ExpectError: regexp.MustCompile(`has no\s+namespace "missing"`),
			},
		},
	})
}

// From Terraform 1.12, a namespace imports by identity too.
func TestAccNamespaceResourceImportByIdentity(t *testing.T) {
	name := testAccDatastoreName()
	config := testAccNamespaceConfig(name, testAccDatastoreDir(t, name), `
resource "pbs_namespace" "test" {
  store     = pbs_datastore.test.name
  namespace = "dept1"
}
`)
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			{Config: config},
			{Config: config, ResourceName: "pbs_namespace.test", ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			{Config: config, ResourceName: "pbs_namespace.test", ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		},
	})
}

// PBS keeps a namespace with backups unless delete_groups is set, and deletes
// the backups with it when it is.
func TestAccNamespaceResourceWithBackups(t *testing.T) {
	testAccSkipWithoutBackupClient(t)
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	namespace := func(deleteGroups bool) string {
		return fmt.Sprintf(`
resource "pbs_namespace" "test" {
  store         = pbs_datastore.test.name
  namespace     = "full"
  delete_groups = %t
}
`, deleteGroups)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
		Steps: []acc.TestStep{
			{Config: testAccNamespaceConfig(name, dir, namespace(false))},
			{
				PreConfig:   func() { testAccWriteBackup(t, name, "full") },
				Config:      testAccNamespaceConfig(name, dir, ""),
				ExpectError: regexp.MustCompile(`set\s+delete_groups\s+=\s+true`),
			},
			{
				Config: testAccNamespaceConfig(name, dir, namespace(true)),
				Check:  testAccCheckNamespace(name, "full", true),
			},
			{
				Config: testAccNamespaceConfig(name, dir, ""),
				Check:  testAccCheckNamespace(name, "full", false),
			},
		},
	})
}

// testAccDatastoreTask starts a datastore task through the API, such as
// garbage collection or mounting, and waits for it.
func testAccDatastoreTask(t *testing.T, store, task string) {
	t.Helper()
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	env, err := client.Post(ctx, pbsclient.Path("admin", "datastore", store, task), nil, nil)
	if err != nil {
		t.Fatalf("starting %s on %s: %v", task, store, err)
	}
	if err := client.WaitTaskIn(ctx, env.Data); err != nil {
		t.Fatalf("%s on %s: %v", task, store, err)
	}
}
