package provider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_apt_repository, pbs_apt_standard_repository and
// pbs_apt_repositories. Every stand has Debian's debian.sources and the
// pbs-enterprise.sources the proxmox-backup-server package ships, with the
// enterprise repository enabled; the packages stand adds proxmox.sources
// with the no-subscription repository, the image stand has no other file.
// No stand has the test repository. A test that finds a stand without the
// entries it needs skips.
//
// The tests change the stand's source files, and PBS cannot remove an entry
// it added, so testAccRestoreAPTSources puts the files back when a test
// ends: all of /etc/apt/sources.list.d through Docker when it can, and
// otherwise the enabled flag of every entry that changed, through the API.

// testAccAPTState reads the stand's source files, and the matcher of its
// release.
func testAccAPTState(t *testing.T) (*pbsclient.Client, pbsclient.APTRepositories, pbsclient.APTMatcher) {
	t.Helper()
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	version, err := client.ServerVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repos, err := client.APTRepositories(ctx, client.Node())
	if err != nil {
		t.Fatalf("reading the stand's APT repositories: %v", err)
	}
	return client, repos, pbsclient.NewAPTMatcher(version)
}

// testAccAPTEntryOf returns where the stand's first entry of the standard
// repository of handle is, and skips the test when it has none.
func testAccAPTEntryOf(t *testing.T, handle string) (string, int64) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		return "/etc/apt/sources.list.d/pbs-enterprise.sources", 0
	}
	_, repos, matcher := testAccAPTState(t)
	path, index, ok := repos.FindStandardRepository(matcher, handle, false)
	if !ok {
		t.Skipf("the stand has no entry of the %s repository", handle)
	}
	return path, index
}

// testAccRestoreAPTSources puts the stand's source files back as they are
// now when the test ends.
func testAccRestoreAPTSources(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		return
	}
	if container := os.Getenv(envAccContainer); container != "" {
		if _, err := exec.LookPath("docker"); err == nil {
			snapshot, err := exec.Command("docker", "exec", container, "tar", "-C", "/etc/apt", "-cf", "-", "sources.list.d").Output()
			if err != nil {
				t.Fatalf("saving the stand's APT sources: %v", err)
			}
			t.Cleanup(func() {
				restore := exec.Command("docker", "exec", "-i", container, "sh", "-c",
					"rm -rf /etc/apt/sources.list.d && tar -C /etc/apt -xf -")
				restore.Stdin = bytes.NewReader(snapshot)
				if out, err := restore.CombinedOutput(); err != nil {
					t.Errorf("restoring the stand's APT sources: %v\n%s", err, out)
				}
			})
			return
		}
	}
	// PBS rewrites a whole file whenever it changes an entry, so only the
	// entries whose flag differs are written.
	client, before, _ := testAccAPTState(t)
	t.Cleanup(func() {
		ctx := context.Background()
		now, err := client.APTRepositories(ctx, client.Node())
		if err != nil {
			t.Errorf("reading the stand's APT repositories: %v", err)
			return
		}
		for _, f := range before.Files {
			for i, e := range f.Repositories {
				if current, ok := now.Repository(f.Path, int64(i)); !ok || current.Enabled == e.Enabled {
					continue
				}
				if err := client.SetAPTRepositoryEnabled(ctx, client.Node(), f.Path, int64(i), e.Enabled, ""); err != nil {
					t.Errorf("restoring entry %d of %s: %v", i, f.Path, err)
				}
			}
		}
	})
}

// testAccCheckAPTEntry checks whether the entry at index of the file at
// path is enabled.
func testAccCheckAPTEntry(path string, index int64, enabled bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		repos, err := client.APTRepositories(context.Background(), client.Node())
		if err != nil {
			return err
		}
		e, ok := repos.Repository(path, index)
		if !ok {
			return fmt.Errorf("the stand has no entry at index %d of %s", index, path)
		}
		if e.Enabled != enabled {
			return fmt.Errorf("entry %d of %s: enabled = %t, want %t", index, path, e.Enabled, enabled)
		}
		return nil
	}
}

// testAccCheckAPTStandardStatus checks the status PBS reports for a
// standard repository: "none" when it is not configured, "true" or "false".
func testAccCheckAPTStandardStatus(handle, want string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		repos, err := client.APTRepositories(context.Background(), client.Node())
		if err != nil {
			return err
		}
		s, ok := repos.StandardRepository(handle)
		if !ok {
			return fmt.Errorf("PBS offers no standard repository %s", handle)
		}
		got := "none"
		if s.Status != nil {
			got = strconv.FormatBool(*s.Status)
		}
		if got != want {
			return fmt.Errorf("status of %s = %s, want %s", handle, got, want)
		}
		return nil
	}
}

// testAccCheckListElement checks attributes of the element of a list
// attribute whose key attribute has the value keyValue.
func testAccCheckListElement(resourceName, list, key, keyValue string, want map[string]string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("%s is not in state", resourceName)
		}
		attributes := rs.Primary.Attributes
		n, _ := strconv.Atoi(attributes[list+".#"])
		for i := 0; i < n; i++ {
			prefix := fmt.Sprintf("%s.%d.", list, i)
			if attributes[prefix+key] != keyValue {
				continue
			}
			for name, value := range want {
				if got := attributes[prefix+name]; got != value {
					return fmt.Errorf("%s: %s%s = %q, want %q", resourceName, prefix, name, got, value)
				}
			}
			return nil
		}
		return fmt.Errorf("%s has no %s with %s = %q", resourceName, list, key, keyValue)
	}
}

// The stand's files and standard repositories as the data source reads
// them, checked against what the client reads.
func TestAccAPTRepositoriesDataSource(t *testing.T) {
	const name = "data.pbs_apt_repositories.this"
	enterprisePath, enterpriseIndex := testAccAPTEntryOf(t, pbsclient.APTHandleEnterprise)
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{{
			Config: providerConfig + `data "pbs_apt_repositories" "this" {}` + "\n",
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttr(name, "node", "localhost"),
				acc.TestCheckResourceAttrSet(name, "digest"),
				testAccCheckListed(name, "standard_repositories", "handle", "enterprise", "no-subscription", "test"),
				testAccCheckListed(name, "files", "path", "/etc/apt/sources.list.d/debian.sources", enterprisePath),
				testAccCheckListElement(name, "standard_repositories", "handle", "enterprise", map[string]string{
					"name": "Enterprise", "configured": "true", "file_path": enterprisePath,
					"index": strconv.FormatInt(enterpriseIndex, 10),
				}),
				testAccCheckListElement(name, "repositories", "handle", "enterprise", map[string]string{
					"file_path": enterprisePath, "index": strconv.FormatInt(enterpriseIndex, 10),
					"components.0": "pbs-enterprise", "package_types.0": "deb", "file_type": "sources",
				}),
				testAccCheckListElement(name, "infos", "path", enterprisePath, map[string]string{"kind": "origin", "message": "Proxmox"}),
			),
		}},
	})
}

// The requester's case: the enterprise repository off on a host without a
// subscription, imported, on again and off. Destroying the resource leaves
// the entry off.
func TestAccAPTRepository(t *testing.T) {
	const name = "pbs_apt_repository.enterprise"
	path, index := testAccAPTEntryOf(t, pbsclient.APTHandleEnterprise)
	config := func(enabled bool) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_apt_repository" "enterprise" {
  file_path = %q
  index     = %d
  enabled   = %t
}
`, path, index, enabled)
	}
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); testAccRestoreAPTSources(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckAPTEntry(path, index, false),
		Steps: []acc.TestStep{
			{
				Config: config(false),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(name, "id", fmt.Sprintf("localhost,%s,%d", path, index)),
					acc.TestCheckResourceAttr(name, "node", "localhost"),
					acc.TestCheckResourceAttr(name, "enabled", "false"),
					acc.TestCheckResourceAttr(name, "file_type", "sources"),
					acc.TestCheckResourceAttr(name, "components.0", "pbs-enterprise"),
					acc.TestCheckResourceAttr(name, "uris.0", "https://enterprise.proxmox.com/debian/pbs"),
					acc.TestCheckResourceAttr(name, "suites.0", "trixie"),
					testAccCheckAPTEntry(path, index, false),
					testAccCheckAPTStandardStatus(pbsclient.APTHandleEnterprise, "false"),
				),
			},
			{Config: config(false), ResourceName: name, ImportState: true, ImportStateVerify: true},
			{
				Config: config(true),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(name, "enabled", "true"),
					testAccCheckAPTEntry(path, index, true),
					testAccCheckAPTStandardStatus(pbsclient.APTHandleEnterprise, "true"),
				),
			},
			{Config: config(false), Check: testAccCheckAPTEntry(path, index, false)},
		},
	})
}

// The test repository, which no stand has: PBS adds it, a pbs_apt_repository
// disables it by the standard repository's file_path and index, and
// destroying the standard repository leaves it disabled. The enterprise
// repository, which every stand has, is taken over and disabled by the
// destroy.
func TestAccAPTStandardRepository(t *testing.T) {
	if os.Getenv("TF_ACC") != "" {
		_, repos, _ := testAccAPTState(t)
		if s, ok := repos.StandardRepository(pbsclient.APTHandleTest); !ok || s.Status != nil {
			t.Skip("the stand has the test repository already, or PBS does not offer it")
		}
	}
	enterprisePath, enterpriseIndex := testAccAPTEntryOf(t, pbsclient.APTHandleEnterprise)
	config := func(testEnabled bool) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_apt_standard_repository" "test" {
  handle = "test"
}

resource "pbs_apt_repository" "test" {
  file_path = pbs_apt_standard_repository.test.file_path
  index     = pbs_apt_standard_repository.test.index
  enabled   = %t
}

resource "pbs_apt_standard_repository" "enterprise" {
  handle = "enterprise"
}
`, testEnabled)
	}
	const testName, enterpriseName = "pbs_apt_standard_repository.test", "pbs_apt_standard_repository.enterprise"
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); testAccRestoreAPTSources(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckAPTStandardStatus(pbsclient.APTHandleTest, "false"),
			testAccCheckAPTStandardStatus(pbsclient.APTHandleEnterprise, "false"),
			testAccCheckAPTEntry(enterprisePath, enterpriseIndex, false),
		),
		Steps: []acc.TestStep{
			{
				Config: config(true),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(testName, "id", "localhost,test"),
					acc.TestCheckResourceAttr(testName, "enabled", "true"),
					acc.TestCheckResourceAttr(testName, "name", "Test"),
					acc.TestCheckResourceAttr(testName, "file_path", "/etc/apt/sources.list.d/proxmox.sources"),
					acc.TestCheckResourceAttrSet(testName, "index"),
					acc.TestCheckResourceAttrPair("pbs_apt_repository.test", "index", testName, "index"),
					acc.TestCheckResourceAttr("pbs_apt_repository.test", "components.0", "pbs-test"),
					testAccCheckAPTStandardStatus(pbsclient.APTHandleTest, "true"),
					acc.TestCheckResourceAttr(enterpriseName, "enabled", "true"),
					acc.TestCheckResourceAttr(enterpriseName, "file_path", enterprisePath),
					acc.TestCheckResourceAttr(enterpriseName, "index", strconv.FormatInt(enterpriseIndex, 10)),
				),
			},
			{
				Config: config(false),
				Check:  testAccCheckAPTStandardStatus(pbsclient.APTHandleTest, "false"),
			},
			// The refresh reads the test repository disabled.
			{
				Config: config(false),
				Check:  acc.TestCheckResourceAttr(testName, "enabled", "false"),
			},
			{Config: config(false), ResourceName: testName, ImportState: true, ImportStateVerify: true},
			{Config: config(false), ResourceName: enterpriseName, ImportState: true, ImportStateVerify: true},
		},
	})
}

// From Terraform 1.12, both resources import by identity too.
func TestAccAPTResourcesImportByIdentity(t *testing.T) {
	path, index := testAccAPTEntryOf(t, pbsclient.APTHandleEnterprise)
	config := providerConfig + fmt.Sprintf(`
resource "pbs_apt_repository" "enterprise" {
  file_path = %q
  index     = %d
  enabled   = true
}

resource "pbs_apt_standard_repository" "enterprise" {
  handle = "enterprise"
}
`, path, index)
	steps := []acc.TestStep{{Config: config}}
	for _, name := range []string{"pbs_apt_repository.enterprise", "pbs_apt_standard_repository.enterprise"} {
		steps = append(steps,
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithID})
	}
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); testAccRestoreAPTSources(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		Steps:                    steps,
	})
}
