package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_sync_encryption_key, pbs_sync_encryption_keys and
// the encryption keys of a push sync job, from PBS 4.2. The job pushes from
// the stand to itself, as in the sync job tests, into a datastore the test
// creates; nothing runs it.

// testAccSkipWithoutSyncEncryptionKeys skips a test of sync encryption keys
// on a stand older than PBS 4.2, which has none.
func testAccSkipWithoutSyncEncryptionKeys(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") != "" && !testAccVersionAtLeast(4, 2, 0) {
		t.Skipf("the stand runs PBS %q; sync encryption keys need 4.2", os.Getenv(envAccVersion))
	}
}

// testAccKeyFile returns a key file for a random key, as
// `proxmox-backup-client key create --kdf none` writes it but without a
// fingerprint, which PBS does not need, and its creation time as a Unix
// time.
func testAccKeyFile(t *testing.T) (string, int64) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	stamp := now.Format("2006-01-02T15:04:05-07:00")
	file, err := json.Marshal(map[string]any{
		"kdf":      nil,
		"created":  stamp,
		"modified": stamp,
		"data":     base64.StdEncoding.EncodeToString(key),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(file), now.Unix()
}

// testAccCheckEncryptionKey checks a sync encryption key as PBS lists it.
func testAccCheckEncryptionKey(id string, check func(pbsclient.EncryptionKey) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		key, _, err := client.GetEncryptionKey(context.Background(), id)
		if err != nil {
			return err
		}
		return check(key)
	}
}

// testAccCheckEncryptionKeysDestroyed checks that PBS lists none of the keys,
// archived ones included.
func testAccCheckEncryptionKeysDestroyed(ids ...string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		keys, _, err := client.ListEncryptionKeys(context.Background())
		if err != nil {
			return err
		}
		for _, key := range keys {
			if slices.Contains(ids, key.ID) {
				return fmt.Errorf("sync encryption key %s still exists: %+v", key.ID, key)
			}
		}
		return nil
	}
}

// A key PBS generates and one imported from a key file; a push job
// encrypting with the first, rotated to the second, which PBS records by
// keeping the first as associated, then holding none; the first key archived
// in place; both imported and listed. Destroying deletes the job before the
// keys, which PBS deletes only once no job holds them, and archives the
// active one first.
func TestAccSyncEncryptionKeys(t *testing.T) {
	testAccSkipWithoutSyncEncryptionKeys(t)
	remote := "tfacc-" + testAccRandom(8)
	target := testAccDatastoreName()
	dir := testAccDatastoreDir(t, target)
	source := testAccDatastore(t)
	pushID := "tfacc-push-" + testAccRandom(6)
	generated, imported := "tfacc-gen-"+testAccRandom(6), "tfacc-imp-"+testAccRandom(6)
	keyFile, created := testAccKeyFile(t)
	const (
		generatedName = "pbs_sync_encryption_key.generated"
		importedName  = "pbs_sync_encryption_key.imported"
		jobName       = "pbs_sync_job.push"
	)

	config := func(archived bool, active, associated string) string {
		return providerConfig + testAccSelfRemote(t, remote, "") + fmt.Sprintf(`
resource "pbs_sync_encryption_key" "generated" {
  id       = %[1]q
  archived = %[2]t
}

resource "pbs_sync_encryption_key" "imported" {
  id             = %[3]q
  key_wo         = %[4]q
  key_wo_version = 1
}

resource "pbs_datastore" "target" {
  name         = %[5]q
  path         = %[6]q
  destroy_data = true
}

resource "pbs_sync_job" "push" {
  id                    = %[7]q
  sync_direction        = "push"
  store                 = %[8]q
  remote                = pbs_remote.self.name
  remote_store          = pbs_datastore.target.name
  active_encryption_key = pbs_sync_encryption_key.%[9]s.id
  %[10]s

  # Destroyed before both keys: PBS deletes no key a job holds.
  depends_on = [pbs_sync_encryption_key.generated, pbs_sync_encryption_key.imported]
}

data "pbs_sync_encryption_keys" "all" {
  depends_on = [pbs_sync_encryption_key.generated, pbs_sync_encryption_key.imported]
}
`, generated, archived, imported, keyFile, target, dir, pushID, source, active, associated)
	}
	checkJob := func(active string, associated ...string) acc.TestCheckFunc {
		return testAccCheckSyncJob(pushID, func(job pbsclient.SyncJob) error {
			if job.ActiveEncryptionKey != active || !slices.Equal(job.AssociatedKey, associated) {
				return fmt.Errorf("PBS has the job with active-encryption-key %q and associated-key %v, want %q and %v",
					job.ActiveEncryptionKey, job.AssociatedKey, active, associated)
			}
			return nil
		})
	}
	updates := func(resourceName string) acc.ConfigPlanChecks {
		return acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
		}}
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckSyncDestroyed([]string{remote}, []string{pushID}),
			testAccCheckDatastoresDestroyed([]string{target}, nil, nil),
			testAccCheckEncryptionKeysDestroyed(generated, imported),
		),
		Steps: []acc.TestStep{
			{
				Config: config(false, "generated", ""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(generatedName, "id", generated),
					acc.TestCheckResourceAttrSet(generatedName, "fingerprint"),
					acc.TestCheckResourceAttrSet(generatedName, "created"),
					acc.TestCheckResourceAttr(generatedName, "archived", "false"),
					acc.TestCheckNoResourceAttr(generatedName, "archived_at"),
					acc.TestCheckNoResourceAttr(generatedName, "key_wo"),
					// An imported key keeps the creation time of its file.
					acc.TestCheckResourceAttr(importedName, "created", strconv.FormatInt(created, 10)),
					acc.TestCheckResourceAttr(importedName, "key_wo_version", "1"),
					acc.TestCheckNoResourceAttr(importedName, "key_wo"),
					acc.TestCheckResourceAttr(importedName, "archived", "false"),
					testAccCheckEncryptionKey(generated, func(key pbsclient.EncryptionKey) error {
						if key.Fingerprint == "" || key.Archived() {
							return fmt.Errorf("PBS lists the generated key as %+v", key)
						}
						return nil
					}),
					acc.TestCheckResourceAttr(jobName, "active_encryption_key", generated),
					acc.TestCheckNoResourceAttr(jobName, "associated_key"),
					checkJob(generated),
					testAccCheckListed("data.pbs_sync_encryption_keys.all", "keys", "id", generated, imported),
				),
			},
			{
				// A new active key; PBS keeps the one before as associated,
				// which the plan says.
				Config:           config(false, "imported", ""),
				ConfigPlanChecks: updates(jobName),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(jobName, "active_encryption_key", imported),
					acc.TestCheckResourceAttr(jobName, "associated_key.#", "1"),
					acc.TestCheckTypeSetElemAttr(jobName, "associated_key.*", generated),
					checkJob(imported, generated),
				),
			},
			{
				// An empty associated_key holds none.
				Config:           config(false, "imported", "associated_key = []"),
				ConfigPlanChecks: updates(jobName),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(jobName, "associated_key.#", "0"),
					checkJob(imported),
				),
			},
			{
				// A key no job encrypts with may be archived, in place.
				Config:           config(true, "imported", "associated_key = []"),
				ConfigPlanChecks: updates(generatedName),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(generatedName, "archived", "true"),
					acc.TestCheckResourceAttrSet(generatedName, "archived_at"),
					testAccCheckEncryptionKey(generated, func(key pbsclient.EncryptionKey) error {
						if !key.Archived() {
							return fmt.Errorf("PBS lists the generated key as not archived: %+v", key)
						}
						return nil
					}),
					acc.TestCheckTypeSetElemNestedAttrs("data.pbs_sync_encryption_keys.all", "keys.*", map[string]string{
						"id": generated, "archived": "true",
					}),
					acc.TestCheckTypeSetElemNestedAttrs("data.pbs_sync_encryption_keys.all", "keys.*", map[string]string{
						"id": imported, "archived": "false", "created": strconv.FormatInt(created, 10),
					}),
				),
			},
			{
				// PBS never returns a key.
				ResourceName:            generatedName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"key_wo", "key_wo_version"},
			},
			{
				ResourceName:            importedName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"key_wo", "key_wo_version"},
			},
		},
	})
}

// From Terraform 1.12, a key imports by identity too. A key PBS generates
// has no key_wo in its configuration, so that an import plans no change.
func TestAccSyncEncryptionKeyImportByIdentity(t *testing.T) {
	testAccSkipWithoutSyncEncryptionKeys(t)
	id := "tfacc-key-" + testAccRandom(6)
	config := providerConfig + fmt.Sprintf(`
resource "pbs_sync_encryption_key" "test" {
  id = %q
}
`, id)
	const resourceName = "pbs_sync_encryption_key.test"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckEncryptionKeysDestroyed(id),
		Steps: []acc.TestStep{
			{Config: config},
			{Config: config, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			{Config: config, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		},
	})
}
