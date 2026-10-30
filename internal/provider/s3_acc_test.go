package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_s3_endpoint, its data sources, pbs_s3_buckets and
// datastores on S3. PBS contacts no object store when it saves an endpoint,
// so the endpoint tests point at hosts that do not exist. The others use the
// S3 server scripts/bootstrap-test-pbs.sh starts in the stand's network
// namespace — Silo, a MinIO fork, with a self-signed certificate — and skip
// without it. Their datastores share the stand's bucket: a datastore's name
// prefixes its objects there, and every test's name is its own. What the
// bucket holds is read with mc in the S3 server's container.

// The facts scripts/bootstrap-test-pbs.sh exports about its S3 server.
const (
	// envAccS3Container is the S3 server's Docker container, and
	// envAccS3MCAlias mc's name for the server there.
	envAccS3Container = "PBS_ACC_S3_CONTAINER"
	envAccS3MCAlias   = "PBS_ACC_S3_MC_ALIAS"
	// envAccS3Endpoint and envAccS3Port are where PBS reaches the server,
	// envAccS3Fingerprint is its certificate's fingerprint, and
	// envAccS3Region a region it accepts: it accepts any.
	envAccS3Endpoint    = "PBS_ACC_S3_ENDPOINT"
	envAccS3Port        = "PBS_ACC_S3_PORT"
	envAccS3Fingerprint = "PBS_ACC_S3_FINGERPRINT"
	envAccS3Region      = "PBS_ACC_S3_REGION"
	// envAccS3AccessKey and envAccS3SecretKey are the server's account.
	envAccS3AccessKey = "PBS_ACC_S3_ACCESS_KEY"
	envAccS3SecretKey = "PBS_ACC_S3_SECRET_KEY"
	// envAccS3Bucket is the bucket the datastore tests use, envAccS3Buckets
	// every bucket of the server, comma-separated.
	envAccS3Bucket  = "PBS_ACC_S3_BUCKET"
	envAccS3Buckets = "PBS_ACC_S3_BUCKETS"
)

// testAccSkipWithoutS3 skips a test that needs the stand's S3 server when
// the stand runs none.
func testAccSkipWithoutS3(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") != "" && os.Getenv(envAccS3Endpoint) == "" {
		t.Skip(envAccS3Endpoint + " is not set: the stand runs no S3 server")
	}
}

// testAccSkipWithoutS3Objects skips a test that also looks into the stand's
// buckets, with mc in the S3 server's container, when it cannot: without the
// server, its container or Docker.
func testAccSkipWithoutS3Objects(t *testing.T) {
	t.Helper()
	testAccSkipWithoutS3(t)
	if os.Getenv("TF_ACC") == "" {
		return
	}
	if os.Getenv(envAccS3Container) == "" || os.Getenv(envAccS3MCAlias) == "" {
		t.Skip(envAccS3Container + " and " + envAccS3MCAlias + " are not set: the buckets cannot be looked into")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("looking into the buckets needs docker:", err)
	}
}

// testAccS3Setting returns a fact about the stand's S3 server, or fallback
// where the stand does not say, as without TF_ACC, when no test runs.
func testAccS3Setting(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// testAccS3Bucket is the bucket of the stand's S3 server that the datastore
// tests share.
func testAccS3Bucket() string {
	return testAccS3Setting(envAccS3Bucket, "tfacc-s3")
}

// testAccS3StandEndpoint is a pbs_s3_endpoint, the resource named name with
// the given ID, on the stand's S3 server, which accepts the certificate with
// fingerprint. The server's endpoint is an IP address, so requests name the
// bucket in their path.
func testAccS3StandEndpoint(name, id, fingerprint string) string {
	return fmt.Sprintf(`
resource "pbs_s3_endpoint" %q {
  id                    = %q
  endpoint              = %q
  port                  = %s
  region                = %q
  path_style            = true
  fingerprint           = %q
  access_key            = %q
  secret_key_wo         = %q
  secret_key_wo_version = 1
}
`, name, id, testAccS3Setting(envAccS3Endpoint, "127.0.0.1"), testAccS3Setting(envAccS3Port, "9000"),
		testAccS3Setting(envAccS3Region, "us-east-1"), fingerprint,
		testAccS3Setting(envAccS3AccessKey, "unused"), testAccS3Setting(envAccS3SecretKey, "unused"))
}

// testAccS3StandFingerprint is the fingerprint of the stand's S3 server's
// certificate, as the bootstrap script exports it: upper-case hex pairs,
// colon-separated.
func testAccS3StandFingerprint() string {
	return testAccS3Setting(envAccS3Fingerprint, pbsclient.FormatFingerprint(strings.Repeat("ab", 32)))
}

// testAccRandomFingerprint returns a random SHA-256 fingerprint in PBS's
// form, colon-separated lower-case hex pairs.
func testAccRandomFingerprint() string {
	return pbsclient.FormatFingerprint(testAccRandom(64))
}

// testAccCheckS3Endpoint checks an S3 endpoint as PBS reports it.
func testAccCheckS3Endpoint(id string, check func(pbsclient.S3Endpoint) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		endpoint, err := client.GetS3Endpoint(context.Background(), id)
		if err != nil {
			return err
		}
		return check(endpoint)
	}
}

// testAccCheckS3EndpointsDestroyed checks that the S3 endpoints are gone.
func testAccCheckS3EndpointsDestroyed(ids ...string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := client.GetS3Endpoint(context.Background(), id); err == nil {
				return fmt.Errorf("S3 endpoint %s still exists", id)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		return nil
	}
}

// testAccMC runs mc in the stand's S3 container, with stdin as its input.
// mc does not check the server's certificate: the test only looks into the
// buckets, and PBS's own check of the certificate is what is tested.
func testAccMC(stdin string, args ...string) ([]byte, error) {
	cmd := exec.Command("docker", append([]string{
		"exec", "-i", os.Getenv(envAccS3Container), "mc", "--insecure", "--no-color",
	}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("mc %s failed: %w\n%s%s", strings.Join(args, " "), err, out, stderr.String())
	}
	return out, nil
}

// testAccS3Path is the path of key in bucket, as mc in the S3 container
// names it.
func testAccS3Path(bucket, key string) string {
	return os.Getenv(envAccS3MCAlias) + "/" + bucket + "/" + key
}

// testAccS3Keys lists the keys of the objects in bucket under prefix.
func testAccS3Keys(bucket, prefix string) ([]string, error) {
	out, err := testAccMC("", "--json", "ls", "--recursive", testAccS3Path(bucket, ""))
	if err != nil {
		return nil, err
	}
	var keys []string
	for line := range strings.Lines(string(out)) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry struct {
			Status string `json:"status"`
			Type   string `json:"type"`
			Key    string `json:"key"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("reading mc's listing of %s: %w: %s", bucket, err, line)
		}
		if entry.Status != "success" {
			return nil, fmt.Errorf("mc could not list %s: %s", bucket, line)
		}
		if entry.Type == "file" && strings.HasPrefix(entry.Key, prefix) {
			keys = append(keys, entry.Key)
		}
	}
	return keys, nil
}

// testAccS3Put writes an object to bucket outside PBS.
func testAccS3Put(t *testing.T, bucket, key, content string) {
	t.Helper()
	if _, err := testAccMC(content, "--quiet", "pipe", testAccS3Path(bucket, key)); err != nil {
		t.Fatal(err)
	}
}

// testAccCheckS3Datastore checks what bucket holds under the name of a
// datastore on S3: PBS's mark that the datastore is in use, while it exists,
// and nothing once it is destroyed with its data.
func testAccCheckS3Datastore(bucket, name string, exists bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		keys, err := testAccS3Keys(bucket, name+"/")
		if err != nil {
			return err
		}
		switch {
		case exists && !slices.Contains(keys, name+"/.in-use"):
			return fmt.Errorf("bucket %s has no in-use mark of datastore %s; it holds %v under %s/", bucket, name, keys, name)
		case !exists && len(keys) > 0:
			return fmt.Errorf("bucket %s still holds %v under %s/", bucket, keys, name)
		}
		return nil
	}
}

// testAccCheckS3Object checks whether bucket holds an object under key.
func testAccCheckS3Object(bucket, key string, exists bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		keys, err := testAccS3Keys(bucket, key)
		if err != nil {
			return err
		}
		if slices.Contains(keys, key) != exists {
			return fmt.Errorf("bucket %s holds %s = %t, want %t", bucket, key, !exists, exists)
		}
		return nil
	}
}

// testAccS3CleanUp removes every object under a datastore's name from bucket
// when the test ends, which the test's own destroy leaves when a step fails
// midway. Tests that call it call testAccSkipWithoutS3Objects first.
func testAccS3CleanUp(t *testing.T, bucket, name string) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		return
	}
	t.Cleanup(func() {
		if _, err := testAccMC("", "--quiet", "rm", "--recursive", "--force", testAccS3Path(bucket, name+"/")); err != nil {
			t.Logf("removing %s/ from bucket %s: %v", name, bucket, err)
		}
	})
}

// testAccCheckS3InUseBy checks which host the in-use mark of a datastore on
// S3 names, by not naming other.
func testAccCheckS3InUseBy(bucket, name, other string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		out, err := testAccMC("", "cat", testAccS3Path(bucket, name+"/.in-use"))
		if err != nil {
			return err
		}
		var mark struct {
			Hostname string `json:"hostname"`
		}
		if err := json.Unmarshal(out, &mark); err != nil {
			return fmt.Errorf("the in-use mark of datastore %s is %q: %w", name, out, err)
		}
		if mark.Hostname == "" || mark.Hostname == other {
			return fmt.Errorf("the in-use mark of datastore %s names host %q, want the stand's", name, mark.Hostname)
		}
		return nil
	}
}

// An endpoint with every attribute the stand's PBS knows, changed in place,
// imported, and read by the data sources. PBS does not contact the object
// store, so the endpoint is a host that does not exist, with the bucket and
// the region in its name.
func TestAccS3Endpoint(t *testing.T) {
	id := "tfacc-" + testAccRandom(8)
	const resourceName = "pbs_s3_endpoint.test"
	first, second := testAccRandomFingerprint(), testAccRandomFingerprint()
	// The second fingerprint is written another way, which PBS takes.
	secondWritten := strings.ToUpper(strings.ReplaceAll(second, ":", ""))

	quirks := []string{s3QuirkSkipIfNoneMatch}
	if testAccVersionAtLeast(4, 1, 6) {
		quirks = append(quirks, s3QuirkDeleteObjectsSlow)
	}
	quirksHCL, _ := json.Marshal(quirks)
	rates := testAccVersionAtLeast(4, 1, 0)
	limits := testAccVersionAtLeast(4, 2, 4)
	var firstExtra, secondExtra string
	if rates {
		// In PBS's spelling, which it writes back, so that an import reads
		// them as configured.
		firstExtra += `
  rate_in   = "10 MiB"
  burst_in  = "20 MiB"
  rate_out  = "1.5 GB"
  burst_out = "2 GB"`
		secondExtra += `
  rate_in = "20 MiB"`
	}
	if limits {
		firstExtra += `
  limit_active_requests  = 100
  limit_passive_requests = 200
  use_node_proxy         = true`
		secondExtra += `
  limit_active_requests = 50`
	}

	initial := providerConfig + fmt.Sprintf(`
resource "pbs_s3_endpoint" "test" {
  id                    = %q
  endpoint              = "{{bucket}}.s3.{{region}}.example.invalid"
  region                = "eu-central-1"
  port                  = 9443
  fingerprint           = %q
  access_key            = "tfacc-access-1"
  secret_key_wo         = "tfacc-secret-1"
  secret_key_wo_version = 1
  provider_quirks       = %s
%s
}
`, id, first, quirksHCL, firstExtra)
	changed := providerConfig + fmt.Sprintf(`
resource "pbs_s3_endpoint" "test" {
  id                    = %q
  endpoint              = "s3.example.invalid"
  path_style            = true
  fingerprint           = %q
  access_key            = "tfacc-access-2"
  secret_key_wo         = "tfacc-secret-2"
  secret_key_wo_version = 2
%s
}

data "pbs_s3_endpoint" "test" {
  id = pbs_s3_endpoint.test.id
}

data "pbs_s3_endpoints" "all" {
  depends_on = [pbs_s3_endpoint.test]
}
`, id, secondWritten, secondExtra)

	initialChecks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr(resourceName, "id", id),
		acc.TestCheckResourceAttr(resourceName, "endpoint", "{{bucket}}.s3.{{region}}.example.invalid"),
		acc.TestCheckResourceAttr(resourceName, "port", "9443"),
		acc.TestCheckResourceAttr(resourceName, "fingerprint", first),
		acc.TestCheckResourceAttr(resourceName, "path_style", "false"),
		acc.TestCheckResourceAttr(resourceName, "provider_quirks.#", fmt.Sprint(len(quirks))),
		acc.TestCheckNoResourceAttr(resourceName, "secret_key_wo"),
		acc.TestCheckResourceAttr(resourceName, "secret_key_wo_version", "1"),
		acc.TestCheckResourceAttr(resourceName, "use_node_proxy", fmt.Sprint(limits)),
		testAccCheckS3Endpoint(id, func(e pbsclient.S3Endpoint) error {
			if e.Endpoint != "{{bucket}}.s3.{{region}}.example.invalid" || e.Region != "eu-central-1" ||
				e.Port == nil || *e.Port != 9443 || e.Fingerprint != first || e.AccessKey != "tfacc-access-1" ||
				len(e.ProviderQuirks) != len(quirks) {
				return fmt.Errorf("PBS has the endpoint as %+v", e)
			}
			if rates && (e.RateIn != "10 MiB" || e.BurstIn != "20 MiB" || e.RateOut != "1.5 GB" || e.BurstOut != "2 GB") {
				return fmt.Errorf("PBS has the rates of the endpoint as %+v", e)
			}
			if limits && (e.LimitActiveRequests == nil || *e.LimitActiveRequests != 100 ||
				e.LimitPassiveRequests == nil || *e.LimitPassiveRequests != 200 || e.UseNodeProxy == nil || !*e.UseNodeProxy) {
				return fmt.Errorf("PBS has the limits of the endpoint as %+v", e)
			}
			return nil
		}),
	}
	for _, quirk := range quirks {
		initialChecks = append(initialChecks, acc.TestCheckTypeSetElemAttr(resourceName, "provider_quirks.*", quirk))
	}
	if rates {
		initialChecks = append(initialChecks,
			acc.TestCheckResourceAttr(resourceName, "rate_in", "10 MiB"),
			acc.TestCheckResourceAttr(resourceName, "burst_out", "2 GB"),
		)
	}
	if limits {
		initialChecks = append(initialChecks, acc.TestCheckResourceAttr(resourceName, "limit_passive_requests", "200"))
	}

	changedChecks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr(resourceName, "path_style", "true"),
		acc.TestCheckNoResourceAttr(resourceName, "region"),
		acc.TestCheckNoResourceAttr(resourceName, "port"),
		acc.TestCheckNoResourceAttr(resourceName, "provider_quirks"),
		acc.TestCheckNoResourceAttr(resourceName, "burst_in"),
		acc.TestCheckNoResourceAttr(resourceName, "limit_passive_requests"),
		acc.TestCheckResourceAttr(resourceName, "use_node_proxy", "false"),
		acc.TestCheckResourceAttr(resourceName, "secret_key_wo_version", "2"),
		testAccCheckS3Endpoint(id, func(e pbsclient.S3Endpoint) error {
			if e.Endpoint != "s3.example.invalid" || e.Region != "" || e.Port != nil || e.Fingerprint != second ||
				e.AccessKey != "tfacc-access-2" || e.PathStyle == nil || !*e.PathStyle || len(e.ProviderQuirks) != 0 ||
				e.BurstIn != "" || e.RateOut != "" || e.BurstOut != "" || e.LimitPassiveRequests != nil ||
				(e.UseNodeProxy != nil && *e.UseNodeProxy) {
				return fmt.Errorf("PBS has the changed endpoint as %+v", e)
			}
			if rates && e.RateIn != "20 MiB" {
				return fmt.Errorf("PBS has rate-in %q, want 20 MiB", e.RateIn)
			}
			if limits && (e.LimitActiveRequests == nil || *e.LimitActiveRequests != 50) {
				return fmt.Errorf("PBS has limit-active-requests %v, want 50", e.LimitActiveRequests)
			}
			return nil
		}),
		// The data sources report the fingerprint in PBS's form.
		acc.TestCheckResourceAttr("data.pbs_s3_endpoint.test", "fingerprint", second),
		acc.TestCheckResourceAttr("data.pbs_s3_endpoint.test", "endpoint", "s3.example.invalid"),
		acc.TestCheckResourceAttr("data.pbs_s3_endpoint.test", "access_key", "tfacc-access-2"),
		acc.TestCheckResourceAttr("data.pbs_s3_endpoint.test", "path_style", "true"),
		acc.TestCheckNoResourceAttr("data.pbs_s3_endpoint.test", "port"),
		acc.TestCheckNoResourceAttr("data.pbs_s3_endpoint.test", "provider_quirks"),
		testAccCheckListed("data.pbs_s3_endpoints.all", "endpoints", "id", id),
		acc.TestCheckTypeSetElemNestedAttrs("data.pbs_s3_endpoints.all", "endpoints.*", map[string]string{
			"id": id, "fingerprint": second, "path_style": "true",
		}),
	}
	if rates {
		changedChecks = append(changedChecks, acc.TestCheckResourceAttr("data.pbs_s3_endpoint.test", "rate_in", "20 MiB"))
	}
	if limits {
		changedChecks = append(changedChecks, acc.TestCheckResourceAttr("data.pbs_s3_endpoint.test", "limit_active_requests", "50"))
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckS3EndpointsDestroyed(id),
		Steps: []acc.TestStep{
			{
				Config: initial,
				Check:  acc.ComposeAggregateTestCheckFunc(initialChecks...),
			},
			{
				// PBS never returns the secret key.
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"secret_key_wo", "secret_key_wo_version"},
			},
			{
				// Everything but the ID changes in place, the secret key with
				// its version.
				Config: changed,
				ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
				}},
				Check: acc.ComposeAggregateTestCheckFunc(changedChecks...),
			},
		},
	})
}

// From Terraform 1.12, an S3 endpoint imports by identity too. An import
// block plans no change only when the configuration matches what an import
// reads, and the secret key exists only in Terraform, so the endpoint is
// configured without one after it was created.
func TestAccS3EndpointImportByIdentity(t *testing.T) {
	id := "tfacc-" + testAccRandom(8)
	endpoint := func(secret string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_s3_endpoint" "test" {
  id         = %q
  endpoint   = "s3.example.invalid"
  path_style = true
  access_key = "tfacc-access"
%s}
`, id, secret)
	}
	created := endpoint("  secret_key_wo         = \"tfacc-secret\"\n  secret_key_wo_version = 1\n")
	imported := endpoint("")
	const resourceName = "pbs_s3_endpoint.test"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckS3EndpointsDestroyed(id),
		Steps: []acc.TestStep{
			{Config: created},
			{Config: imported},
			{Config: imported, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			{Config: imported, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		},
	})
}

// A datastore on the stand's S3 server: PBS lists the server's buckets
// through the endpoint, marks the datastore in use in the bucket, changes
// its request counters in place, imports it, and deletes every object under
// its name when it is destroyed with its data.
func TestAccS3Datastore(t *testing.T) {
	testAccSkipWithoutS3Objects(t)
	endpointID := "tfacc-" + testAccRandom(8)
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	bucket := testAccS3Bucket()
	buckets := strings.Split(testAccS3Setting(envAccS3Buckets, bucket), ",")
	counters := testAccVersionAtLeast(4, 2, 0)
	const resourceName = "pbs_datastore.test"

	config := func(gcSchedule, thresholds string) string {
		if !counters {
			thresholds = ""
		}
		return providerConfig + testAccS3StandEndpoint("test", endpointID, testAccS3StandFingerprint()) + fmt.Sprintf(`
data "pbs_s3_buckets" "test" {
  s3_endpoint = pbs_s3_endpoint.test.id
}

resource "pbs_datastore" "test" {
  name         = %q
  path         = %q
  gc_schedule  = %q
  destroy_data = true

  backend = {
    type   = "s3"
    client = pbs_s3_endpoint.test.id
    bucket = %q
  }
%s
}

data "pbs_datastore" "test" {
  name = pbs_datastore.test.name
}
`, name, dir, gcSchedule, bucket, thresholds)
	}
	initial := config("daily", `
  notification_thresholds = {
    s3_put    = 100000
    s3_upload = "500GiB"
  }
  counter_reset_schedule = "monthly"`)
	changed := config("sat 05:00", `
  notification_thresholds = {
    s3_get      = 1000000
    s3_download = "100GiB"
  }
  counter_reset_schedule = "mon 02:00"`)

	initialChecks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr(resourceName, "backend.type", "s3"),
		acc.TestCheckResourceAttr(resourceName, "backend.client", endpointID),
		acc.TestCheckResourceAttr(resourceName, "backend.bucket", bucket),
		acc.TestCheckNoResourceAttr(resourceName, "backend.max_cache_size"),
		acc.TestCheckResourceAttr(resourceName, "path", dir),
		acc.TestCheckResourceAttr(resourceName, "mount_status", pbsclient.MountStatusNonRemovable),
		testAccCheckListed("data.pbs_s3_buckets.test", "buckets", "name", buckets...),
		acc.TestCheckResourceAttr("data.pbs_datastore.test", "backend_type", "s3"),
		acc.TestCheckResourceAttr("data.pbs_datastore.test", "backend.client", endpointID),
		acc.TestCheckResourceAttr("data.pbs_datastore.test", "backend.bucket", bucket),
		acc.TestCheckResourceAttr("data.pbs_datastore.test", "path", dir),
		testAccCheckS3Datastore(bucket, name, true),
		testAccCheckS3InUseBy(bucket, name, ""),
	}
	changedChecks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr(resourceName, "gc_schedule", "sat 05:00"),
		testAccCheckS3Datastore(bucket, name, true),
	}
	if counters {
		initialChecks = append(initialChecks,
			acc.TestCheckResourceAttr(resourceName, "notification_thresholds.s3_put", "100000"),
			acc.TestCheckResourceAttr(resourceName, "notification_thresholds.s3_upload", "500GiB"),
			acc.TestCheckNoResourceAttr(resourceName, "notification_thresholds.s3_get"),
			acc.TestCheckResourceAttr(resourceName, "counter_reset_schedule", "monthly"),
			acc.TestCheckResourceAttr("data.pbs_datastore.test", "notification_thresholds.s3_put", "100000"),
			acc.TestCheckResourceAttr("data.pbs_datastore.test", "counter_reset_schedule", "monthly"),
			testAccCheckS3Thresholds(name, map[string]string{"s3-put": "100000", "s3-upload": "500GiB"}, "monthly"),
		)
		changedChecks = append(changedChecks,
			acc.TestCheckResourceAttr(resourceName, "notification_thresholds.s3_get", "1000000"),
			acc.TestCheckNoResourceAttr(resourceName, "notification_thresholds.s3_put"),
			acc.TestCheckResourceAttr(resourceName, "counter_reset_schedule", "mon 02:00"),
			testAccCheckS3Thresholds(name, map[string]string{"s3-get": "1000000", "s3-download": "100GiB"}, "mon 02:00"),
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
			testAccCheckS3EndpointsDestroyed(endpointID),
			testAccCheckS3Datastore(bucket, name, false),
		),
		Steps: []acc.TestStep{
			{
				Config: initial,
				Check:  acc.ComposeAggregateTestCheckFunc(initialChecks...),
			},
			{
				Config: changed,
				ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
				}},
				Check: acc.ComposeAggregateTestCheckFunc(changedChecks...),
			},
			{
				// The flags that act on creation and destruction exist only
				// in Terraform.
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"reuse_datastore", "overwrite_in_use", "destroy_data", "keep_job_configs"},
			},
		},
	})
}

// testAccCheckS3Thresholds checks the request counters' settings of a
// datastore on S3 as PBS reports them.
func testAccCheckS3Thresholds(name string, thresholds map[string]string, schedule string) acc.TestCheckFunc {
	return testAccCheckDatastoreConfig(name, func(ds pbsclient.Datastore) error {
		parsed, err := pbsclient.ParsePropertyString(ds.NotificationThresholds, "")
		if err != nil {
			return fmt.Errorf("PBS has notification-thresholds %q: %w", ds.NotificationThresholds, err)
		}
		if len(parsed) != len(thresholds) || ds.CounterResetSchedule != schedule {
			return fmt.Errorf("PBS has notification-thresholds %q and counter-reset-schedule %q, want %v and %q",
				ds.NotificationThresholds, ds.CounterResetSchedule, thresholds, schedule)
		}
		for key, want := range thresholds {
			if parsed[key] != want {
				return fmt.Errorf("PBS has notification-thresholds %q, want %v", ds.NotificationThresholds, thresholds)
			}
		}
		return nil
	})
}

// A bucket that marks a datastore in use by another PBS: PBS refuses to
// create the datastore there, and takes it over with reuse_datastore and
// overwrite_in_use, marking it in use by itself.
func TestAccS3DatastoreInUse(t *testing.T) {
	testAccSkipWithoutS3Objects(t)
	endpointID := "tfacc-" + testAccRandom(8)
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	bucket := testAccS3Bucket()
	config := func(takeOver bool) string {
		return providerConfig + testAccS3StandEndpoint("test", endpointID, testAccS3StandFingerprint()) + fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name             = %q
  path             = %q
  reuse_datastore  = %t
  overwrite_in_use = %t
  destroy_data     = true

  backend = {
    type   = "s3"
    client = pbs_s3_endpoint.test.id
    bucket = %q
  }
}
`, name, dir, takeOver, takeOver, bucket)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
			testAccCheckS3EndpointsDestroyed(endpointID),
			testAccCheckS3Datastore(bucket, name, false),
		),
		Steps: []acc.TestStep{
			{
				// The mark another PBS would have left.
				PreConfig:   func() { testAccS3Put(t, bucket, name+"/.in-use", `{"hostname":"elsewhere"}`) },
				Config:      config(false),
				ExpectError: regexp.MustCompile(`in\s+use\s+by\s+host\s+elsewhere`),
			},
			{
				Config: config(true),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_datastore.test", "reuse_datastore", "true"),
					acc.TestCheckResourceAttr("pbs_datastore.test", "overwrite_in_use", "true"),
					acc.TestCheckNoResourceAttr("pbs_datastore.test", "maintenance_mode"),
					testAccCheckS3InUseBy(bucket, name, "elsewhere"),
				),
			},
		},
	})
}

// A datastore on S3 destroyed without destroy_data, the default: PBS deletes
// only its in-use mark from the bucket, and keeps what it holds, here a
// namespace, which Terraform forgets rather than destroys. Created again
// under the same name with reuse_datastore, without overwrite_in_use, the
// datastore marks itself in use and reads the namespace back from the
// bucket; PBS restores an empty namespace so from 4.1.5. Destroyed with
// destroy_data at last, it leaves nothing.
func TestAccS3DatastoreReattach(t *testing.T) {
	testAccSkipWithoutS3Objects(t)
	endpointID := "tfacc-" + testAccRandom(8)
	name := testAccDatastoreName()
	dir := testAccDatastoreDir(t, name)
	bucket := testAccS3Bucket()
	testAccS3CleanUp(t, bucket, name)
	const namespace = "kept"
	// Where PBS keeps the namespace in the bucket: an empty object.
	namespaceMark := name + "/.cnt/ns/" + namespace + "/.namespace"
	const resourceName = "pbs_datastore.test"

	endpoint := providerConfig + testAccS3StandEndpoint("test", endpointID, testAccS3StandFingerprint())
	datastore := func(attributes string) string {
		return fmt.Sprintf(`
resource "pbs_datastore" "test" {
  name = %q
  path = %q
%s
  backend = {
    type   = "s3"
    client = pbs_s3_endpoint.test.id
    bucket = %q
  }
}
`, name, dir, attributes, bucket)
	}
	created := endpoint + datastore("") + fmt.Sprintf(`
resource "pbs_namespace" "test" {
  store     = pbs_datastore.test.name
  namespace = %q
}
`, namespace)
	// Deleting the namespace would delete its mark in the bucket.
	destroyed := endpoint + `
removed {
  from = pbs_namespace.test

  lifecycle {
    destroy = false
  }
}
`
	reattached := endpoint + datastore("  reuse_datastore = true\n")
	cleanedUp := endpoint + datastore("  reuse_datastore = true\n  destroy_data    = true\n")

	reattachedChecks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr(resourceName, "reuse_datastore", "true"),
		acc.TestCheckResourceAttr(resourceName, "overwrite_in_use", "false"),
		acc.TestCheckNoResourceAttr(resourceName, "maintenance_mode"),
		testAccCheckDatastoreConfig(name, func(ds pbsclient.Datastore) error {
			if ds.MaintenanceMode != "" {
				return fmt.Errorf("the datastore is still in maintenance mode %q", ds.MaintenanceMode)
			}
			return nil
		}),
		// The mark is new: the destroy deleted the one before.
		testAccCheckS3InUseBy(bucket, name, ""),
		testAccCheckS3Object(bucket, namespaceMark, true),
	}
	if testAccVersionAtLeast(4, 1, 5) {
		reattachedChecks = append(reattachedChecks, testAccCheckNamespace(name, namespace, true))
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
			testAccCheckS3EndpointsDestroyed(endpointID),
			testAccCheckS3Datastore(bucket, name, false),
		),
		Steps: []acc.TestStep{
			{
				Config: created,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "destroy_data", "false"),
					testAccCheckNamespace(name, namespace, true),
					testAccCheckS3Datastore(bucket, name, true),
					testAccCheckS3Object(bucket, namespaceMark, true),
				),
			},
			{
				Config: destroyed,
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckDatastoresDestroyed([]string{name}, nil, nil),
					testAccCheckS3Object(bucket, name+"/.in-use", false),
					testAccCheckS3Object(bucket, namespaceMark, true),
				),
			},
			{
				Config: reattached,
				Check:  acc.ComposeAggregateTestCheckFunc(reattachedChecks...),
			},
			{
				// Set in an apply of its own, as destroying reads it from
				// state.
				Config: cleanedUp,
				Check:  acc.TestCheckResourceAttr(resourceName, "destroy_data", "true"),
			},
		},
	})
}

// PBS checks the certificate of an object store it does not trust against
// the endpoint's fingerprint, so listing the buckets with the fingerprint of
// another certificate — PBS's own, real but wrong — fails. A wrong
// fingerprint fails within seconds, where an address nothing answers at
// would outlast the provider's request timeout.
func TestAccS3BucketsWrongFingerprint(t *testing.T) {
	testAccSkipWithoutS3(t)
	id := "tfacc-" + testAccRandom(8)
	wrong := os.Getenv(envCertFingerprint)
	if wrong == "" {
		wrong = testAccRandomFingerprint()
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckS3EndpointsDestroyed(id),
		Steps: []acc.TestStep{{
			Config: providerConfig + testAccS3StandEndpoint("wrong", id, wrong) + `
data "pbs_s3_buckets" "wrong" {
  s3_endpoint = pbs_s3_endpoint.wrong.id
}
`,
			ExpectError: regexp.MustCompile(`Unable\s+to\s+list\s+the\s+buckets`),
		}},
	})
}
