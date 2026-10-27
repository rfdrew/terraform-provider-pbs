package provider

import (
	"errors"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// testAccProtoV6ProviderFactories wires the in-process provider into the
// acceptance test framework.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"pbs": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccPreCheck fails fast when the acceptance environment is incomplete.
//
// Acceptance tests talk to a real PBS and create, change and delete real
// configuration in it, so they only run when TF_ACC is set. Point
// PBS_ENDPOINT and PBS_API_TOKEN (and PBS_TLS_FINGERPRINT, for the usual
// self-signed certificate) at a throwaway server, never a production one:
// `make pbs-up` starts one and prints the exports.
func testAccPreCheck(t *testing.T) {
	t.Helper()
	for _, name := range []string{envEndpoint, envAPIToken} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s must be set for acceptance tests", name)
		}
	}
}

// providerConfig relies on the PBS_* variables being present in the
// environment, so no credentials appear in the test configurations.
const providerConfig = `provider "pbs" {}` + "\n"

// scripts/bootstrap-test-pbs.sh also exports facts about the test server the
// acceptance tests check against. They are optional: a test reading them
// skips what depends on them.
const (
	// envAccUsername and envAccPassword are a user with a password and an
	// Admin ACL on /, for the tests that sign in with a password.
	envAccUsername = "PBS_ACC_USERNAME"
	envAccPassword = "PBS_ACC_PASSWORD"
	// envAccVersion is the server's version, e.g. 4.2.8.
	envAccVersion = "PBS_ACC_VERSION"
)

// testAccClient connects to the acceptance server the way the provider does,
// from the same PBS_* environment variables and through the same settings
// code, for checks the provider itself does not make.
func testAccClient() (*pbsclient.Client, error) {
	var diags diag.Diagnostics
	s := providerModel{}.settings(&diags)
	if diags.HasError() {
		var errs []error
		for _, d := range diags.Errors() {
			errs = append(errs, errors.New(d.Summary()+": "+d.Detail()))
		}
		return nil, errors.Join(errs...)
	}
	return pbsclient.New(s.clientOptions())
}
