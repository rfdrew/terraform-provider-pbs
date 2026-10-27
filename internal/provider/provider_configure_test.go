package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestProviderSchemaIsValid(t *testing.T) {
	resp := providerSchema(t)
	requireNoErrors(t, resp.Schema.ValidateImplementation(context.Background()))
	for _, name := range []string{"api_token", "password"} {
		if !resp.Schema.Attributes[name].IsSensitive() {
			t.Errorf("%s is not sensitive", name)
		}
	}
}

func TestProviderHasNoDuplicateTypeNames(t *testing.T) {
	p := New("test")()
	seen := map[string]bool{}
	for _, newDataSource := range p.DataSources(context.Background()) {
		var resp datasource.MetadataResponse
		newDataSource().Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "pbs"}, &resp)
		if seen[resp.TypeName] {
			t.Errorf("data source %s is registered twice", resp.TypeName)
		}
		seen[resp.TypeName] = true
	}
	if !seen["pbs_version"] || !seen["pbs_fingerprint"] {
		t.Fatalf("data sources = %v", seen)
	}

	seen = map[string]bool{}
	for _, newResource := range p.Resources(context.Background()) {
		var resp resource.MetadataResponse
		newResource().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "pbs"}, &resp)
		if seen[resp.TypeName] {
			t.Errorf("resource %s is registered twice", resp.TypeName)
		}
		seen[resp.TypeName] = true
	}
	if !seen["pbs_user"] || !seen["pbs_api_token"] || !seen["pbs_acl"] {
		t.Fatalf("resources = %v", seen)
	}
}

// settingsFor runs settings for a provider block, with only the given
// environment variables set.
func settingsFor(t *testing.T, config map[string]any, env map[string]string) (providerSettings, diag.Diagnostics) {
	t.Helper()
	clearPBSEnv(t)
	for name, value := range env {
		t.Setenv(name, value)
	}
	s := providerSchema(t).Schema
	var model providerModel
	raw := providerConfigValue(t, config)
	var diags diag.Diagnostics
	diags.Append(tfsdk.Config{Schema: s, Raw: raw}.Get(context.Background(), &model)...)
	requireNoErrors(t, diags)
	return model.settings(&diags), diags
}

func TestSettingsFromConfiguration(t *testing.T) {
	s, diags := settingsFor(t, map[string]any{
		"endpoint":             "https://pbs.example.com:8007",
		"api_token":            fakeAPIToken,
		"tls_cert_fingerprint": "AA:" + strings.Repeat("bb:", 30) + "CC",
		"node":                 "pbs1",
		"request_timeout":      "45s",
		"task_timeout":         "1h",
	}, map[string]string{envEndpoint: "https://ignored.test", envNode: "ignored"})
	requireNoErrors(t, diags)
	if s.endpoint != "https://pbs.example.com:8007" || s.apiToken != fakeAPIToken || s.node != "pbs1" ||
		s.timeout != 45*time.Second || s.taskTimeout != time.Hour || s.certFingerprint != "aa"+strings.Repeat("bb", 30)+"cc" {
		t.Fatalf("settings = %+v", s)
	}
}

func TestSettingsFromEnvironment(t *testing.T) {
	s, diags := settingsFor(t, map[string]any{}, map[string]string{
		envEndpoint:           "https://pbs.example.com:8007",
		envUsername:           "root@pam",
		envPassword:           "secret",
		envInsecureSkipVerify: "true",
		envTaskTimeout:        "5m",
	})
	requireNoErrors(t, diags)
	if s.username != "root@pam" || s.password != "secret" || !s.insecureSkipVerify || s.taskTimeout != 5*time.Minute ||
		s.timeout != 30*time.Second || s.node != "" {
		t.Fatalf("settings = %+v", s)
	}
}

// Credentials are taken as a whole: a password in the provider block is not
// in conflict with a token in the environment.
func TestConfiguredCredentialsReplaceTheEnvironments(t *testing.T) {
	s, diags := settingsFor(t, map[string]any{
		"endpoint": "https://pbs.example.com:8007",
		"username": "root@pam",
		"password": "secret",
	}, map[string]string{envAPIToken: fakeAPIToken})
	requireNoErrors(t, diags)
	if s.apiToken != "" || s.username != "root@pam" {
		t.Fatalf("settings = %+v", s)
	}
}

func TestSettingsErrors(t *testing.T) {
	endpoint := map[string]any{"endpoint": "https://pbs.test"}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{"endpoint": "https://pbs.test"}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	tests := map[string]struct {
		config  map[string]any
		env     map[string]string
		wantErr string
	}{
		"no endpoint":            {map[string]any{"api_token": fakeAPIToken}, nil, "Missing PBS endpoint"},
		"no credentials":         {endpoint, nil, "Missing PBS credentials"},
		"token and password":     {with(map[string]any{"api_token": fakeAPIToken, "username": "root@pam", "password": "x"}), nil, "Conflicting PBS credentials"},
		"both in environment":    {endpoint, map[string]string{envAPIToken: fakeAPIToken, envPassword: "x"}, "Conflicting PBS credentials"},
		"password without user":  {with(map[string]any{"password": "x"}), nil, "Missing PBS username"},
		"user without password":  {with(map[string]any{"username": "root@pam"}), nil, "Missing PBS password"},
		"malformed token in env": {endpoint, map[string]string{envAPIToken: "root@pam=secret"}, "Invalid PBS API token"},
		"two TLS settings":       {with(map[string]any{"api_token": fakeAPIToken, "insecure_skip_verify": true, "ca_cert_file": "/ca.pem"}), nil, "Conflicting TLS settings"},
		"TLS conflict with env":  {with(map[string]any{"api_token": fakeAPIToken, "insecure_skip_verify": true}), map[string]string{envCAFile: "/ca.pem"}, envCAFile},
		"bad insecure env":       {with(map[string]any{"api_token": fakeAPIToken}), map[string]string{envInsecureSkipVerify: "yes please"}, "Invalid " + envInsecureSkipVerify},
		"bad timeout env":        {with(map[string]any{"api_token": fakeAPIToken}), map[string]string{envTaskTimeout: "-1s"}, envTaskTimeout + " must be a positive duration"},
		"bad fingerprint env":    {with(map[string]any{"api_token": fakeAPIToken}), map[string]string{envCertFingerprint: "abc"}, "Invalid TLS certificate fingerprint"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, diags := settingsFor(t, tc.config, tc.env)
			requireErrorContaining(t, diags, tc.wantErr)
			for _, d := range diags {
				if strings.Contains(d.Detail(), fakeTokenSecret) || strings.Contains(d.Detail(), "root@pam=secret") {
					t.Fatalf("a diagnostic quotes the secret: %s", d.Detail())
				}
			}
		})
	}
}

func TestConfigureConnectsWithAToken(t *testing.T) {
	fake := newFakePBS()
	data := fake.configured(t)
	if data.version.String() != "4.2.8" || data.client.AuthID() != fakeTokenID || data.client.Node() != "localhost" {
		t.Fatalf("provider data = %+v", data)
	}
	if got := fake.lastCall(t, "GET /version").header.Get("User-Agent"); got != "terraform-provider-pbs/test" {
		t.Fatalf("User-Agent = %q", got)
	}
}

func TestConfigureConnectsWithAPassword(t *testing.T) {
	fake := newFakePBS()
	clearPBSEnv(t)
	resp := configureProvider(t, &pbsProvider{version: "test", transport: fake}, map[string]any{
		"endpoint": "https://pbs.test:8007",
		"username": fakeUsername,
		"password": fakePassword,
	})
	requireNoErrors(t, resp.Diagnostics)
	requireNoWarnings(t, resp.Diagnostics)
	if fake.count("POST /access/ticket") != 1 {
		t.Fatalf("calls = %v", fake.routes())
	}
}

func TestConfigureWarnsAboutPBS3(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /version", http.StatusOK, `{"data":{"release":"14","repoid":"abc","version":"3.4"}}`)
	clearPBSEnv(t)
	resp := configureProvider(t, &pbsProvider{transport: fake}, map[string]any{"endpoint": "https://pbs.test", "api_token": fakeAPIToken})
	requireNoErrors(t, resp.Diagnostics)
	requireWarningContaining(t, resp.Diagnostics, "reports PBS 3.4.14")
}

func TestConfigureExplainsFailures(t *testing.T) {
	tests := map[string]struct {
		config  map[string]any
		setup   func(*fakePBS)
		wantErr string
	}{
		"wrong token": {
			config:  map[string]any{"api_token": fakeTokenID + ":wrong-secret"},
			wantErr: "PBS rejected the API token \"tfacc@pbs!acc\"",
		},
		"wrong password": {
			config:  map[string]any{"username": fakeUsername, "password": "wrong"},
			wantErr: "rejected the username or password",
		},
		"second factor": {
			config:  map[string]any{"username": fakeUsername, "password": fakePassword},
			setup:   func(f *fakePBS) { f.tfa = true },
			wantErr: "two-factor authentication",
		},
		"not a PBS": {
			config:  map[string]any{"api_token": fakeAPIToken},
			setup:   func(f *fakePBS) { f.handle("GET /version", nil) },
			wantErr: "is not the root address of a Proxmox Backup Server",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			if tc.setup != nil {
				tc.setup(fake)
			}
			clearPBSEnv(t)
			config := map[string]any{"endpoint": "https://pbs.test"}
			for k, v := range tc.config {
				config[k] = v
			}
			resp := configureProvider(t, &pbsProvider{transport: fake}, config)
			requireErrorContaining(t, resp.Diagnostics, "Unable to connect to PBS")
			requireErrorContaining(t, resp.Diagnostics, tc.wantErr)
			if resp.DataSourceData != nil {
				t.Fatal("a failed Configure handed out provider data")
			}
		})
	}
}

func TestConfigureRefusesUnknownSettings(t *testing.T) {
	fake := newFakePBS()
	clearPBSEnv(t)
	resp := configureProvider(t, &pbsProvider{transport: fake}, map[string]any{"endpoint": tfUnknown, "api_token": fakeAPIToken})
	requireAttributeError(t, resp.Diagnostics, "endpoint")
	if len(fake.routes()) != 0 {
		t.Fatalf("Configure called the server: %v", fake.routes())
	}
}

// --- acceptance --------------------------------------------------------------

// A password sign-in, with the test user scripts/bootstrap-test-pbs.sh
// creates, reaches the same server as the token.
func TestAccProviderSignsInWithAPassword(t *testing.T) {
	username, password := os.Getenv(envAccUsername), os.Getenv(envAccPassword)
	if username == "" || password == "" {
		t.Skipf("set %s and %s to test a password sign-in", envAccUsername, envAccPassword)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				Config: fmt.Sprintf(`
provider "pbs" {
  username = %q
  password = %q
}

data "pbs_version" "this" {}
`, username, password),
				Check: acc.TestCheckResourceAttrSet("data.pbs_version.this", "version"),
			},
		},
	})
}
