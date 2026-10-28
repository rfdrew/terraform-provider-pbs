package pbsclient

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const registerUPID = "UPID:localhost:00000A1B:00001C2D:00000005:6AE11CDF:acme-register:default:tfacc@pbs!acc:"

func TestACMEAccountCalls(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	ctx := context.Background()

	fake.reply("GET /config/acme/account/default", http.StatusOK, `{"data":{
		"account":{"contact":["mailto:ops@example.org","mailto:admin@example.org"],"status":"valid","orders":"https://ca/orders"},
		"directory":"https://acme-staging-v02.api.letsencrypt.org/directory",
		"location":"https://ca/acct/1","tos":"https://ca/tos.pdf"}}`)
	account, err := c.GetACMEAccount(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	if account.Directory != ACMEStagingDirectory || account.Location != "https://ca/acct/1" || account.ToS != "https://ca/tos.pdf" ||
		account.Account.Status != "valid" || strings.Join(account.Emails(), ",") != "ops@example.org,admin@example.org" {
		t.Fatalf("GetACMEAccount() = %+v", account)
	}

	fake.reply("GET /config/acme/account/gone", http.StatusBadRequest, "acme account 'gone' does not exist")
	if _, err := c.GetACMEAccount(ctx, "gone"); !IsNotFound(err) {
		t.Fatalf("GetACMEAccount() error = %v, want not found", err)
	}

	// Registering, updating and deactivating answer a task.
	fake.reply("POST /config/acme/account", http.StatusOK, `{"data":"`+registerUPID+`"}`)
	fake.reply("PUT /config/acme/account/default", http.StatusOK, `{"data":"`+registerUPID+`"}`)
	fake.reply("DELETE /config/acme/account/default", http.StatusOK, `{"data":"`+registerUPID+`"}`)
	fake.replies("GET /nodes/localhost/tasks/"+registerUPID+"/status", http.StatusOK,
		`{"data":{"status":"stopped","exitstatus":"OK"}}`,
		`{"data":{"status":"stopped","exitstatus":"OK"}}`,
		`{"data":{"status":"stopped","exitstatus":"OK"}}`,
		`{"data":{"status":"stopped","exitstatus":"OK"}}`,
		`{"data":{"status":"stopped","exitstatus":"Error: unauthorized: account is not valid"}}`)
	params := url.Values{"name": {"default"}, "contact": {"ops@example.org"}, "tos_url": {"https://ca/tos.pdf"}}
	if err := c.RegisterACMEAccount(ctx, params); err != nil {
		t.Fatalf("RegisterACMEAccount() error = %v", err)
	}
	if got := fake.lastCall(t, "POST /config/acme/account").form; got.Get("tos_url") != "https://ca/tos.pdf" || got.Get("contact") != "ops@example.org" {
		t.Fatalf("POST form = %v", got)
	}
	if err := c.UpdateACMEAccountContact(ctx, "default", "new@example.org"); err != nil {
		t.Fatalf("UpdateACMEAccountContact() error = %v", err)
	}
	if got := fake.lastCall(t, "PUT /config/acme/account/default").form.Get("contact"); got != "new@example.org" {
		t.Fatalf("PUT contact = %q", got)
	}
	if err := c.DeactivateACMEAccount(ctx, "default", false); err != nil {
		t.Fatalf("DeactivateACMEAccount() error = %v", err)
	}
	if query := fake.lastCall(t, "DELETE /config/acme/account/default").query; query.Has("force") {
		t.Fatalf("DELETE query = %v, want no force", query)
	}
	if err := c.DeactivateACMEAccount(ctx, "default", true); err != nil {
		t.Fatalf("DeactivateACMEAccount(force) error = %v", err)
	}
	if query := fake.lastCall(t, "DELETE /config/acme/account/default").query; query.Get("force") != "true" {
		t.Fatalf("DELETE query = %v, want force", query)
	}
	var taskErr *TaskError
	if err := c.UpdateACMEAccountContact(ctx, "default", "x@example.org"); !errors.As(err, &taskErr) {
		t.Fatalf("UpdateACMEAccountContact() error = %v, want the task's", err)
	}

	fake.reply("POST /config/acme/account", http.StatusBadRequest, "account default already exists")
	if err := c.RegisterACMEAccount(ctx, params); !IsAlreadyExists(err) {
		t.Fatalf("RegisterACMEAccount() error = %v, want already exists", err)
	}
	fake.reply("PUT /config/acme/account/default", http.StatusForbidden, "permission check failed")
	if err := c.UpdateACMEAccountContact(ctx, "default", "x@example.org"); !IsForbidden(err) {
		t.Fatalf("UpdateACMEAccountContact() error = %v", err)
	}
	fake.reply("DELETE /config/acme/account/default", http.StatusForbidden, "permission check failed")
	if err := c.DeactivateACMEAccount(ctx, "default", false); !IsForbidden(err) {
		t.Fatalf("DeactivateACMEAccount() error = %v", err)
	}
}

func TestACMETermsOfService(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	ctx := context.Background()

	fake.reply("GET /config/acme/tos", http.StatusOK, `{"data":"https://ca/tos.pdf"}`)
	if tos, err := c.ACMETermsOfService(ctx, ""); err != nil || tos != "https://ca/tos.pdf" {
		t.Fatalf("ACMETermsOfService() = %q, %v", tos, err)
	}
	if query := fake.lastCall(t, "GET /config/acme/tos").query; query.Has("directory") {
		t.Fatalf("query = %v, want PBS's default directory", query)
	}
	fake.reply("GET /config/acme/tos", http.StatusOK, `{"data":null}`)
	if tos, err := c.ACMETermsOfService(ctx, "https://ca.test/dir"); err != nil || tos != "" {
		t.Fatalf("ACMETermsOfService() = %q, %v, want none", tos, err)
	}
	if got := fake.lastCall(t, "GET /config/acme/tos").query.Get("directory"); got != "https://ca.test/dir" {
		t.Fatalf("directory = %q", got)
	}
	fake.reply("GET /config/acme/tos", http.StatusBadRequest, "failed to connect")
	if _, err := c.ACMETermsOfService(ctx, ""); err == nil {
		t.Fatal("ACMETermsOfService() accepted an error")
	}
}

func TestACMEPluginCalls(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	ctx := context.Background()

	fake.reply("GET /config/acme/plugins/cloudflare", http.StatusOK,
		`{"data":{"plugin":"cloudflare","type":"dns","api":"cf","data":"CF_Token=secret\nCF_Zone_ID=zone\n","validation-delay":120},"digest":"abc"}`)
	plugin, digest, err := c.GetACMEPlugin(ctx, "cloudflare")
	if err != nil || digest != "abc" || plugin.API != "cf" || plugin.Type != DNSACMEPluginType || *plugin.ValidationDelay != 120 || plugin.Disable != nil {
		t.Fatalf("GetACMEPlugin() = %+v, %q, %v", plugin, digest, err)
	}
	fake.reply("GET /config/acme/plugins/gone", http.StatusNotFound, "no such plugin")
	if _, _, err := c.GetACMEPlugin(ctx, "gone"); !IsNotFound(err) {
		t.Fatalf("GetACMEPlugin() error = %v, want not found", err)
	}

	settings := map[string]string{"CF_Token": "s3cr3t-token", "CF_Zone_ID": "zone"}
	params := url.Values{"id": {"cloudflare"}, "type": {"dns"}, "api": {"cf"}, "data": {EncodeACMEPluginData(settings)}}
	fake.reply("POST /config/acme/plugins", http.StatusBadRequest, "parameter verification failed - 'data': cannot use s3cr3t-token or "+params.Get("data"))
	err = c.CreateACMEPlugin(ctx, params, settings)
	if err == nil || strings.Contains(err.Error(), "s3cr3t-token") || strings.Contains(err.Error(), params.Get("data")) {
		t.Fatalf("CreateACMEPlugin() error = %v, want the settings redacted", err)
	}
	fake.reply("PUT /config/acme/plugins/cloudflare", http.StatusBadRequest, "bad value s3cr3t-token")
	if err := c.UpdateACMEPlugin(ctx, "cloudflare", params, settings); err == nil || strings.Contains(err.Error(), "s3cr3t-token") {
		t.Fatalf("UpdateACMEPlugin() error = %v, want the settings redacted", err)
	}
	fake.reply("POST /config/acme/plugins", http.StatusOK, `{"data":null}`)
	fake.reply("PUT /config/acme/plugins/cloudflare", http.StatusOK, `{"data":null}`)
	fake.reply("DELETE /config/acme/plugins/cloudflare", http.StatusOK, `{"data":null}`)
	if err := c.CreateACMEPlugin(ctx, params, settings); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateACMEPlugin(ctx, "cloudflare", url.Values{"validation-delay": {"60"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteACMEPlugin(ctx, "cloudflare"); err != nil {
		t.Fatal(err)
	}
}

func TestACMEPluginData(t *testing.T) {
	settings := map[string]string{"CF_Zone_ID": "zone", "CF_Token": "a=b==", "EMPTY": ""}
	encoded := EncodeACMEPluginData(settings)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted, so that a request is the same every run.
	if string(decoded) != "CF_Token=a=b==\nCF_Zone_ID=zone\nEMPTY=" {
		t.Fatalf("decoded data = %q", decoded)
	}
	if got := ParseACMEPluginData(string(decoded)); !maps.Equal(got, settings) {
		t.Fatalf("ParseACMEPluginData() = %v, want %v", got, settings)
	}
	// As the web interface writes it: a trailing newline, CRLF, lines that
	// are no setting.
	got := ParseACMEPluginData("CF_Token=x\r\n\nnot a setting\n=orphan\nCF_Token=y\n")
	if !maps.Equal(got, map[string]string{"CF_Token": "y"}) {
		t.Fatalf("ParseACMEPluginData() = %v", got)
	}
	if got := FormatACMEPluginData(nil); got != "" {
		t.Fatalf("FormatACMEPluginData(nil) = %q", got)
	}
}

func TestNodeConfig(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	ctx := context.Background()

	fake.reply("GET /nodes/pbs1/config", http.StatusOK,
		`{"data":{"acme":"account=prod","acmedomain0":"pbs.example.org,plugin=cloudflare","acmedomain3":"domain=other.example.org,alias=validation.example.net","description":"x"},"digest":"d1"}`)
	config, digest, err := c.GetNodeConfig(ctx, "pbs1")
	if err != nil || digest != "d1" {
		t.Fatalf("GetNodeConfig() = %+v, %q, %v", config, digest, err)
	}
	if account, err := config.ACMEAccountName(); err != nil || account != "prod" {
		t.Fatalf("ACMEAccountName() = %q, %v", account, err)
	}
	if config.ACMEDomains[1] != "" || config.ACMEDomains[3] == "" {
		t.Fatalf("ACMEDomains = %q", config.ACMEDomains)
	}
	domain, err := ParseACMEDomain(config.ACMEDomains[0])
	if err != nil || domain != (ACMEDomain{Domain: "pbs.example.org", Plugin: "cloudflare"}) {
		t.Fatalf("ParseACMEDomain() = %+v, %v", domain, err)
	}
	domain, err = ParseACMEDomain(config.ACMEDomains[3])
	if err != nil || domain != (ACMEDomain{Domain: "other.example.org", Alias: "validation.example.net"}) {
		t.Fatalf("ParseACMEDomain() = %+v, %v", domain, err)
	}
	if got := domain.Format(); got != "other.example.org,alias=validation.example.net" {
		t.Fatalf("Format() = %q", got)
	}
	if _, err := ParseACMEDomain(`"unterminated`); err == nil {
		t.Fatal("ParseACMEDomain() accepted a broken property string")
	}
	if account, err := (NodeConfig{}).ACMEAccountName(); err != nil || account != "default" {
		t.Fatalf("ACMEAccountName() without acme = %q, %v, want PBS's default", account, err)
	}
	if _, err := (NodeConfig{ACME: "prod"}).ACMEAccountName(); err == nil {
		t.Fatal("ACMEAccountName() accepted a value without a key")
	}
	if got := ACMEDomainProperty(4); got != "acmedomain4" {
		t.Fatalf("ACMEDomainProperty(4) = %q", got)
	}

	fake.reply("PUT /nodes/pbs1/config", http.StatusOK, `{"data":null}`)
	params := url.Values{"acme": {"account=prod"}, DigestParam: {"d1"}}
	AddDelete(params, "acmedomain3")
	if err := c.UpdateNodeConfig(ctx, "pbs1", params); err != nil {
		t.Fatal(err)
	}
	if form := fake.lastCall(t, "PUT /nodes/pbs1/config").form; form.Get("delete") != "acmedomain3" || form.Get("digest") != "d1" {
		t.Fatalf("PUT form = %v", form)
	}
	fake.reply("GET /nodes/pbs1/config", http.StatusForbidden, "permission check failed")
	if _, _, err := c.GetNodeConfig(ctx, "pbs1"); !IsForbidden(err) {
		t.Fatalf("GetNodeConfig() error = %v", err)
	}
}

func TestCertificateCallsOnOtherNodes(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	ctx := context.Background()
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK,
		`{"data":[{"filename":"proxy.pem","fingerprint":"aa","subject":"CN=a","issuer":"CN=b","san":["pbs.example.org"],"pem":"x"}]}`)
	cert, err := c.ProxyCertificate(ctx)
	if err != nil || cert.SelfSigned() || cert.PEM != "x" {
		t.Fatalf("ProxyCertificate() = %+v, %v", cert, err)
	}
	fake.reply("POST /nodes/pbs1/certificates/acme/certificate", http.StatusForbidden, "permission check failed")
	if err := c.OrderACMECertificate(ctx, "pbs1"); !IsForbidden(err) {
		t.Fatalf("OrderACMECertificate() error = %v", err)
	}
	fake.reply("DELETE /nodes/pbs1/certificates/custom", http.StatusOK, `{"data":null}`)
	if err := c.DeleteCustomCertificate(ctx, "pbs1"); err != nil {
		t.Fatal(err)
	}
}
