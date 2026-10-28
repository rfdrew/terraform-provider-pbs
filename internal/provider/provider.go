// Package provider implements the Terraform provider for Proxmox Backup
// Server.
package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Ensure the implementation satisfies the framework interfaces.
var _ provider.Provider = &pbsProvider{}

// Address is the provider's source address in the Terraform Registry.
const Address = "registry.terraform.io/rfdrew/pbs"

// testedPBSVersion names the PBS release this provider is built and verified
// against. Configure warns when the server is older than the oldest supported
// release line, minSupportedMajor.minSupportedMinor.
const (
	testedPBSVersion  = "4.2.8"
	minSupportedMajor = 4
	minSupportedMinor = 0
)

// The environment variables the provider reads.
const (
	envEndpoint           = "PBS_ENDPOINT"
	envAPIToken           = "PBS_API_TOKEN"
	envUsername           = "PBS_USERNAME"
	envPassword           = "PBS_PASSWORD"
	envCertFingerprint    = "PBS_TLS_FINGERPRINT"
	envCAFile             = "PBS_CA_CERT_FILE"
	envInsecureSkipVerify = "PBS_INSECURE_SKIP_VERIFY"
	envNode               = "PBS_NODE"
	envRequestTimeout     = "PBS_REQUEST_TIMEOUT"
	envTaskTimeout        = "PBS_TASK_TIMEOUT"
)

type pbsProvider struct {
	// version is set at build time and reported to Terraform.
	version string

	// transport replaces the HTTP transport of the configured client. It is
	// nil outside tests, which use it to answer requests in process.
	transport http.RoundTripper
}

// New returns a provider factory for the given version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &pbsProvider{version: version}
	}
}

// providerData is what Configure hands to resources and data sources: the
// client, and the server's version, which decides whether fields newer than
// PBS 4.0 can be used.
type providerData struct {
	client  *pbsclient.Client
	version pbsclient.Version
}

type providerModel struct {
	Endpoint           types.String `tfsdk:"endpoint"`
	APIToken           types.String `tfsdk:"api_token"`
	Username           types.String `tfsdk:"username"`
	Password           types.String `tfsdk:"password"`
	TLSCertFingerprint types.String `tfsdk:"tls_cert_fingerprint"`
	CACertFile         types.String `tfsdk:"ca_cert_file"`
	InsecureSkipVerify types.Bool   `tfsdk:"insecure_skip_verify"`
	Node               types.String `tfsdk:"node"`
	RequestTimeout     types.String `tfsdk:"request_timeout"`
	TaskTimeout        types.String `tfsdk:"task_timeout"`
}

func (p *pbsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pbs"
	resp.Version = p.version
}

func (p *pbsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the configuration of a [Proxmox Backup Server](https://www.proxmox.com/en/products/proxmox-backup-server/overview) " +
			"(PBS) through its REST API. Built and verified against PBS " + testedPBSVersion + "; PBS 4.0 and " +
			"newer are supported.\n\n" +
			"The provider signs in either with an API token (`api_token`) or with a username and password. A " +
			"token is the usual choice; note that a token has no privileges of its own, so it needs ACL entries " +
			"of its own, besides those of its user. A few calls are closed to API tokens — changing a user's " +
			"password, creating a network interface — and the resources that make them say so.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Root URL of the server, e.g. `https://pbs.example.com:8007`: the address " +
					"of its web interface, or the one a reverse proxy serves it under. Required, here or in the " +
					"environment. May also be set with the `" + envEndpoint + "` environment variable.",
				Validators: []validator.String{httpsURLValidator()},
			},
			"api_token": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "API token to sign in with, as PBS shows it when the token is created: " +
					"`<user>@<realm>!<token name>:<secret>`. Conflicts with `username` and `password`. May also be " +
					"set with the `" + envAPIToken + "` environment variable.",
				Validators: []validator.String{apiTokenValidator{}},
			},
			"username": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "User to sign in as, with its realm: `root@pam`, `admin@pbs`. Needs " +
					"`password`; conflicts with `api_token`. A user with two-factor authentication cannot sign in " +
					"this way. May also be set with the `" + envUsername + "` environment variable.",
				Validators: []validator.String{stringvalidator.RegexMatches(userIDPattern, "must be a user ID such as root@pam or admin@pbs")},
			},
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "Password of `username`. May also be set with the `" + envPassword +
					"` environment variable.",
				Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"tls_cert_fingerprint": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "SHA-256 fingerprint of the server's TLS certificate, to trust that one " +
					"certificate instead of verifying it against certificate authorities; the host name is then " +
					"not checked. PBS shows it on its dashboard (\"Show Fingerprint\") and with " +
					"`proxmox-backup-manager cert info`: 64 hexadecimal digits in either case, optionally " +
					"separated by colons. Conflicts with `ca_cert_file` and `insecure_skip_verify`. May also be " +
					"set with the `" + envCertFingerprint + "` environment variable.",
				Validators: []validator.String{certFingerprintValidator()},
			},
			"ca_cert_file": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Path to a PEM file of CA certificates to verify the server's certificate " +
					"with, instead of the system's trusted roots. The host name in `endpoint` must then be one " +
					"of the names in the certificate. Conflicts with `tls_cert_fingerprint` and " +
					"`insecure_skip_verify`. May also be set with the `" + envCAFile + "` environment variable.",
				Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"insecure_skip_verify": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Skip verification of the server's TLS certificate. Defaults to `false`. " +
					"Prefer `tls_cert_fingerprint`, which trusts exactly one certificate. Conflicts with " +
					"`tls_cert_fingerprint` and `ca_cert_file`. May also be set with the `" +
					envInsecureSkipVerify + "` environment variable.",
			},
			"node": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Name of the node in `/nodes/{node}` API paths. Defaults to `localhost`, " +
					"which every PBS answers to. May also be set with the `" + envNode + "` environment variable.",
				Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"request_timeout": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Time limit for each HTTP request to the server, as a Go duration such as " +
					"`30s` or `2m`. Defaults to `30s`. PBS finishes a request even when the provider has stopped " +
					"waiting for it, so a write that timed out may still have taken effect. May also be set with " +
					"the `" + envRequestTimeout + "` environment variable.",
				Validators: []validator.String{positiveDurationValidator()},
			},
			"task_timeout": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Time limit for waiting on a PBS worker task, such as creating or " +
					"deleting a datastore, as a Go duration. Defaults to `30m`. The task goes on when the " +
					"provider stops waiting. May also be set with the `" + envTaskTimeout + "` environment variable.",
				Validators: []validator.String{positiveDurationValidator()},
			},
		},
	}
}

// providerSettings is the configuration after the environment has filled in
// what the provider block leaves out.
type providerSettings struct {
	endpoint           string
	apiToken           string
	username           string
	password           string
	certFingerprint    string
	caFile             string
	insecureSkipVerify bool
	node               string
	timeout            time.Duration
	taskTimeout        time.Duration
}

// settingSource names where a setting came from, for error messages: the
// attribute, or the environment variable that stood in for it.
func settingSource(configured attr.Value, attribute, env string) string {
	if configured.IsNull() {
		return env
	}
	return "`" + attribute + "`"
}

// addSettingError reports an invalid setting, pinned to its attribute when the
// value came from the configuration rather than the environment.
func addSettingError(diags *diag.Diagnostics, configured attr.Value, attribute, summary, detail string) {
	if configured.IsNull() {
		diags.AddError(summary, detail)
		return
	}
	diags.AddAttributeError(path.Root(attribute), summary, detail)
}

// stringSetting is the configured value of a string attribute or, when the
// configuration leaves it out, the environment variable's. An empty variable
// counts as unset.
func stringSetting(configured types.String, env string) string {
	if !configured.IsNull() {
		return configured.ValueString()
	}
	return os.Getenv(env)
}

// settings merges the configuration with the environment and validates the
// result. Explicit configuration wins over the environment. The credentials
// are taken as a whole: when the configuration sets any of api_token,
// username and password, the environment's credentials are ignored, so that
// a token in the environment does not conflict with a password in the
// configuration.
func (m providerModel) settings(diags *diag.Diagnostics) providerSettings {
	s := providerSettings{
		endpoint:        stringSetting(m.Endpoint, envEndpoint),
		certFingerprint: stringSetting(m.TLSCertFingerprint, envCertFingerprint),
		caFile:          stringSetting(m.CACertFile, envCAFile),
		node:            stringSetting(m.Node, envNode),
		timeout:         pbsclient.DefaultTimeout,
		taskTimeout:     pbsclient.DefaultTaskTimeout,
	}
	credentialsConfigured := !m.APIToken.IsNull() || !m.Username.IsNull() || !m.Password.IsNull()
	if credentialsConfigured {
		s.apiToken, s.username, s.password = m.APIToken.ValueString(), m.Username.ValueString(), m.Password.ValueString()
	} else {
		s.apiToken, s.username, s.password = os.Getenv(envAPIToken), os.Getenv(envUsername), os.Getenv(envPassword)
	}

	if !m.InsecureSkipVerify.IsNull() {
		s.insecureSkipVerify = m.InsecureSkipVerify.ValueBool()
	} else if env := os.Getenv(envInsecureSkipVerify); env != "" {
		parsed, err := strconv.ParseBool(env)
		if err != nil {
			diags.AddError(
				"Invalid "+envInsecureSkipVerify,
				"Expected a boolean such as \"true\" or \"false\", got "+strconv.Quote(env)+".",
			)
		}
		s.insecureSkipVerify = parsed
	}

	for _, d := range []struct {
		configured types.String
		attribute  string
		env        string
		into       *time.Duration
	}{
		{m.RequestTimeout, "request_timeout", envRequestTimeout, &s.timeout},
		{m.TaskTimeout, "task_timeout", envTaskTimeout, &s.taskTimeout},
	} {
		if value := stringSetting(d.configured, d.env); value != "" {
			parsed, err := parsePositiveDuration(value)
			if err != nil {
				addSettingError(diags, d.configured, d.attribute, "Invalid "+strings.ReplaceAll(d.attribute, "_", " "),
					settingSource(d.configured, d.attribute, d.env)+" "+err.Error()+".")
			}
			*d.into = parsed
		}
	}

	if s.endpoint == "" {
		diags.AddAttributeError(
			path.Root("endpoint"),
			"Missing PBS endpoint",
			"Set the provider's `endpoint` attribute or the "+envEndpoint+" environment variable to the root URL "+
				"of the Proxmox Backup Server, e.g. https://pbs.example.com:8007.",
		)
	}

	credentialSource := "the provider block"
	if !credentialsConfigured {
		credentialSource = "the environment (" + envAPIToken + ", " + envUsername + ", " + envPassword + ")"
	}
	switch {
	case s.apiToken != "" && (s.username != "" || s.password != ""):
		diags.AddError(
			"Conflicting PBS credentials",
			"Both an API token and a username or password are set in "+credentialSource+". Set either "+
				"`api_token`, or `username` and `password`.",
		)
	case s.apiToken != "":
		if _, _, err := pbsclient.SplitAPIToken(s.apiToken); err != nil {
			addSettingError(diags, m.APIToken, "api_token", "Invalid PBS API token",
				settingSource(m.APIToken, "api_token", envAPIToken)+": "+err.Error()+".")
		}
	case s.username == "" && s.password == "":
		diags.AddError(
			"Missing PBS credentials",
			"Set the provider's `api_token` attribute or the "+envAPIToken+" environment variable to an API "+
				"token, as PBS shows it when the token is created (`<user>@<realm>!<token name>:<secret>`), or "+
				"set `username` and `password` ("+envUsername+" and "+envPassword+").",
		)
	case s.username == "":
		diags.AddAttributeError(path.Root("username"), "Missing PBS username",
			"A password is set in "+credentialSource+", but no username: set `username` or "+envUsername+
				" to the user it belongs to, such as root@pam.")
	case s.password == "":
		diags.AddAttributeError(path.Root("password"), "Missing PBS password",
			"A username is set in "+credentialSource+", but no password: set `password` or "+envPassword+".")
	}

	if s.certFingerprint != "" {
		normalised, err := pbsclient.NormaliseFingerprint(s.certFingerprint)
		if err != nil {
			addSettingError(diags, m.TLSCertFingerprint, "tls_cert_fingerprint", "Invalid TLS certificate fingerprint",
				settingSource(m.TLSCertFingerprint, "tls_cert_fingerprint", envCertFingerprint)+" must be the "+
					"SHA-256 fingerprint of a certificate: 64 hexadecimal digits, optionally separated by colons.")
		}
		s.certFingerprint = normalised
	}

	var tlsSettings []string
	if s.certFingerprint != "" {
		tlsSettings = append(tlsSettings, settingSource(m.TLSCertFingerprint, "tls_cert_fingerprint", envCertFingerprint))
	}
	if s.caFile != "" {
		tlsSettings = append(tlsSettings, settingSource(m.CACertFile, "ca_cert_file", envCAFile))
	}
	if s.insecureSkipVerify {
		tlsSettings = append(tlsSettings, settingSource(m.InsecureSkipVerify, "insecure_skip_verify", envInsecureSkipVerify))
	}
	if len(tlsSettings) > 1 {
		diags.AddError(
			"Conflicting TLS settings",
			"tls_cert_fingerprint, ca_cert_file and insecure_skip_verify each decide on their own how the "+
				"server's certificate is trusted, so only one of them may be set, counting the "+
				envCertFingerprint+", "+envCAFile+" and "+envInsecureSkipVerify+" environment variables. "+
				"Set: "+strings.Join(tlsSettings, ", ")+".",
		)
	}

	return s
}

// clientOptions turns settings into the client's options.
func (s providerSettings) clientOptions() pbsclient.Options {
	return pbsclient.Options{
		Endpoint:           s.endpoint,
		APIToken:           s.apiToken,
		Username:           s.username,
		Password:           s.password,
		CertFingerprint:    s.certFingerprint,
		CAFile:             s.caFile,
		InsecureSkipVerify: s.insecureSkipVerify,
		Node:               s.node,
		Timeout:            s.timeout,
		TaskTimeout:        s.taskTimeout,
	}
}

func (p *pbsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// A value that is only known after apply cannot be used to connect, and
	// silently falling back to the environment would connect somewhere else.
	for _, setting := range []struct {
		value     attr.Value
		attribute string
		env       string
	}{
		{config.Endpoint, "endpoint", envEndpoint},
		{config.APIToken, "api_token", envAPIToken},
		{config.Username, "username", envUsername},
		{config.Password, "password", envPassword},
		{config.TLSCertFingerprint, "tls_cert_fingerprint", envCertFingerprint},
		{config.CACertFile, "ca_cert_file", envCAFile},
		{config.InsecureSkipVerify, "insecure_skip_verify", envInsecureSkipVerify},
		{config.Node, "node", envNode},
		{config.RequestTimeout, "request_timeout", envRequestTimeout},
		{config.TaskTimeout, "task_timeout", envTaskTimeout},
	} {
		if setting.value.IsUnknown() {
			resp.Diagnostics.AddAttributeError(
				path.Root(setting.attribute),
				"Unknown PBS provider setting",
				"The provider cannot connect to PBS while `"+setting.attribute+"` is unknown, as it is when it "+
					"refers to something that is only known after apply. Set it to a value known at plan time, "+
					"use the "+setting.env+" environment variable instead, or apply what it depends on first "+
					"with -target.",
			)
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	settings := config.settings(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	opts := settings.clientOptions()
	opts.UserAgent = "terraform-provider-pbs/" + p.version
	opts.Transport = p.transport
	client, err := pbsclient.New(opts)
	if err != nil {
		resp.Diagnostics.AddError("Invalid PBS provider configuration", err.Error())
		return
	}

	// GET /version is open to every authenticated user, a token without any
	// ACL included, so it checks the endpoint, the TLS settings and the
	// credentials at once: failing here produces one clear error instead of
	// the same failure repeated across every resource.
	version, err := client.ServerVersion(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to connect to PBS", connectErrorDetail(client, err))
		return
	}
	tflog.Info(ctx, "connected to PBS", map[string]any{"endpoint": client.BaseURL(), "version": version.String(), "auth_id": client.AuthID()})

	if !version.AtLeast(minSupportedMajor, minSupportedMinor, 0) {
		resp.Diagnostics.AddWarning(
			"Unsupported PBS version",
			"The server at "+client.BaseURL()+" reports PBS "+version.String()+". This provider supports PBS "+
				fmt.Sprintf("%d.%d", minSupportedMajor, minSupportedMinor)+" and newer and is verified against "+
				testedPBSVersion+"; PBS 3 reached its end of life in August 2026. Resources may fail or behave "+
				"differently with this release.",
		)
	}

	data := &providerData{client: client, version: version}
	resp.DataSourceData = data
	resp.ResourceData = data
	resp.EphemeralResourceData = data
}

// connectErrorDetail explains why the first call failed.
func connectErrorDetail(client *pbsclient.Client, err error) string {
	var untrusted *pbsclient.UntrustedCertificateError
	switch {
	case errors.As(err, &untrusted) && client.PinsCertificate() && untrusted.Presented() != "":
		return "The server presents a certificate with SHA-256 fingerprint " +
			pbsclient.FormatFingerprint(untrusted.Presented()) + ", not the one tls_cert_fingerprint names. PBS " +
			"serves a new certificate after pbs_node_certificate ordered one, after a renewal, or after its " +
			"certificate was deleted, which makes PBS generate a new self-signed one. For a certificate of a public " +
			"CA, such as Let's Encrypt, remove tls_cert_fingerprint (and PBS_TLS_FINGERPRINT), so that the provider " +
			"verifies it against the system's CAs, with endpoint naming one of its domains. For a self-signed one, " +
			"set tls_cert_fingerprint to the new fingerprint — after comparing it with `proxmox-backup-manager cert " +
			"info` on the host. " + err.Error()
	case errors.As(err, &untrusted) && untrusted.Presented() != "":
		return "The server's certificate, with SHA-256 fingerprint " + pbsclient.FormatFingerprint(untrusted.Presented()) +
			", does not verify for " + client.EndpointHost() + ". If PBS serves a self-signed certificate — such as the " +
			"one it generates after its certificate was deleted —, set tls_cert_fingerprint to its fingerprint, after " +
			"comparing it with `proxmox-backup-manager cert info` on the host; if it serves one of a public CA, set " +
			"endpoint to one of the certificate's domains. " + err.Error()
	case errors.Is(err, pbsclient.ErrSecondFactor):
		return "PBS accepted the password of " + strconv.Quote(client.AuthID()) + ", but the user has " +
			"two-factor authentication enabled, which the provider cannot complete. Create an API token for the " +
			"user and set `api_token` instead. " + err.Error()
	case pbsclient.IsUnauthorized(err) && client.UsesAPIToken():
		return "PBS rejected the API token " + strconv.Quote(client.AuthID()) + " (HTTP 401). Check that the " +
			"token exists, is enabled and has not expired, that its user is enabled, and that the secret is " +
			"the one PBS showed when the token was created or last regenerated. " + err.Error()
	case pbsclient.IsUnauthorized(err):
		return "PBS rejected the username or password of " + strconv.Quote(client.AuthID()) + " (HTTP 401). " +
			"Check that the username includes its realm, such as root@pam or admin@pbs. " + err.Error()
	case pbsclient.IsEndpointMissing(err):
		return "GET " + client.BaseURL() + "/api2/json/version answered 404, so `endpoint` is not the root " +
			"address of a Proxmox Backup Server. " + err.Error()
	}
	return fmt.Sprintf("Could not reach the Proxmox Backup Server at %s: %s", client.BaseURL(), err)
}

func (p *pbsProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewUserResource,
		NewAPITokenResource,
		NewACLResource,
		NewDatastoreResource,
		NewPruneJobResource,
		NewVerifyJobResource,
		NewSMTPEndpointResource,
		NewSendmailEndpointResource,
		NewGotifyEndpointResource,
		NewWebhookEndpointResource,
		NewNotificationMatcherResource,
		NewACMEAccountResource,
		NewACMEPluginResource,
		NewNodeACMEResource,
		NewNodeCertificateResource,
	}
}

func (p *pbsProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewVersionDataSource,
		NewFingerprintDataSource,
		NewUserDataSource,
		NewUsersDataSource,
		NewAPITokensDataSource,
		NewACLDataSource,
		NewRolesDataSource,
		NewPermissionsDataSource,
		NewACMEToSDataSource,
		NewNotificationTargetsDataSource,
		NewNotificationMatcherFieldsDataSource,
	}
}

// providerDataFrom pulls the configured client out of the framework's
// provider data, guarding against the nil that appears during early
// validation walks.
func providerDataFrom(raw any, diags interface {
	AddError(summary, detail string)
}) *providerData {
	if raw == nil {
		return nil
	}
	data, ok := raw.(*providerData)
	if !ok {
		diags.AddError(
			"Unexpected provider data",
			"The provider was configured with an unexpected internal type. This is a bug in the provider.",
		)
		return nil
	}
	return data
}

// apiErrorDetail explains a failed API call, with advice for the failures
// that depend on how the provider signs in rather than on the call.
func apiErrorDetail(client *pbsclient.Client, privilege string, err error) string {
	if pbsclient.IsForbidden(err) {
		detail := strconv.Quote(client.AuthID()) + " lacks the privilege for this call"
		if privilege != "" {
			detail += " (" + privilege + ")"
		}
		detail += "."
		if client.UsesAPIToken() {
			detail += " An API token has no privileges of its own: besides its user's ACL entries, it needs " +
				"entries for the token ID itself."
		}
		return detail + " " + err.Error()
	}
	return err.Error()
}
