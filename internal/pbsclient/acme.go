package pbsclient

import (
	"context"
	"encoding/base64"
	"net/url"
	"sort"
	"strings"
)

// ACME: accounts at a certificate authority, challenge plugins, and the
// node's ACME settings, which say which account orders a certificate for
// which domains. What PBS 4.0 and 4.2 do, read in their source
// (src/api2/config/acme.rs, src/api2/node/config.rs and the proxmox-acme-api
// crate):
//
//   - An account is a file of its own, /etc/proxmox-backup/acme/accounts/
//     <name>, holding the key and what the CA answered at registration;
//     there is no digest. Registering, updating and deactivating one talk to
//     the CA, so all three answer with the UPID of a task — acme-register,
//     acme-update, acme-deactivate — whose exit status carries the CA's
//     error. Only "account 'x' already exists" is refused before the task.
//   - Reading an account answers what PBS stored: the directory URL, the
//     account's URL at the CA (location), the terms of service agreed to,
//     and the CA's account object, whose contact list is what the CA
//     returned, without asking it again. A missing account is 400 "acme
//     account 'x' does not exist", on GET and in the tasks of PUT and
//     DELETE.
//   - Deactivating an account tells the CA, which cannot be undone, and
//     renames the file to _deactivated_<name>_<n>: the name is free again.
//     With force, the file is renamed even when the CA refuses.
//   - Plugins live in /etc/proxmox-backup/acme/plugins.cfg, with a digest.
//     The built-in plugin "standalone" answers HTTP-01 challenges on port 80
//     and always exists: it cannot be created ("ACME plugin ID ... already
//     exists") or updated ("cannot update plugin of type ..."), and deleting
//     it changes nothing. Every other plugin is a DNS plugin: an API of
//     acme.sh, such as cf for Cloudflare, and its settings, "data", which
//     the API takes base64-encoded and returns decoded. A missing plugin is
//     404 "no such plugin".
//   - The node's settings live in node.cfg: "acme", the account as
//     "account=<name>" (missing means the account named "default"), and up
//     to five domains, "acmedomain0" to "acmedomain4", each
//     "<domain>[,alias=<domain>][,plugin=<id>]" (without a plugin, the
//     domain is validated by "standalone"). PBS stores them as given and
//     refuses the same domain twice, in any case.

// DefaultACMEDirectory is the directory PBS uses when none is given: Let's
// Encrypt's production directory. ACMEStagingDirectory is Let's Encrypt's
// staging directory, for trying things out: its certificates are not
// trusted, and its rate limits are far higher.
const (
	DefaultACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	ACMEStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// StandaloneACMEPlugin is the ID of the built-in plugin that answers HTTP-01
// challenges, and the type PBS reports for it; DNSACMEPluginType is the type
// of every other plugin.
const (
	StandaloneACMEPlugin = "standalone"
	DNSACMEPluginType    = "dns"
)

// MaxACMEDomains is how many domains a node's ACME settings hold.
const MaxACMEDomains = 5

// ACMEAccount is an ACME account as PBS reports it.
type ACMEAccount struct {
	// Directory is the URL of the CA's ACME directory.
	Directory string `json:"directory"`
	// Location is the account's URL at the CA.
	Location string `json:"location"`
	// ToS is the URL of the terms of service agreed to, if any.
	ToS string `json:"tos,omitempty"`
	// Account is the CA's account object, as it was last returned.
	Account ACMEAccountData `json:"account"`
}

// ACMEAccountData is the part of the CA's account object PBS reports.
type ACMEAccountData struct {
	// Contact is the contact list, "mailto:" URLs.
	Contact []string `json:"contact,omitempty"`
	// Status is valid, deactivated or revoked.
	Status string `json:"status,omitempty"`
}

// Emails returns the account's contact addresses without "mailto:".
func (a ACMEAccount) Emails() []string {
	var emails []string
	for _, contact := range a.Account.Contact {
		emails = append(emails, strings.TrimPrefix(contact, "mailto:"))
	}
	return emails
}

// GetACMEAccount reads an ACME account.
func (c *Client) GetACMEAccount(ctx context.Context, name string) (ACMEAccount, error) {
	var account ACMEAccount
	_, err := c.Get(ctx, Path("config", "acme", "account", name), nil, &account)
	return account, err
}

// RegisterACMEAccount registers an account at a CA from params — "name",
// "contact" and optionally "directory" and "tos_url" — and waits for the
// task, whose error, such as the CA refusing, is a *TaskError.
func (c *Client) RegisterACMEAccount(ctx context.Context, params url.Values) error {
	env, err := c.Post(ctx, "/config/acme/account", params, nil)
	if err != nil {
		return err
	}
	return c.WaitTaskIn(ctx, env.Data)
}

// UpdateACMEAccountContact has the CA change an account's contact addresses,
// and waits for the task.
func (c *Client) UpdateACMEAccountContact(ctx context.Context, name, contact string) error {
	env, err := c.Put(ctx, Path("config", "acme", "account", name), url.Values{"contact": {contact}}, nil)
	if err != nil {
		return err
	}
	return c.WaitTaskIn(ctx, env.Data)
}

// DeactivateACMEAccount has the CA deactivate an account, for good, and
// waits for the task. With force, PBS forgets the account even when the CA
// refuses.
func (c *Client) DeactivateACMEAccount(ctx context.Context, name string, force bool) error {
	var params url.Values
	if force {
		params = url.Values{"force": {"true"}}
	}
	env, err := c.Delete(ctx, Path("config", "acme", "account", name), params, nil)
	if err != nil {
		return err
	}
	return c.WaitTaskIn(ctx, env.Data)
}

// ACMETermsOfService returns the URL of the terms of service a CA's
// directory advertises, empty when it advertises none. An empty directory is
// PBS's default. PBS asks the CA.
func (c *Client) ACMETermsOfService(ctx context.Context, directory string) (string, error) {
	var params url.Values
	if directory != "" {
		params = url.Values{"directory": {directory}}
	}
	var tos *string
	if _, err := c.Get(ctx, "/config/acme/tos", params, &tos); err != nil {
		return "", err
	}
	if tos == nil {
		return "", nil
	}
	return *tos, nil
}

// ACMEPlugin is an ACME challenge plugin as PBS reports it.
type ACMEPlugin struct {
	ID string `json:"plugin"`
	// Type is "dns", or "standalone" for the built-in plugin.
	Type string `json:"type"`
	// API is the DNS plugin's acme.sh API, such as cf.
	API string `json:"api,omitempty"`
	// Data is the DNS plugin's settings, decoded: KEY=value lines.
	Data string `json:"data,omitempty"`
	// ValidationDelay is unset for the default, 30 seconds.
	ValidationDelay *int64 `json:"validation-delay,omitempty"`
	Disable         *bool  `json:"disable,omitempty"`
}

// GetACMEPlugin reads an ACME plugin and the digest of plugins.cfg.
func (c *Client) GetACMEPlugin(ctx context.Context, id string) (ACMEPlugin, string, error) {
	var plugin ACMEPlugin
	env, err := c.Get(ctx, Path("config", "acme", "plugins", id), nil, &plugin)
	if err != nil {
		return plugin, "", err
	}
	return plugin, env.Digest, nil
}

// CreateACMEPlugin creates a DNS plugin from params, which must hold "id",
// "type" (dns), "api" and "data", encoded with EncodeACMEPluginData. The
// settings are kept out of any error.
func (c *Client) CreateACMEPlugin(ctx context.Context, params url.Values, settings map[string]string) error {
	_, err := c.Post(ctx, "/config/acme/plugins", params, nil)
	return redactAPIError(err, pluginSecrets(params, settings)...)
}

// UpdateACMEPlugin changes the properties params carries, and deletes those
// named in its delete parameter. The settings are kept out of any error.
func (c *Client) UpdateACMEPlugin(ctx context.Context, id string, params url.Values, settings map[string]string) error {
	_, err := c.Put(ctx, Path("config", "acme", "plugins", id), params, nil)
	return redactAPIError(err, pluginSecrets(params, settings)...)
}

// DeleteACMEPlugin deletes an ACME plugin.
func (c *Client) DeleteACMEPlugin(ctx context.Context, id string) error {
	_, err := c.Delete(ctx, Path("config", "acme", "plugins", id), nil, nil)
	return err
}

// pluginSecrets are what an error about a plugin must not show: the encoded
// data and every value in it.
func pluginSecrets(params url.Values, settings map[string]string) []string {
	secrets := []string{params.Get("data")}
	for _, value := range settings {
		secrets = append(secrets, value)
	}
	return secrets
}

// A DNS plugin's settings are what acme.sh reads from the environment, such
// as CF_Token and CF_Account_ID for Cloudflare. PBS hands them to
// proxmox-acme, which runs the acme.sh API, as KEY=value lines; the web
// interface writes them that way, and the API takes them base64-encoded.

// EncodeACMEPluginData writes settings as KEY=value lines, sorted by key, so
// that a request is the same from one run to the next, base64-encoded as PBS
// takes them.
func EncodeACMEPluginData(settings map[string]string) string {
	return base64.StdEncoding.EncodeToString([]byte(FormatACMEPluginData(settings)))
}

// FormatACMEPluginData writes settings as KEY=value lines, sorted by key.
func FormatACMEPluginData(settings map[string]string) string {
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, key+"="+settings[key])
	}
	return strings.Join(lines, "\n")
}

// ParseACMEPluginData reads the KEY=value lines PBS returns. Blank lines are
// skipped, and so are lines without "=", which a map cannot hold; a key that
// appears twice keeps its last value, as a shell would.
func ParseACMEPluginData(data string) map[string]string {
	settings := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSuffix(line, "\r")
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		settings[key] = value
	}
	return settings
}

// NodeConfig is the part of a node's configuration, GET
// /nodes/{node}/config, that holds its ACME settings. ACMEDomains[i] is
// acmedomain<i>, empty when unset.
type NodeConfig struct {
	ACME        string
	ACMEDomains [MaxACMEDomains]string
}

// nodeConfigJSON is NodeConfig as PBS sends it.
type nodeConfigJSON struct {
	ACME        string `json:"acme,omitempty"`
	ACMEDomain0 string `json:"acmedomain0,omitempty"`
	ACMEDomain1 string `json:"acmedomain1,omitempty"`
	ACMEDomain2 string `json:"acmedomain2,omitempty"`
	ACMEDomain3 string `json:"acmedomain3,omitempty"`
	ACMEDomain4 string `json:"acmedomain4,omitempty"`
}

// ACMEDomainProperty is the name of the node property that holds ACME
// domain slot i.
func ACMEDomainProperty(i int) string { return "acmedomain" + string(rune('0'+i)) }

// GetNodeConfig reads a node's ACME settings and the digest of node.cfg. It
// needs Sys.Audit on /system.
func (c *Client) GetNodeConfig(ctx context.Context, node string) (NodeConfig, string, error) {
	var raw nodeConfigJSON
	env, err := c.Get(ctx, Path("nodes", node, "config"), nil, &raw)
	if err != nil {
		return NodeConfig{}, "", err
	}
	return NodeConfig{
		ACME:        raw.ACME,
		ACMEDomains: [MaxACMEDomains]string{raw.ACMEDomain0, raw.ACMEDomain1, raw.ACMEDomain2, raw.ACMEDomain3, raw.ACMEDomain4},
	}, env.Digest, nil
}

// UpdateNodeConfig changes the node properties params carries, and deletes
// those named in its delete parameter. It needs Sys.Modify on /system.
// Callers hold WithConfigLock(ConfigNode) and pass the digest they read.
func (c *Client) UpdateNodeConfig(ctx context.Context, node string, params url.Values) error {
	_, err := c.Put(ctx, Path("nodes", node, "config"), params, nil)
	return err
}

// ACMEAccountName returns the account a node's "acme" property names, or
// "default", the account PBS uses when the property is unset.
func (n NodeConfig) ACMEAccountName() (string, error) {
	if strings.TrimSpace(n.ACME) == "" {
		return "default", nil
	}
	p, err := ParsePropertyString(n.ACME, "")
	if err != nil {
		return "", err
	}
	return p["account"], nil
}

// ACMEDomain is one of a node's ACME domains.
type ACMEDomain struct {
	Domain string
	// Alias is the domain whose _acme-challenge record a DNS plugin sets
	// instead of the domain's own, for a CNAME delegating it.
	Alias string
	// Plugin is the plugin that validates the domain; empty means
	// standalone.
	Plugin string
}

// ParseACMEDomain parses an acmedomain<i> property.
func ParseACMEDomain(s string) (ACMEDomain, error) {
	p, err := ParsePropertyString(s, "domain")
	if err != nil {
		return ACMEDomain{}, err
	}
	return ACMEDomain{Domain: p["domain"], Alias: p["alias"], Plugin: p["plugin"]}, nil
}

// Format writes the domain as PBS reads it: the domain first and bare, then
// alias and plugin when set.
func (d ACMEDomain) Format() string {
	p := PropertyString{"domain": d.Domain}
	if d.Alias != "" {
		p["alias"] = d.Alias
	}
	if d.Plugin != "" {
		p["plugin"] = d.Plugin
	}
	return p.Format("domain")
}
