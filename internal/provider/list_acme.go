package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// NewACMEAccountListResource returns the pbs_acme_account list resource.
func NewACMEAccountListResource() list.ListResource {
	return &importedList{
		newResource:   NewACMEAccountResource,
		identityOrder: []string{"name"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the ACME accounts of a Proxmox Backup Server, for `terraform query`, to import " +
				"them as `pbs_acme_account` resources. PBS leaves out deactivated accounts, whose files it renames to " +
				"names starting with `_`, and any other account file whose name starts with `_`.\n\n" +
				"Needs `" + certificatesPrivilege + "`, which PBS requires even to read accounts.\n\n" +
				"An account's `contact` is what the CA returned when PBS last registered or updated it. Let's Encrypt " +
				"has returned no addresses since June 2025, so for its accounts `contact` is null, and the generated " +
				"configuration is invalid (`Missing Configuration for Required Attribute`) until you fill in the " +
				"addresses; the first apply then sends them to the CA, which Let's Encrypt accepts and ignores. " +
				"`tos_url` is the URL of the terms of service agreed to at registration.\n\n" +
				"~> **Destroying an imported account deactivates it at the CA, for good**, as destroying any " +
				"`pbs_acme_account` does — and removing its resource block after the import plans exactly that. To " +
				"stop managing an account, remove it from the state instead.\n\n" + listRequirementNote,
		},
		enumerate: listACMEAccounts,
	}
}

// listACMEAccounts names the accounts PBS lists. The list has the names
// only; reading an account, for its directory, would cost a call each.
func listACMEAccounts(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	names, err := data.client.ListACMEAccounts(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS ACME accounts", apiErrorDetail(data.client, certificatesPrivilege, err))
		return nil
	}
	objects := make([]listedObject, 0, len(names))
	for _, name := range names {
		objects = append(objects, listedObject{identity: map[string]any{"name": name}, displayName: name})
	}
	return objects
}

// NewACMEPluginListResource returns the pbs_acme_plugin list resource.
func NewACMEPluginListResource() list.ListResource {
	return &importedList{
		newResource:   NewACMEPluginResource,
		identityOrder: []string{"id"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the ACME challenge plugins of a Proxmox Backup Server, for `terraform query`, " +
				"to import them as `pbs_acme_plugin` resources: the DNS plugins and the built-in `" +
				pbsclient.StandaloneACMEPlugin + "` plugin, which always exists and can only be imported.\n\n" +
				"Needs `" + certificatesPrivilege + "`, which PBS requires even to read plugins.\n\n" +
				"A DNS plugin's settings, `data`, are sensitive: they are null in the results, and the generated " +
				"configuration has `data = null # sensitive`, which the resource refuses for a DNS plugin (`Missing " +
				"setting of a DNS plugin`). Fill in the settings PBS has — its web interface shows them — before " +
				"running `terraform plan`: other settings plan an update, which writes them to PBS. The `" +
				pbsclient.StandaloneACMEPlugin + "` plugin has no settings, and its generated configuration needs " +
				"nothing.\n\n" +
				"When PBS cannot parse `/etc/proxmox-backup/acme/plugins.cfg`, as after a bad edit by hand, it " +
				"refuses to list any plugin, or to read one: the list block fails with PBS's error, which names the " +
				"line. Fix the file, and list again.\n\n" + listRequirementNote,
		},
		enumerate: listACMEPlugins,
	}
}

// listACMEPlugins names the plugins PBS lists. PBS answers each plugin's
// settings too, which the client drops: the engine reads every plugin
// through the resource anyway.
//
// A plugins.cfg PBS cannot parse — an unknown section type or property, a
// value its schema refuses — fails the whole listing with 400 "parsing
// \"/etc/proxmox-backup/acme/plugins.cfg\" failed: line N - ..."
// (proxmox-acme-api's plugin_config.rs, plugin_config, and
// proxmox-section-config's SectionConfig::parse), which is an error here
// too. The *Error* placeholder PBS puts in place of a section it parsed but
// cannot convert (plugin_api_impl.rs, modify_cfg_for_api) does not occur
// with PBS's plugin types, whose sections always convert once parsed; it is
// left out all the same, should a release ever send it.
func listACMEPlugins(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	plugins, err := data.client.ListACMEPlugins(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS ACME plugins", apiErrorDetail(data.client, certificatesPrivilege, err))
		return nil
	}
	objects := make([]listedObject, 0, len(plugins))
	unreadable := 0
	for _, plugin := range plugins {
		if plugin.ID == pbsclient.UnreadableACMEPlugin {
			unreadable++
			continue
		}
		objects = append(objects, listedObject{identity: map[string]any{"id": plugin.ID}, displayName: acmePluginDisplayName(plugin)})
	}
	if unreadable > 0 {
		diags.AddWarning("Left out ACME plugins PBS cannot read",
			fmt.Sprintf("PBS lists %d plugin(s) as %q, its placeholder for a section of /etc/proxmox-backup/acme/plugins.cfg "+
				"it cannot convert into a plugin. They are left out; check the sections of the file.", unreadable,
				pbsclient.UnreadableACMEPlugin))
	}
	return objects
}

// acmePluginDisplayName tells what kind of plugin a plugin is: the built-in
// HTTP-01 one, or a DNS plugin and its API.
func acmePluginDisplayName(plugin pbsclient.ACMEPlugin) string {
	if plugin.Type == pbsclient.StandaloneACMEPlugin {
		return displayNameWithComment(plugin.ID, "built-in HTTP-01 plugin")
	}
	what := plugin.Type + " plugin"
	if plugin.Type == pbsclient.DNSACMEPluginType {
		what = "DNS plugin"
	}
	if plugin.API != "" {
		what += ", API " + plugin.API
	}
	if plugin.Disable != nil && *plugin.Disable {
		what += ", disabled"
	}
	return displayNameWithComment(plugin.ID, what)
}
