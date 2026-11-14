package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &realmSyncAction{}
	_ action.ActionWithConfigure = &realmSyncAction{}
)

// NewRealmSyncAction returns the pbs_realm_sync action.
func NewRealmSyncAction() action.Action {
	return &realmSyncAction{}
}

// realmSyncAction syncs the users of an LDAP or Active Directory realm from
// its directory, as the Sync button of a realm in the web interface does;
// see internal/pbsclient/realm_sync.go for what PBS does.
//
// It does not hold the provider's lock of user.cfg while the sync runs.
// The sync takes PBS's own locks of user.cfg and acl.cfg, those every user,
// token and ACL write takes, so writes of pbs_user, pbs_api_token and
// pbs_acl in the same run never fail because of it: user writes send no
// digest, and ACL writes retry on a digest conflict. Holding the lock would
// not order the sync and those writes either — Terraform's dependencies do
// —, and it would stall every user and token write of the run, without
// regard to a cancelled context, for as long as the directory search takes.
type realmSyncAction struct {
	actionBase
}

type realmSyncModel struct {
	Realm          types.String `tfsdk:"realm"`
	DryRun         types.Bool   `tfsdk:"dry_run"`
	EnableNew      types.Bool   `tfsdk:"enable_new"`
	RemoveVanished types.Set    `tfsdk:"remove_vanished"`
	taskWaitModel
}

// realmSyncNamed is how many user IDs a report names per kind of change,
// and how many skipped entries a warning quotes.
const (
	realmSyncNamed   = 3
	realmSyncSkipped = 10
)

func (a *realmSyncAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_realm_sync"
}

func (a *realmSyncAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Syncs the users of an LDAP or Active Directory realm of a Proxmox Backup Server from its " +
			"directory, as **Sync** under Configuration → Access Control → Realms does: PBS creates a user for every " +
			"entry of the directory it takes for one — below `base_dn`, of one of `user_classes`, matching " +
			"`filter` —, takes the names and email address of the users it has from the directory, and deletes " +
			"the users it no longer finds as `remove_vanished` says. The users it creates have no privileges until " +
			"a `pbs_acl` grants them some.\n\n" +
			"Needs `" + userModifyPrivilege + "`. The action first checks that the realm exists and is an LDAP or " +
			"Active Directory realm: PBS would start the sync of a realm of another type, and fail it.\n\n" +
			"When it waits, the action reports how many users PBS created, updated and deleted, as the task's log " +
			"names them — `dry_run` previews that without changing anything —, and warns about the entries of the " +
			"directory PBS skipped.\n\n" +
			"~> **A sync changes users Terraform manages.** It overwrites the first name, last name and email " +
			"address of the realm's users, `pbs_user` resources included, with the directory's — from the " +
			"attributes the realm's `sync_attributes` names —, which the next plan shows as drift and reverts; " +
			"with `properties` in `remove_vanished`, it also clears those the directory gives no valid value for, " +
			"including those `sync_attributes` does not map: without `sync_attributes`, all three of every user it " +
			"syncs. With `entry`, it deletes the realm's users the directory does not have, `pbs_user` resources " +
			"included, with their API tokens — and with `acl` too, their ACL entries and their tokens': the next " +
			"apply creates them again, the tokens with new secrets. A change of the realm's `base_dn`, `filter`, " +
			"`user_classes` or `user_attr` changes which users a sync finds: preview what a sync with `entry` " +
			"deletes then with `dry_run = true`. `enable_new = false` disables the users it finds that have no " +
			"enabled flag stored in PBS, which includes the enabled users `pbs_user` creates (see " +
			"`sync_defaults.enable_new` of `pbs_realm_ldap`). Manage the users of a realm either with `pbs_user` or " +
			"by syncing, or give `pbs_user` the directory's values. Terraform orders the sync and the writes of " +
			"users in the same run by their dependencies only: a user created in the same run may be synced, or " +
			"deleted by `entry`, or not, depending on which comes first.\n\n" +
			"PBS refuses a second sync of a realm only while it is starting the first one: two syncs of the same " +
			"realm can run at the same time, so trigger the action from one place.\n\n" + actionRequirementNote,
		Attributes: taskWaitAttributes(map[string]schema.Attribute{
			"realm": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Name of the LDAP or Active Directory realm, such as " +
					"`pbs_realm_ldap.corp.realm`.",
				Validators: realmValidators(),
			},
			"dry_run": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Whether only to find out what the sync would do: PBS logs the users it would " +
					"create, update and delete, which the action reports, and saves nothing. Defaults to `false`.",
			},
			"enable_new": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Whether the users the sync creates are enabled — and the users it updates " +
					"that have no enabled flag stored in PBS, such as the enabled users `pbs_user` creates. Defaults " +
					"to the realm's `sync_defaults.enable_new`, and to `true` when the realm sets none.",
			},
			"remove_vanished": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "What the sync removes that the directory no longer has, instead of what the " +
					"realm's `sync_defaults.remove_vanished` says: `entry` the realm's users it does not find, with " +
					"their API tokens; `acl`, together with `entry`, the ACL entries of those users and their " +
					"tokens, and alone nothing; `properties` the first name, last name and email address of the users " +
					"it finds that the directory gives no valid value for, including those the realm's " +
					"`sync_attributes` does not map — so, for a realm without `sync_attributes`, all three of every " +
					"user it syncs. Defaults to the realm's `sync_defaults.remove_vanished`, which " +
					"removes nothing when the realm sets none. An empty set removes nothing, whatever the realm says.",
				Validators: []validator.Set{
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(stringvalidator.OneOf("acl", "entry", "properties")),
				},
			},
		}),
	}
}

func (a *realmSyncAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config realmSyncModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	realm := config.Realm.ValueString()
	options := pbsclient.RealmSyncOptions{DryRun: config.DryRun.ValueBool()}
	if !config.EnableNew.IsNull() {
		enableNew := config.EnableNew.ValueBool()
		options.EnableNew = &enableNew
	}
	if !config.RemoveVanished.IsNull() {
		var values []string
		resp.Diagnostics.Append(config.RemoveVanished.ElementsAs(ctx, &values, false)...)
		// Not nil, even when empty: an empty set removes nothing.
		options.RemoveVanished = append([]string{}, values...)
	}
	if resp.Diagnostics.HasError() || !a.checkRealm(ctx, client, realm, resp) {
		return
	}
	progress := newActionProgress(ctx, resp)

	upid, err := client.StartRealmSync(ctx, realm, options)
	if err != nil {
		resp.Diagnostics.AddError("Unable to start the sync of PBS realm "+realm, realmSyncErrorDetail(client, realm, err))
		return
	}
	what := fmt.Sprintf("Sync of PBS realm %q", realm)
	if options.DryRun {
		what = fmt.Sprintf("Dry run of the sync of PBS realm %q", realm)
	}
	task := actionTask{client: client, upid: upid, what: what}
	if _, finished := task.await(ctx, config.taskWaitModel, progress, &resp.Diagnostics); !finished {
		return
	}

	// The log names every user the sync changed, one per line; a sync of a
	// large directory logs many, so it is read whole once, here.
	lines, _, _, err := client.TaskLog(ctx, upid, 1, 0)
	if err != nil {
		tflog.Debug(ctx, "could not read the PBS task log", map[string]any{"upid": upid.Raw, "error": err.Error()})
		return
	}
	summary := pbsclient.ParseRealmSyncLog(lines)
	progress.say("%s", describeRealmSync(realm, options.DryRun || summary.DryRun, summary))
	if len(summary.Skipped) > 0 {
		skipped := summary.Skipped
		more := ""
		if len(skipped) > realmSyncSkipped {
			more = fmt.Sprintf("\n\n… and %d more, in the task's log (Administration → Tasks in the web interface, or "+
				"`proxmox-backup-manager task log '%s'` on the host).", len(skipped)-realmSyncSkipped, upid.Raw)
			skipped = skipped[:realmSyncSkipped]
		}
		resp.Diagnostics.AddWarning("PBS skipped entries of the directory",
			fmt.Sprintf("The sync of realm %q found %d entries of the directory it could not make users of, which PBS "+
				"logs without counting them as warnings. Typically an entry lacks the attribute the realm takes the "+
				"user name from — `user_attr`, or `sAMAccountName` in an Active Directory realm —, or its value is no "+
				"valid user name; `filter` and `user_classes` of the realm keep entries that are no users out of the "+
				"sync:\n\n%s%s", realm, len(summary.Skipped), indentLines(strings.Join(skipped, "\n")), more))
	}
}

// checkRealm checks that PBS has the realm and can sync it, which PBS
// itself checks only in the task: a realm of another type starts a task that
// fails with "cannot sync realm <realm> of type <type>". Every user may list
// the realms.
func (a *realmSyncAction) checkRealm(ctx context.Context, client *pbsclient.Client, realm string, resp *action.InvokeResponse) bool {
	realms, err := client.ListRealms(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the realms of PBS", apiErrorDetail(client, "", err))
		return false
	}
	i := slices.IndexFunc(realms, func(r pbsclient.RealmInfo) bool { return r.Realm == realm })
	switch {
	case i < 0:
		resp.Diagnostics.AddError("PBS realm not found",
			fmt.Sprintf("PBS has no realm %q to sync. Check the name, or create the realm first: refer to it as "+
				"`pbs_realm_ldap.<name>.realm` or `pbs_realm_ad.<name>.realm`, so that Terraform creates it first.", realm))
		return false
	case realms[i].Type != pbsclient.RealmTypeLDAP && realms[i].Type != pbsclient.RealmTypeAD:
		resp.Diagnostics.AddError("Cannot sync PBS realm "+realm,
			fmt.Sprintf("PBS syncs the users of LDAP and Active Directory realms only, and %q is a realm of type %s: "+
				"PBS would start the sync and fail it with \"cannot sync realm %s of type %s\".",
				realm, realms[i].Type, realm, realms[i].Type))
		return false
	}
	return true
}

// realmSyncErrorDetail explains why PBS refused to start a sync.
func realmSyncErrorDetail(client *pbsclient.Client, realm string, err error) string {
	switch {
	case pbsclient.IsRealmUnknown(err):
		return fmt.Sprintf("PBS has no realm %q any more: it was deleted while the action started. %s", realm, err)
	case pbsclient.IsTaskAlreadyRunning(err):
		return fmt.Sprintf("PBS was starting another sync of realm %q at the same moment; invoke the action again. %s", realm, err)
	}
	return apiErrorDetail(client, userModifyPrivilege, err)
}

// describeRealmSync says in a line what a sync did, or would do in a dry
// run, naming the first users of each kind of change.
func describeRealmSync(realm string, dryRun bool, summary pbsclient.RealmSyncSummary) string {
	named := func(ids []string) string {
		if len(ids) == 0 {
			return ""
		}
		names := strings.Join(ids[:min(len(ids), realmSyncNamed)], ", ")
		if len(ids) > realmSyncNamed {
			names += ", …"
		}
		return " (" + names + ")"
	}
	users := "users"
	if len(summary.Created) == 1 {
		users = "user"
	}
	created := fmt.Sprintf("%d %s%s", len(summary.Created), users, named(summary.Created))
	updated := fmt.Sprintf("%d%s", len(summary.Updated), named(summary.Updated))
	deleted := fmt.Sprintf("%d%s", len(summary.Deleted), named(summary.Deleted))
	if dryRun {
		return fmt.Sprintf("dry run of realm %s: PBS would create %s, update %s and delete %s; nothing changed",
			realm, created, updated, deleted)
	}
	return fmt.Sprintf("realm %s: PBS created %s, updated %s and deleted %s", realm, created, updated, deleted)
}
