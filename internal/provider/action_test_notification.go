package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &notificationTestAction{}
	_ action.ActionWithConfigure = &notificationTestAction{}
)

// NewNotificationTestAction returns the pbs_notification_test action.
func NewNotificationTestAction() action.Action {
	return &notificationTestAction{}
}

// notificationTestAction has PBS send a test notification through an
// endpoint, as the Test button of the Notifications panel does. What PBS
// 4.x does, read in its source (src/api2/config/notifications/targets.rs
// test_target, proxmox-notify api/common.rs test_target and lib.rs
// Bus::test_target, Bus::from_config; the same since 4.0):
//
//   - POST /config/notifications/targets/{name}/test needs Sys.Modify on
//     /system/notifications and answers once PBS has tried to deliver: no
//     task. SMTP gives up after 5 s, Gotify and webhooks after 10 s; for
//     sendmail, success means that the local mail system took the message.
//   - The notification has severity info, no metadata fields, the subject
//     "Test notification", and goes to the endpoint directly: matchers play
//     no part, and PBS has no call to test one. A disabled endpoint is
//     tested all the same.
//   - 404 "endpoint 'x' does not exist" for a name that is no endpoint — a
//     matcher, say —, and for a Gotify, SMTP or webhook endpoint whose
//     secrets are missing from notifications-priv.cfg, which PBS does not
//     load. 500 "Could not test target: ..." when the delivery fails, with
//     the reason, and "Could not instantiate notification bus: ..." when
//     PBS cannot read its notification configuration.
//
// The secrets of a webhook are not known here, unlike in the endpoint's
// resource, so they cannot be kept out of an error; PBS masks their exact
// text in the errors of a webhook itself.
type notificationTestAction struct {
	actionBase
}

type notificationTestModel struct {
	Name types.String `tfsdk:"name"`
}

func (a *notificationTestAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_test"
}

func (a *notificationTestAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Has a Proxmox Backup Server send a test notification through a notification endpoint — " +
			"sendmail, SMTP, Gotify or webhook —, as **Test** in the Notifications panel does, and fails when PBS " +
			"cannot deliver it. PBS answers once it has tried: an SMTP server gets 5 seconds, a Gotify server or " +
			"webhook 10; for a sendmail endpoint, success means that the node's mail system took the message, not " +
			"that it arrived.\n\n" +
			"The notification has the subject \"Test notification\", severity `info` and no metadata fields, and " +
			"goes to the endpoint directly: the notification matchers play no part, so the test says nothing about " +
			"which notifications they route to the endpoint, and PBS has no call to test a matcher. A disabled " +
			"endpoint is tested all the same; the action then warns, as PBS sends it nothing else. PBS ignores a " +
			"Gotify, SMTP or webhook endpoint whose secrets are missing from its configuration, and answers that it " +
			"does not exist.\n\n" +
			"The endpoint resources test an endpoint whenever they create or change it with `send_test_on_apply`; " +
			"the action tests one whenever it runs, such as after a change of something the delivery depends on — " +
			"`http_proxy` of `pbs_node_config` for Gotify and webhooks —, or with `terraform apply -invoke`.\n\n" +
			"Needs `" + notificationsModifyPrivilege + "`.\n\n" + actionRequirementNote,
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Name of the endpoint, such as `pbs_notification_endpoint_smtp.mail.name`, or " +
					"`mail-to-root`, the sendmail endpoint PBS ships.",
				Validators: safeIDValidators(minNotificationNameLength),
			},
		},
	}
}

func (a *notificationTestAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config notificationTestModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	name := config.Name.ValueString()
	progress := newActionProgress(ctx, resp)

	progress.say("sending a test notification through endpoint %s", name)
	if err := client.TestNotificationTarget(ctx, name); err != nil {
		resp.Diagnostics.AddError("PBS test notification failed", notificationTestErrorDetail(client, name, err))
		return
	}

	// Which kind of endpoint it is, and whether it is disabled, are in the
	// list of endpoints, which needs Sys.Audit as well: without it, the
	// action reports less.
	targets, err := client.ListNotificationTargets(ctx)
	if err != nil {
		tflog.Debug(ctx, "could not list the PBS notification endpoints", map[string]any{"error": err.Error()})
		progress.say("PBS delivered the test notification through endpoint %s", name)
		return
	}
	i := slices.IndexFunc(targets, func(t pbsclient.NotificationTarget) bool { return t.Name == name })
	if i < 0 {
		progress.say("PBS delivered the test notification through endpoint %s", name)
		return
	}
	target := targets[i]
	if target.Type == "sendmail" {
		progress.say("PBS handed the test notification of sendmail endpoint %s to the node's mail system", name)
	} else {
		progress.say("PBS delivered the test notification through %s endpoint %s", target.Type, name)
	}
	if target.Disable != nil && *target.Disable {
		resp.Diagnostics.AddWarning("PBS notification endpoint is disabled",
			fmt.Sprintf("PBS delivered the test notification through endpoint %q, which is disabled: PBS sends it no "+
				"other notification until it is enabled again.", name))
	}
}

// notificationTestErrorDetail explains a test notification PBS did not
// deliver.
func notificationTestErrorDetail(client *pbsclient.Client, name string, err error) string {
	var apiErr *pbsclient.Error
	switch {
	case pbsclient.IsNotFound(err):
		return fmt.Sprintf("PBS has no notification endpoint %q it can use: the name may be wrong or that of a "+
			"matcher, which PBS cannot test, or the endpoint is a Gotify, SMTP or webhook endpoint whose secrets "+
			"are missing from /etc/proxmox-backup/notifications-priv.cfg, which makes PBS ignore it — set them "+
			"again, with a new version of the endpoint's write-only secret. %s", name, err)
	case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusInternalServerError &&
		strings.HasPrefix(apiErr.Message, "Could not test target:"):
		return fmt.Sprintf("PBS tried to deliver the test notification through endpoint %q and failed; the reason "+
			"follows. Check the endpoint's settings, and that the node — not the machine Terraform runs on — reaches "+
			"its server. %s", name, err)
	}
	return apiErrorDetail(client, notificationsModifyPrivilege, err)
}
