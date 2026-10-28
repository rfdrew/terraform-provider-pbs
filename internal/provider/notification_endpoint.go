package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// What the notification endpoint resources — sendmail, SMTP, Gotify and
// webhook — have in common: PBS's built-in sendmail endpoint, the
// send_test_on_apply option, and the errors of a create.

// mailToRoot is the sendmail endpoint PBS ships, which mails root@pam and
// which default-matcher targets.
const mailToRoot = "mail-to-root"

// sendTestOnApplyAttribute is send_test_on_apply. delivery says how PBS
// delivers a test through the endpoint and when it gives up.
func sendTestOnApplyAttribute(delivery string) schema.BoolAttribute {
	return schema.BoolAttribute{
		Optional: true,
		Computed: true,
		Default:  booldefault.StaticBool(false),
		MarkdownDescription: "Have PBS send a test notification through the endpoint after every apply that " +
			"creates or changes it, unless it is disabled, so that a wrong setting fails the apply instead of " +
			"going unnoticed until a real notification is lost. Defaults to `false`. It exists only in " +
			"Terraform: turning it on changes nothing in PBS and sends nothing by itself, and every test " +
			"delivers a real message. " + delivery + " A failed test fails the apply. When the test after a " +
			"create fails, the provider deletes the endpoint again, so the next apply creates and tests it " +
			"again — should that delete fail too, the endpoint is kept and marked tainted; when the test after " +
			"an update fails, the endpoint keeps the change, and the next apply tests again only if the endpoint " +
			"changes again. " +
			"Sending a test needs `" + notificationsModifyPrivilege + "`.",
	}
}

// sendTestOnApplyOrDefault is send_test_on_apply as state records it: false
// for state written before the attribute existed, or by an import.
func sendTestOnApplyOrDefault(v types.Bool) types.Bool {
	if v.IsNull() || v.IsUnknown() {
		return types.BoolValue(false)
	}
	return v
}

// testCreatedEndpoint has PBS send a test notification through the endpoint
// name, which a create has just saved, when send_test_on_apply asks for one
// and the endpoint is enabled, and reports whether the endpoint stays. When
// the test fails, deleteEndpoint deletes it again, so that Create records
// nothing for Terraform to taint: with create_before_destroy, the
// replacement of a tainted endpoint would need the name it holds, which PBS
// refuses to give twice. Only when that delete fails too does the endpoint
// stay, to be recorded and tainted. secrets are kept out of the error.
func testCreatedEndpoint(ctx context.Context, client *pbsclient.Client, name string, plan notificationTestPlan,
	deleteEndpoint func(context.Context, string) error, diags *diag.Diagnostics, secrets ...string) bool {
	if !plan.wantsTest() {
		return true
	}
	err := client.TestNotificationTarget(ctx, name, secrets...)
	if err == nil {
		return true
	}
	detail := apiErrorDetail(client, notificationsModifyPrivilege, err)
	deleteErr := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return deleteEndpoint(ctx, name) })
	if deleteErr == nil || pbsclient.IsNotFound(deleteErr) {
		diags.AddAttributeError(path.Root("send_test_on_apply"), "PBS test notification failed",
			fmt.Sprintf("PBS created notification endpoint %q, but the test notification sent through it failed, so the "+
				"provider deleted the endpoint again: the next apply creates and tests it again. %s", name, detail))
		return false
	}
	diags.AddAttributeError(path.Root("send_test_on_apply"), "PBS test notification failed",
		fmt.Sprintf("PBS created notification endpoint %q, but the test notification sent through it failed, and deleting "+
			"the endpoint again failed too, so it is recorded in state and marked tainted: the next apply replaces it. "+
			"With create_before_destroy, the replacement cannot take the name the endpoint holds, so run `terraform "+
			"untaint` on it instead, once the cause is fixed. %s Deleting the endpoint: %s",
			name, detail, apiErrorDetail(client, notificationsModifyPrivilege, deleteErr)))
	return true
}

// testChangedEndpoint has PBS send a test notification through the endpoint
// name, after an update has saved a change of it, when send_test_on_apply
// asks for one and the endpoint is enabled. A failure is an error, after the
// state has been set. secrets are kept out of the error.
func testChangedEndpoint(ctx context.Context, client *pbsclient.Client, name string, plan notificationTestPlan, diags *diag.Diagnostics, secrets ...string) {
	if !plan.wantsTest() {
		return
	}
	if err := client.TestNotificationTarget(ctx, name, secrets...); err != nil {
		diags.AddAttributeError(path.Root("send_test_on_apply"), "PBS test notification failed",
			fmt.Sprintf("PBS saved the change of notification endpoint %q, but the test notification sent through it "+
				"failed. The next apply tests it again only if the endpoint changes again. %s",
				name, apiErrorDetail(client, notificationsModifyPrivilege, err)))
	}
}

// notificationTestPlan is what decides whether an apply sends a test.
type notificationTestPlan struct {
	SendTestOnApply types.Bool
	Disable         types.Bool
}

func (p notificationTestPlan) wantsTest() bool {
	return p.SendTestOnApply.ValueBool() && !p.Disable.ValueBool()
}

// endpointExistsDetail explains a create PBS refused because the name is
// taken, by an endpoint of any type or a matcher.
func endpointExistsDetail(kind, name string, err error) string {
	builtin := ""
	if kind == "sendmail" {
		builtin = " — such as the built-in " + mailToRoot + ", which always exists —"
	}
	return fmt.Sprintf("PBS already has a notification endpoint or matcher named %q; endpoints and matchers share one "+
		"namespace. If it is a %s endpoint%s import it to manage it with Terraform, with an import block whose id "+
		"is %q or with `terraform import`; otherwise choose another name. %s", name, kind, builtin, name, err)
}

// userCreatedOrigin plans origin as user-created for an endpoint that cannot
// be built in — every one but those named in builtin — and leaves it to
// apply for a built-in one, which a change can turn from builtin into
// modified-builtin or back.
type userCreatedOrigin struct {
	builtin []string
}

func (m userCreatedOrigin) Description(_ context.Context) string {
	return "origin is user-created for an endpoint PBS does not ship."
}

func (m userCreatedOrigin) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (m userCreatedOrigin) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if !req.PlanValue.IsUnknown() || req.Plan.Raw.IsNull() {
		return
	}
	var name types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	if name.IsUnknown() || name.IsNull() {
		return
	}
	for _, builtin := range m.builtin {
		if name.ValueString() == builtin {
			return
		}
	}
	resp.PlanValue = types.StringValue(pbsclient.OriginUserCreated)
}

var _ planmodifier.String = userCreatedOrigin{}
