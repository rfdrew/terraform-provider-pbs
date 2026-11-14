package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// The list resources of the notification endpoints — one per type, as the
// resources are — and of the matchers. PBS's targets list,
// GET /config/notifications/targets, names every endpoint of every type with
// its type and comment, the built-in mail-to-root included, in one call that
// needs Sys.Audit on /system/notifications
// (src/api2/config/notifications/targets.rs, list_targets, and
// proxmox-notify's api/mod.rs, get_targets); each endpoint list takes the
// endpoints of its type from it. Matchers come from their own list,
// ListNotificationMatchers, which names default-matcher too.

// notificationEndpointListKind is a type of notification endpoint, as the
// targets list names it, and what the descriptions say about it.
type notificationEndpointListKind struct {
	// typ is the type the targets list gives, and the resource's name
	// ends with: sendmail, smtp, gotify or webhook.
	typ string
	// name is how sentences call the endpoints, such as "Gotify".
	name string
	// secrets says what the generated configuration cannot know.
	secrets string
}

var (
	sendmailEndpointListKind = notificationEndpointListKind{
		typ: "sendmail", name: "sendmail",
		secrets: "The built-in `" + mailToRoot + "` is listed too: PBS ships it, and it cannot be created or " +
			"deleted, so importing it is how to manage it with Terraform; destroying the resource resets it to its " +
			"built-in settings. A sendmail endpoint has no secrets: the generated configuration of every one " +
			"plans no change.",
	}
	smtpEndpointListKind = notificationEndpointListKind{
		typ: "smtp", name: "SMTP",
		secrets: "The password is write-only and never read: the generated configuration has " +
			"`password_wo = null # sensitive` and `password_wo_version = null`, and the endpoint keeps the " +
			"password PBS has, which plans no change for an endpoint without a `username`. One with a `username` " +
			"needs both set all the same, as `username` requires `password_wo`: validating its generated " +
			"configuration fails with `Invalid Attribute Combination` until they are, and the first apply then " +
			"sends the password.",
	}
	gotifyEndpointListKind = notificationEndpointListKind{
		typ: "gotify", name: "Gotify",
		secrets: "The application token is write-only and never read, but `token_wo` and `token_wo_version` are " +
			"required: the generated configuration has `token_wo = null # sensitive` and " +
			"`token_wo_version = null`, so validating it fails with `Missing Configuration for Required " +
			"Attribute` for both until they are set, and the first apply then sends the token.",
	}
	webhookEndpointListKind = notificationEndpointListKind{
		typ: "webhook", name: "webhook",
		secrets: "PBS returns the names of a webhook's secrets but never their values, and each entry of `secret` " +
			"requires `value_wo` and `value_wo_version`: the generated configuration of an endpoint with secrets " +
			"has `value_wo = null # sensitive` and `value_wo_version = null` in every entry, so validating it " +
			"fails with `Missing Configuration for Required Attribute` for both, in every entry, until they are " +
			"set, and the first apply then sends every value. One without secrets plans no change.",
	}
)

// NewSendmailEndpointListResource returns the
// pbs_notification_endpoint_sendmail list resource.
func NewSendmailEndpointListResource() list.ListResource {
	return newNotificationEndpointList(NewSendmailEndpointResource, sendmailEndpointListKind)
}

// NewSMTPEndpointListResource returns the pbs_notification_endpoint_smtp
// list resource.
func NewSMTPEndpointListResource() list.ListResource {
	return newNotificationEndpointList(NewSMTPEndpointResource, smtpEndpointListKind)
}

// NewGotifyEndpointListResource returns the pbs_notification_endpoint_gotify
// list resource.
func NewGotifyEndpointListResource() list.ListResource {
	return newNotificationEndpointList(NewGotifyEndpointResource, gotifyEndpointListKind)
}

// NewWebhookEndpointListResource returns the
// pbs_notification_endpoint_webhook list resource.
func NewWebhookEndpointListResource() list.ListResource {
	return newNotificationEndpointList(NewWebhookEndpointResource, webhookEndpointListKind)
}

// newNotificationEndpointList returns the list resource of the endpoints of
// one type, which newResource manages.
func newNotificationEndpointList(newResource func() resource.Resource, kind notificationEndpointListKind) list.ListResource {
	resourceType := "pbs_notification_endpoint_" + kind.typ
	return &importedList{
		newResource:   newResource,
		identityOrder: []string{"name"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the " + kind.name + " notification endpoints of a Proxmox Backup Server, for " +
				"`terraform query`, to import them as `" + resourceType + "` resources. Endpoints of other types " +
				"have list resources of their own.\n\n" + kind.secrets + " `send_test_on_apply` exists only in " +
				"Terraform: the generated configuration sets it to `false`.\n\n" +
				"Needs `" + notificationsReadPrivilege + "`; without it, PBS refuses the list.\n\n" +
				listRequirementNote,
			Attributes: map[string]listschema.Attribute{},
		},
		enumerate: func(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
			return listNotificationEndpoints(ctx, data, kind, diags)
		},
	}
}

// listNotificationEndpoints names the endpoints of kind's type.
func listNotificationEndpoints(ctx context.Context, data *providerData, kind notificationEndpointListKind, diags *diag.Diagnostics) []listedObject {
	targets, err := data.client.ListNotificationTargets(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS "+kind.name+" notification endpoints",
			apiErrorDetail(data.client, notificationsReadPrivilege, err))
		return nil
	}
	var objects []listedObject
	for _, target := range targets {
		if target.Type != kind.typ {
			continue
		}
		objects = append(objects, listedObject{
			identity:    map[string]any{"name": target.Name},
			displayName: displayNameWithComment(target.Name, target.Comment),
		})
	}
	return objects
}

// NewNotificationMatcherListResource returns the pbs_notification_matcher
// list resource.
func NewNotificationMatcherListResource() list.ListResource {
	return &importedList{
		newResource:   NewNotificationMatcherResource,
		identityOrder: []string{"name"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the notification matchers of a Proxmox Backup Server, for `terraform query`, " +
				"to import them as `pbs_notification_matcher` resources. The built-in `" + defaultMatcher + "` is " +
				"listed too: PBS ships it, and it cannot be created or deleted, so importing it is how to manage it " +
				"with Terraform; destroying the resource resets it to its built-in settings. A matcher has no " +
				"secrets, so the generated configuration of each one plans no change. The rules of a matcher that " +
				"PBS 4.2.10 and later hold as an expression, as the web interface stores them, are generated as " +
				"`expression = jsonencode(…)`.\n\n" +
				"Needs `" + notificationsReadPrivilege + "`; without it, PBS refuses the list.\n\n" +
				listRequirementNote,
			Attributes: map[string]listschema.Attribute{},
		},
		enumerate: listNotificationMatchers,
	}
}

func listNotificationMatchers(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	matchers, err := data.client.ListNotificationMatchers(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS notification matchers", apiErrorDetail(data.client, notificationsReadPrivilege, err))
		return nil
	}
	objects := make([]listedObject, 0, len(matchers))
	for _, matcher := range matchers {
		objects = append(objects, listedObject{
			identity:    map[string]any{"name": matcher.Name},
			displayName: displayNameWithComment(matcher.Name, matcher.Comment),
		})
	}
	return objects
}
