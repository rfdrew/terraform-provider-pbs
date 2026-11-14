package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                   = &notificationMatcherResource{}
	_ resource.ResourceWithConfigure      = &notificationMatcherResource{}
	_ resource.ResourceWithIdentity       = &notificationMatcherResource{}
	_ resource.ResourceWithImportState    = &notificationMatcherResource{}
	_ resource.ResourceWithModifyPlan     = &notificationMatcherResource{}
	_ resource.ResourceWithValidateConfig = &notificationMatcherResource{}
)

// NewNotificationMatcherResource returns the pbs_notification_matcher
// resource.
func NewNotificationMatcherResource() resource.Resource { return &notificationMatcherResource{} }

type notificationMatcherResource struct {
	data *providerData
}

type notificationMatcherModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Target        types.Set    `tfsdk:"target"`
	MatchSeverity types.Set    `tfsdk:"match_severity"`
	MatchField    types.Set    `tfsdk:"match_field"`
	MatchCalendar types.Set    `tfsdk:"match_calendar"`
	Mode          types.String `tfsdk:"mode"`
	InvertMatch   types.Bool   `tfsdk:"invert_match"`
	Expression    types.String `tfsdk:"expression"`
	Disable       types.Bool   `tfsdk:"disable"`
	Comment       types.String `tfsdk:"comment"`
	Origin        types.String `tfsdk:"origin"`
}

// notificationMatcherDeletable are the properties PBS lets a matcher update
// delete: all of them.
var notificationMatcherDeletable = []string{
	"comment", "disable", "expression", "invert-match", "match-calendar", "match-field", "match-severity", "mode", "target",
}

// How a matcher combines its match_* rules; all is PBS's default.
const (
	matcherModeAll = "all"
	matcherModeAny = "any"
)

// defaultMatcher is the matcher PBS ships, which routes every notification
// but those of successful prune jobs to the built-in sendmail endpoint
// mail-to-root.
const defaultMatcher = "default-matcher"

// severityMatcherPattern is one entry of match_severity: severities
// separated by commas, without spaces, which PBS would remove.
var severityMatcherPattern = regexp.MustCompile(`^(info|notice|warning|error|unknown)(,(info|notice|warning|error|unknown))*$`)

func (r *notificationMatcherResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_matcher"
}

func (r *notificationMatcherResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server notification matcher: a rule that sends the " +
			"notifications it matches to endpoints, such as a `pbs_notification_endpoint_smtp`. PBS hands every " +
			"notification to every matcher; each one that matches sends it to its `target`s.\n\n" +
			"A notification has a severity — `info`, `notice`, `warning`, `error` or `unknown` — and fields, such " +
			"as `type` (`gc`, `prune`, `sync`, `verify`, `tape-backup`, `package-updates`, `acme`…), `datastore`, " +
			"`job-id` or `hostname`. A matcher matches by severity, by field and by time of day, with `match_*` " +
			"rules or with an `expression`; one without either matches every notification.\n\n" +
			"**`match_*` rules or an `expression`.** The `match_*` rules combine one way, as `mode` says, and " +
			"`invert_match` inverts their result. An `expression`, from PBS 4.2.10, is a tree of nested rules, as " +
			"the matcher editor of the web interface builds them. A matcher has one or the " +
			"other. PBS 4.2.10 and later store the rules of a matcher created or edited in the web interface as an " +
			"expression, and convert a matcher's `match_*` rules, `mode` and `invert_match` into one when it is " +
			"edited there: the next plan of a matcher managed with `match_*` rules then removes the expression and " +
			"restores the rules. Edit the rules of a matcher Terraform manages only through Terraform.\n\n" +
			"**The built-in `default-matcher`** routes every notification but those of successful prune jobs to " +
			"`mail-to-root`, the built-in sendmail endpoint. It cannot be created or deleted, only changed: manage " +
			"it by importing it, and destroying the resource resets it to its built-in settings. To send all " +
			"notifications by SMTP instead, import it and point its `target` at the SMTP endpoint, keeping its " +
			"other settings, as in the example.\n\n" +
			"Endpoint and matcher names share one namespace. Managing matchers needs `" +
			notificationsModifyPrivilege + "`, reading them `" + notificationsReadPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `name`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Matcher name, 2 to 32 characters: letters, digits, `_`, `.` and `-`, not " +
					"starting with `.` or `-`; `" + defaultMatcher + "` for the built-in matcher, which must be " +
					"imported. Changing it replaces the matcher.",
				Validators:    safeIDValidators(minNotificationNameLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"target": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Names of the endpoints to send matching notifications to, such as the `name` " +
					"of a `pbs_notification_endpoint_smtp`, or `mail-to-root`. They must exist. A matcher without " +
					"targets sends nothing.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(safeIDValidators(minNotificationNameLength)...),
				},
			},
			"match_severity": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Severities to match. Each entry is one severity — `info`, `notice`, " +
					"`warning`, `error` or `unknown` — or several separated by commas, such as `warning,error`, " +
					"which match a notification of any of them. Conflicts with `expression`.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(stringvalidator.RegexMatches(severityMatcherPattern,
						"must be severities — info, notice, warning, error or unknown — separated by commas without spaces")),
				},
			},
			"match_field": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Fields to match, each `exact:<field>=<value>[,<value>…]` for one of the " +
					"values, such as `exact:type=prune` or `exact:datastore=store1,store2`, or " +
					"`regex:<field>=<regular expression>`, such as `regex:hostname=^pbs-`. Conflicts with `expression`.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(fieldMatcherValidator()),
				},
			},
			"match_calendar": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Times to match, each a time range with optional days, such as `8-17`, " +
					"`mon..fri 8-17` or `sat,sun 10:00-14:30`. PBS checks them. Conflicts with `expression`.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(textValidators(1, 256)...),
				},
			},
			"mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(matcherModeAll),
				MarkdownDescription: "How the `match_*` rules combine: `all`, the default, matches a notification " +
					"that every rule matches, `any` one that one of them does. `any` conflicts with `expression`, " +
					"whose `any-of` does the same.",
				Validators: []validator.String{stringvalidator.OneOf(matcherModeAll, matcherModeAny)},
			},
			"invert_match": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether to match the notifications the rules do not match instead. Defaults " +
					"to `false`; it has no effect on a matcher without rules. `true` conflicts with `expression`, " +
					"whose `not` does the same.",
			},
			"expression": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The matcher's rules as a match expression, PBS 4.2.10 and later: a JSON rule " +
					"tree, best written with `jsonencode()`, as in the example. Each rule is an object with one key: " +
					"`all-of`, `any-of` or `one-of`, a list of rules, matches when all, at least one or exactly one " +
					"of them match; `not`, a rule, when that one does not; `constant`, `true` or `false`, always or " +
					"never; and `match`, a test of the notification:\n\n" +
					"  - `{ type = \"severity\", severities = [\"warning\", \"error\"] }` — its severity is one of " +
					"`severities`: `info`, `notice`, `warning`, `error` or `unknown`;\n" +
					"  - `{ type = \"field\", field = \"type\", values = [\"gc\", \"prune\"] }` — the field has one " +
					"of the `values`; with `regex = \"^backup-\"` instead of `values`, it matches the regular " +
					"expression. A notification without the field does not match;\n" +
					"  - `{ type = \"calendar\", schedule = \"mon..fri 9-17\" }` — it was sent in the time range, " +
					"with optional days, as in `match_calendar`.\n\n" +
					"  The provider checks the rules when planning; PBS checks regular expressions and schedules. PBS " +
					"stores the expression compacted, with its keys in its own order: the same rules written another " +
					"way are no change. Conflicts with `match_severity`, `match_field` and `match_calendar`, " +
					"with `mode = \"any\"` and with `invert_match = true`.",
				Validators:    []validator.String{matchExpressionValidator{}},
				PlanModifiers: []planmodifier.String{sameJSONKeepsPrior{}},
			},
			"disable": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the matcher is disabled: it matches nothing. Defaults to `false`.",
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
			"origin": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Where the matcher comes from: `user-created`; `builtin` for " +
					"`" + defaultMatcher + "` with its built-in settings; `modified-builtin` once it is changed.",
			},
		},
	}
}

// fieldMatcherValidator checks an entry of match_field in the form PBS writes
// it back in: exact:<field>=<values> without spaces around the commas, or
// regex:<field>=<expression>, neither with white space at either end.
func fieldMatcherValidator() validator.String {
	return stringCheck{
		description: "must be exact:<field>=<value>[,<value>...] or regex:<field>=<regular expression>, such as " +
			"exact:type=prune, without spaces around commas or at either end",
		check: func(s string) bool {
			kind, rest, ok := strings.Cut(s, ":")
			if !ok || (kind != "exact" && kind != "regex") {
				return false
			}
			field, value, ok := strings.Cut(rest, "=")
			if !ok || !safeIDPattern.MatchString(field) || value == "" || strings.ContainsFunc(value, unicode.IsControl) {
				return false
			}
			if kind == "regex" {
				return strings.TrimSpace(value) == value
			}
			for _, v := range strings.Split(value, ",") {
				if v == "" || strings.TrimSpace(v) != v {
					return false
				}
			}
			return true
		},
	}
}

func (r *notificationMatcherResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Matcher name, such as `default-matcher`."})
}

func (r *notificationMatcherResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// notificationMatcherDefaults is the model of a matcher as PBS creates it
// when a property is left out, the prior state of a create.
var notificationMatcherDefaults = notificationMatcherModel{
	Target:        types.SetNull(types.StringType),
	MatchSeverity: types.SetNull(types.StringType),
	MatchField:    types.SetNull(types.StringType),
	MatchCalendar: types.SetNull(types.StringType),
	Mode:          types.StringValue(matcherModeAll),
	InvertMatch:   types.BoolValue(false),
	Expression:    types.StringNull(),
	Disable:       types.BoolValue(false),
	Comment:       types.StringNull(),
}

// changes records the properties that differ between prior and m.
func (m *notificationMatcherModel) changes(prior notificationMatcherModel, c *propertyChanges) {
	c.StringSet("target", m.Target, prior.Target)
	c.StringSet("match-severity", m.MatchSeverity, prior.MatchSeverity)
	c.StringSet("match-field", m.MatchField, prior.MatchField)
	c.StringSet("match-calendar", m.MatchCalendar, prior.MatchCalendar)
	c.StringDefault("mode", m.Mode, prior.Mode, matcherModeAll)
	c.BoolDefault("invert-match", m.InvertMatch, prior.InvertMatch, false)
	c.String("expression", m.Expression, prior.Expression)
	c.BoolDefault("disable", m.Disable, prior.Disable, false)
	c.String("comment", m.Comment, prior.Comment)
}

// fromNotificationMatcher records a matcher as PBS reports it. The name is
// the one it was looked up by. The expression m holds, the planned or the
// prior one, stays when PBS reports the same rules, which it rewrites.
func (m *notificationMatcherModel) fromNotificationMatcher(name string, matcher pbsclient.NotificationMatcher, diags *diag.Diagnostics) {
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	m.Target = stringSetOrNull(matcher.Target, diags)
	m.MatchSeverity = stringSetOrNull(matcher.MatchSeverity, diags)
	m.MatchField = stringSetOrNull(matcher.MatchField, diags)
	m.MatchCalendar = stringSetOrNull(matcher.MatchCalendar, diags)
	m.Mode = stringOr(matcher.Mode, matcherModeAll)
	m.InvertMatch = boolOr(matcher.InvertMatch, false)
	m.Expression = keepSameJSON(m.Expression, matcher.Expression)
	m.Disable = boolOr(matcher.Disable, false)
	m.Comment = stringOrNull(matcher.Comment)
	m.Origin = stringOr(matcher.Origin, pbsclient.OriginUserCreated)
}

func (r *notificationMatcherResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan notificationMatcherModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(notificationMatcherDefaults, changes)
	params := changes.Values()
	params.Set("name", name)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.CreateNotificationMatcher(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS notification endpoint or matcher already exists",
				fmt.Sprintf("PBS already has a notification endpoint or matcher named %q; endpoints and matchers share "+
					"one namespace. If it is a matcher — such as the built-in %s, which always exists — import it to "+
					"manage it with Terraform, with an import block whose id is %q or with `terraform import`; "+
					"otherwise choose another name. %s", name, defaultMatcher, name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS notification matcher", matcherErrorDetail(client, err))
		return
	}

	// From here on the matcher exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	matcher, err := client.GetNotificationMatcher(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		plan.Origin = types.StringValue(pbsclient.OriginUserCreated)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS notification matcher back after creation",
			fmt.Sprintf("PBS created notification matcher %q, and it was recorded in state, but reading it back failed, "+
				"so it is marked tainted: the next apply replaces it. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromNotificationMatcher(name, matcher, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// matcherErrorDetail explains a failed write of a matcher, naming the cause
// when a target does not exist.
func matcherErrorDetail(client *pbsclient.Client, err error) string {
	// 404 "endpoint 'x' does not exist", rather than the matcher's own
	// "matcher 'x' not found".
	var apiErr *pbsclient.Error
	if errors.As(err, &apiErr) && strings.HasPrefix(apiErr.Message, "endpoint '") && strings.HasSuffix(apiErr.Message, "does not exist") {
		return "A target of the matcher is not a notification endpoint PBS has; targets name endpoints, not " +
			"matchers. " + err.Error()
	}
	return apiErrorDetail(client, notificationsModifyPrivilege, err)
}

func (r *notificationMatcherResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state notificationMatcherModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the matcher gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	matcher, err := r.data.client.GetNotificationMatcher(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS notification matcher",
			apiErrorDetail(r.data.client, notificationsReadPrivilege, err))
		return
	}
	state.fromNotificationMatcher(name, matcher, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ValidateConfig refuses match_* rules, mode any and invert_match true next
// to an expression, which PBS refuses next to it. Mode all and
// invert_match false are PBS's defaults, which the resource never sends:
// Terraform writes them into the configuration it generates for a matcher
// with an expression, as they are optional attributes with a value.
func (r *notificationMatcherResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config notificationMatcherModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	// An unknown expression may turn out null, as a variable does in the
	// validation Terraform runs before every plan.
	if resp.Diagnostics.HasError() || config.Expression.IsNull() || config.Expression.IsUnknown() {
		return
	}
	conflict := func(name, setting, instead string) {
		resp.Diagnostics.AddAttributeError(path.Root(name), "Conflicting matcher rules",
			fmt.Sprintf("%s cannot be set next to expression, which holds all of the matcher's rules and which PBS "+
				"refuses next to it: %s.", setting, instead))
	}
	for name, rules := range map[string]types.Set{
		"match_severity": config.MatchSeverity, "match_field": config.MatchField, "match_calendar": config.MatchCalendar,
	} {
		if !rules.IsNull() && !rules.IsUnknown() {
			conflict(name, name, "write the rules into the expression as match rules instead, or leave the expression out")
		}
	}
	if config.Mode.ValueString() == matcherModeAny {
		conflict("mode", `mode = "any"`, "combine rules with any-of in the expression instead")
	}
	if config.InvertMatch.ValueBool() {
		conflict("invert_match", "invert_match = true", "invert rules with not in the expression instead")
	}
}

// ModifyPlan refuses an expression on a server older than PBS 4.2.10, which
// does not know the property. It also keeps origin when nothing else
// changes: the framework plans the computed origin as unknown when the
// configuration differs from the state at all, also when it differs only
// in how it writes the expression, which sameJSONKeepsPrior then plans as
// the prior one, and the plan would show an update that changes nothing.
func (r *notificationMatcherResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var expression, origin types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("expression"), &expression)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("origin"), &origin)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.data.requireRelease(&resp.Diagnostics, path.Root("expression"), expression, pbs4210)
	if req.State.Raw.IsNull() || !origin.IsUnknown() {
		return
	}
	var prior types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("origin"), &prior)...)
	unchanged := resp.Plan
	resp.Diagnostics.Append(unchanged.SetAttribute(ctx, path.Root("origin"), prior)...)
	if !resp.Diagnostics.HasError() && unchanged.Raw.Equal(req.State.Raw) {
		resp.Plan = unchanged
	}
}

func (r *notificationMatcherResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state notificationMatcherModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, notificationMatcherDeletable...)
	plan.changes(state, changes)
	// PBS refuses an expression next to mode or invert-match even at its
	// default, and a matcher may store one so — default-matcher's built-in
	// section has mode all —, which the state cannot tell from an absent
	// one: an update of a matcher with an expression deletes both, which PBS
	// does before it checks, and also when they are absent.
	if !plan.Expression.IsNull() && !changes.Empty() {
		changes.Delete("mode", "invert-match")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if !changes.Empty() {
		err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error {
			return client.UpdateNotificationMatcher(ctx, name, changes.Values())
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS notification matcher", matcherErrorDetail(client, err))
			return
		}
	}

	matcher, err := client.GetNotificationMatcher(ctx, name)
	if err != nil {
		// origin is unknown in the plan, and state must not be.
		plan.Origin = state.Origin
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS notification matcher back after update",
			fmt.Sprintf("PBS updated notification matcher %q, and the change was recorded in state, but reading it "+
				"back failed. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromNotificationMatcher(name, matcher, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// Delete deletes the matcher. PBS answers the same for a built-in one, which
// it resets to its built-in settings instead: it stays, as PBS keeps it.
func (r *notificationMatcherResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state notificationMatcherModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.DeleteNotificationMatcher(ctx, name) })
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS notification matcher", apiErrorDetail(client, notificationsModifyPrivilege, err))
		return
	}
	if origin := state.Origin.ValueString(); origin == pbsclient.OriginBuiltin || origin == pbsclient.OriginModifiedBuiltin {
		tflog.Info(ctx, "reset a built-in PBS notification matcher to its built-in settings", map[string]any{"name": name})
	}
}

// ImportState imports a matcher, built-in ones included, by name, given
// either as the import id or, from Terraform 1.12, as the identity of an
// import block. Read fills in the rest, or drops a matcher that does not
// exist, which Terraform reports.
func (r *notificationMatcherResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "notification matcher", defaultMatcher)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}
