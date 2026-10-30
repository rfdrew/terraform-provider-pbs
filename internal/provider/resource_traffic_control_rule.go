package provider

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                   = &trafficControlRuleResource{}
	_ resource.ResourceWithConfigure      = &trafficControlRuleResource{}
	_ resource.ResourceWithIdentity       = &trafficControlRuleResource{}
	_ resource.ResourceWithImportState    = &trafficControlRuleResource{}
	_ resource.ResourceWithModifyPlan     = &trafficControlRuleResource{}
	_ resource.ResourceWithValidateConfig = &trafficControlRuleResource{}
)

// NewTrafficControlRuleResource returns the pbs_traffic_control_rule
// resource.
func NewTrafficControlRuleResource() resource.Resource { return &trafficControlRuleResource{} }

type trafficControlRuleResource struct {
	data *providerData
}

type trafficControlRuleModel struct {
	Name      types.String  `tfsdk:"name"`
	ID        types.String  `tfsdk:"id"`
	Network   types.Set     `tfsdk:"network"`
	Users     types.Set     `tfsdk:"users"`
	Timeframe types.Set     `tfsdk:"timeframe"`
	RateIn    byteSizeValue `tfsdk:"rate_in"`
	BurstIn   byteSizeValue `tfsdk:"burst_in"`
	RateOut   byteSizeValue `tfsdk:"rate_out"`
	BurstOut  byteSizeValue `tfsdk:"burst_out"`
	Comment   types.String  `tfsdk:"comment"`
}

// trafficControlDeletable are the properties PBS lets a rule update delete.
// network is required.
var trafficControlDeletable = []string{"rate-in", "burst-in", "rate-out", "burst-out", "comment", "timeframe", "users"}

// Privileges the traffic control resources need, for error messages: to
// change rules, and to read one.
const (
	trafficControlPrivilege     = "Sys.Modify on /"
	trafficControlReadPrivilege = "Sys.Audit on /"
)

// maxCIDRLength bounds a network, as PBS does.
const maxCIDRLength = 43

// cidrPattern is the shape of PBS's CIDR notation: an address, a slash and a
// prefix length of one or two digits for IPv4, up to three for IPv6. PBS
// does not check the prefix length's range, but its proxy ignores a network
// whose length is out of range; net.ParseCIDR refuses that.
var cidrPattern = regexp.MustCompile(`^([0-9.]+/[0-9]{1,2}|[0-9A-Fa-f:.]+/[0-9]{1,3})$`)

// cidrValidator accepts a network in CIDR notation, IPv4 or IPv6, as PBS
// does: host bits may be set, as in 192.0.2.1/24, and an IPv4 address has no
// leading zeros.
func cidrValidator() validator.String {
	return stringCheck{
		description: "must be an IPv4 or IPv6 network in CIDR notation, such as 192.0.2.0/24 or 2001:db8::/32",
		check: func(s string) bool {
			if len(s) > maxCIDRLength || !cidrPattern.MatchString(s) {
				return false
			}
			prefix, err := netip.ParsePrefix(s)
			return err == nil && prefix.Addr().Zone() == ""
		},
	}
}

// dailyDurationPattern is a time range with optional days, as PBS's
// parse_daily_duration takes it: days such as mon, sat,sun or mon..fri — or
// their full names, in any case — then a start and an end time, H or H:MM,
// separated by "-".
var dailyDurationPattern = regexp.MustCompile(`(?i)^(?:((?:` + weekdayPattern + `)(?:\.\.(?:` + weekdayPattern + `))?` +
	`(?:,(?:` + weekdayPattern + `)(?:\.\.(?:` + weekdayPattern + `))?)*) *)?([0-9]+)(?::([0-9]+))? *- *([0-9]+)(?::([0-9]+))?$`)

// weekdayPattern is a day of the week, as PBS spells it.
const weekdayPattern = `monday|tuesday|wednesday|thursday|friday|saturday|sunday|mon|tue|wed|thu|fri|sat|sun`

// isDailyDuration reports whether PBS takes s as a daily time range: hours
// below 24, minutes below 60, and a start no later than the end, as the
// range cannot cross midnight.
func isDailyDuration(s string) bool {
	m := dailyDurationPattern.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	minutes := func(hour, minute string) (int, bool) {
		h, err := strconv.Atoi(hour)
		if err != nil || h > 23 {
			return 0, false
		}
		mm := 0
		if minute != "" {
			if mm, err = strconv.Atoi(minute); err != nil || mm > 59 {
				return 0, false
			}
		}
		return h*60 + mm, true
	}
	start, ok := minutes(m[2], m[3])
	if !ok {
		return false
	}
	end, ok := minutes(m[4], m[5])
	return ok && start <= end
}

// timeframeValidator checks a time range with optional days.
func timeframeValidator() validator.String {
	return stringCheck{
		description: "must be a time range with optional days, such as 8-17, mon..fri 8:00-18:00 or sat,sun 10:00-14:30: " +
			"hours 0 to 23, the start no later than the end",
		check: isDailyDuration,
	}
}

func (r *trafficControlRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_traffic_control_rule"
}

func (r *trafficControlRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server traffic control rule: a bandwidth limit on the " +
			"connections clients from some networks open to PBS on its port, 8007 — backups, restores, and the " +
			"sync jobs of other servers — optionally only for some users, or at some times. `rate_in` limits what " +
			"PBS receives, such as backups, and `rate_out` what it sends, such as restores. All the connections " +
			"a rule applies to share its limits.\n\n" +
			"**One rule per connection.** PBS applies the one rule that matches a connection best: of the rules " +
			"whose `network`, `users` and `timeframe` match, a rule with `users` beats one without, and then the " +
			"one with the longest matching network prefix wins; between equals, PBS picks either. A direction the " +
			"winning rule sets no rate for is not limited, so a rule without rates exempts its clients from a " +
			"broader one. PBS documents that all matching rules apply, but its code picks one.\n\n" +
			"Connections PBS opens itself are not limited by these rules: sync jobs and S3 endpoints have rate " +
			"limits of their own. PBS applies a change to open connections within seconds. Time frames are in the " +
			"server's local time.\n\n" +
			"Managing traffic control rules needs `" + trafficControlPrivilege + "`; reading them `" +
			trafficControlReadPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Rule name, 3 to 32 characters: letters, digits, `_`, `.` and `-`, not " +
					"starting with `.` or `-`. Changing it replaces the rule.",
				Validators:    safeIDValidators(minSafeIDLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `name`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"network": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
				MarkdownDescription: "Client networks the rule applies to, in CIDR notation, such as " +
					"`192.0.2.0/24` or `2001:db8::/32`; `0.0.0.0/0` and `::/0` together for every client, as a rule " +
					"for some `users` needs.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(cidrValidator()),
				},
			},
			"users": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Users the rule applies to, such as `sync@pbs`, from the matching networks; " +
					"connections of an API token count as its user's, and connections that have not signed in as " +
					"none. Every client when left out. Needs PBS 4.1 or newer.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(userIDValidators()...),
				},
			},
			"timeframe": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Times the rule applies at, each a time range with optional days, such as " +
					"`8-17`, `mon..fri 8:00-18:00` or `sat,sun 10:00-14:30`, in the server's local time; always when " +
					"left out. A range includes its start but not its end, and cannot cross midnight: `22-24` is " +
					"refused, `22:00-23:59` ends a minute early.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(timeframeValidator()),
				},
			},
			"rate_in": trafficRateAttribute("Rate limit on the data PBS receives from the matching clients " +
				"together, such as backups, in bytes per second; no limit when left out."),
			"burst_in": burstAttribute("rate_in", "receive"),
			"rate_out": trafficRateAttribute("Rate limit on the data PBS sends to the matching clients together, " +
				"such as restores, in bytes per second; no limit when left out."),
			"burst_out": burstAttribute("rate_out", "send"),
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
		},
	}
}

func (r *trafficControlRuleResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Rule name, such as `office`."})
}

func (r *trafficControlRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// trafficRateAttribute is one of a rule's rates and bursts, at least one
// byte: a rate of 0 limits nothing on PBS 4.0.21 and newer, and divides by
// zero before. PBS truncates a size to whole bytes, so 0.5 is 0 too.
func trafficRateAttribute(description string) schema.StringAttribute {
	a := rateAttribute(description)
	a.Validators = append(a.Validators, stringCheck{
		description: "must be at least 1 byte",
		check: func(s string) bool {
			n, ok := wholeBytes(s)
			return !ok || n >= 1
		},
	})
	return a
}

// wholeBytes is the number of bytes PBS takes a size for: the number times
// the unit, truncated, where pbsclient.ParseByteSize rounds, so that 0.5 is
// no byte at all. ok is false for a size that does not parse, which
// byteSizeValidators refuse.
func wholeBytes(s string) (n uint64, ok bool) {
	if _, err := pbsclient.ParseByteSize(s); err != nil {
		return 0, false
	}
	end := strings.IndexFunc(s, func(r rune) bool { return r != '.' && (r < '0' || r > '9') })
	if end < 0 {
		end = len(s)
	}
	value, err := strconv.ParseFloat(s[:end], 64)
	if err != nil {
		return 0, false
	}
	unit, err := pbsclient.ParseByteSize("1" + s[end:])
	if err != nil {
		return 0, false
	}
	return uint64(value * float64(unit)), true
}

// burstAttribute is burst_in or burst_out, which PBS ignores without the
// rate of its direction.
func burstAttribute(rate, verb string) schema.StringAttribute {
	a := trafficRateAttribute("How many bytes over `" + rate + "` PBS may " + verb + " at once, after a quiet " +
		"period; as much as `" + rate + "` when left out. Requires `" + rate + "`.")
	a.Validators = append(a.Validators, stringvalidator.AlsoRequires(path.MatchRoot(rate)))
	return a
}

// ValidateConfig warns about an IPv4-mapped IPv6 network, which PBS never
// matches: it compares the addresses of such clients as IPv4.
func (r *trafficControlRuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config trafficControlRuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Network.IsUnknown() {
		return
	}
	for _, network := range sortedStrings(config.Network.Elements()) {
		if prefix, err := netip.ParsePrefix(network); err == nil && prefix.Addr().Is4In6() {
			resp.Diagnostics.AddAttributeWarning(path.Root("network"), "Network PBS never matches",
				fmt.Sprintf("%s is an IPv4-mapped IPv6 network. PBS compares the address of a client connecting so "+
					"as an IPv4 address, so the network matches no client: write it as IPv4.", network))
		}
	}
}

// ModifyPlan refuses users on a server older than PBS 4.1.
func (r *trafficControlRuleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan trafficControlRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.data.requireRelease(&resp.Diagnostics, path.Root("users"), plan.Users, pbs41)
}

// trafficControlRuleDefaults is the model of a rule as PBS creates it when a
// property is left out, the prior state of a create.
var trafficControlRuleDefaults = trafficControlRuleModel{
	Network:   types.SetNull(types.StringType),
	Users:     types.SetNull(types.StringType),
	Timeframe: types.SetNull(types.StringType),
	RateIn:    byteSizeOrNull(""),
	BurstIn:   byteSizeOrNull(""),
	RateOut:   byteSizeOrNull(""),
	BurstOut:  byteSizeOrNull(""),
	Comment:   types.StringNull(),
}

// changes records the properties that differ between prior and m.
func (m *trafficControlRuleModel) changes(prior trafficControlRuleModel, c *propertyChanges) {
	c.StringSet("network", m.Network, prior.Network)
	c.StringSet("users", m.Users, prior.Users)
	c.StringSet("timeframe", m.Timeframe, prior.Timeframe)
	c.String("rate-in", sameSize(m.RateIn, prior.RateIn), prior.RateIn.StringValue)
	c.String("burst-in", sameSize(m.BurstIn, prior.BurstIn), prior.BurstIn.StringValue)
	c.String("rate-out", sameSize(m.RateOut, prior.RateOut), prior.RateOut.StringValue)
	c.String("burst-out", sameSize(m.BurstOut, prior.BurstOut), prior.BurstOut.StringValue)
	c.String("comment", m.Comment, prior.Comment)
}

// fromRule records a rule as PBS reports it. The name is the one it was
// looked up by.
func (m *trafficControlRuleModel) fromRule(name string, rule pbsclient.TrafficControlRule, diags *diag.Diagnostics) {
	m.Name = types.StringValue(name)
	m.ID = types.StringValue(name)
	m.Network = stringSetOrNull(rule.Network, diags)
	m.Users = stringSetOrNull(rule.Users, diags)
	m.Timeframe = stringSetOrNull(rule.Timeframe, diags)
	m.RateIn = byteSizeOrNull(rule.RateIn)
	m.BurstIn = byteSizeOrNull(rule.BurstIn)
	m.RateOut = byteSizeOrNull(rule.RateOut)
	m.BurstOut = byteSizeOrNull(rule.BurstOut)
	m.Comment = stringOrNull(rule.Comment)
}

func (r *trafficControlRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan trafficControlRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(trafficControlRuleDefaults, changes)
	params := changes.Values()
	params.Set("name", name)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigTrafficControl, func() error { return client.CreateTrafficControlRule(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS traffic control rule already exists",
				fmt.Sprintf("PBS already has a traffic control rule %q. To manage it with Terraform, import it, with "+
					"an import block whose id is %q or with `terraform import`. %s", name, name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS traffic control rule", apiErrorDetail(client, trafficControlPrivilege, err))
		return
	}

	// From here on the rule exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	rule, err := client.GetTrafficControlRule(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS traffic control rule back after creation",
			fmt.Sprintf("PBS created traffic control rule %q, and it was recorded in state, but reading it back "+
				"failed, so it is marked tainted: the next apply replaces it. %s", name,
				apiErrorDetail(client, trafficControlReadPrivilege, err)))
		return
	}
	plan.fromRule(name, rule, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

func (r *trafficControlRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state trafficControlRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the rule gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	rule, err := r.data.client.GetTrafficControlRule(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS traffic control rule",
			apiErrorDetail(r.data.client, trafficControlReadPrivilege, err))
		return
	}
	state.fromRule(name, rule, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *trafficControlRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state trafficControlRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, trafficControlDeletable...)
	plan.changes(state, changes)
	if resp.Diagnostics.HasError() {
		return
	}
	if !changes.Empty() {
		err := client.WithConfigLock(pbsclient.ConfigTrafficControl, func() error {
			return client.UpdateTrafficControlRule(ctx, name, changes.Values())
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS traffic control rule", apiErrorDetail(client, trafficControlPrivilege, err))
			return
		}
	}

	rule, err := client.GetTrafficControlRule(ctx, name)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS traffic control rule back after update",
			fmt.Sprintf("PBS updated traffic control rule %q, and the change was recorded in state, but reading it "+
				"back failed. %s", name, apiErrorDetail(client, trafficControlReadPrivilege, err)))
		return
	}
	plan.fromRule(name, rule, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// Delete deletes the rule; one already gone is not an error.
func (r *trafficControlRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state trafficControlRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigTrafficControl, func() error {
		return client.DeleteTrafficControlRule(ctx, state.Name.ValueString())
	})
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS traffic control rule", apiErrorDetail(client, trafficControlPrivilege, err))
	}
}

// ImportState imports a rule by name, given either as the import id or,
// from Terraform 1.12, as the identity of an import block. Read fills in the
// rest, or drops a rule that does not exist, which Terraform reports.
func (r *trafficControlRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "traffic control rule", "office")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}
