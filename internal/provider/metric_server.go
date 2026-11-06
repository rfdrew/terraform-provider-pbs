package provider

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// What the metric server resources — pbs_metric_server_influxdb_http and
// pbs_metric_server_influxdb_udp — share. Both types live in
// metricserver.cfg, in one namespace (see typed_section.go), and PBS checks
// an enabled server of either type before it saves it, on every create and
// update: the errors of that check get advice on what to look at.

// Privileges the metric server resources need, for error messages.
const (
	metricServerReadPrivilege   = "Sys.Audit on /"
	metricServerModifyPrivilege = "Sys.Modify on /"
)

var (
	influxDBHTTPKind = sectionKind{object: "metric server", typ: pbsclient.MetricServerTypeInfluxDBHTTP,
		name: "InfluxDB HTTP", file: pbsclient.ConfigMetricServers}
	influxDBUDPKind = sectionKind{object: "metric server", typ: pbsclient.MetricServerTypeInfluxDBUDP,
		name: "InfluxDB UDP", file: pbsclient.ConfigMetricServers}
)

// metricServerCommonAttributes are the attributes of both resources: id,
// name, enable and comment. check says what PBS checks before it saves an
// enabled server of the type.
func metricServerCommonAttributes(check string) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Same value as `name`, present because Terraform requires an `id`.",
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"name": schema.StringAttribute{
			Required: true,
			MarkdownDescription: "Metric server name, 3 to 32 characters: letters, digits, `_`, `.` and `-`, not " +
				"starting with `.` or `-`. InfluxDB HTTP and UDP servers share one namespace. Changing it replaces " +
				"the server.",
			Validators:    safeIDValidators(minSafeIDLength),
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"enable": schema.BoolAttribute{
			Optional: true,
			Computed: true,
			Default:  booldefault.StaticBool(true),
			MarkdownDescription: "Whether PBS sends its metrics to the server. PBS " + check + " only while the server " +
				"is enabled: set `false` to save a server PBS cannot reach yet. Defaults to `true`.",
		},
		"comment": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
			Validators:          textValidators(1, maxCommentLength),
		},
	}
}

// addMetricServerExistsError explains a create PBS refused because the name
// is taken, by a metric server of either type.
func addMetricServerExistsError(diags *diag.Diagnostics, kind sectionKind, name string, err error) {
	diags.AddAttributeError(path.Root("name"), "PBS metric server already exists",
		fmt.Sprintf("PBS already has a metric server %q; InfluxDB HTTP and UDP servers share one namespace. If it is "+
			"an %s server, import it to manage it with Terraform, with an import block whose id is %q or with "+
			"`terraform import`; otherwise choose another name. %s", name, kind.name, name, err))
}

// metricServerWriteError reports a create or update PBS refused. When the
// check of the server failed, it says what to look at; target is the URL or
// host:port PBS checked, and verifyTLS whether an HTTP server verifies the
// certificate of an https:// URL. PBS 4 does not say why it could not
// connect, so the advice for that follows from the URL, not from PBS's text.
func metricServerWriteError(diags *diag.Diagnostics, client *pbsclient.Client, kind sectionKind, summary, target string, verifyTLS bool, err error) {
	check, status := pbsclient.MetricServerCheckFailureOf(err)
	if check == pbsclient.MetricServerCheckPassed {
		diags.AddError(summary, apiErrorDetail(client, metricServerModifyPrivilege, err))
		return
	}
	var advice string
	if kind.typ == pbsclient.MetricServerTypeInfluxDBUDP {
		advice = fmt.Sprintf("PBS could not resolve %s or connect a UDP socket to it from its own host, so it saved "+
			"nothing. Nothing has to listen for this check: PBS only resolves the name and connects the socket, "+
			"so the name must resolve on the PBS host — not on the machine running Terraform — and the PBS host "+
			"must have a route to the address.", target)
	} else {
		health := strings.TrimSuffix(target, "/") + "/health"
		switch check {
		case pbsclient.MetricServerUnauthorized:
			advice = fmt.Sprintf("The server answered GET %s with %d, refusing the token or the lack of one, so PBS "+
				"saved nothing. InfluxDB 2 answers /health without a token; InfluxDB 3 wants one unless it runs "+
				"with --disable-authz health, and a reverse proxy may want one too. PBS sends the token it has: "+
				"the one in `token_wo` when `token_wo_version` changes, the one it stored otherwise.", health, status)
		case pbsclient.MetricServerNoHealth:
			advice = fmt.Sprintf("The server answered GET %s with 404, so PBS saved nothing: there is no InfluxDB "+
				"API at that path. `url` is InfluxDB's base URL, such as https://influxdb.example.com:8086, "+
				"without /api/v2: PBS appends /health and /api/v2/write itself, after the URL's path.", health)
		case pbsclient.MetricServerBadStatus:
			advice = fmt.Sprintf("The server answered GET %s with %d instead of a 2xx, so PBS saved nothing. PBS "+
				"follows no redirects: give the URL the server answers on; a 5xx means InfluxDB is not ready.",
				health, status)
		default:
			advice = fmt.Sprintf("PBS could not connect to %s, so it saved nothing. PBS does not say why — a name "+
				"that does not resolve, a port nothing listens on, a firewall and a failed TLS handshake all read "+
				"\"client error (Connect)\" — so check that the PBS host, not the machine running Terraform, "+
				"reaches the URL's host and port, and that InfluxDB listens there. PBS does not use the node's "+
				"HTTP proxy for this.", target)
			if strings.HasPrefix(target, "https://") {
				if verifyTLS {
					advice += " For an https:// URL, the server's certificate must also be valid for the URL's host " +
						"and signed by a CA the PBS host trusts: add an internal CA to the PBS host's trust store " +
						"(/usr/local/share/ca-certificates, then update-ca-certificates). `verify_tls = false` skips " +
						"the verification, but then PBS sends the token to whatever answers at the URL."
				} else {
					advice += " For an https:// URL, the server must speak TLS on that port."
				}
			}
		}
		advice = "Before it saves an enabled InfluxDB HTTP server, PBS sends GET " + health + " from its own host " +
			"and needs a 2xx answer. " + advice
	}
	diags.AddError(summary, advice+" To save the server without the check, set `enable = false`. "+err.Error())
}

// deleteMetricServer deletes the server; one already gone is not an error.
// PBS's delete removes a metric server of either type, so the server is
// read first, and deleted only while it still has the resource's type.
func deleteMetricServer(ctx context.Context, client *pbsclient.Client, kind sectionKind, name string, diags *diag.Diagnostics) {
	deleteSection(ctx, client, kind, name, metricServerModifyPrivilege,
		func() (string, error) { return client.MetricServerDigest(ctx, kind.typ, name) },
		func(digest string) error { return client.DeleteMetricServer(ctx, kind.typ, name, digest) },
		diags)
}

// isMetricServerHost reports whether s is a host as PBS takes it in the
// address of a metric server: a DNS name of letters, digits and inner
// hyphens, an IPv4 address, or an IPv6 address in brackets, without a zone.
func isMetricServerHost(s string) bool {
	if inner, ok := strings.CutPrefix(s, "["); ok {
		inner, ok = strings.CutSuffix(inner, "]")
		if !ok {
			return false
		}
		addr, err := netip.ParseAddr(inner)
		return err == nil && addr.Is6() && addr.Zone() == ""
	}
	return hostNamePattern.MatchString(s)
}

// isPort reports whether s is a port number, 1 to 65535, as PBS's pattern
// takes it: up to five digits, leading zeros allowed in up to four, so that
// 0089 passes but 08089 does not.
func isPort(s string) bool {
	if s == "" || len(s) > 5 || strings.Trim(s, "0123456789") != "" || (len(s) == 5 && s[0] == '0') {
		return false
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

// splitMetricServerHostPort splits "<host>:<port>" at the colon after the
// host, which for an IPv6 address follows its closing bracket. ok is false
// when there is no colon there.
func splitMetricServerHostPort(s string) (host, port string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 || strings.HasSuffix(s[:i], ":") || (strings.HasPrefix(s, "[") && !strings.HasSuffix(s[:i], "]")) {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// metricServerHostPortValidator accepts the address of an InfluxDB UDP
// server: "<host>:<port>", with a DNS name, an IPv4 address or an IPv6
// address in brackets, and a port from 1 to 65535.
func metricServerHostPortValidator() validator.String {
	return stringCheck{
		description: "must be <host>:<port>, the host a DNS name, an IPv4 address or an IPv6 address in brackets, " +
			"such as influxdb.example.com:8089, 192.0.2.10:8089 or [2001:db8::10]:8089",
		check: func(s string) bool {
			host, port, ok := splitMetricServerHostPort(s)
			return ok && isMetricServerHost(host) && isPort(port)
		},
	}
}

// influxDBURLValidator accepts what PBS takes as the URL of an InfluxDB
// HTTP server and can use: http:// or https://, a DNS name, an IPv4 address
// or an IPv6 address in brackets, an optional port, and an optional path of
// printable ASCII — without credentials, query, fragment or white space.
// PBS's own pattern lets a query and Unicode through, but drops the query
// when it builds its requests and cannot parse such a path.
func influxDBURLValidator() validator.String {
	return stringCheck{
		description: "must be an http:// or https:// URL with a DNS name, an IPv4 address or an IPv6 address in " +
			"brackets, an optional port and an optional path, without credentials, query, fragment, white space " +
			"or characters outside printable ASCII",
		check: func(s string) bool {
			rest, ok := strings.CutPrefix(s, "https://")
			if !ok {
				rest, ok = strings.CutPrefix(s, "http://")
			}
			if !ok {
				return false
			}
			authority, urlPath, _ := strings.Cut(rest, "/")
			for _, r := range urlPath {
				if r <= ' ' || r >= 0x7f || r == '?' || r == '#' {
					return false
				}
			}
			if host, port, ok := splitMetricServerHostPort(authority); ok && !strings.HasSuffix(authority, "]") {
				return isMetricServerHost(host) && isPort(port)
			}
			return isMetricServerHost(authority)
		},
	}
}
