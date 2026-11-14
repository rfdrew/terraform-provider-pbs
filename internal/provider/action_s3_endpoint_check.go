package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &s3EndpointCheckAction{}
	_ action.ActionWithConfigure = &s3EndpointCheckAction{}
)

// NewS3EndpointCheckAction returns the pbs_s3_endpoint_check action.
func NewS3EndpointCheckAction() action.Action {
	return &s3EndpointCheckAction{}
}

// s3EndpointCheckAction asks PBS to check that it can use a bucket through
// an S3 endpoint, as `proxmox-backup-manager s3 check` does. PBS answers
// the check itself, without a task.
type s3EndpointCheckAction struct {
	actionBase
}

type s3EndpointCheckModel struct {
	S3Endpoint  types.String `tfsdk:"s3_endpoint"`
	Bucket      types.String `tfsdk:"bucket"`
	StorePrefix types.String `tfsdk:"store_prefix"`
	Timeout     types.String `tfsdk:"timeout"`
}

// s3CheckPrivilege is what checking an S3 endpoint needs.
const s3CheckPrivilege = "Sys.Modify on /"

// defaultS3CheckTimeout is how long the action waits for PBS's answer by
// default: PBS gives up on an object store that does not answer after
// about 34 seconds, longer than the client's request timeout.
const defaultS3CheckTimeout = 2 * time.Minute

func (a *s3EndpointCheckAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_s3_endpoint_check"
}

func (a *s3EndpointCheckAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Checks that Proxmox Backup Server can use a bucket through an S3 endpoint, as " +
			"`proxmox-backup-manager s3 check` does: PBS reaches the bucket, then writes an empty test object, " +
			"`<store_prefix>/" + pbsclient.S3CheckObject + "`, reads it back and deletes it. The action fails when a " +
			"step fails. Use it after creating or changing a `pbs_s3_endpoint`, before a datastore relies on it; " +
			"PBS contacts no object store when it saves an endpoint.\n\n" +
			"Needs `Sys.Modify` on `/`. Every PBS 4 release can check an endpoint. PBS answers the check " +
			"itself, without a task; an object store that does not answer takes it about half a minute to give " +
			"up.\n\n" +
			"PBS reports only which step failed, not why: the action says what usually causes it, and " +
			"`proxmox-backup-manager s3 check <endpoint> <bucket>` on the PBS host prints the cause as well. The " +
			"requests count in the S3 request statistics of the bucket's datastore whose name is `store_prefix`, " +
			"if there is one.\n\n" + actionRequirementNote,
		Attributes: map[string]schema.Attribute{
			"s3_endpoint": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID of the S3 endpoint, such as `pbs_s3_endpoint.main.id`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"bucket": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Bucket to check, 3 to 63 lower-case letters, digits and hyphens, such as " +
					"`pbs_datastore.s3.backend.bucket`.",
				Validators: s3BucketValidators(),
			},
			"store_prefix": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Where in the bucket to write the test object: the name of the datastore the " +
					"check is for, under which PBS keeps that datastore's objects, such as `pbs_datastore.s3.name`. " +
					"Left out, the test object is at the top of the bucket.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					noControlOrPadding,
					stringCheck{
						description: "must not begin or end with a slash",
						check: func(s string) bool {
							return !strings.HasPrefix(s, "/") && !strings.HasSuffix(s, "/")
						},
					},
				},
			},
			"timeout": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "How long to wait for PBS's answer, as a Go duration such as `5m`. Defaults to " +
					"`2m`. When it runs out, the action fails.",
				Validators: []validator.String{positiveDurationValidator()},
			},
		},
	}
}

func (a *s3EndpointCheckAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config s3EndpointCheckModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id, bucket, prefix := config.S3Endpoint.ValueString(), config.Bucket.ValueString(), config.StorePrefix.ValueString()
	timeout := defaultS3CheckTimeout
	if !config.Timeout.IsNull() {
		timeout, _ = parsePositiveDuration(config.Timeout.ValueString())
	}
	object := pbsclient.S3CheckObject
	if prefix != "" {
		object = prefix + "/" + object
	}
	progress := newActionProgress(ctx, resp)

	progress.say("PBS is checking bucket %q through S3 endpoint %q", bucket, id)
	err := client.CheckS3Endpoint(pbsclient.WithRequestTimeout(ctx, timeout), id, bucket, prefix)
	if err != nil {
		summary, detail := s3CheckErrorDetail(client, id, bucket, object, timeout, err)
		resp.Diagnostics.AddError(summary, detail)
		return
	}
	progress.say("PBS reached bucket %q through S3 endpoint %q, and wrote, read and deleted object %q there", bucket, id, object)
}

// s3CheckErrorDetail explains a failed S3 endpoint check, from the step PBS
// names: its answer has nothing else. It returns the summary and detail of
// the error.
func s3CheckErrorDetail(client *pbsclient.Client, id, bucket, object string, timeout time.Duration, err error) (string, string) {
	const failed = "PBS S3 endpoint check failed"
	cause := fmt.Sprintf(" `proxmox-backup-manager s3 check %s %s` on the PBS host prints the cause, which PBS leaves "+
		"out of its answer. %s", id, bucket, err)
	var urlErr *url.Error
	switch pbsclient.S3CheckFailedStep(err) {
	case pbsclient.S3CheckConfigLookup:
		return "Unable to check PBS S3 endpoint " + id, fmt.Sprintf("PBS has no S3 endpoint %q. %s", id, err)
	case pbsclient.S3CheckClientCreation:
		// The check sets up no rate limits; its request counters live under
		// /var/lib/proxmox-backup/s3-statistics from PBS 4.1.7
		// (src/api2/admin/s3.rs check; proxmox-s3-client client.rs
		// S3Client::new).
		return failed, fmt.Sprintf("PBS could not set up its S3 client for endpoint %q, before it contacted the object "+
			"store: its fingerprint may be invalid, its endpoint address and port may not form a valid host name "+
			"once {{bucket}} and {{region}} are filled in, or PBS (4.1.7 and later) could not open its request "+
			"counters under /var/lib/proxmox-backup/s3-statistics."+cause, id)
	case pbsclient.S3CheckHeadBucket:
		return failed, fmt.Sprintf("PBS could not reach bucket %q through S3 endpoint %q. Usually the endpoint's "+
			"address, port or region is wrong, PBS does not trust its certificate (set `fingerprint` for a "+
			"self-signed one), its access or secret key is wrong, the bucket does not exist, or the access key may "+
			"not use it. Check too that PBS reaches the object store, through the node's HTTP proxy with "+
			"`use_node_proxy`."+cause, bucket, id)
	case pbsclient.S3CheckPutObject:
		return failed, fmt.Sprintf("PBS reached bucket %q through S3 endpoint %q, but could not write object %q there: "+
			"the access key may not write objects (s3:PutObject), or the bucket refuses writes, such as when it is "+
			"full or locked."+cause, bucket, id, object)
	case pbsclient.S3CheckGetObject:
		return failed, fmt.Sprintf("PBS wrote object %q to bucket %q through S3 endpoint %q, but could not read it "+
			"back: the access key may not read objects (s3:GetObject). The object stays in the bucket."+cause,
			object, bucket, id)
	case pbsclient.S3CheckDeleteObject:
		return failed, fmt.Sprintf("PBS wrote and read object %q in bucket %q through S3 endpoint %q, but could not "+
			"delete it: the access key may not delete objects (s3:DeleteObject), which pruning and garbage "+
			"collection need. The object stays in the bucket."+cause, object, bucket, id)
	}
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return "PBS S3 endpoint check did not finish", fmt.Sprintf("PBS did not answer within %s: it was most likely "+
			"still trying to reach bucket %q through S3 endpoint %q, which does not answer. Check the endpoint's "+
			"address and port, and that PBS reaches the object store, through the node's HTTP proxy with "+
			"`use_node_proxy`; or raise the action's `timeout`. %s", timeout, bucket, id, err)
	}
	return "Unable to check PBS S3 endpoint " + id, apiErrorDetail(client, s3CheckPrivilege, err)
}
