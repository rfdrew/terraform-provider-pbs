package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &s3EndpointDataSource{}
	_ datasource.DataSourceWithConfigure = &s3EndpointDataSource{}
	_ datasource.DataSource              = &s3EndpointsDataSource{}
	_ datasource.DataSourceWithConfigure = &s3EndpointsDataSource{}
	_ datasource.DataSource              = &s3BucketsDataSource{}
	_ datasource.DataSourceWithConfigure = &s3BucketsDataSource{}
)

// NewS3EndpointDataSource returns the pbs_s3_endpoint data source.
func NewS3EndpointDataSource() datasource.DataSource { return &s3EndpointDataSource{} }

// NewS3EndpointsDataSource returns the pbs_s3_endpoints data source.
func NewS3EndpointsDataSource() datasource.DataSource { return &s3EndpointsDataSource{} }

// NewS3BucketsDataSource returns the pbs_s3_buckets data source.
func NewS3BucketsDataSource() datasource.DataSource { return &s3BucketsDataSource{} }

type s3EndpointDataSource struct {
	data *providerData
}

type s3EndpointsDataSource struct {
	data *providerData
}

type s3BucketsDataSource struct {
	data *providerData
}

// s3EndpointDataModel is an S3 endpoint as the pbs_s3_endpoint and
// pbs_s3_endpoints data sources report it. PBS never returns the secret key,
// so neither do they.
type s3EndpointDataModel struct {
	ID                   types.String  `tfsdk:"id"`
	Endpoint             types.String  `tfsdk:"endpoint"`
	Port                 types.Int64   `tfsdk:"port"`
	Region               types.String  `tfsdk:"region"`
	Fingerprint          types.String  `tfsdk:"fingerprint"`
	AccessKey            types.String  `tfsdk:"access_key"`
	PathStyle            types.Bool    `tfsdk:"path_style"`
	ProviderQuirks       types.Set     `tfsdk:"provider_quirks"`
	RateIn               byteSizeValue `tfsdk:"rate_in"`
	BurstIn              byteSizeValue `tfsdk:"burst_in"`
	RateOut              byteSizeValue `tfsdk:"rate_out"`
	BurstOut             byteSizeValue `tfsdk:"burst_out"`
	LimitActiveRequests  types.Int64   `tfsdk:"limit_active_requests"`
	LimitPassiveRequests types.Int64   `tfsdk:"limit_passive_requests"`
	UseNodeProxy         types.Bool    `tfsdk:"use_node_proxy"`
}

type s3EndpointsDataSourceModel struct {
	Endpoints []s3EndpointDataModel `tfsdk:"endpoints"`
}

type s3BucketModel struct {
	Name types.String `tfsdk:"name"`
}

type s3BucketsDataSourceModel struct {
	Endpoint types.String    `tfsdk:"s3_endpoint"`
	Buckets  []s3BucketModel `tfsdk:"buckets"`
}

func s3EndpointData(e pbsclient.S3Endpoint, diags *diag.Diagnostics) s3EndpointDataModel {
	return s3EndpointDataModel{
		ID:                   types.StringValue(e.ID),
		Endpoint:             types.StringValue(e.Endpoint),
		Port:                 int64OrNull(e.Port),
		Region:               stringOrNull(e.Region),
		Fingerprint:          pbsFingerprint(fingerprintOrNull(e.Fingerprint)),
		AccessKey:            types.StringValue(e.AccessKey),
		PathStyle:            boolOr(e.PathStyle, false),
		ProviderQuirks:       stringSetOrNull(e.ProviderQuirks, diags),
		RateIn:               byteSizeOrNull(e.RateIn),
		BurstIn:              byteSizeOrNull(e.BurstIn),
		RateOut:              byteSizeOrNull(e.RateOut),
		BurstOut:             byteSizeOrNull(e.BurstOut),
		LimitActiveRequests:  int64OrNull(e.LimitActiveRequests),
		LimitPassiveRequests: int64OrNull(e.LimitPassiveRequests),
		UseNodeProxy:         boolOr(e.UseNodeProxy, false),
	}
}

// s3EndpointDataAttributes are the attributes of an S3 endpoint in a data
// source, all computed but the ID when it is the lookup key.
func s3EndpointDataAttributes(idRequired bool) map[string]schema.Attribute {
	id := schema.StringAttribute{Computed: true, MarkdownDescription: "Endpoint ID, such as `backblaze`."}
	if idRequired {
		id = schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "ID of the S3 endpoint to read, such as `backblaze`.",
			Validators:          safeIDValidators(minSafeIDLength),
		}
	}
	byteSize := func(description, null string) schema.StringAttribute {
		return schema.StringAttribute{
			CustomType:          byteSizeType{},
			Computed:            true,
			MarkdownDescription: description + ", as PBS writes it, such as `10 MiB`; " + null + ".",
		}
	}
	return map[string]schema.Attribute{
		"id": id,
		"endpoint": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Host name or IP address of the object store, possibly with `{{bucket}}` and `{{region}}`.",
		},
		"port":   schema.Int64Attribute{Computed: true, MarkdownDescription: "Port of the object store; null for 443."},
		"region": schema.StringAttribute{Computed: true, MarkdownDescription: "Region; null for `us-west-1`."},
		"fingerprint": schema.StringAttribute{
			Computed: true,
			MarkdownDescription: "SHA-256 fingerprint of the certificate PBS accepts besides those its CAs validate, " +
				"as colon-separated lower-case hex pairs; null when there is none.",
		},
		"access_key": schema.StringAttribute{
			Computed:            true,
			Sensitive:           true,
			MarkdownDescription: "Access key ID PBS signs its requests with.",
		},
		"path_style": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether PBS addresses a bucket in the path of its requests rather than in the host name.",
		},
		"provider_quirks": schema.SetAttribute{
			ElementType:         types.StringType,
			Computed:            true,
			MarkdownDescription: "Features of the S3 API the object store lacks, which PBS works around; null for none.",
		},
		"rate_in":   byteSize("Rate limit on downloads, in bytes per second", "null for no limit"),
		"burst_in":  byteSize("How many bytes over `rate_in` PBS may download at once", "null for as much as `rate_in`"),
		"rate_out":  byteSize("Rate limit on uploads, in bytes per second", "null for no limit"),
		"burst_out": byteSize("How many bytes over `rate_out` PBS may upload at once", "null for as much as `rate_out`"),
		"limit_active_requests": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "How many `PUT`, `POST` and `DELETE` requests a second PBS sends at most; null for no limit.",
		},
		"limit_passive_requests": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "How many `GET` and `HEAD` requests a second PBS sends at most; null for no limit.",
		},
		"use_node_proxy": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether PBS connects through the HTTP proxy of its node configuration.",
		},
	}
}

func (d *s3EndpointDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_s3_endpoint"
}

func (d *s3EndpointDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a Proxmox Backup Server S3 endpoint, without its secret key, which PBS never " +
			"returns. It does not contact the object store: `pbs_s3_buckets` does. Needs `Sys.Audit` on " +
			"`/system/s3-endpoint/<id>`.",
		Attributes: s3EndpointDataAttributes(true),
	}
}

func (d *s3EndpointDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *s3EndpointDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config s3EndpointDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := config.ID.ValueString()
	endpoint, err := d.data.client.GetS3Endpoint(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS S3 endpoint not found",
				fmt.Sprintf("PBS has no S3 endpoint %q. %s", id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS S3 endpoint",
			apiErrorDetail(d.data.client, s3EndpointPrivilege(s3EndpointReadPrivilege, id), err))
		return
	}
	model := s3EndpointData(endpoint, &resp.Diagnostics)
	model.ID = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (d *s3EndpointsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_s3_endpoints"
}

func (d *s3EndpointsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the S3 endpoints of a Proxmox Backup Server, without their secret keys: those " +
			"on which the provider's user or token has `Sys.Audit`, `/system/s3-endpoint/<id>` or above; PBS leaves " +
			"the others out.",
		Attributes: map[string]schema.Attribute{
			"endpoints": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The S3 endpoints, sorted by ID.",
				NestedObject:        schema.NestedAttributeObject{Attributes: s3EndpointDataAttributes(false)},
			},
		},
	}
}

func (d *s3EndpointsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *s3EndpointsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	endpoints, err := d.data.client.ListS3Endpoints(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS S3 endpoints",
			apiErrorDetail(d.data.client, "Sys.Audit on /system/s3-endpoint", err))
		return
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID < endpoints[j].ID })
	model := s3EndpointsDataSourceModel{Endpoints: []s3EndpointDataModel{}}
	for _, e := range endpoints {
		model.Endpoints = append(model.Endpoints, s3EndpointData(e, &resp.Diagnostics))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// s3BucketsPrivilege is what listing an endpoint's buckets needs: more than
// reading the endpoint.
const s3BucketsPrivilege = "Sys.Audit on /"

func (d *s3BucketsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_s3_buckets"
}

func (d *s3BucketsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the buckets of an object store that the access key of a Proxmox Backup Server " +
			"S3 endpoint may see. PBS connects to the object store for it, so the list also checks that the " +
			"endpoint works: its address, keys, region and fingerprint. A wrong host name or a refused port fails within " +
			"seconds, but an address that drops connection attempts makes PBS try for over half a minute, and one " +
			"that accepts connections and never answers longer still, which may outlast the provider's " +
			"`request_timeout`. Needs `" +
			s3BucketsPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"s3_endpoint": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID of the S3 endpoint, such as the `id` of a `pbs_s3_endpoint`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
			"buckets": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The buckets, sorted by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{Computed: true, MarkdownDescription: "Bucket name."},
				}},
			},
		},
	}
}

func (d *s3BucketsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *s3BucketsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config s3BucketsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := config.Endpoint.ValueString()
	buckets, err := d.data.client.ListS3Buckets(ctx, id)
	if err != nil {
		var apiErr *pbsclient.Error
		switch {
		case errors.As(err, &apiErr) && apiErr.Message == "config lookup failed":
			resp.Diagnostics.AddAttributeError(path.Root("s3_endpoint"), "PBS S3 endpoint not found",
				fmt.Sprintf("PBS has no S3 endpoint %q. %s", id, err))
		case errors.As(err, &apiErr) && (apiErr.Message == "failed to list buckets" || apiErr.Message == "client creation failed"):
			resp.Diagnostics.AddError("Unable to list the buckets of a PBS S3 endpoint",
				fmt.Sprintf("PBS could not list the buckets through S3 endpoint %q. PBS reports no cause; its journal "+
					"shows it for a certificate PBS refused and for an answer of the object store, such as a wrong key, "+
					"region or permissions, but not for a wrong address or port. Check the endpoint's address and port, its access and secret keys, its region and, for "+
					"a self-signed certificate, its fingerprint, and whether PBS reaches the object store, through "+
					"the node's proxy with use_node_proxy. %s", id, err))
		default:
			resp.Diagnostics.AddError("Unable to list the buckets of a PBS S3 endpoint",
				apiErrorDetail(d.data.client, s3BucketsPrivilege, err))
		}
		return
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Name < buckets[j].Name })
	config.Buckets = []s3BucketModel{}
	for _, b := range buckets {
		config.Buckets = append(config.Buckets, s3BucketModel{Name: types.StringValue(b.Name)})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
