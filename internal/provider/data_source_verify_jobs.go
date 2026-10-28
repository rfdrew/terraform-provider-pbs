package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &verifyJobDataSource{}
	_ datasource.DataSourceWithConfigure = &verifyJobDataSource{}
	_ datasource.DataSource              = &verifyJobsDataSource{}
	_ datasource.DataSourceWithConfigure = &verifyJobsDataSource{}
)

// NewVerifyJobDataSource returns the pbs_verify_job data source.
func NewVerifyJobDataSource() datasource.DataSource { return &verifyJobDataSource{} }

// NewVerifyJobsDataSource returns the pbs_verify_jobs data source.
func NewVerifyJobsDataSource() datasource.DataSource { return &verifyJobsDataSource{} }

type verifyJobDataSource struct {
	data *providerData
}

type verifyJobsDataSource struct {
	data *providerData
}

type verifyJobsDataSourceModel struct {
	Store types.String     `tfsdk:"store"`
	Jobs  []verifyJobModel `tfsdk:"jobs"`
}

// verifyJobDataAttributes are the attributes of a verify job in a data
// source.
func verifyJobDataAttributes(idRequired bool) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":    jobIDAttribute(idRequired, "verify-store1"),
		"store": schema.StringAttribute{Computed: true, MarkdownDescription: "Datastore the job verifies."},
		"ns": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Namespace the job verifies; null for the datastore's root namespace.",
		},
		"max_depth": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "How many levels of namespaces below `ns` the job verifies too; 7 for all of them.",
		},
		"schedule": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "When the job runs, as a PBS calendar event; null when it runs only when started by hand.",
		},
		"ignore_verified": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the job skips backups verified before, unless that verification is older than `outdated_after`.",
		},
		"outdated_after": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "How many days after its last verification a backup is verified again; null for never.",
		},
		"read_threads": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "How many threads read chunks; null when the datastore's default applies.",
		},
		"verify_threads": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "How many threads verify chunks; null when the datastore's default applies.",
		},
		"comment": schema.StringAttribute{Computed: true, MarkdownDescription: "Comment; null when there is none."},
	}
}

func (d *verifyJobDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_verify_job"
}

func (d *verifyJobDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a Proxmox Backup Server verify job, with the attributes of `pbs_verify_job`. " +
			"Needs `Datastore.Audit` or `Datastore.Verify` on the job's datastore.",
		Attributes: verifyJobDataAttributes(true),
	}
}

func (d *verifyJobDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *verifyJobDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config verifyJobModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := config.ID.ValueString()
	job, err := d.data.client.GetVerifyJob(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS verify job not found",
				fmt.Sprintf("PBS has no verify job %q. %s", id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS verify job",
			apiErrorDetail(d.data.client, "Datastore.Audit on the job's datastore", err))
		return
	}
	config.fromVerifyJob(id, job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

func (d *verifyJobsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_verify_jobs"
}

func (d *verifyJobsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the verify jobs of a Proxmox Backup Server, with the attributes of " +
			"`pbs_verify_job`: those on whose datastore, or namespace, the provider's user or token has " +
			"`Datastore.Audit` or `Datastore.Verify`; PBS leaves the others out.",
		Attributes: map[string]schema.Attribute{
			"store": jobStoreFilterAttribute(),
			"jobs": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The verify jobs, sorted by ID.",
				NestedObject:        schema.NestedAttributeObject{Attributes: verifyJobDataAttributes(false)},
			},
		},
	}
}

func (d *verifyJobsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *verifyJobsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config verifyJobsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	jobs, err := d.data.client.ListVerifyJobs(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS verify jobs", apiErrorDetail(d.data.client, "", err))
		return
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })

	config.Jobs = []verifyJobModel{}
	for _, job := range jobs {
		if !config.Store.IsNull() && job.Store != config.Store.ValueString() {
			continue
		}
		var m verifyJobModel
		m.fromVerifyJob(job.ID, job)
		config.Jobs = append(config.Jobs, m)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
