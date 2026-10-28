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

// The job data sources report a job with the attributes, and the defaults,
// of its resource, so that a job read here and one managed there look the
// same. The singular ones read a job by ID, the plural ones list the jobs
// the provider may see, optionally of one datastore.

var (
	_ datasource.DataSource              = &pruneJobDataSource{}
	_ datasource.DataSourceWithConfigure = &pruneJobDataSource{}
	_ datasource.DataSource              = &pruneJobsDataSource{}
	_ datasource.DataSourceWithConfigure = &pruneJobsDataSource{}
)

// NewPruneJobDataSource returns the pbs_prune_job data source.
func NewPruneJobDataSource() datasource.DataSource { return &pruneJobDataSource{} }

// NewPruneJobsDataSource returns the pbs_prune_jobs data source.
func NewPruneJobsDataSource() datasource.DataSource { return &pruneJobsDataSource{} }

type pruneJobDataSource struct {
	data *providerData
}

type pruneJobsDataSource struct {
	data *providerData
}

type pruneJobsDataSourceModel struct {
	Store types.String    `tfsdk:"store"`
	Jobs  []pruneJobModel `tfsdk:"jobs"`
}

// jobIDAttribute is a job's ID in a data source: the lookup key, or computed.
func jobIDAttribute(required bool, example string) schema.StringAttribute {
	if required {
		return schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "ID of the job to read, such as `" + example + "`.",
			Validators:          safeIDValidators(minSafeIDLength),
		}
	}
	return schema.StringAttribute{Computed: true, MarkdownDescription: "Job ID, such as `" + example + "`."}
}

// jobStoreFilterAttribute is the store a job list data source may be limited
// to.
func jobStoreFilterAttribute() schema.StringAttribute {
	return schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: "List only the jobs of this datastore, such as `store1`: those whose `store` it is.",
		Validators:          safeIDValidators(minSafeIDLength),
	}
}

// pruneJobDataAttributes are the attributes of a prune job in a data source.
func pruneJobDataAttributes(idRequired bool) map[string]schema.Attribute {
	keep := map[string]schema.Attribute{}
	for _, k := range keepKinds {
		keep[k.attribute] = schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "How many backups the job keeps that are " + k.description + "; null when it keeps none for this reason.",
		}
	}
	return map[string]schema.Attribute{
		"id":       jobIDAttribute(idRequired, "daily-store1"),
		"store":    schema.StringAttribute{Computed: true, MarkdownDescription: "Datastore the job prunes."},
		"schedule": schema.StringAttribute{Computed: true, MarkdownDescription: "When the job runs, as a PBS calendar event."},
		"ns": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Namespace the job prunes; null for the datastore's root namespace.",
		},
		"max_depth": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "How many levels of namespaces below `ns` the job prunes too; null for all of them.",
		},
		"keep": schema.SingleNestedAttribute{
			Computed: true,
			MarkdownDescription: "Retention: how many backups of each kind the job keeps; null when the job sets " +
				"no retention option, so that it keeps every backup.",
			Attributes: keep,
		},
		"disable": schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the job is disabled."},
		"comment": schema.StringAttribute{Computed: true, MarkdownDescription: "Comment; null when there is none."},
	}
}

func (d *pruneJobDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_prune_job"
}

func (d *pruneJobDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a Proxmox Backup Server prune job, with the attributes of `pbs_prune_job`. " +
			"Needs `Datastore.Audit` on the job's datastore.",
		Attributes: pruneJobDataAttributes(true),
	}
}

func (d *pruneJobDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *pruneJobDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config pruneJobModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := config.ID.ValueString()
	job, err := d.data.client.GetPruneJob(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS prune job not found",
				fmt.Sprintf("PBS has no prune job %q. %s", id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS prune job",
			apiErrorDetail(d.data.client, "Datastore.Audit on the job's datastore", err))
		return
	}
	config.fromPruneJob(id, job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

func (d *pruneJobsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_prune_jobs"
}

func (d *pruneJobsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the prune jobs of a Proxmox Backup Server, with the attributes of " +
			"`pbs_prune_job`: those on whose datastore, or namespace, the provider's user or token has " +
			"`Datastore.Audit` or `Datastore.Modify`; PBS leaves the others out.",
		Attributes: map[string]schema.Attribute{
			"store": jobStoreFilterAttribute(),
			"jobs": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The prune jobs, sorted by ID.",
				NestedObject:        schema.NestedAttributeObject{Attributes: pruneJobDataAttributes(false)},
			},
		},
	}
}

func (d *pruneJobsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *pruneJobsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config pruneJobsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	jobs, err := d.data.client.ListPruneJobs(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS prune jobs", apiErrorDetail(d.data.client, "", err))
		return
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })

	config.Jobs = []pruneJobModel{}
	for _, job := range jobs {
		if !config.Store.IsNull() && job.Store != config.Store.ValueString() {
			continue
		}
		var m pruneJobModel
		m.fromPruneJob(job.ID, job)
		config.Jobs = append(config.Jobs, m)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
