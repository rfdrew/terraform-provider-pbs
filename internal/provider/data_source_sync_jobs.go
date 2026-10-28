package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &syncJobDataSource{}
	_ datasource.DataSourceWithConfigure = &syncJobDataSource{}
	_ datasource.DataSource              = &syncJobsDataSource{}
	_ datasource.DataSourceWithConfigure = &syncJobsDataSource{}
)

// NewSyncJobDataSource returns the pbs_sync_job data source.
func NewSyncJobDataSource() datasource.DataSource { return &syncJobDataSource{} }

// NewSyncJobsDataSource returns the pbs_sync_jobs data source.
func NewSyncJobsDataSource() datasource.DataSource { return &syncJobsDataSource{} }

type syncJobDataSource struct {
	data *providerData
}

type syncJobsDataSource struct {
	data *providerData
}

type syncJobsDataSourceModel struct {
	Store         types.String   `tfsdk:"store"`
	SyncDirection types.String   `tfsdk:"sync_direction"`
	Jobs          []syncJobModel `tfsdk:"jobs"`
}

// syncJobReadDescription is what reading sync jobs needs.
const syncJobReadDescription = "`Datastore.Audit` on the job's `store`, and `Remote.Audit` on `/remote/<remote>` " +
	"for a pull, `Datastore.Audit` on `remote_store` for a local pull, or `Remote.Audit` on " +
	"`/remote/<remote>/<remote_store>` for a push"

// syncJobDataAttributes are the attributes of a sync job in a data source.
func syncJobDataAttributes(idRequired bool) map[string]schema.Attribute {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	computedBool := func(description string) schema.BoolAttribute {
		return schema.BoolAttribute{Computed: true, MarkdownDescription: description}
	}
	computedInt := func(description string) schema.Int64Attribute {
		return schema.Int64Attribute{Computed: true, MarkdownDescription: description}
	}
	byteSize := func(description string) schema.StringAttribute {
		return schema.StringAttribute{
			CustomType:          byteSizeType{},
			Computed:            true,
			MarkdownDescription: description + ", as PBS writes it, such as `10 MiB`; null for no limit.",
		}
	}
	return map[string]schema.Attribute{
		"id":             jobIDAttribute(idRequired, "pull-offsite"),
		"sync_direction": computedString("`pull` or `push`."),
		"store":          computedString("Local datastore: the target of a pull, the source of a push."),
		"ns":             computedString("Namespace in `store`; null for the datastore's root namespace."),
		"remote":         computedString("Name of the remote; null for a local pull."),
		"remote_store":   computedString("Datastore on the remote, or the local datastore a local pull copies from."),
		"remote_ns":      computedString("Namespace in `remote_store`; null for its root namespace."),
		"max_depth":      computedInt("How many levels of namespaces below the source namespace the job syncs too; null for all of them."),
		"schedule":       computedString("When the job runs, as a PBS calendar event; null when it runs only when started by hand or mounted."),
		"owner":          computedString("User or API token the job acts as; null for `root@pam`."),
		"remove_vanished": computedBool("Whether the job deletes from the target what the source no longer " +
			"has."),
		"group_filter": schema.SetAttribute{
			ElementType:         types.StringType,
			Computed:            true,
			MarkdownDescription: "Which backup groups the job syncs; null for all of them.",
		},
		"transfer_last":   computedInt("How many of the most recent backups of each group the job copies; null for all."),
		"encrypted_only":  computedBool("Whether the job copies only encrypted backups."),
		"verified_only":   computedBool("Whether the job copies only verified backups."),
		"resync_corrupt":  computedBool("Whether a pull copies again the backups whose local copy failed verification."),
		"run_on_mount":    computedBool("Whether the job runs when a removable datastore it syncs with is mounted."),
		"unmount_on_done": computedBool("Whether PBS unmounts the removable datastore after a run its mount started."),
		"worker_threads":  computedInt("How many backup groups the job syncs at the same time; null for one at a time."),
		"rate_in":         byteSize("Rate limit on what the job receives, in bytes per second"),
		"burst_in":        byteSize("How many bytes over `rate_in` the job may receive at once"),
		"rate_out":        byteSize("Rate limit on what the job sends, in bytes per second"),
		"burst_out":       byteSize("How many bytes over `rate_out` the job may send at once"),
		"comment":         computedString("Comment; null when there is none."),
	}
}

func (d *syncJobDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sync_job"
}

func (d *syncJobDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a Proxmox Backup Server sync job of either direction, with the attributes of " +
			"`pbs_sync_job`. Needs " + syncJobReadDescription + ".",
		Attributes: syncJobDataAttributes(true),
	}
}

func (d *syncJobDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *syncJobDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config syncJobModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := config.ID.ValueString()
	job, err := d.data.client.GetSyncJob(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS sync job not found",
				fmt.Sprintf("PBS has no sync job %q. %s", id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS sync job",
			syncJobErrorDetail(d.data.client, "Datastore.Audit on the job's datastore, and Remote.Audit on its remote", err))
		return
	}
	config.fromSyncJob(id, job, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

func (d *syncJobsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sync_jobs"
}

func (d *syncJobsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the sync jobs of a Proxmox Backup Server, pulls and pushes alike, with the " +
			"attributes of `pbs_sync_job`: those the provider's user or token may read, with " +
			syncJobReadDescription + "; PBS leaves the others out.",
		Attributes: map[string]schema.Attribute{
			"store": jobStoreFilterAttribute(),
			"sync_direction": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "List only the jobs of this direction, `pull` or `push`; both when left out.",
				Validators: []validator.String{
					stringvalidator.OneOf(pbsclient.SyncDirectionPull, pbsclient.SyncDirectionPush),
				},
			},
			"jobs": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The sync jobs, sorted by ID.",
				NestedObject:        schema.NestedAttributeObject{Attributes: syncJobDataAttributes(false)},
			},
		},
	}
}

func (d *syncJobsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *syncJobsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config syncJobsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	jobs, err := d.data.client.ListSyncJobs(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS sync jobs", apiErrorDetail(d.data.client, "", err))
		return
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })

	config.Jobs = []syncJobModel{}
	for _, job := range jobs {
		if (!config.Store.IsNull() && job.Store != config.Store.ValueString()) ||
			(!config.SyncDirection.IsNull() && job.Direction() != config.SyncDirection.ValueString()) {
			continue
		}
		var m syncJobModel
		m.fromSyncJob(job.ID, job, &resp.Diagnostics)
		config.Jobs = append(config.Jobs, m)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
