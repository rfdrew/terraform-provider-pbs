package provider

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource                   = &tasksDataSource{}
	_ datasource.DataSourceWithConfigure      = &tasksDataSource{}
	_ datasource.DataSourceWithValidateConfig = &tasksDataSource{}
)

// The worker tasks of PBS — backups, garbage collections, job runs and the
// rest of what it does in the background — are operational data, which
// pbs_tasks lists and pbs_task reads one of; pbsclient/task_list.go sums up
// what PBS does. Both report times in RFC 3339 format, which timecmp() and
// timeadd() work with, plus a duration in seconds, rather than the seconds
// since the epoch of pbs_gc_status: HCL cannot turn a time into a number,
// nor subtract one from another.

// tasksDefaultLimit is how many tasks pbs_tasks lists without a limit, as
// PBS does.
const tasksDefaultLimit = 50

// taskVisibilityPath is the ACL path whose Sys.Audit shows every task.
const taskVisibilityPath = "/system/tasks"

// taskVisibilityDescription is what both data sources say about which
// tasks PBS shows (check_task_access and check_job_privs,
// src/api2/node/tasks.rs, proxmox-backup 7c86c5ad5, after 4.2.11).
const taskVisibilityDescription = "PBS lists only the tasks the provider's user or API token may see, and leaves " +
	"out the others without an error. With `Sys.Audit` on `/system/tasks` — the `Audit` or `Admin` role on `/`, " +
	"`/system` or `/system/tasks`, with propagation, as ACL entries have by default — it sees every task. Without " +
	"it, it sees the tasks it started itself — a user also those of its API tokens, a token only its own — and " +
	"the tasks of jobs it holds the privileges of: sync jobs (`Datastore.Backup` on the local datastore, and " +
	"`Remote.Read` on the remote datastore or, for a local job, `Datastore.Backup` on the source; PBS checks these " +
	"for push jobs too), verify jobs (`Datastore.Verify` on the datastore), and garbage collection, prunes and " +
	"prune jobs (`Datastore.Modify` on the datastore). Scheduled runs belong to `root@pam`. `Datastore.Audit` " +
	"shows no task of anyone else: backups, restores and verifications started by others stay hidden. " +
	"`sees_all_tasks` of `pbs_tasks` tells which case applies, as `pbs_permissions` with `path = \"/system/tasks\"` " +
	"does."

// taskAccessRule completes the error of a task PBS will not show.
const taskAccessRule = "PBS shows a task to the user or API token that started it, to that token's user, and to " +
	"holders of Sys.Audit on /system/tasks or of the privileges of the job the task runs: Datastore.Verify for " +
	"a verify job, the privileges of a pull for a sync job, Datastore.Modify for garbage collection and prunes."

// NewTasksDataSource returns the pbs_tasks data source.
func NewTasksDataSource() datasource.DataSource { return &tasksDataSource{} }

type tasksDataSource struct {
	data *providerData
}

type tasksDataSourceModel struct {
	Node         types.String `tfsdk:"node"`
	Store        types.String `tfsdk:"store"`
	WorkerType   types.String `tfsdk:"worker_type"`
	AuthID       types.String `tfsdk:"auth_id"`
	Status       types.Set    `tfsdk:"status"`
	Running      types.Bool   `tfsdk:"running"`
	Since        types.String `tfsdk:"since"`
	Until        types.String `tfsdk:"until"`
	Limit        types.Int64  `tfsdk:"limit"`
	SeesAllTasks types.Bool   `tfsdk:"sees_all_tasks"`
	Tasks        []taskModel  `tfsdk:"tasks"`
}

// taskModel is a task: an element of pbs_tasks, and what pbs_task reads.
type taskModel struct {
	UPID       types.String `tfsdk:"upid"`
	WorkerType types.String `tfsdk:"worker_type"`
	WorkerID   types.String `tfsdk:"worker_id"`
	AuthID     types.String `tfsdk:"auth_id"`
	StartTime  types.String `tfsdk:"start_time"`
	EndTime    types.String `tfsdk:"end_time"`
	Duration   types.Int64  `tfsdk:"duration"`
	Status     types.String `tfsdk:"status"`
	ExitStatus types.String `tfsdk:"exit_status"`
}

// taskStatuses are how a task can end, which `status` filters by.
var taskStatuses = []string{pbsclient.TaskStateOK, pbsclient.TaskStateWarning, pbsclient.TaskStateError, pbsclient.TaskStateUnknown}

// taskAttributes are the attributes of a task, all computed.
func taskAttributes() map[string]schema.Attribute {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	return map[string]schema.Attribute{
		"upid": computedString("Task ID (UPID), which `pbs_task` reads the task by."),
		"worker_type": computedString("Type of the task, such as `garbage_collection`, `verificationjob`, " +
			"`syncjob`, `prunejob`, `backup`, `reader` (a restore) or `aptupdate`."),
		"worker_id": computedString("What the task works on, as PBS names it by type: the datastore of a garbage " +
			"collection, `<datastore>:<job>` of a verify job, `<remote>:<remote datastore>:<datastore>:<namespace>:<job>` " +
			"of a sync job (`-` as the remote of a local one, and the namespace empty for the root), `<datastore>` or " +
			"`<datastore>:<namespace>` of a prune job; null for a task without one, such as `aptupdate`. The tasks of " +
			"one sync or verify job end in `:<job>`."),
		"auth_id": computedString("User or API token that started the task, such as `root@pam`, which " +
			"scheduled jobs run as, or `backup@pbs!ci`."),
		"start_time": computedString("When the task started, in RFC 3339 format (UTC)."),
		"end_time": computedString("When the task ended, in RFC 3339 format (UTC); null while it runs. For a task " +
			"PBS lost track of, the time of the last line of its log that has one, or `start_time`."),
		"duration": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "How long the task ran, in seconds: `end_time` minus `start_time`; null while it runs.",
		},
		"status": computedString("`running`, or how the task ended: `ok`, `warning`, `error`, or `unknown` when " +
			"PBS lost track of it, because PBS was stopped while it ran, say. PBS before 4.1 may report a task whose " +
			"error has several lines as `unknown` too."),
		"exit_status": computedString("How the task ended, as PBS words it: `OK`, `WARNINGS: <count>`, `unknown`, " +
			"or the first line of the error; null while it runs."),
	}
}

// newTaskModel builds the state of a task. end and exit are nil while it
// runs.
func newTaskModel(upid, workerType, workerID, authID string, start int64, end *int64, exit *string) taskModel {
	model := taskModel{
		UPID:       types.StringValue(upid),
		WorkerType: types.StringValue(workerType),
		WorkerID:   stringOrNull(workerID),
		AuthID:     types.StringValue(authID),
		StartTime:  epochToRFC3339(start),
		EndTime:    types.StringNull(),
		Duration:   types.Int64Null(),
		Status:     types.StringValue(pbsclient.TaskStateRunning),
		ExitStatus: types.StringNull(),
	}
	if exit != nil {
		model.Status = types.StringValue(pbsclient.TaskStateOf(*exit))
		model.ExitStatus = types.StringValue(*exit)
	}
	if end != nil && *end > 0 {
		model.EndTime = epochToRFC3339(*end)
		model.Duration = types.Int64Value(*end - start)
	}
	return model
}

// taskFromListItem is the state of a task pbs_tasks lists.
func taskFromListItem(task pbsclient.TaskListItem) taskModel {
	return newTaskModel(task.UPID, task.WorkerType, task.WorkerID, task.User, task.StartTime, task.EndTime, task.Status)
}

func (d *tasksDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tasks"
}

func (d *tasksDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the worker tasks of a Proxmox Backup Server node — backups, garbage " +
			"collections, verifications, prunes, syncs and the other work PBS does in the background — as " +
			"Administration → Tasks shows them: running tasks first, the most recently started first, then " +
			"finished tasks, the most recently ended first. It is meant for `check` blocks and outputs: whether a " +
			"task failed lately, when a datastore was last verified, whether anything runs before maintenance. " +
			"It reads what PBS has when Terraform reads it, on every plan, and never waits for a task; the actions " +
			"that start a task wait for it. Use `plantimestamp()` in `since` rather than `timestamp()`, which is " +
			"known only on apply and puts the read off until then.\n\n" +
			"Times are in RFC 3339 format, for `timecmp()` and `timeadd()`, unlike the seconds since the Unix epoch " +
			"of `pbs_gc_status`. There is no filter by job: the tasks of a sync or verify job are those whose " +
			"`worker_id` ends in `:<job>`, such as " +
			"`[for t in data.pbs_tasks.this.tasks : t if endswith(coalesce(t.worker_id, \"-\"), \":nightly\")]`.\n\n" +
			"PBS keeps finished tasks in its task archive: with `task_log_max_days` of `pbs_node_config` set, for " +
			"at least that many days, however many tasks that is; without it, the most recent 20 files of up to " +
			"512 KiB, more than 100 000 tasks. It removes a task's log with the task.\n\n" +
			taskVisibilityDescription,
		Attributes: map[string]schema.Attribute{
			"node": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Node to read: `localhost` or the node's host name. Defaults to the provider's `node`.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 63),
					stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
				},
			},
			"store": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "List only the tasks of this datastore, such as `store1`: its backups, garbage " +
					"collections, prunes and prune jobs, verifications of every kind, and the runs of sync jobs whose " +
					"local datastore it is (the target of a pull, the source of a push). PBS counts no other task as a " +
					"datastore's: not restores (`reader`), syncs started by hand (`sync`), creating, removing, mounting " +
					"or unmounting the datastore, or S3 refreshes. A datastore PBS does not have lists no task.",
				Validators: safeIDValidators(minSafeIDLength),
			},
			"worker_type": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "List only the tasks of this type, such as `garbage_collection`, " +
					"`verificationjob`, `syncjob`, `prunejob`, `backup` or `aptupdate`. The type must match exactly: " +
					"`prune` does not list `prunejob` tasks.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.RegexMatches(workerTypePattern, "must be a worker type such as garbage_collection, without colons or white space"),
				},
			},
			"auth_id": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "List only the tasks this user or API token started, such as `root@pam`, which " +
					"scheduled jobs run as, or `backup@pbs!ci`. A user ID lists the tasks of the user's API tokens too.",
				Validators: authIDValidators(),
			},
			"status": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				MarkdownDescription: "List only finished tasks that ended in one of these ways: `ok`, `warning`, " +
					"`error`, or `unknown` (PBS lost track of the task, because PBS was stopped while it ran, say). " +
					"Running tasks are left out, so `running = true` cannot be combined with it.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(stringvalidator.OneOf(taskStatuses...)),
				},
			},
			"running": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether to list only running tasks. It cannot be `true` together with `status`.",
			},
			"since": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "List only the tasks that started at or after this time, in RFC 3339 format, " +
					"such as `timeadd(plantimestamp(), \"-24h\")`. PBS stops reading its task archive at the first " +
					"task that ended before it, which keeps the read quick.",
				Validators: []validator.String{rfc3339Validator()},
			},
			"until": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "List only the tasks that started at or before this time, in RFC 3339 format.",
				Validators:          []validator.String{rfc3339Validator()},
			},
			"limit": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many tasks to list at most, the most recent first. Defaults to `50`, as in " +
					"PBS. `0` lists every task that matches, which can be many thousands and has PBS read its whole " +
					"task archive: combine it with `since`.",
				Validators: []validator.Int64{int64validator.AtLeast(0)},
			},
			"sees_all_tasks": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "Whether the provider's user or API token has `Sys.Audit` on `/system/tasks`, " +
					"and so sees every task; false when PBS leaves out the tasks it may not see. A `check` that no " +
					"task failed should assert it too.",
			},
			"tasks": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The tasks, in PBS's order: running tasks first, the most recently started " +
					"first, then finished tasks, the most recently ended first.",
				NestedObject: schema.NestedAttributeObject{Attributes: taskAttributes()},
			},
		},
	}
}

func (d *tasksDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// tasksRunningWithStatus reports that `running = true` was set with
// `status`, which together list nothing: PBS leaves out every running task
// when it filters by how tasks ended. `running = false` with it is fine.
func tasksRunningWithStatus(running types.Bool, status types.Set, diags *diag.Diagnostics) {
	if running.ValueBool() && !status.IsNull() && !status.IsUnknown() {
		diags.AddAttributeError(path.Root("running"), "Invalid Attribute Combination",
			"`running = true` lists running tasks, and `status` finished tasks, which PBS lists without the "+
				"running ones: set one of them.")
	}
}

func (d *tasksDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var running types.Bool
	var status types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("running"), &running)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("status"), &status)...)
	if !resp.Diagnostics.HasError() {
		tasksRunningWithStatus(running, status, &resp.Diagnostics)
	}
}

// taskTime parses a configured time into seconds since the epoch, rounded
// up when ceil is set and down otherwise: PBS keeps start times in whole
// seconds. It returns nil for a null value.
func taskTime(value types.String, attribute string, ceil bool, diags *diag.Diagnostics) *int64 {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	t, err := time.Parse(time.RFC3339, value.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root(attribute), "Invalid Attribute Value",
			fmt.Sprintf("Attribute %s must be a time in RFC 3339 format, such as 2026-11-14T00:00:00Z: %s", attribute, err))
		return nil
	}
	seconds := t.Unix()
	if ceil && t.Nanosecond() > 0 {
		seconds++
	}
	return &seconds
}

// taskMatch returns what pbs_tasks keeps of the tasks PBS lists for the
// filters PBS matches as a part of the value: the worker type exactly, and
// the auth ID exactly or, for a user ID, as the user of a token. It is nil
// when neither is set.
func taskMatch(workerType, authID string) func(pbsclient.TaskListItem) bool {
	if workerType == "" && authID == "" {
		return nil
	}
	_, _, authIDIsToken := pbsclient.SplitTokenID(authID)
	return func(task pbsclient.TaskListItem) bool {
		if workerType != "" && task.WorkerType != workerType {
			return false
		}
		if authID == "" || task.User == authID {
			return true
		}
		user, _, isToken := pbsclient.SplitTokenID(task.User)
		return !authIDIsToken && isToken && user == authID
	}
}

// seesAllTasks reports whether the client's user or token has Sys.Audit on
// /system/tasks, and so sees every task. PBS leaves a path the caller has
// no privilege on out of the answer.
func seesAllTasks(ctx context.Context, client *pbsclient.Client) (bool, error) {
	permissions, err := client.Permissions(ctx, "", taskVisibilityPath)
	if err != nil {
		return false, err
	}
	_, ok := permissions[taskVisibilityPath]["Sys.Audit"]
	return ok, nil
}

func (d *tasksDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config tasksDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tasksRunningWithStatus(config.Running, config.Status, &resp.Diagnostics)
	client := d.data.client
	node := config.Node.ValueString()
	if node == "" {
		node = client.Node()
	}

	// PBS matches typefilter and userfilter as a part of the type and the
	// auth ID; they narrow its answer, and taskMatch keeps the exact ones.
	filter := pbsclient.TaskListFilter{
		Store:      config.Store.ValueString(),
		TypeFilter: config.WorkerType.ValueString(),
		UserFilter: config.AuthID.ValueString(),
		Running:    config.Running.ValueBool(),
		Since:      taskTime(config.Since, "since", true, &resp.Diagnostics),
		Until:      taskTime(config.Until, "until", false, &resp.Diagnostics),
		Limit:      tasksDefaultLimit,
	}
	if !config.Limit.IsNull() {
		filter.Limit = int(config.Limit.ValueInt64())
	}
	if !config.Status.IsNull() {
		resp.Diagnostics.Append(config.Status.ElementsAs(ctx, &filter.Statuses, false)...)
		slices.Sort(filter.Statuses)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tasks, err := client.ListTasksMatching(ctx, node, filter, taskMatch(filter.TypeFilter, filter.UserFilter))
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS tasks", apiErrorDetail(client, "", err))
		return
	}
	seesAll, err := seesAllTasks(ctx, client)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS privileges of "+strconv.Quote(client.AuthID()),
			"pbs_tasks reads them to tell whether PBS lists every task. "+apiErrorDetail(client, "", err))
		return
	}

	// PBS's order is kept: limit takes the most recent tasks.
	config.Node = types.StringValue(node)
	config.SeesAllTasks = types.BoolValue(seesAll)
	config.Tasks = make([]taskModel, 0, len(tasks))
	for _, task := range tasks {
		config.Tasks = append(config.Tasks, taskFromListItem(task))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
