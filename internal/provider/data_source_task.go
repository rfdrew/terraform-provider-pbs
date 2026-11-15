package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &taskDataSource{}
	_ datasource.DataSourceWithConfigure = &taskDataSource{}
)

// taskEndLogLines is how many lines at the end of a task's log pbs_task
// reads to work out when the task ended, which PBS reports only from 4.2.1
// on (commit 2683bca43). PBS itself reads the last 8 KiB
// (upid_read_status, proxmox-rest-server worker_task.rs); an error with
// more lines than this below its TASK ERROR line ends at the start time
// instead.
const taskEndLogLines = 50

// maxTaskLogLines is the most lines `log_lines` asks for.
const maxTaskLogLines = 1000

// NewTaskDataSource returns the pbs_task data source.
func NewTaskDataSource() datasource.DataSource { return &taskDataSource{} }

type taskDataSource struct {
	data *providerData
}

type taskDataSourceModel struct {
	taskModel
	LogLines types.Int64 `tfsdk:"log_lines"`
	Log      types.List  `tfsdk:"log"`
}

func (d *taskDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_task"
}

func (d *taskDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attributes := taskAttributes()
	attributes["upid"] = schema.StringAttribute{
		Required: true,
		MarkdownDescription: "Task ID (UPID) to read, such as `upid` of `pbs_gc_status` or of an element of " +
			"`pbs_tasks`: `UPID:<node>:<pid>:<pstart>:<task ID>:<start time>:<type>:<worker ID>:<auth ID>:`.",
		Validators: []validator.String{upidValidator()},
	}
	attributes["log_lines"] = schema.Int64Attribute{
		Optional: true,
		MarkdownDescription: fmt.Sprintf("How many lines at the end of the task's log to read into `log`, 1 to "+
			"%d. Leave it out to read no log.", maxTaskLogLines),
		Validators: []validator.Int64{int64validator.Between(1, maxTaskLogLines)},
	}
	attributes["log"] = schema.ListAttribute{
		Computed:    true,
		ElementType: types.StringType,
		MarkdownDescription: "The last `log_lines` lines of the task's log, as PBS wrote them. A line starts " +
			"with the time it was written, such as `2026-11-14T10:00:00+01:00: starting garbage collection on store " +
			"store1`, except the further lines of a message of several lines, which have none. A finished task's " +
			"last line with a time is `TASK OK`, `TASK WARNINGS: <count>` or `TASK ERROR: <error>`, and an error of " +
			"several lines goes on below it. Null without `log_lines`.",
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads one worker task of a Proxmox Backup Server by its ID — such as `upid` of " +
			"`pbs_gc_status` or of an element of `pbs_tasks` — with whether it still runs, how it ended and, with " +
			"`log_lines`, the end of its log. It does not wait for the task. A task PBS no longer knows — its log " +
			"removed with the oldest tasks of its archive, after `task_log_max_days` of `pbs_node_config`, say, or " +
			"a task of another server — is an error, which a `check` block turns into a warning.\n\n" +
			"Reading a task needs to be the user or API token that started it, or that token's user, or " +
			"`Sys.Audit` on `/system/tasks`, or the privileges of the job the task runs, as `pbs_tasks` describes; " +
			"PBS answers anyone else \"task access not allowed\".",
		Attributes: attributes,
	}
}

func (d *taskDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *taskDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config taskDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := d.data.client
	upid, err := pbsclient.ParseUPID(config.UPID.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("upid"), "Invalid PBS task ID", err.Error())
		return
	}

	// The status is read on the node the UPID names, as PBS reports it.
	status, err := client.TaskStatus(ctx, upid)
	switch {
	case pbsclient.IsTaskAccessDenied(err):
		resp.Diagnostics.AddError("Unable to read PBS task",
			fmt.Sprintf("%q may not read task %s. %s %s", client.AuthID(), upid.Raw, taskAccessRule, err))
		return
	case err != nil:
		resp.Diagnostics.AddError("Unable to read PBS task", apiErrorDetail(client, "", err))
		return
	}

	logLines := int(config.LogLines.ValueInt64())
	var tail []pbsclient.TaskLogLine
	readTail := func(n int) bool {
		lines, err := client.TaskLogTail(ctx, upid, n)
		switch {
		case pbsclient.IsNotFound(err):
			// 400 "No such file or directory (os error 2)".
			resp.Diagnostics.AddAttributeError(path.Root("upid"), "PBS task not found",
				fmt.Sprintf("PBS has no log of task %s: it removed the log with the oldest tasks of its archive, "+
					"after task_log_max_days of pbs_node_config, say, or the task ran on another server. %s", upid.Raw, err))
			return false
		case err != nil:
			resp.Diagnostics.AddError("Unable to read the log of PBS task", apiErrorDetail(client, "", err))
			return false
		}
		tail = lines
		return true
	}

	running := status.Status == pbsclient.TaskStateRunning
	end := status.EndTime
	var exit *string
	if !running {
		exit = &status.ExitStatus
	}
	switch {
	case !running && end == nil:
		// PBS reports the end time from 4.2.1 on, and never for a task it
		// has no log of: as PBS does, the end is the time of the last line
		// of the log that has one, or the start time when none has. The
		// same read tells a task PBS does not know, which it reports as
		// "unknown", from one that ended so.
		if !readTail(max(logLines, taskEndLogLines)) {
			return
		}
		ended, ok := pbsclient.TaskEndFromLog(tail)
		if !ok {
			ended = status.StartTime
		}
		end = &ended
	case logLines > 0:
		if !readTail(logLines) {
			return
		}
	}

	workerType, authID := status.Type, status.AuthID()
	if workerType == "" {
		workerType = upid.WorkerType
	}
	if status.User == "" {
		authID = upid.AuthID
	}
	model := taskDataSourceModel{
		taskModel: newTaskModel(upid.Raw, workerType, status.ID, authID, status.StartTime, end, exit),
		LogLines:  config.LogLines,
		Log:       types.ListNull(types.StringType),
	}
	if logLines > 0 {
		texts := []string{}
		for _, line := range tail[max(len(tail)-logLines, 0):] {
			texts = append(texts, line.Text)
		}
		list, diags := types.ListValueFrom(ctx, types.StringType, texts)
		resp.Diagnostics.Append(diags...)
		model.Log = list
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
