package pbsclient

import (
	"context"
	"net/url"
)

// Prune and verify jobs work on one datastore, or a namespace of it, on a
// schedule; prune jobs live in prune.cfg, verify jobs in verification.cfg.
// What PBS 4.0 and 4.2 do, as observed on real servers:
//
//   - A read leaves out every property at its default: a verify job created
//     with only its ID and datastore reads as {id, store}, without
//     max-depth, ignore-verified or the thread counts.
//   - A missing job is 400 "no such prune 'x'" or "no such verification
//     'x'", on GET and DELETE alike; IsNotFound covers them.
//   - Deleting a datastore deletes its jobs too, unless keep-job-configs is
//     set.

// KeepOptions say how many backups of each kind a prune keeps. Unset kinds
// are not kept for their own sake.
type KeepOptions struct {
	KeepLast    *int64 `json:"keep-last,omitempty"`
	KeepHourly  *int64 `json:"keep-hourly,omitempty"`
	KeepDaily   *int64 `json:"keep-daily,omitempty"`
	KeepWeekly  *int64 `json:"keep-weekly,omitempty"`
	KeepMonthly *int64 `json:"keep-monthly,omitempty"`
	KeepYearly  *int64 `json:"keep-yearly,omitempty"`
}

// PruneJob is a prune job as PBS reports it.
type PruneJob struct {
	ID       string `json:"id"`
	Store    string `json:"store"`
	Schedule string `json:"schedule"`
	// NS is the namespace, empty for the datastore's root.
	NS string `json:"ns,omitempty"`
	// MaxDepth is how many levels of namespaces below NS the job covers;
	// unset means all.
	MaxDepth *int64 `json:"max-depth,omitempty"`
	Disable  *bool  `json:"disable,omitempty"`
	Comment  string `json:"comment,omitempty"`
	KeepOptions
}

// VerifyJob is a verify job as PBS reports it.
type VerifyJob struct {
	ID    string `json:"id"`
	Store string `json:"store"`
	// NS is the namespace, empty for the datastore's root.
	NS string `json:"ns,omitempty"`
	// MaxDepth is how many levels of namespaces below NS the job covers;
	// unset means 7, all of them.
	MaxDepth       *int64 `json:"max-depth,omitempty"`
	Schedule       string `json:"schedule,omitempty"`
	IgnoreVerified *bool  `json:"ignore-verified,omitempty"`
	OutdatedAfter  *int64 `json:"outdated-after,omitempty"`
	ReadThreads    *int64 `json:"read-threads,omitempty"`
	VerifyThreads  *int64 `json:"verify-threads,omitempty"`
	Comment        string `json:"comment,omitempty"`
}

// ListPruneJobs lists the prune jobs the caller may audit.
func (c *Client) ListPruneJobs(ctx context.Context) ([]PruneJob, error) {
	var jobs []PruneJob
	_, err := c.Get(ctx, "/config/prune", nil, &jobs)
	return jobs, err
}

// GetPruneJob reads one prune job.
func (c *Client) GetPruneJob(ctx context.Context, id string) (PruneJob, error) {
	var job PruneJob
	_, err := c.Get(ctx, Path("config", "prune", id), nil, &job)
	return job, err
}

// CreatePruneJob creates a prune job from params, which must hold "id",
// "store" and "schedule".
func (c *Client) CreatePruneJob(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/prune", params, nil)
	return err
}

// UpdatePruneJob changes the properties params carries, and deletes those
// named in its delete parameter.
func (c *Client) UpdatePruneJob(ctx context.Context, id string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "prune", id), params, nil)
	return err
}

// DeletePruneJob deletes a prune job.
func (c *Client) DeletePruneJob(ctx context.Context, id string) error {
	_, err := c.Delete(ctx, Path("config", "prune", id), nil, nil)
	return err
}

// ListVerifyJobs lists the verify jobs the caller may audit.
func (c *Client) ListVerifyJobs(ctx context.Context) ([]VerifyJob, error) {
	var jobs []VerifyJob
	_, err := c.Get(ctx, "/config/verify", nil, &jobs)
	return jobs, err
}

// GetVerifyJob reads one verify job.
func (c *Client) GetVerifyJob(ctx context.Context, id string) (VerifyJob, error) {
	var job VerifyJob
	_, err := c.Get(ctx, Path("config", "verify", id), nil, &job)
	return job, err
}

// CreateVerifyJob creates a verify job from params, which must hold "id" and
// "store".
func (c *Client) CreateVerifyJob(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/verify", params, nil)
	return err
}

// UpdateVerifyJob changes the properties params carries, and deletes those
// named in its delete parameter.
func (c *Client) UpdateVerifyJob(ctx context.Context, id string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "verify", id), params, nil)
	return err
}

// DeleteVerifyJob deletes a verify job.
func (c *Client) DeleteVerifyJob(ctx context.Context, id string) error {
	_, err := c.Delete(ctx, Path("config", "verify", id), nil, nil)
	return err
}
