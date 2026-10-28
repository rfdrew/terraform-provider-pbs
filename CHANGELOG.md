# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Provider configuration: an API token or a username and password, TLS
  pinned by certificate fingerprint, a CA file or no verification, node name,
  request and task timeouts, all also from `PBS_*` environment variables.
- `pbs_version` data source: the server's release.
- `pbs_fingerprint` data source: the SHA-256 fingerprint of the certificate
  the server serves, with its subject and validity.
- `pbs_user` resource: a user of any realm, with its comment, names, email,
  whether it is enabled and when it expires, and — for the `pbs` realm — a
  write-only password (`password_wo` and `password_wo_version`). PBS takes a
  password at creation from an API token too, but changes it later only for a
  provider that signs in with a password; with a token, such a change is a
  plan-time error. Destroying a user also removes its own ACL entries, which
  PBS would keep and apply again to a user created later under the same ID;
  that needs `Sys.Audit` on `/access/acl`, without which destroying fails
  rather than leave them behind.
- `pbs_api_token` resource: an API token of a user, with its secret in state
  (sensitive) and a `regenerate` trigger that has PBS replace the secret. The
  token ID is known at plan time.
- `pbs_acl` resource: one role of a user or API token on an ACL path,
  imported by `path|auth_id|role`. Creating an entry that already exists
  fails rather than taking it over, and granting `NoAccess`, which PBS lets
  no other role share, warns about the roles it removed.
- Managing the credentials the provider itself signs in with: after it
  changes its own password or regenerates its own API token's secret, the
  provider goes on with the new one for the rest of the run, and warns that
  its configuration needs updating.
- Data sources `pbs_user`, `pbs_users`, `pbs_api_tokens`, `pbs_acl`,
  `pbs_roles` and `pbs_permissions`, the last for what a user or token may
  actually do on a path.
- `pbs_datastore` resource: a datastore in a directory, with its comment,
  garbage collection schedule, verification of new backups, notification
  mode and legacy mail settings, tuning options and maintenance mode. The
  provider waits for PBS's tasks that create and delete a datastore, up to
  `task_timeout`, and reports the task's error when one fails.
  `reuse_datastore` creates the datastore on a chunk store a destroyed one
  left behind, keeping its backups. Destroying a datastore keeps its
  backups unless `destroy_data` is set, and deletes its jobs and ACL
  entries, as PBS does, unless `keep_job_configs` is set; a plan that
  replaces a datastore warns about that, and a new name in the same
  directory, which PBS cannot do without reusing the old chunk store, is a
  plan-time error unless `reuse_datastore` is set. A deletion PBS ends with
  warnings, keeping the datastore, is an error. Maintenance modes PBS sets
  itself while it unmounts, refreshes or deletes a datastore are not
  reported as drift. Datastores on S3 object storage and removable
  datastores are not supported yet.
- `pbs_prune_job` resource: a prune job of a datastore or of a namespace in
  it, with its schedule and namespace depth. Retention lives here, in
  `keep`: how many of the last backups and of the last backups of each
  hour, day, week, month and year to keep. A job PBS deleted with its
  datastore is created again: in the same apply when it follows the
  datastore's new name, otherwise on the next.
- `pbs_verify_job` resource: a verify job of a datastore or of a namespace
  in it, with its schedule, whether to skip backups verified before and
  after how many days to verify them again. Its thread counts,
  `read_threads` and `verify_threads`, need PBS 4.1. Like a prune job, it
  follows a renamed datastore.
- `pbs_notification_endpoint_smtp` resource: a mail server PBS sends
  notifications through, with its connection security, port, sender and
  recipients, by address or by user, and a write-only password
  (`password_wo` and `password_wo_version`).
- `pbs_notification_matcher` resource: a rule that routes notifications by
  severity, field and time to endpoints. The built-in `default-matcher`,
  which PBS neither creates nor deletes, is managed by importing it, and
  destroying the resource resets it to its built-in settings, which send
  everything but successful prune jobs to `mail-to-root`.
- Attributes for properties newer than PBS 4.0 — so far the verify job's
  thread counts and the datastore's defaults for them, from 4.1 — are
  checked against the server's version at plan time: the plan fails with
  the release the attribute needs instead of PBS refusing the request.
- All resources import by ID and, from Terraform 1.12, by resource
  identity.
