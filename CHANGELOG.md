# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pbs_apt_repository` resource: enables or disables an existing entry of a
  node's APT source files, addressed by `file_path` and `index`, such as the
  enterprise repository on a host without a subscription — the counterpart
  of `proxmox_apt_repository` in bpg/proxmox, imported by
  `<node>,<file path>,<index>`. It neither adds nor removes an entry:
  creating the resource takes over the entry, and destroying it leaves the
  entry as it is. Every write carries the digest of the source files. Should
  entries before the managed one be added or removed outside Terraform, a
  refresh warns, says where the entry went and keeps it in state, and an
  update refuses to change the entry that took its place.
- `pbs_apt_standard_repository` resource: adds one of PBS's standard
  repositories — `enterprise`, `no-subscription` or `test` — or enables its
  entry when the node has one, and tells where the entry is (`file_path`,
  `index`) for a `pbs_apt_repository`; imported by `<node>,<handle>`.
  Destroying it disables the repository, as PBS cannot remove it; the
  counterpart in bpg/proxmox leaves it enabled. Manage a repository with one
  resource, and move it with a `moved` block.
- `pbs_apt_repositories` data source: every entry of a node's APT source
  files, with the standard repository it belongs to, the standard
  repositories with whether the node has them and where, the files PBS
  cannot parse, and PBS's notes on the entries.
- `pbs_realm_ldap` resource: an LDAP realm, to sign in to PBS with the
  accounts of a directory such as OpenLDAP or FreeIPA, with its servers,
  port, `mode` (`ldap`, `ldaps` or `ldap+starttls`), certificate check
  (`verify`, `capath`), `base_dn`, `bind_dn`, the `user_attr` whose value
  is the user name, and what a sync does with the directory: `filter`,
  `user_classes`, `sync_attributes` and `sync_defaults`. PBS connects to
  the server on every create and update, even of `comment` alone, from its
  own host: it binds as `bind_dn`, reads `base_dn` and saves nothing when
  that fails, and the error says what to check. The bind password is
  write-only (`password_wo` and `password_wo_version`); PBS needs it to
  create a realm with a `bind_dn`, so the plan fails without it, a
  replacement included, while removing it keeps the password PBS has. PBS
  ignores `capath` in an update, so setting, changing or removing it
  replaces the realm; `default = true` takes the flag from the realm that
  had it. Users still come from `pbs_user` or a sync, which the provider
  does not start.
- `pbs_realm_ad` resource: an Active Directory realm, with the attributes of
  `pbs_realm_ldap` but `user_attr`: users sign in as
  `<sAMAccountName>@<realm>`, and `bind_dn` may be a user principal name
  such as `pbs@example.com`. Without `base_dn`, PBS asks the domain
  controller for the domain's naming context when it creates the realm, and
  keeps it.

## [0.2.0] - 2026-10-28

Verified against Proxmox Backup Server 4.0.22, 4.2.0 and 4.2.8. The
requirements are those of 0.1.0, and configurations written for 0.1.0 work
unchanged.

### Added

- `pbs_namespace` resource: a namespace of a datastore, such as `dept1` or
  `dept1/hosts`, imported by `<store>:<namespace>`. It has no settings, so
  any change replaces it. Creating one that exists takes it over, with a
  warning. Destroying it deletes the namespaces below it too; it fails for a
  namespace with backups unless `delete_groups` is set, and for protected
  snapshots unless `error_on_protected = false`, both read from state. While
  a removable datastore is not mounted, a refresh keeps its namespaces in
  state, with a warning.
- Removable datastores in `pbs_datastore`: `backing_device`, the UUID of the
  file system on the disk, with a `path` relative to it, `gc_on_unmount`
  (PBS 4.2), and the computed `mount_status`. They can be imported too; a
  datastore on S3 object storage still cannot.
- Data sources `pbs_datastore` and `pbs_datastores`, the configuration of
  datastores of every kind; `pbs_namespaces`, the namespaces of a datastore
  or below one of them; `pbs_datastore_status`, the size, use and free space
  of a datastore and when PBS expects it to be full; and `pbs_gc_status`,
  the schedule and outcome of a datastore's garbage collection.
- `pbs_notification_endpoint_sendmail` resource: mail handed to the host's
  mail transport agent, with its recipients, sender and author. The
  built-in `mail-to-root` cannot be created, only imported, and destroying
  it resets it to its built-in settings, as `default-matcher` does.
- `pbs_notification_endpoint_gotify` resource: notifications pushed to a
  Gotify server, with a write-only application token (`token_wo` and
  `token_wo_version`).
- `pbs_notification_endpoint_webhook` resource: an HTTP request for every
  notification, with its method, headers and body as templates, and
  secrets for them whose values are write-only. Each secret has a version
  of its own: a change sends the values of new secrets and of those whose
  version changed, and keeps the values PBS has for the others. The
  provider encodes headers and body in base64, as PBS stores them.
- `send_test_on_apply` on every notification endpoint resource, SMTP
  included: PBS sends a test notification through an enabled endpoint
  after every apply that creates or changes it, and a failed test fails the
  apply. An endpoint whose test fails right after its creation is deleted
  again, so that the next apply creates it anew, also under
  `create_before_destroy`. It defaults to `false`.
- Data sources `pbs_notification_targets`, every notification endpoint, and
  `pbs_notification_matcher_fields`, the metadata fields a matcher can
  match with the values PBS knows for them.
- `pbs_remote` resource: another PBS that sync jobs pull from or push to,
  with its host, port, user or API token, certificate fingerprint and use of
  the node's HTTP proxy (`use_node_proxy`, PBS 4.2), and a write-only
  password or token secret (`password_wo` and `password_wo_version`), which
  creating a remote requires. The fingerprint is taken in any case, with or
  without colons, sent as PBS shows it, and a change of spelling alone is no
  change. PBS contacts nothing when it saves a remote; it refuses to delete
  one a sync job uses, and the error says to set `create_before_destroy` when
  a new name replaces it.
- `pbs_sync_job` resource: a sync job of either direction —
  `sync_direction = "pull"`, from a remote or, without `remote`, from another
  local datastore, or `"push"`, to a remote — with its namespaces, depth,
  schedule, owner, `remove_vanished`, group filters, `transfer_last`,
  `encrypted_only`, `verified_only`, `resync_corrupt`, `run_on_mount`,
  `unmount_on_done` (PBS 4.1), `worker_threads` (PBS 4.2) and rate and burst
  limits. A new direction replaces the job. Rate and burst limits are byte
  sizes compared by value, so PBS's own spelling, such as `10 MiB` for
  `10MiB`, is no change. The plan refuses what PBS would: a push without a
  remote, a local pull into its own source, `resync_corrupt` on a push,
  `unmount_on_done` without `run_on_mount`, and a `max_depth` below the
  deepest namespace. A job that PBS deleted with its datastore is created
  again, as prune and verify jobs are. The sync encryption keys of PBS 4.2
  are left alone.
- Data sources `pbs_remote` and `pbs_remotes`, without passwords;
  `pbs_remote_datastores` and `pbs_remote_namespaces`, which have PBS sign in
  to a remote and list what its auth ID may see there, and so check a
  remote; `pbs_sync_job` and `pbs_sync_jobs`, which list pull and push jobs
  alike; `pbs_verify_job`, `pbs_verify_jobs`, `pbs_prune_job` and
  `pbs_prune_jobs`.
- Guide: copy backups to an offsite PBS, by push or by pull, with
  verification and retention offsite.
- `pbs_realm_openid` resource: an OpenID Connect realm, to sign in to PBS
  through an identity provider such as Authentik, with its issuer URL,
  client ID, scopes, ACR values, audiences (PBS 4.2.1), prompt, username
  claim, `autocreate` and `default`. The client key goes either in
  `client_key`, kept in state as sensitive, where a change made outside
  Terraform shows, or in the write-only `client_key_wo` with
  `client_key_wo_version`; a realm created without either is a public
  client. Removing `client_key` deletes the key from PBS, removing
  `client_key_wo` leaves it. A new `username_claim`, which PBS cannot
  change, replaces the realm, and the plan warns when that loses a key the
  configuration leaves to PBS; `default = true` takes the flag from the
  realm that had it. PBS contacts the issuer only when someone signs in,
  not when it saves the realm. Requested in
  [#6](https://github.com/rfdrew/terraform-provider-pbs/issues/6).
- Data source `pbs_realms`: every realm, of every type, with its type,
  comment and whether it is the default.

### Fixed

- A `password_wo` of `pbs_user` or `pbs_notification_endpoint_smtp`, or a
  value in `data` of `pbs_acme_plugin`, that failed validation, for example
  with a trailing line break, was repeated in the error message; it no
  longer is.
- `pbs_acme_account` failed to register an account about once in 128
  times: PBS writes some of the account keys it generates in a form that
  CAs built on go-jose, Let's Encrypt and Pebble among them, refuse as
  malformed ("Parse error reading JWS", or "invalid EC public key, wrong
  length for x" or "for y"). The provider now tries up to three keys in
  all, registering the account again with a new key, unless PBS kept an
  account of that name.
- A null element in a set, list or map — a variable left null in
  `mailto = ["ops@example.com", var.extra]`, say — is refused when the
  configuration is validated. Before, `mailto` and `mailto_user` of the
  sendmail and SMTP endpoints, the sets of `pbs_notification_matcher`,
  `group_filter` of `pbs_sync_job` and `header` and `secret` of
  `pbs_notification_endpoint_webhook` dropped it, and the apply failed with
  "Provider produced inconsistent result after apply"; `domains` of
  `pbs_node_acme` and `data` of `pbs_acme_plugin` failed with a less clear
  error.

## [0.1.0] - 2026-10-28

First release. Verified against Proxmox Backup Server 4.0.22, 4.2.0 and
4.2.8.

### Requirements

- Proxmox Backup Server 4.0 or newer; the provider warns about older
  releases.
- Terraform 1.11 or newer, or OpenTofu 1.11 or newer, the first releases with
  write-only attributes; import by resource identity needs Terraform 1.12.

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
- `pbs_acme_account` resource: an account at an ACME certificate authority,
  Let's Encrypt's production directory by default, agreeing to its terms of
  service with `tos_url`. The provider waits for PBS's tasks that register,
  update and deactivate an account, and reports the CA's error. Only
  `contact` changes in place; a new terms of service URL is recorded without
  contacting the CA, so that Let's Encrypt publishing new terms does not
  register a new account. Destroying the account deactivates it at the CA,
  which cannot be undone; the plan warns about it. Let's Encrypt no longer
  returns contacts, so `contact` stays as configured.
- `pbs_acme_plugin` resource: a DNS challenge plugin, such as Cloudflare's
  `cf` with an API token, whose settings (`data`) are sensitive and in
  state, as PBS returns them. The built-in `standalone` plugin, for HTTP-01,
  can be imported, not created, and destroying it leaves it.
- `pbs_node_acme` resource: the ACME account and the up to five domains of
  a node, each with its plugin and challenge alias. A domain keeps its slot
  in PBS while it stays, so reordering changes nothing; the node's other
  settings are left alone.
- `pbs_node_certificate` resource: the certificate of the web interface and
  API, ordered from the node's ACME account (`source = "acme"`). The
  provider waits for the order and reports why it failed. A refresh reads
  the certificate PBS renewed on its own without planning anything;
  `triggers` orders a new one in place. Destroying it has PBS go back to a
  new self-signed certificate, whose fingerprint the destroy reports.
- `pbs_acme_tos` data source: the terms of service of an ACME directory.
- When the provider has PBS change its certificate, it trusts the new
  certificate for the rest of the run, whatever its TLS settings: it makes
  the change over a connection it trusted before, which PBS keeps on the old
  certificate, and reads the new one over it. Calls that meet the new
  certificate meanwhile wait for the change and go through. The provider
  warns when its settings need changing before the next run, and a failed
  connection explains a certificate that no longer matches
  `tls_cert_fingerprint`. A pinned fingerprint matches the server's own
  certificate only, not one the server sends after it, which anyone could
  send.

[Unreleased]: https://github.com/rfdrew/terraform-provider-pbs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rfdrew/terraform-provider-pbs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rfdrew/terraform-provider-pbs/releases/tag/v0.1.0
