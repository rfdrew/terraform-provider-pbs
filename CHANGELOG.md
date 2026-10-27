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
- The three resources import by ID and, from Terraform 1.12, by resource
  identity.
