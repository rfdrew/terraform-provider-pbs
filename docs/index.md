---
page_title: "Provider: Proxmox Backup Server"
description: |-
  Manage the configuration of a Proxmox Backup Server through its REST API.
---

# Proxmox Backup Server Provider

Manages the configuration of a
[Proxmox Backup Server](https://www.proxmox.com/en/products/proxmox-backup-server/overview)
(PBS) through its REST API.

-> **Proxmox Backup Server, not PBS Professional.** Several providers on the
registries are called `pbs`. This one, `rfdrew/pbs`, is an independent
implementation for Proxmox Backup Server: it is not a fork of
`mcfitz2/pbs` or `yavasura/pbs` and does not share state with them, and it
has nothing to do with `DaveTCode/pbs`, which manages Altair PBS Professional.

## Compatibility

The provider is built and verified against **PBS 4.2.8**, and tested against
the 4.0 and 4.2 release lines. PBS 4.0 and newer are supported; the provider
warns when the server reports an older release. PBS 3 reached its end of life
in August 2026.

| Supported PBS | Terraform | OpenTofu |
| --- | --- | --- |
| 4.0 and newer | 1.11+ | 1.11+ |

Terraform and OpenTofu 1.11 are the first releases with write-only
attributes, which the provider uses for passwords and other secrets that PBS
never returns.

## What it manages

* **Access** — users (`pbs_user`), their API tokens (`pbs_api_token`) and
  the roles they have on ACL paths (`pbs_acl`), and OpenID Connect realms,
  to sign in through an identity provider such as Authentik
  (`pbs_realm_openid`); to read them, `pbs_user`, `pbs_users`,
  `pbs_api_tokens`, `pbs_acl`, `pbs_roles`, `pbs_permissions`, which shows
  what a user or token may actually do, and `pbs_realms`. LDAP and Active
  Directory realms are not supported yet.
* **Datastores** — datastores in a directory, on a removable disk or on S3
  object storage (`pbs_datastore`), the S3 endpoints those on S3 use
  (`pbs_s3_endpoint`), their namespaces (`pbs_namespace`), and the jobs
  that look after them: prune jobs (`pbs_prune_job`), which hold the
  retention, and verify jobs (`pbs_verify_job`); to read them,
  `pbs_datastore`, `pbs_datastores`, `pbs_namespaces`, `pbs_s3_endpoint`,
  `pbs_s3_endpoints` and `pbs_s3_buckets`, which lists the buckets an
  endpoint reaches, and how they are doing, `pbs_datastore_status` and
  `pbs_gc_status`.
* **Notifications** — endpoints that deliver notifications: by the host's
  sendmail (`pbs_notification_endpoint_sendmail`), the built-in
  `mail-to-root` included, by SMTP (`pbs_notification_endpoint_smtp`), to
  Gotify (`pbs_notification_endpoint_gotify`) and as webhooks
  (`pbs_notification_endpoint_webhook`), each able to send a test
  notification on apply; and the matchers that route notifications to them
  (`pbs_notification_matcher`), the built-in `default-matcher` included.
  Built-in entries are managed by importing them. `pbs_notification_targets`
  and `pbs_notification_matcher_fields` read the endpoints and what
  matchers can match.
* **Certificate** — a certificate from Let's Encrypt or another ACME CA for
  the web interface and API: the account at the CA (`pbs_acme_account`),
  a DNS challenge plugin such as Cloudflare's (`pbs_acme_plugin`), the
  node's domains (`pbs_node_acme`) and the certificate itself
  (`pbs_node_certificate`), which PBS renews on its own; `pbs_acme_tos`
  reads a CA's terms of service. CAs that require External Account Binding
  are not supported yet.
* **Replication** — other PBS servers as remotes (`pbs_remote`), and sync
  jobs that pull backups from them, push backups to them or copy them
  between two datastores of one server (`pbs_sync_job`), with the keys
  push jobs encrypt the backups with (`pbs_sync_encryption_key`, PBS 4.2);
  to read them, `pbs_remote`, `pbs_remotes`, `pbs_sync_job`,
  `pbs_sync_jobs` and `pbs_sync_encryption_keys`, and
  `pbs_remote_datastores` and `pbs_remote_namespaces`, which sign in to a
  remote and list what it holds. `pbs_verify_job`, `pbs_verify_jobs`,
  `pbs_prune_job` and `pbs_prune_jobs` read the other jobs.
* **Traffic control** — bandwidth limits on the connections of clients by
  network, user and time of day (`pbs_traffic_control_rule`); to read them,
  `pbs_traffic_control_rule` and `pbs_traffic_control_rules`.
* **APT repositories** — the standard Proxmox repositories of the node
  (`pbs_apt_standard_repository`), such as `no-subscription` for a host
  without a subscription, and whether an entry of its APT source files is
  enabled (`pbs_apt_repository`), such as the enterprise repository PBS
  installs; `pbs_apt_repositories` lists the entries and the standard
  repositories. PBS cannot remove an entry, only disable it.
* **Read-only information** — `pbs_version`, the server's release, and
  `pbs_fingerprint`, the SHA-256 fingerprint of its certificate, which
  Proxmox VE and other PBS servers pin it by.

The usual first step is access for a Proxmox VE cluster: a user, an API
token for it, and the role to back up to a datastore, for the token and its
user both.

```terraform
resource "pbs_user" "pve" {
  userid  = "pve@pbs"
  comment = "PVE cluster"
}

resource "pbs_api_token" "pve" {
  userid     = pbs_user.pve.userid
  token_name = "cluster1"
}

resource "pbs_acl" "pve_user" {
  path    = "/datastore/store1"
  auth_id = pbs_user.pve.userid
  role    = "DatastoreBackup"
}

resource "pbs_acl" "pve_token" {
  path    = "/datastore/store1"
  auth_id = pbs_api_token.pve.tokenid
  role    = "DatastoreBackup"
}
```

Proxmox VE then signs in to PBS with the token ID, `pve@pbs!cluster1`, as the
user name and the token's secret, `pbs_api_token.pve.value`, as the password.

The guide **Set up PBS for a Proxmox VE cluster** goes the whole way, in one
configuration: a datastore with prune and verify
jobs, notifications by mail, this access, outputs with what the storage
in Proxmox VE needs, and a certificate from Let's Encrypt. The guide
**Copy backups to an offsite PBS** adds a second server, with a remote and
a sync job, and the guide **Back up to S3 object storage** puts a datastore
on an S3-compatible object store.

## Authentication

The provider signs in either with an **API token**, the usual choice, or
with a **username and password**.

* **An API token has no privileges of its own.** Besides its user's ACL
  entries, it needs entries for the token ID (`user@realm!name`) itself —
  for instance `Admin` on `/` for a token that manages the whole server.
* **A few calls are closed to API tokens** — changing a user's password, and
  creating network interfaces, which only `root@pam` may do. The resources
  that make them say so.
* **A user with two-factor authentication cannot sign in with a password**:
  the provider cannot complete the second factor. Use an API token instead.

Prefer the environment over configuration, so that the token stays out of
your configuration and version control:

```shell
export PBS_ENDPOINT="https://pbs.example.com:8007"
export PBS_API_TOKEN="terraform@pbs!provider:3f0c6c1e-8a0e-4bd2-9c7e-0c5f8b5a7f11"
export PBS_TLS_FINGERPRINT="2f:f2:f7:e9:8b:a5:62:fe:bb:6d:63:40:33:8b:4a:97:e6:d4:80:5d:f9:96:b9:63:ee:4c:08:31:c2:d0:00:5c"
```

PBS generates a self-signed certificate at installation. Its fingerprint is
on the dashboard ("Show Fingerprint") and in
`proxmox-backup-manager cert info`; `tls_cert_fingerprint` trusts exactly
that certificate. For a certificate from a private CA, use `ca_cert_file`
instead, and for one from a public CA, such as the Let's Encrypt
certificate `pbs_node_certificate` orders, none of them: the provider
verifies it against the system's CAs, for the host name in `endpoint`.

When the provider has PBS change its certificate — ordering one with
`pbs_node_certificate`, or destroying it, which brings back a self-signed
one — it trusts the new certificate for the rest of the run, whatever these
settings say, and warns when they need changing before the next run.

## Example Usage

```terraform
terraform {
  required_providers {
    pbs = {
      source  = "rfdrew/pbs"
      version = "~> 0.2"
    }
  }
}

# Credentials are best supplied through the environment so they stay out of
# the configuration: PBS_ENDPOINT, PBS_API_TOKEN and PBS_TLS_FINGERPRINT.
provider "pbs" {
  endpoint  = "https://pbs.example.com:8007"
  api_token = var.pbs_api_token

  # PBS generated its own certificate at installation; its dashboard shows the
  # fingerprint under "Show Fingerprint".
  tls_cert_fingerprint = "2f:f2:f7:e9:8b:a5:62:fe:bb:6d:63:40:33:8b:4a:97:e6:d4:80:5d:f9:96:b9:63:ee:4c:08:31:c2:d0:00:5c"
}

variable "pbs_api_token" {
  description = "PBS API token, as PBS shows it when the token is created: <user>@<realm>!<token name>:<secret>."
  type        = string
  sensitive   = true
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `api_token` (String, Sensitive) API token to sign in with, as PBS shows it when the token is created: `<user>@<realm>!<token name>:<secret>`. Conflicts with `username` and `password`. May also be set with the `PBS_API_TOKEN` environment variable.
- `ca_cert_file` (String) Path to a PEM file of CA certificates to verify the server's certificate with, instead of the system's trusted roots. The host name in `endpoint` must then be one of the names in the certificate. Conflicts with `tls_cert_fingerprint` and `insecure_skip_verify`. May also be set with the `PBS_CA_CERT_FILE` environment variable.
- `endpoint` (String) Root URL of the server, e.g. `https://pbs.example.com:8007`: the address of its web interface, or the one a reverse proxy serves it under. Required, here or in the environment. May also be set with the `PBS_ENDPOINT` environment variable.
- `insecure_skip_verify` (Boolean) Skip verification of the server's TLS certificate. Defaults to `false`. Prefer `tls_cert_fingerprint`, which trusts exactly one certificate. Conflicts with `tls_cert_fingerprint` and `ca_cert_file`. May also be set with the `PBS_INSECURE_SKIP_VERIFY` environment variable.
- `node` (String) Name of the node in `/nodes/{node}` API paths. Defaults to `localhost`, which every PBS answers to. May also be set with the `PBS_NODE` environment variable.
- `password` (String, Sensitive) Password of `username`. May also be set with the `PBS_PASSWORD` environment variable.
- `request_timeout` (String) Time limit for each HTTP request to the server, as a Go duration such as `30s` or `2m`. Defaults to `30s`. PBS finishes a request even when the provider has stopped waiting for it, so a write that timed out may still have taken effect. May also be set with the `PBS_REQUEST_TIMEOUT` environment variable.
- `task_timeout` (String) Time limit for waiting on a PBS worker task, such as creating or deleting a datastore, as a Go duration. Defaults to `30m`. The task goes on when the provider stops waiting. May also be set with the `PBS_TASK_TIMEOUT` environment variable.
- `tls_cert_fingerprint` (String) SHA-256 fingerprint of the server's TLS certificate, to trust that one certificate instead of verifying it against certificate authorities; the host name is then not checked. PBS shows it on its dashboard ("Show Fingerprint") and with `proxmox-backup-manager cert info`: 64 hexadecimal digits in either case, optionally separated by colons. Conflicts with `ca_cert_file` and `insecure_skip_verify`. May also be set with the `PBS_TLS_FINGERPRINT` environment variable.
- `username` (String) User to sign in as, with its realm: `root@pam`, `admin@pbs`. Needs `password`; conflicts with `api_token`. A user with two-factor authentication cannot sign in this way. May also be set with the `PBS_USERNAME` environment variable.
