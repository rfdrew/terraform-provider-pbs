# Terraform Provider for Proxmox Backup Server

Manage the configuration of a [Proxmox Backup Server](https://www.proxmox.com/en/products/proxmox-backup-server/overview)
(PBS) as code, with Terraform or OpenTofu, through its REST API.

> **Proxmox Backup Server, not PBS Professional.** This is `rfdrew/pbs`, an
> independent implementation. It is not a fork of `mcfitz2/pbs` or
> `yavasura/pbs` and does not share state with them, and it is unrelated to
> `DaveTCode/pbs`, which manages Altair PBS Professional.

**Status: early development.** Users, API tokens and ACL entries
(`pbs_user`, `pbs_api_token`, `pbs_acl`), OpenID Connect, LDAP and Active
Directory realms (`pbs_realm_openid`, `pbs_realm_ldap`, `pbs_realm_ad`),
datastores — removable ones and those on S3 object storage too, with their
S3 endpoints (`pbs_s3_endpoint`) —
with their namespaces and their prune and verify jobs (`pbs_datastore`,
`pbs_namespace`, `pbs_prune_job`, `pbs_verify_job`), traffic control
rules (`pbs_traffic_control_rule`),
notifications by mail, Gotify and webhooks (`pbs_notification_endpoint_*`,
`pbs_notification_matcher`), InfluxDB metric servers
(`pbs_metric_server_influxdb_http`, `pbs_metric_server_influxdb_udp`), a
Let's Encrypt certificate for the web
interface (`pbs_acme_account`, `pbs_acme_plugin`, `pbs_node_acme`,
`pbs_node_certificate`) or one of your own, the node's settings, DNS,
time zone and subscription (`pbs_node_config`, `pbs_dns`, `pbs_timezone`,
`pbs_subscription`), and its network interfaces, with the step that
applies changes to them (`pbs_network_interface`, `pbs_network_apply`),
can be managed, with data sources to read the
users, tokens and ACL entries, the roles and the effective permissions,
the realms, the datastores, their namespaces, usage and garbage
collection, the notification targets and matcher fields, the metric
servers, the ACME directories, DNS APIs and accounts, the node's status,
certificate, network interfaces, disks, pending updates, services,
subscription and time, besides `pbs_version`,
`pbs_fingerprint` and `pbs_acme_tos`. Remotes and sync jobs (`pbs_remote`,
`pbs_sync_job`) copy backups between servers, encrypted with keys PBS keeps
(`pbs_sync_encryption_key`) if need be, with data sources for them and
for the other jobs. APT repositories (`pbs_apt_standard_repository`,
`pbs_apt_repository`, and the data source `pbs_apt_repositories`) switch a host
from the enterprise repository to the no-subscription one. The guide
[Set up PBS for a Proxmox VE cluster](docs/guides/pve-backup-server.md)
puts them together, [Copy backups to an offsite PBS](docs/guides/offsite-sync.md)
adds a second server, [Back up to S3 object storage](docs/guides/s3-datastore.md)
puts a datastore on S3, and [Managing the network of a PBS node](docs/guides/network.md)
changes network interfaces without cutting the node off.

With Terraform 1.14.1 or later, actions run jobs, garbage collection, realm
syncs, certificate renewals and other one-off operations (`pbs_sync_job_run`,
`pbs_verify_job_run`, `pbs_prune_job_run`, `pbs_datastore_gc`,
`pbs_datastore_mount`, `pbs_datastore_unmount`, `pbs_datastore_s3_refresh`,
`pbs_s3_endpoint_check`, `pbs_realm_sync`, `pbs_notification_test`,
`pbs_node_certificate_renew`, `pbs_apt_update`, `pbs_network_reload`). With
Terraform 1.14 or later, list resources let `terraform query` find existing
objects and generate the configuration that imports them — users, tokens, ACL
entries, datastores, jobs, remotes, notification endpoints and most other
resources.

## Requirements

* PBS 4.0 or newer; verified against 4.2.8.
* Terraform 1.11+ or OpenTofu 1.11+.
* For actions, Terraform 1.14.1+; for list resources and `terraform query`,
  Terraform 1.14+. OpenTofu supports neither yet.

## Usage

```hcl
terraform {
  required_providers {
    pbs = {
      source = "rfdrew/pbs"
    }
  }
}

provider "pbs" {
  endpoint             = "https://pbs.example.com:8007"
  api_token            = var.pbs_api_token # "<user>@<realm>!<token name>:<secret>"
  tls_cert_fingerprint = "2f:f2:f7:…:00:5c"
}

data "pbs_fingerprint" "this" {}
```

Every setting can also come from the environment: `PBS_ENDPOINT`,
`PBS_API_TOKEN` (or `PBS_USERNAME` and `PBS_PASSWORD`), `PBS_TLS_FINGERPRINT`.
See [`docs/index.md`](docs/index.md) for the full reference.

## Development

```shell
make build      # build the provider binary
make test       # unit tests, against an in-process fake PBS
make pbs-up     # boot a throwaway PBS in Docker and print the PBS_* exports
make testacc    # acceptance tests against that PBS
make pbs-down   # remove it
make docs       # regenerate docs/ with tfplugindocs
```

Proxmox publishes no container image for PBS, so `make pbs-up`
(`scripts/bootstrap-test-pbs.sh`) installs the official
`proxmox-backup-server` package into a Debian trixie container that runs
systemd. It needs Docker with privileged containers. `PBS_TEST_PBS_VERSION=4.0`
pins an older release line, and `PBS_TEST_VARIANT=image` uses the community
image `ayufan/proxmox-backup-server` instead, which needs no privileges but
has no `root@pam`. The packages stand also gets a file system on a loop
device, for the tests of removable datastores; `PBS_TEST_REMOVABLE=0` leaves
it out, and those tests skip. Next to PBS runs an S3 server, Silo — a
maintained fork of MinIO, whose own images are gone — with a self-signed
certificate, for the tests of S3 endpoints and datastores on S3;
`PBS_TEST_S3=0` leaves it out, and those tests skip.

Run the acceptance tests only against such a throwaway server: they create,
change and delete real configuration.

## License

[MPL-2.0](LICENSE)
