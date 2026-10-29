# Terraform Provider for Proxmox Backup Server

Manage the configuration of a [Proxmox Backup Server](https://www.proxmox.com/en/products/proxmox-backup-server/overview)
(PBS) as code, with Terraform or OpenTofu, through its REST API.

> **Proxmox Backup Server, not PBS Professional.** This is `rfdrew/pbs`, an
> independent implementation. It is not a fork of `mcfitz2/pbs` or
> `yavasura/pbs` and does not share state with them, and it is unrelated to
> `DaveTCode/pbs`, which manages Altair PBS Professional.

**Status: early development.** Users, API tokens and ACL entries
(`pbs_user`, `pbs_api_token`, `pbs_acl`), OpenID Connect realms
(`pbs_realm_openid`), datastores — removable ones too —
with their namespaces and their prune and verify jobs (`pbs_datastore`,
`pbs_namespace`, `pbs_prune_job`, `pbs_verify_job`) and
notifications by mail, Gotify and webhooks (`pbs_notification_endpoint_*`,
`pbs_notification_matcher`) and a Let's Encrypt certificate for the web
interface (`pbs_acme_account`, `pbs_acme_plugin`, `pbs_node_acme`,
`pbs_node_certificate`) can be managed, with data sources to read the
users, tokens and ACL entries, the roles and the effective permissions,
the realms, the datastores, their namespaces, usage and garbage
collection, the notification targets and matcher fields, besides `pbs_version`,
`pbs_fingerprint` and `pbs_acme_tos`. Remotes and sync jobs (`pbs_remote`,
`pbs_sync_job`) copy backups between servers, with data sources for them and
for the other jobs. APT repositories (`pbs_apt_standard_repository`,
`pbs_apt_repository`, and the data source `pbs_apt_repositories`) switch a host
from the enterprise repository to the no-subscription one. The guide
[Set up PBS for a Proxmox VE cluster](docs/guides/pve-backup-server.md)
puts them together, and [Copy backups to an offsite PBS](docs/guides/offsite-sync.md)
adds a second server.

## Requirements

* PBS 4.0 or newer; verified against 4.2.8.
* Terraform 1.11+ or OpenTofu 1.11+.

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
it out, and those tests skip.

Run the acceptance tests only against such a throwaway server: they create,
change and delete real configuration.

## License

[MPL-2.0](LICENSE)
