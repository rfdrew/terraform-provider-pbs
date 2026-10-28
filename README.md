# Terraform Provider for Proxmox Backup Server

Manage the configuration of a [Proxmox Backup Server](https://www.proxmox.com/en/products/proxmox-backup-server/overview)
(PBS) as code, with Terraform or OpenTofu, through its REST API.

> **Proxmox Backup Server, not PBS Professional.** This is `rfdrew/pbs`, an
> independent implementation. It is not a fork of `mcfitz2/pbs` or
> `yavasura/pbs` and does not share state with them, and it is unrelated to
> `DaveTCode/pbs`, which manages Altair PBS Professional.

**Status: early development.** Users, API tokens and ACL entries
(`pbs_user`, `pbs_api_token`, `pbs_acl`), datastores with their prune and
verify jobs (`pbs_datastore`, `pbs_prune_job`, `pbs_verify_job`) and
notifications by mail (`pbs_notification_endpoint_smtp`,
`pbs_notification_matcher`) can be managed, with data sources to read the
users, tokens and ACL entries, the roles and the effective permissions,
besides `pbs_version` and `pbs_fingerprint`. Namespaces, remotes, sync
jobs, other notification endpoints and ACME come next. The guide
[Set up PBS for a Proxmox VE cluster](docs/guides/pve-backup-server.md)
puts them together.

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
has no `root@pam`.

Run the acceptance tests only against such a throwaway server: they create,
change and delete real configuration.

## License

[MPL-2.0](LICENSE)
