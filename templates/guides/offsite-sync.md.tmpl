---
page_title: "Copy backups to an offsite PBS"
subcategory: ""
description: |-
  Two Proxmox Backup Servers, the one with the backups and one offsite, in one configuration: an API token on the offsite server, a remote and a push sync job on the first, and verification and retention offsite. A pull by the offsite server is the alternative.
---

# Copy backups to an offsite PBS

A second Proxmox Backup Server in another place keeps a copy of the backups
that survives the loss of the first. A sync job makes the copy: on a
schedule, it copies the backups the target does not have yet, chunk by
chunk, so that after the first run only what is new travels. Encrypted
backups stay encrypted; the offsite server never needs their keys.

This guide configures both servers in one Terraform configuration, through
two provider configurations:

* on the **offsite server**, a datastore for the copy, and a user and an API
  token that may write to it;
* on the **primary server**, the one Proxmox VE backs up to, the offsite
  server as a remote, and a sync job that pushes the backups there every
  night;
* on the offsite server again, a verify job and a prune job of its own, with
  a longer retention than the primary's.

A sync job can also run the other way: the offsite server pulls from the
primary. The last section shows that variant, and when to prefer it.

`pbs.example.com`, `pbs-offsite.example.com`, `store1` and `offsite1` are
placeholders. `store1` is the primary's datastore, as in the guide **Set up
PBS for a Proxmox VE cluster**.

## Before you start

* **PBS 4.0 or newer** on both servers, and Terraform or OpenTofu 1.11 or
  newer.
* **The primary reaches the offsite server** on port 8007, its API. For the
  pull variant, the offsite server reaches the primary instead.
* **An API token for Terraform on each server** that may manage it, such as
  one with the `Admin` role on `/`, for the token and its user both.
* **The offsite disk is mounted** at `/mnt/datastore/offsite1`, as for any
  `pbs_datastore`.

## Providers

```terraform
terraform {
  required_providers {
    pbs = {
      source  = "rfdrew/pbs"
      version = "~> 0.3"
    }
  }
}

# The primary server, configured from PBS_API_TOKEN and PBS_TLS_FINGERPRINT.
provider "pbs" {
  endpoint = "https://pbs.example.com:8007"
}

# The offsite server.
provider "pbs" {
  alias                = "offsite"
  endpoint             = "https://pbs-offsite.example.com:8007"
  api_token            = var.offsite_api_token
  tls_cert_fingerprint = var.offsite_tls_fingerprint
}

variable "offsite_api_token" {
  description = "API token for Terraform on the offsite PBS, <user>@<realm>!<name>:<secret>."
  type        = string
  sensitive   = true
  ephemeral   = true
}

variable "offsite_tls_fingerprint" {
  description = "Fingerprint of the offsite PBS's certificate, as its dashboard shows it."
  type        = string
}
```

Every provider configuration reads the `PBS_*` environment variables for
what it does not set, so the offsite configuration sets its token and
fingerprint itself: the environment's belong to the primary.

```shell
export PBS_API_TOKEN='terraform@pbs!provider:<secret on pbs.example.com>'
export PBS_TLS_FINGERPRINT='<fingerprint of pbs.example.com>'
export TF_VAR_offsite_api_token='terraform@pbs!provider:<secret on pbs-offsite.example.com>'
export TF_VAR_offsite_tls_fingerprint='<fingerprint of pbs-offsite.example.com>'
```

## On the offsite server

```terraform
resource "pbs_datastore" "offsite1" {
  provider = pbs.offsite

  name        = "offsite1"
  path        = "/mnt/datastore/offsite1"
  comment     = "Offsite copy of pbs.example.com"
  gc_schedule = "daily"
}

resource "pbs_user" "sync" {
  provider = pbs.offsite

  userid  = "sync@pbs"
  comment = "Pushes from pbs.example.com"
}

resource "pbs_api_token" "sync" {
  provider = pbs.offsite

  userid     = pbs_user.sync.userid
  token_name = "primary"
}

resource "pbs_acl" "sync_user" {
  provider = pbs.offsite

  path    = "/datastore/${pbs_datastore.offsite1.name}"
  auth_id = pbs_user.sync.userid
  role    = "DatastoreBackup"
}

resource "pbs_acl" "sync_token" {
  provider = pbs.offsite

  path    = "/datastore/${pbs_datastore.offsite1.name}"
  auth_id = pbs_api_token.sync.tokenid
  role    = "DatastoreBackup"
}
```

The primary signs in to the offsite server with this token, which, like any
token, has no privileges of its own: it needs an ACL entry of its own as
well as its user's. `DatastoreBackup` lets it create backups in `offsite1`
and read those it owns, which is all a push into the datastore's root
namespace needs. The backup groups it creates are owned by the token. A push
that is also to delete what the primary pruned, `remove_vanished`, needs
`DatastorePowerUser` instead, and one that creates namespaces offsite —
for a `remote_ns`, or the namespaces of `store1` — `Datastore.Modify`, which
`DatastoreAdmin` has.

## On the primary server

```terraform
# The certificate the offsite server serves, read there.
data "pbs_fingerprint" "offsite" {
  provider = pbs.offsite
}

resource "pbs_remote" "offsite" {
  name        = "offsite"
  host        = "pbs-offsite.example.com"
  auth_id     = pbs_api_token.sync.tokenid
  fingerprint = data.pbs_fingerprint.offsite.fingerprint
  comment     = "Offsite copy"

  password_wo         = pbs_api_token.sync.value
  password_wo_version = 1
}

resource "pbs_sync_job" "offsite" {
  id             = "push-offsite"
  sync_direction = "push"
  store          = "store1"
  remote         = pbs_remote.offsite.name
  remote_store   = pbs_datastore.offsite1.name
  schedule       = "21:00"
  rate_out       = "50MB"
  comment        = "Offsite copy of store1"
}

# PBS signs in to the remote to list its datastores: reading this fails when
# the host, the fingerprint or the token does not work. The remote lists only
# the datastores the token may see, so the scan waits for its ACL entries.
data "pbs_remote_datastores" "offsite" {
  remote = pbs_remote.offsite.name

  depends_on = [pbs_acl.sync_user, pbs_acl.sync_token]
}

check "offsite_datastore_is_reachable" {
  assert {
    condition     = contains([for ds in data.pbs_remote_datastores.offsite.datastores : ds.store], pbs_datastore.offsite1.name)
    error_message = "The primary cannot see the datastore offsite1 on the offsite PBS."
  }
}
```

The remote stores the token's secret, which PBS never returns: it is
write-only, so Terraform passes it to PBS without keeping it in the plan, and
the state holds it only as the token's `value`, marked sensitive. When the
token is regenerated, increment `password_wo_version` to send the new secret.
The remote trusts the offsite server's self-signed certificate by its
fingerprint, read from the server itself; when that certificate changes —
with an ACME certificate from a public CA, for one — leave `fingerprint` out,
and PBS verifies it against its system's CAs.

Every night at 21:00 the job pushes the backups of `store1` that `offsite1`
lacks, at most 50 MB per second, as root@pam on the primary — the default
`owner`, which may read every backup there. To create and read such a job,
the provider's token needs `RemoteDatastore.Backup` and `Remote.Audit` on
`/remote/offsite/offsite1`, and `Datastore.Audit` with `Datastore.Read` on
`/datastore/store1`, which `Admin` on `/` includes.

Terraform does not run the job. Start the first, long run by hand, from the
datastore's Sync Jobs tab in the primary's web interface, and follow it in
the task log there.

~> **The remote outlives no job that uses it.** PBS refuses to delete a
remote a sync job uses. Terraform destroys the job first, since it refers to
the remote; but when a new `name` replaces the remote, set
`lifecycle { create_before_destroy = true }` on it, so that the job moves to
the new remote before the old one goes.

## Verification and retention offsite

```terraform
resource "pbs_verify_job" "offsite1" {
  provider = pbs.offsite

  id             = "verify-offsite1"
  store          = pbs_datastore.offsite1.name
  schedule       = "sun 03:00"
  outdated_after = 60
}

resource "pbs_prune_job" "offsite1" {
  provider = pbs.offsite

  id       = "prune-offsite1"
  store    = pbs_datastore.offsite1.name
  schedule = "daily"

  keep = {
    daily   = 14
    weekly  = 8
    monthly = 12
    yearly  = 2
  }
}
```

A copy is only worth what it restores, so the offsite server verifies its
backups itself, every Sunday, each about every two months. The push leaves
alone what the primary prunes — `remove_vanished` is `false` — so the offsite
copy keeps a history of its own, which its own prune job trims: two weeks of
dailies, two months of weeklies, a year of monthlies and two yearlies, longer
than the primary keeps. A backup the primary pruned is not pushed again.

## The other way: the offsite server pulls

In a pull, the offsite server signs in to the primary and copies from it.
The primary then holds no credentials of the offsite server, so whoever takes
over the primary cannot delete the offsite copy through them; in a push it is
the other way round. Pull when the offsite copy is to survive an attack on
the primary, push when the offsite server must not reach the primary.

```terraform
# On the primary: a token that may read store1.
resource "pbs_user" "offsite_reader" {
  userid  = "offsite@pbs"
  comment = "Pulls of pbs-offsite.example.com"
}

resource "pbs_api_token" "offsite_reader" {
  userid     = pbs_user.offsite_reader.userid
  token_name = "pull"
}

resource "pbs_acl" "offsite_reader_user" {
  path    = "/datastore/store1"
  auth_id = pbs_user.offsite_reader.userid
  role    = "DatastoreReader"
}

resource "pbs_acl" "offsite_reader_token" {
  path    = "/datastore/store1"
  auth_id = pbs_api_token.offsite_reader.tokenid
  role    = "DatastoreReader"
}

data "pbs_fingerprint" "primary" {}

# On the offsite server: the primary as a remote, and the pull job.
resource "pbs_remote" "primary" {
  provider = pbs.offsite

  name        = "primary"
  host        = "pbs.example.com"
  auth_id     = pbs_api_token.offsite_reader.tokenid
  fingerprint = data.pbs_fingerprint.primary.fingerprint

  password_wo         = pbs_api_token.offsite_reader.value
  password_wo_version = 1
}

resource "pbs_sync_job" "primary" {
  provider = pbs.offsite

  id           = "pull-primary"
  store        = pbs_datastore.offsite1.name
  remote       = pbs_remote.primary.name
  remote_store = "store1"
  schedule     = "21:00"
  rate_in      = "50MB"
}
```

`DatastoreReader` lets the token read every backup in `store1` and nothing
else. The pull job copies them into `offsite1`, owned by root@pam on the
offsite server, its default `owner`. Leave out everything of the push: the
`offsite` remote and sync job, the `offsite` fingerprint and datastore scan
with their check, and the `sync` user, token and ACL entries. Keep the
`offsite1` datastore and its verify and prune jobs.
