---
page_title: "Set up PBS for a Proxmox VE cluster"
subcategory: ""
description: |-
  One configuration that readies a Proxmox Backup Server for the backups of a Proxmox VE cluster: a datastore with prune and verify jobs, notifications by mail, an API token for the cluster, and a Let's Encrypt certificate.
---

# Set up PBS for a Proxmox VE cluster

This guide takes a freshly installed Proxmox Backup Server to the point where
a Proxmox VE cluster backs up to it, with one Terraform configuration:

* a datastore on a disk of its own, with garbage collection;
* a prune job, which holds the retention, and a verify job;
* notifications by mail, through an SMTP relay;
* a user and an API token for Proxmox VE, allowed to back up to the
  datastore;
* outputs with what the storage in Proxmox VE needs;
* optionally, a certificate from Let's Encrypt for the web interface and
  API, validated through Cloudflare DNS, which Proxmox VE and the provider
  then trust without a fingerprint.

The code blocks below make up the configuration, in the order they are
explained; put them in one file or several. `pbs.example.com`, `store1`,
`cluster1` and the mail addresses are placeholders.

## Before you start

* **PBS 4.0 or newer**, and Terraform or OpenTofu 1.11 or newer, the first
  releases with write-only attributes, which the SMTP password is.
* **The disk is mounted.** Terraform does not partition, format or mount
  disks: create the file system on the PBS host and mount it, here at
  `/mnt/datastore/store1`. The directory must be empty but for dotfiles and
  `lost+found`. If you create the file system in the PBS web interface, under
  Administration → Storage / Disks → Directory, clear "Add as Datastore", so
  that Terraform creates the datastore.
* **An API token for Terraform** that may manage the whole server, such as
  one with the `Admin` role on `/`, for the token and for its user both.

## Provider

```terraform
terraform {
  required_providers {
    pbs = {
      source  = "rfdrew/pbs"
      version = "~> 0.2"
    }
  }
}

locals {
  # The host name Proxmox VE reaches PBS at.
  pbs_host = "pbs.example.com"
}

provider "pbs" {
  endpoint = "https://${local.pbs_host}:8007"
}
```

The provider takes its token and the fingerprint of PBS's certificate from
the environment, and Terraform the SMTP password, so that none of them is in
the configuration:

```shell
export PBS_API_TOKEN='terraform@pbs!provider:<secret>'
export PBS_TLS_FINGERPRINT='<fingerprint, as the PBS dashboard shows it>'
export TF_VAR_smtp_password='<password on the SMTP relay>'
```

## Datastore

```terraform
resource "pbs_datastore" "store1" {
  name        = "store1"
  path        = "/mnt/datastore/store1"
  comment     = "Backups of cluster1"
  gc_schedule = "daily"
}
```

PBS creates a chunk store in the directory, which deduplicates the backups,
and the provider waits for that task. Pruning a backup removes only its
index; garbage collection, here daily, then frees the chunks no backup uses
any more. The datastore reports garbage collection and its jobs through
PBS's notification system, the default `notification_mode`, so the matcher
further down decides where those notifications go.

~> **Destroying the datastore deletes its jobs and access rights.** When the
datastore is destroyed, or replaced by a change of `name` or `path`, PBS
deletes its prune and verify jobs and every ACL entry on
`/datastore/store1` with it, unless `keep_job_configs` is set. Terraform
creates its own again — the ones below, which refer to the datastore's name,
in the same apply. The backups stay on disk unless `destroy_data` is set, and
PBS cannot rename a datastore: a new `name` with the same `path` needs
`reuse_datastore = true`, which creates the new datastore on the old one's
chunk store, backups included.

## Retention and verification

```terraform
resource "pbs_prune_job" "store1" {
  id       = "daily-store1"
  store    = pbs_datastore.store1.name
  schedule = "daily"

  keep = {
    last    = 3
    daily   = 7
    weekly  = 4
    monthly = 6
  }
}

resource "pbs_verify_job" "store1" {
  id             = "verify-store1"
  store          = pbs_datastore.store1.name
  schedule       = "sat 03:00"
  outdated_after = 30
}
```

Retention lives in the prune job, not in the datastore. Every day it prunes
each backup group, the backups of one guest, to the 3 most recent backups
and one for each of 7 more days, 4 more weeks and 6 more months. Proxmox VE
can prune as well, by the retention of its storage and backup jobs: leave
the storage at "Keep all backups" and set no retention in the backup jobs,
so that the prune job alone decides.

The verify job reads the backups every Saturday at 03:00 and checks each
chunk against its checksum, so that a damaged backup is found before it is
needed. It skips backups verified in the last 30 days: each one is verified
once, and again about every month.

## Notifications

```terraform
resource "pbs_notification_endpoint_smtp" "mail" {
  name         = "smtp"
  server       = "smtp.example.com"
  mode         = "starttls"
  port         = 587
  username     = "pbs@example.com"
  from_address = "pbs@example.com"
  mailto       = ["backup-admins@example.com"]

  password_wo         = var.smtp_password
  password_wo_version = 1

  send_test_on_apply = true
}

variable "smtp_password" {
  description = "Password of pbs@example.com on smtp.example.com."
  type        = string
  sensitive   = true
  ephemeral   = true
}

import {
  to = pbs_notification_matcher.default
  id = "default-matcher"
}

resource "pbs_notification_matcher" "default" {
  name    = "default-matcher"
  comment = "Route everything but successful prune job notifications to SMTP"
  target  = [pbs_notification_endpoint_smtp.mail.name]

  mode           = "all"
  invert_match   = true
  match_field    = ["exact:type=prune"]
  match_severity = ["info"]
}
```

The SMTP password is write-only: Terraform passes it to PBS without storing
it in the plan or state. PBS receives it when the endpoint is created; to
change it, set the new password and increment `password_wo_version`. PBS
does not contact the relay when it saves the endpoint, so a wrong setting
would show only when it sends the first notification; `send_test_on_apply`
has PBS send a test mail after every apply that creates or changes the
endpoint, and a mail the relay refuses fails the apply.

A notification reaches an endpoint only through a matcher. PBS's built-in
`default-matcher` routes every notification but those of successful prune
jobs to `mail-to-root`, the host's sendmail. It always exists and cannot be
created, so the `import` block takes it over, and the resource changes only
its `target`. The other settings are the built-in ones, and they matter:
without `match_field`, `match_severity` and `invert_match`, the matcher
would match every notification, successful prunes included. Destroying the
resource does not delete `default-matcher`; PBS resets it to its built-in
settings, and notifications go to `mail-to-root` again.

Mail is not the only channel. A `pbs_notification_endpoint_gotify` pushes
notifications to a Gotify server, and a `pbs_notification_endpoint_webhook`
sends them to any service that takes an HTTP request, with credentials kept
in write-only secrets; a matcher of its own, such as one with
`match_severity = ["error"]`, routes the failures there as well.

## Access for Proxmox VE

```terraform
resource "pbs_user" "pve" {
  userid  = "pve@pbs"
  comment = "PVE cluster cluster1"
}

resource "pbs_api_token" "pve" {
  userid     = pbs_user.pve.userid
  token_name = "cluster1"
  comment    = "Backups of cluster1"
}

resource "pbs_acl" "pve_user" {
  path    = "/datastore/${pbs_datastore.store1.name}"
  auth_id = pbs_user.pve.userid
  role    = "DatastoreBackup"
}

resource "pbs_acl" "pve_token" {
  path    = "/datastore/${pbs_datastore.store1.name}"
  auth_id = pbs_api_token.pve.tokenid
  role    = "DatastoreBackup"
}
```

Proxmox VE signs in with the API token. A token has no privileges of its
own: it acts with those of its own ACL entries that its user has too, so the
token needs its own `DatastoreBackup` entry besides its user's. The role
lets it create backups on this datastore and restore the ones it owns. The
paths refer to the datastore's name, so Terraform creates the entries after
the datastore.

## Outputs

```terraform
data "pbs_fingerprint" "this" {}

output "pve_storage_server" {
  value = local.pbs_host
}

output "pve_storage_datastore" {
  value = pbs_datastore.store1.name
}

output "pve_storage_username" {
  value = pbs_api_token.pve.tokenid
}

output "pve_storage_password" {
  value     = pbs_api_token.pve.value
  sensitive = true
}

output "pve_storage_fingerprint" {
  value = data.pbs_fingerprint.this.fingerprint
}
```

After `terraform apply`, `terraform output` shows all of them but the
password, which `terraform output -raw pve_storage_password` prints. PBS
shows a token's secret only when it creates the token; Terraform keeps it in
state, marked sensitive, so protect the state as you would the secret. The
fingerprint pins the certificate PBS serves, and changes whenever the
certificate does, after an ACME renewal for one.

## In Proxmox VE

Add the storage under Datacenter → Storage → Add → Proxmox Backup Server,
from the outputs:

* **ID** — the storage's name in Proxmox VE, such as `pbs-store1`.
* **Server** — `pve_storage_server`.
* **Username** — `pve_storage_username`, the token ID `pve@pbs!cluster1`.
* **Password** — `pve_storage_password`, the token's secret.
* **Datastore** — `pve_storage_datastore`.
* **Fingerprint** — `pve_storage_fingerprint`.

Leave **Namespace** empty to back up to the datastore's root namespace. The
**Encryption** tab adds client-side encryption; keep a copy of its key
outside the cluster, as encrypted backups cannot be restored without it. On
**Backup Retention**, keep "Keep all backups", as above.

The same from the shell of a cluster node, with `pvesm`; quote the token ID,
which contains `!`:

```shell
pvesm add pbs pbs-store1 --server pbs.example.com --datastore store1 \
  --username 'pve@pbs!cluster1' --password '<token secret>' \
  --fingerprint '<fingerprint>'
```

Then choose the storage in a backup job under Datacenter → Backup. When the
fingerprint changes, update it in the storage's settings as well — or give
PBS a certificate of a public CA, as below, and leave the fingerprint out.

## A certificate from Let's Encrypt

PBS's self-signed certificate is trusted by its fingerprint alone, and that
fingerprint must be copied wherever PBS is used. A certificate from Let's
Encrypt is trusted by the systems' CAs instead, and PBS renews it on its
own. PBS proves to Let's Encrypt that it controls the domain with the DNS-01
challenge, through Cloudflare's API here, so the server needs no inbound
connection from the internet; it does need to reach Let's Encrypt and
Cloudflare.

### Cloudflare API token

In the Cloudflare dashboard, under My Profile → API Tokens → Create Token,
start from "Create Custom Token" and give the token one permission,
**Zone → DNS → Edit**, with **Zone Resources** set to the zone of PBS's
domain alone. Note the zone's ID, from the zone's overview page: with it,
the plugin needs no permission to list zones.

```shell
export TF_VAR_cloudflare_api_token='<token>'
```

### Account, plugin, domains and certificate

```terraform
locals {
  # Let's Encrypt's staging directory for the first apply, then production:
  # "https://acme-v02.api.letsencrypt.org/directory".
  acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
}

data "pbs_acme_tos" "letsencrypt" {
  directory = local.acme_directory
}

resource "pbs_acme_account" "letsencrypt" {
  name      = "default"
  contact   = "backup-admins@example.com"
  directory = local.acme_directory
  tos_url   = data.pbs_acme_tos.letsencrypt.url
}

resource "pbs_acme_plugin" "cloudflare" {
  id  = "cloudflare"
  api = "cf"
  data = {
    CF_Token   = var.cloudflare_api_token
    CF_Zone_ID = "<zone ID>"
  }
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token with Zone → DNS → Edit on the zone."
  type        = string
  sensitive   = true
}

resource "pbs_node_acme" "this" {
  account = pbs_acme_account.letsencrypt.name
  domains = [{ domain = local.pbs_host, plugin = pbs_acme_plugin.cloudflare.id }]
}

resource "pbs_node_certificate" "this" {
  source = "acme"

  # A new certificate whenever the domains or the account change.
  triggers = {
    domains = join(",", sort(pbs_node_acme.this.domains[*].domain))
    account = pbs_acme_account.letsencrypt.location
  }
}
```

The account registers at Let's Encrypt and agrees to its terms of service.
Let's Encrypt publishes new terms now and then; the next plan then shows the
new URL, which the provider records without registering a new account.
Destroying the account deactivates it at Let's Encrypt for good.

The plugin's `data` holds the token; PBS returns it when it is read, so it
is in state, marked sensitive, and a token changed in the PBS web interface
shows in the plan. `pbs_node_acme` sets the node's domains, and
`pbs_node_certificate` has PBS order the certificate, set the TXT record
through Cloudflare, wait 30 seconds (`validation_delay`) for it to reach
Cloudflare's servers, and install the certificate. The order runs as a PBS
task; if it fails, the error names the reason, and the task log in the PBS
web interface (Administration → Tasks) shows each step.

### Switching the trust

The certificate PBS served when the run started is the one
`PBS_TLS_FINGERPRINT` pins, and the apply replaces it. The provider keeps a
connection open that it trusted before the change, reads the new
certificate over it, and trusts the new certificate for the rest of the run,
so the apply goes on; it warns that its settings need changing. Before the
next run:

* **Remove `PBS_TLS_FINGERPRINT`** (and `tls_cert_fingerprint`), so that
  the provider verifies the certificate against the system's CAs. The
  `endpoint` must name one of the certificate's domains — here it does,
  `https://${local.pbs_host}:8007` — and that name must resolve to PBS. Do
  not pin the new fingerprint instead: it changes with every renewal, about
  every two months with today's 90-day certificates.
* **Remove the fingerprint from the storage in Proxmox VE**, under
  Datacenter → Storage, or with `pvesm set pbs-store1 --delete fingerprint`,
  or from `proxmox_storage_pbs` in the bpg/proxmox provider. Proxmox VE then
  verifies the certificate against its CAs, for the storage's `server`, which
  must be the certificate's domain too. Drop the `pve_storage_fingerprint`
  output.

### Trying it out against Let's Encrypt's staging directory

Let's Encrypt limits how many certificates it issues for the same domains,
five a week. Its staging directory has far higher limits, and issues
certificates nobody trusts, so do the first apply against staging, as above,
and check the result once by hand:

1. Apply. The certificate's `issuer` names one of Let's Encrypt's staging
   CAs, marked `(STAGING)`, and the browser shows a certificate warning for
   `https://pbs.example.com:8007`.
2. For the runs against staging, set `PBS_TLS_FINGERPRINT` to the new
   certificate's `fingerprint`, which the apply's warning names: neither the
   provider nor Proxmox VE trusts a staging certificate by a CA. The
   `pve_storage_fingerprint` output was read before the certificate changed;
   `terraform apply -refresh-only` reads it again.
3. Switch `local.acme_directory` to production and apply. The new directory
   replaces the account, which deactivates the staging one, and the account
   in `triggers` orders a certificate from production in place.
4. Unset `PBS_TLS_FINGERPRINT`, remove the fingerprint from the Proxmox VE
   storage, and check that `terraform plan` connects and plans nothing.

Destroying `pbs_node_certificate` has PBS go back to a new self-signed
certificate, with a new fingerprint, which the destroy prints: pin that one
again wherever PBS is used. Should the destroy say that it could not confirm
the new certificate, compare the fingerprint with `proxmox-backup-manager
cert info` on the host first. The Let's Encrypt certificate is not revoked;
it expires.
