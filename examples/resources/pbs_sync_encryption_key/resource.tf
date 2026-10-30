# A key PBS generates, for the push-hosted sync job of the pbs_sync_job
# example to encrypt the backups it copies to a PBS someone else runs (PBS
# 4.2+). The key never reaches Terraform: PBS keeps it in
# /etc/proxmox-backup/encryption-keys/hosted-2026.enc. Copy that file to a
# safe place outside PBS: should this server be lost, the backups on the
# remote cannot be restored without it.
resource "pbs_sync_encryption_key" "hosted" {
  id = "hosted-2026"
}

# A key of your own instead, kept wherever the configuration's other secrets
# are, from a key file without a password:
# `proxmox-backup-client key create --kdf none sync-key.json`. It is
# write-only: it never reaches the plan or state. A key cannot change, so a
# new key_wo_version replaces the key, which PBS refuses while a sync job
# holds it.
resource "pbs_sync_encryption_key" "own" {
  id             = "own-2026"
  key_wo         = var.sync_key_file
  key_wo_version = 1
}

variable "sync_key_file" {
  description = "Content of sync-key.json, a key file without a password."
  type        = string
  sensitive   = true
  ephemeral   = true
}

# To rotate the job's key, create a new one and make it the job's
# active_encryption_key: PBS then keeps hosted-2026 in the job's
# associated_key, for the backups it encrypted. Then set archived = true here,
# so that PBS encrypts nothing more with it but keeps it for decrypting, for
# as long as the remote holds such backups.
