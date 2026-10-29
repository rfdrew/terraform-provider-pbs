data "pbs_sync_encryption_keys" "all" {}

# The fingerprint of each key, which the backups it encrypted carry: a
# restore needs the key whose fingerprint the backup shows.
output "sync_key_fingerprints" {
  value = { for k in data.pbs_sync_encryption_keys.all.keys : k.id => k.fingerprint }
}

# The keys PBS may still encrypt with, those not archived.
output "unarchived_sync_keys" {
  value = [for k in data.pbs_sync_encryption_keys.all.keys : k.id if !k.archived]
}
