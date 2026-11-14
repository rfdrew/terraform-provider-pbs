# terraform query lists the sync encryption keys (PBS 4.2 and later),
# archived ones included; with -generate-config-out=generated.tf it also
# writes an import block and a pbs_sync_encryption_key resource for each.
# The keys themselves are never read.
list "pbs_sync_encryption_key" "all" {
  provider = pbs
}
