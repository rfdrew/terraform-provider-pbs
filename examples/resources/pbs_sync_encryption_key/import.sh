# Sync encryption keys are imported by ID. PBS never returns the key, so
# key_wo_version is empty after an import. Setting key_wo and key_wo_version
# then keeps the key when key_wo holds the same key, as the fingerprints
# tell, and replaces it when key_wo holds another; leaving both out keeps it.
terraform import pbs_sync_encryption_key.hosted hosted-2026
