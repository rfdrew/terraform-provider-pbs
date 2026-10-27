# The API tokens the Proxmox VE clusters back up with.
data "pbs_api_tokens" "pve" {
  userid = "pve@pbs"
}

output "pve_token_ids" {
  value = [for t in data.pbs_api_tokens.pve.tokens : t.tokenid]
}

# A disabled token makes the backups of the cluster that uses it fail.
check "pve_tokens_are_enabled" {
  assert {
    condition     = alltrue([for t in data.pbs_api_tokens.pve.tokens : t.enable])
    error_message = "Disabled API tokens of pve@pbs: ${join(", ", [for t in data.pbs_api_tokens.pve.tokens : t.token_name if !t.enable])}."
  }
}
