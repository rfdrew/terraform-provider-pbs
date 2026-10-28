data "pbs_remotes" "all" {}

# Which server each remote points at.
output "remote_hosts" {
  value = { for r in data.pbs_remotes.all.remotes : r.name => r.host }
}
