# Every notification endpoint, of every type, and the enabled ones by name.
data "pbs_notification_targets" "all" {}

output "enabled_notification_targets" {
  value = [for t in data.pbs_notification_targets.all.targets : t.name if !t.disable]
}
