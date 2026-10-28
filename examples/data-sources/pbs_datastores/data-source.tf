data "pbs_datastores" "all" {}

output "datastores" {
  value = { for d in data.pbs_datastores.all.datastores : d.name => d.path }
}

# Datastores without a garbage collection schedule, whose pruned backups keep
# their space until a collection is started by hand.
output "datastores_without_gc" {
  value = [for d in data.pbs_datastores.all.datastores : d.name if d.gc_schedule == null]
}
