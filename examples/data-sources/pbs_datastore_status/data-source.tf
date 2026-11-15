data "pbs_datastore_status" "store1" {
  store = "store1"
}

output "store1_free_gib" {
  value = floor(data.pbs_datastore_status.store1.avail / 1073741824)
}

# A warning in every plan once the datastore's file system is more than 90 %
# full.
check "store1_space" {
  assert {
    condition     = data.pbs_datastore_status.store1.used < 0.9 * data.pbs_datastore_status.store1.total
    error_message = "The file system of datastore store1 is more than 90 % full."
  }
}

# How many backups the datastore holds. PBS goes through the whole datastore
# to count them, so it does so only when asked.
data "pbs_datastore_status" "store1_backups" {
  store         = "store1"
  count_backups = true
}

locals {
  store1_counts = data.pbs_datastore_status.store1_backups.counts
}

output "store1_snapshots" {
  value = local.store1_counts.vm.snapshots + local.store1_counts.ct.snapshots + local.store1_counts.host.snapshots
}

# A warning in every plan once a datastore on S3 has made 1.6 million PUT
# requests to its bucket since its counters were last reset.
# s3_statistics is null on a file system and before PBS 4.1.7, which try
# turns into 0.
data "pbs_datastore_status" "s3store1" {
  store = "s3store1"
}

check "s3store1_requests" {
  assert {
    condition     = try(data.pbs_datastore_status.s3store1.s3_statistics.put, 0) < 1600000
    error_message = "Datastore s3store1 has made 1.6 million PUT requests to its bucket since its counters were reset."
  }
}
