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
