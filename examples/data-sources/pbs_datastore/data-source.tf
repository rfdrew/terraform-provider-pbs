# A datastore set up outside Terraform, for the jobs and access rights that
# refer to it.
data "pbs_datastore" "store1" {
  name = "store1"
}

output "store1_path" {
  value = data.pbs_datastore.store1.path
}

# Whether the disk of a removable datastore is mounted right now.
data "pbs_datastore" "usb" {
  name = "usb"
}

output "usb_mounted" {
  value = data.pbs_datastore.usb.mount_status == "mounted"
}
