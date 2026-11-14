terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# The datastore s3store1 of the pbs_datastore example, on S3, assumed in the
# same configuration. When its bucket ran out of space during a backup, PBS
# could not clean up after it: remove that backup's stray objects from the
# bucket by hand, as PBS recommends, then set var.bucket_cleanup to the day,
# which refreshes the datastore so that its local cache matches the bucket
# again. Or refresh it yourself:
# terraform apply -invoke=action.pbs_datastore_s3_refresh.s3store1
#
# One datastore, one PBS: never have a second PBS use this datastore, the
# same bucket under the same name, not even for a test. Each one's garbage
# collection deletes the chunks that only the other's backups use, and a
# refresh does not prevent that. To have the backups on a second PBS, sync
# them.
resource "terraform_data" "bucket_cleanup" {
  input = var.bucket_cleanup

  lifecycle {
    action_trigger {
      events  = [after_update]
      actions = [action.pbs_datastore_s3_refresh.s3store1]
    }
  }
}

# No backup or restore passes the datastore while PBS refreshes it.
action "pbs_datastore_s3_refresh" "s3store1" {
  config {
    store   = pbs_datastore.s3store1.name
    timeout = "1h"
  }
}

variable "bucket_cleanup" {
  description = "Day stray objects were last removed from the bucket by hand, such as 2026-11-14."
  type        = string
}
