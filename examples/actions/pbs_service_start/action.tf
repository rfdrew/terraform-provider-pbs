terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# Start chrony again after it failed, as `pbs_services` shows:
# terraform apply -invoke=action.pbs_service_start.chrony
#
# A service that runs is left alone.
action "pbs_service_start" "chrony" {
  config {
    service = "chrony"
  }
}
