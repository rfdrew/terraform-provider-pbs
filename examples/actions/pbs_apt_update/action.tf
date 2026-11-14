terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# Refresh the package lists once the repository is added, rather than at the
# next daily update, so that the Updates panel lists what it offers. Or
# refresh them yourself:
# terraform apply -invoke=action.pbs_apt_update.now
resource "pbs_apt_standard_repository" "no_subscription" {
  handle = "no-subscription"

  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.pbs_apt_update.now]
    }
  }
}

action "pbs_apt_update" "now" {
  config {
    # Also notify about the updates PBS has not notified about before.
    notify = true
  }
}
