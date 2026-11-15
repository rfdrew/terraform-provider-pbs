data "pbs_node_config" "this" {}

# Warn while the node sends its mail from root, its default; pbs_node_config
# sets email_from.
check "pbs_mail_sender" {
  assert {
    condition     = data.pbs_node_config.this.email_from != null
    error_message = "The PBS node sends its mail from root."
  }
}

output "pbs_task_log_max_days" {
  value = data.pbs_node_config.this.task_log_max_days
}
