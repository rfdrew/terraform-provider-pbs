# The node's settings in node.cfg. Settings left out keep whatever the node
# has; removing one from here later deletes it.
resource "pbs_node_config" "this" {
  email_from        = "pbs@example.net"
  task_log_max_days = 90
  default_lang      = "en"

  # PBS checks updates, the subscription and webhooks through the proxy.
  http_proxy = "http://proxy.example.net:3128"

  # Shown on the login page; everyone must accept it before signing in.
  consent_text = <<-EOT
    **Authorised use only.** Activity on this server is logged.
  EOT

  description = <<-EOT
    # Backup server for cluster1
    Offsite copy: pbs2.example.net
  EOT

  # PBS 4.2.1 or later.
  location = {
    name      = "Vienna"
    latitude  = 48.2082
    longitude = 16.3738
  }
}
