# The metadata fields of notifications, with the values PBS knows for each.
data "pbs_notification_matcher_fields" "all" {}

locals {
  matcher_values = {
    for f in data.pbs_notification_matcher_fields.all.fields : f.name => [for v in f.values : v.value]
  }
  datastores = local.matcher_values["datastore"]
}

# The built-in default-matcher leaves out the notifications of successful
# prune jobs. This matcher mails them to root@pam, for the datastores PBS has
# now; there is none to match until PBS has a datastore the provider's user
# may see.
resource "pbs_notification_matcher" "successful_prunes" {
  count = length(local.datastores) > 0 ? 1 : 0

  name           = "successful-prunes"
  target         = ["mail-to-root"]
  match_severity = ["info"]
  match_field = [
    "exact:type=prune",
    "exact:datastore=${join(",", local.datastores)}",
  ]
}
