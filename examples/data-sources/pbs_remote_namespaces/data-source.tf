data "pbs_remote_namespaces" "offsite" {
  remote = "offsite"
  store  = "archive"
}

# One pull job for each top-level namespace of the offsite datastore archive,
# each into a namespace of the same name in store1, so that each runs on its
# own schedule and may fail on its own. The root namespace is listed as an
# empty string, which the filter leaves out.
resource "pbs_sync_job" "archive" {
  for_each = toset([
    for n in data.pbs_remote_namespaces.offsite.namespaces : n.ns
    if n.ns != "" && !strcontains(n.ns, "/")
  ])

  id           = "pull-archive-${each.key}"
  store        = "store1"
  ns           = each.key
  remote       = "offsite"
  remote_store = "archive"
  remote_ns    = each.key
  schedule     = "sat 04:00"
}
