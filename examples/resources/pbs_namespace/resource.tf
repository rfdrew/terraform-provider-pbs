# Two Proxmox VE clusters back up to one datastore, each into a namespace of
# its own, so that their backups stay apart. pbs_datastore.store1 is the
# datastore of the pbs_datastore example, assumed in the same configuration.
resource "pbs_namespace" "cluster1" {
  store     = pbs_datastore.store1.name
  namespace = "cluster1"
}

# A namespace below another: referring to the parent's namespace attribute
# has Terraform create the parent first, as PBS requires.
resource "pbs_namespace" "cluster1_hosts" {
  store     = pbs_datastore.store1.name
  namespace = "${pbs_namespace.cluster1.namespace}/hosts"
}

# The defaults: destroying a namespace that holds backups fails and keeps
# them. delete_groups = true deletes them with it; like error_on_protected,
# it is read from state, so set it in an apply before the one that destroys
# or replaces the namespace.
resource "pbs_namespace" "scratch" {
  store              = pbs_datastore.store1.name
  namespace          = "scratch"
  delete_groups      = false
  error_on_protected = true
}

# The namespace scopes access. An API token acts only with the privileges its
# user has as well: with the user's role on the whole datastore and the
# token's on the namespace alone, the cluster's token backs up into its
# namespace and those below it, and nowhere else in the datastore — as long
# as the token has no entry on /datastore/store1 itself.
resource "pbs_acl" "pve_user" {
  path    = "/datastore/${pbs_datastore.store1.name}"
  auth_id = "pve@pbs"
  role    = "DatastoreBackup"
}

resource "pbs_acl" "cluster1_token" {
  path    = "/datastore/${pbs_namespace.cluster1.store}/${pbs_namespace.cluster1.namespace}"
  auth_id = "pve@pbs!cluster1"
  role    = "DatastoreBackup"
}
