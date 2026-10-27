# ACL entries are imported by <path>|<user or token ID>|<role>, as the pbs_acl
# data source lists them. Quote the ID: it contains | and, for a token, !.
terraform import pbs_acl.pve_token '/datastore/store1|pve@pbs!cluster1|DatastoreBackup'
