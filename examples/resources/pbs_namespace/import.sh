# Namespaces are imported by <store>:<namespace>. delete_groups and
# error_on_protected exist only in Terraform and have their defaults after an
# import.
terraform import pbs_namespace.cluster1_hosts store1:cluster1/hosts
