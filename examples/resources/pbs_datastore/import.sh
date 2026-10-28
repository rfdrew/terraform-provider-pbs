# Datastores are imported by name. Only datastores in a directory can be
# imported so far, not those on S3 object storage or removable ones.
# reuse_datastore, destroy_data and keep_job_configs exist only in Terraform
# and are false after an import; setting them later changes nothing on the
# server.
terraform import pbs_datastore.store1 store1
