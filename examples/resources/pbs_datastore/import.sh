# Datastores are imported by name. Datastores in a directory and removable
# ones can be imported so far, not those on S3 object storage.
# reuse_datastore, destroy_data and keep_job_configs exist only in Terraform
# and are false after an import; setting them later changes nothing on the
# server.
terraform import pbs_datastore.store1 store1
