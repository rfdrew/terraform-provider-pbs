# Datastores of every kind are imported by name: in a directory, removable,
# and on S3 object storage. reuse_datastore, overwrite_in_use, destroy_data
# and keep_job_configs exist only in Terraform and are false after an
# import; setting them later changes nothing on the server.
terraform import pbs_datastore.store1 store1
