# Sync jobs of either direction are imported by job ID, as the datastore's
# Sync Jobs tab in the web interface, or the pbs_sync_jobs data source, shows
# it.
terraform import pbs_sync_job.offsite push-offsite
