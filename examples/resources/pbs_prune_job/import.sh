# Prune jobs are imported by job ID, as `proxmox-backup-manager prune-job
# list` shows it.
terraform import pbs_prune_job.store1 daily-store1
