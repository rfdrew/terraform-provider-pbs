data "pbs_time" "this" {}

# Warn when the node's clock is more than a minute off: certificates, tickets
# and job schedules depend on it.
check "pbs_clock" {
  assert {
    condition = (
      timecmp(data.pbs_time.this.time, timeadd(plantimestamp(), "-1m")) >= 0 &&
      timecmp(data.pbs_time.this.time, timeadd(plantimestamp(), "1m")) <= 0
    )
    error_message = "The PBS clock says ${data.pbs_time.this.time}, Terraform ${plantimestamp()}."
  }
}

output "pbs_local_time" {
  value = "${data.pbs_time.this.local_time} (${data.pbs_time.this.timezone})"
}
