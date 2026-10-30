data "pbs_traffic_control_rule" "office" {
  name = "office"
}

# Warn when the office rule no longer limits the backups the office sends.
check "office_backups_are_limited" {
  assert {
    condition     = data.pbs_traffic_control_rule.office.rate_in != null
    error_message = "Traffic control rule office has no rate_in: backups may take the office's whole uplink."
  }
}
