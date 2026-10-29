data "pbs_traffic_control_rules" "all" {}

# The rates in bytes per second the connections of each rule reach right now:
# they change from one read to the next.
output "traffic_now" {
  value = {
    for r in data.pbs_traffic_control_rules.all.rules :
    r.name => { in = r.current_rate_in, out = r.current_rate_out }
  }
}
