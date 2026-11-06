resource "pbs_dns" "this" {
  search = "example.net"
  dns1   = "192.0.2.53"
  dns2   = "2001:db8::53"
}
