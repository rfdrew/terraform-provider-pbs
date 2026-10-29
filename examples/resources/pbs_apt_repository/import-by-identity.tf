import {
  to = pbs_apt_repository.enterprise
  identity = {
    node      = "localhost"
    file_path = "/etc/apt/sources.list.d/pbs-enterprise.sources"
    index     = 0
  }
}
