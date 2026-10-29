# An entry is imported by <node>,<file path>,<index>, as in bpg/proxmox: the
# node is localhost or the node's host name, and the index counts the
# entries of the file from 0, disabled ones included.
terraform import pbs_apt_repository.enterprise localhost,/etc/apt/sources.list.d/pbs-enterprise.sources,0
