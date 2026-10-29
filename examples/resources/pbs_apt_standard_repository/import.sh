# A standard repository the node has is imported by <node>,<handle>, as in
# bpg/proxmox: the node is localhost or the node's host name, the handle
# enterprise, no-subscription or test.
terraform import pbs_apt_standard_repository.no_subscription localhost,no-subscription
