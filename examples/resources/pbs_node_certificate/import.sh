# The certificate of a node is imported by the node's name. An import leaves
# source unset; the next apply records it without ordering a certificate.
terraform import pbs_node_certificate.this localhost
