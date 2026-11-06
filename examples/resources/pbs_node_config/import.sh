# The settings of a node are imported by the node's name. An import manages
# every setting the node has: a plan deletes those the configuration leaves
# out.
terraform import pbs_node_config.this localhost
