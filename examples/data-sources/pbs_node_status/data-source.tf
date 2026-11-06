data "pbs_node_status" "this" {}

output "pbs_kernel" {
  value = data.pbs_node_status.this.kernel.release
}

# A warning in every plan once the root file system has less than 10 % free:
# PBS keeps its configuration, logs and task logs there.
check "pbs_root_space" {
  assert {
    condition     = data.pbs_node_status.this.root.avail > 0.1 * data.pbs_node_status.this.root.total
    error_message = "The root file system of the PBS has ${floor(data.pbs_node_status.this.root.avail / 1073741824)} GiB free."
  }
}

# A warning when memory runs short; used leaves out cache the kernel can free.
check "pbs_memory" {
  assert {
    condition     = data.pbs_node_status.this.memory.used < 0.9 * data.pbs_node_status.this.memory.total
    error_message = "The PBS uses more than 90 % of its memory."
  }
}
