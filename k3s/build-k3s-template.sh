#!/bin/bash

function configure_kernel_parameters() {
    cat <<EOF > /etc/sysctl.d/90-kubelet-demands.conf
## K3s kubelet demands
# Values demanded by the kubelet process when K3s is run with the 'protect-kernel-defaults' option enabled.

# This enables or disables panic on out-of-memory feature.
# https://sysctl-explorer.net/vm/panic_on_oom/
vm.panic_on_oom=0

# This value contains a flag that enables memory overcommitment.
# https://sysctl-explorer.net/vm/overcommit_memory/
#  Already enabled with the same value in the 85_memory_optimizations.conf file.
#vm.overcommit_memory=1

# Represents the number of seconds the kernel waits before rebooting on a panic.
# https://sysctl-explorer.net/kernel/panic/
kernel.panic = 10

# Controls the kernel's behavior when an oops or BUG is encountered.
# https://sysctl-explorer.net/kernel/panic_on_oops/
kernel.panic_on_oops = 1
EOF

}


function main() {
    set -e
    trap 'echo "An error occurred. Exiting."; exit 1' ERR

    configure_kernel_parameters

    reboot
    echo "System hardening complete. Please reboot the system."
}
# Run the main function
main