#!/bin/bash

# Function to install microcode based on CPU vendor
function install_microcode() {
    local vendor=$(grep -m 1 "vendor_id" /proc/cpuinfo | awk '{print $3}')

    if [[ "$vendor" == "GenuineIntel" ]]; then
        echo "Intel CPU detected. Installing Intel microcode..."
        apt install intel-microcode -y
    elif [[ "$vendor" == "AuthenticAMD" ]]; then
        echo "AMD CPU detected. Installing AMD microcode..."
        apt install amd64-microcode -y
    else
        echo "Unknown CPU vendor: $vendor. Skipping microcode installation."
    fi
}

function apt_actions () {
    # Enable the Proxmox CE repository
    echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-no-subscription.list

    # disable proxmox enterprise repository and ceph repository
    sed -i 's/^deb/#&/' /etc/apt/sources.list.d/pve-enterprise.list /etc/apt/sources.list.d/ceph.list

    # adding debian non-free and non-free-firmware repositories
    cat <<EOF > /etc/apt/sources.list.d/debian-nonfree.list
deb http://deb.debian.org/debian bookworm non-free non-free-firmware

deb http://security.debian.org/debian-security bookworm-security non-free non-free-firmware

deb http://deb.debian.org/debian bookworm-updates non-free non-free-firmware
EOF

    # install some useful packages
    apt install -y \
        ethtool \
        htop \
        net-tools \
        sudo \
        tree \
        vim \
        lm-sensors \
        s-tui \
        cpufrequtils

    # patch/mitigate CPU vulnerabilities
    install_microcode
}

function harden_ssh() {
    # install google-authenticator to provide TOTP to SSH logins
    apt install -y libpam-google-authenticator

    # backing up sshd pam file and then adding google_authenticator library
    cp /etc/pam.d/sshd /etc/pam.d/sshd.orig
    cat <<EOF >> /etc/pam.d/sshd

# Enforcing TFA with Google Authenticator for SSH
auth required pam_google_authenticator.so nullok secret=\${HOME}/.ssh/google_authenticator
EOF

    # disabling common-auth file that enforces password authentication
    sed -i 's/^@include common-auth/#&/' /etc/pam.d/sshd

    # updating sshd config to lock down capabilities
    # the root user can use publickey authentication with a restricted set of IPs (all PVE hosts) as Proxmox requires this for cluster operations
    # users matching the 'ssauth' group must use publickey and TOTP codes
    # anyone else is not allowed to authenticate
    cat <<EOF > /etc/ssh/sshd_config.d/00-pve-hardening.conf
# General hardening settings
LoginGraceTime 45
PermitRootLogin yes
MaxAuthTries 3
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintLastLog yes
PrintMotd no
AcceptEnv LANG LC_*

# In Proxmox VE, root is used for automated tasks.
# This means that only the ssh keys can be used for
# the superuser authentication.
# This rule should apply to any other account meant to
# launch automated tasks through ssh connections (like backups).
Match User root Address 192.168.10.11,192.168.10.12,192.168.10.13
    AuthenticationMethods publickey

# Only users from the 'ssauth' group can connect remotely through ssh.
# They are required to provide both a valid ssh key and a TFA code.
Match Group sshauth
    PubkeyAuthentication yes
    ChallengeResponseAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication yes
    AuthenticationMethods publickey,keyboard-interactive:pam

# Users not in the sshauth group are not allowed to connect through ssh.
# They won't have any authentication method available.
Match Group *,!sshauth
    AuthenticationMethods none
EOF

    # Disable port 22 line to enable AddressFamily inet and pin ListenAddress to host IP
    sed -i 's/^#\?Port 22/#&/' /etc/ssh/sshd_config
    sed -i 's/^#\?AddressFamily.*/AddressFamily inet/' /etc/ssh/sshd_config
    sed -i "s/^#\?ListenAddress.* 0.0.0.0/ListenAddress $(hostname -I | awk '{print $1}')/" /etc/ssh/sshd_config
    sed -i '/^#\?ListenAddress.* ::/d' /etc/ssh/sshd_config

    systemctl restart sshd.service
}

function harden_os() {
    # create non-root administrative user
    adduser mfx
    addgroup sshauth
    adduser mfx sudo
    adduser mfx sshauth
    su mfx -c 'mkdir -p $HOME/.ssh && google-authenticator -t -d -f -r 3 -R 30 -w 3 -Q UTF8 -i "$(echo $(hostname --fqdn))" -l mfx@pam -s $HOME/.ssh/google_authenticator && chmod 400 $HOME/.ssh/google_authenticator'
    su mfx -c "echo -e 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFdYOGLLAr1GZP+dDo7uBuv/ANIWGmosW4wgaVN807T9 mfx@bluefin\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfhx9qe60Kr4L1FQ0sUdI90+1KdWuEuWKe4qS0upqb71OD6z6LEmaZa/LfUTiuOplbF8nWoqZqMyqLYOjtY+5nDG3iTwxbC7n6j7he/vN2Nuhmf9w88sYXKcPLBu9l50xnwb9pwN0/msvxLBeAlSg5CivJxObBCjnHJ7ZSC662dYhkwbvbTD3Fmk5he57n+V9Xr2lSK0ZJPM9NUtU0ZgMLHutzCuSuaCbV9zMvzpUR/fzGM8mFmlYdEa5KDaln2U8zSf/RinznTtdOo6HTG/hC4YdZDWfnAXVRAk5rvAHITMLghxZFLRd+iQwA/bDXRVd0L1UBBltdgGfuWtKnmdjr3FhoSw40VwXr+HFFGWyUsfIVWtF4Iy2wJnLmHQGYWRjE//BObTOnEv9wsB0ZDK4uz2XBevvt8oXhxjDP7zDDjU1qk6D+arJAcU2606HsNasPglsEjUz5/geVIcefv7o6PXWCIJlbDAsDn28NEN9YAomL7d7AV/d/cuMZtEy1ay0= mfx@bluefin' > /home/mfx/.ssh/authorized_keys && chmod 400 /home/mfx/.ssh/authorized_keys"

    # fail2ban configuration
    apt install -y fail2ban
    cat <<EOF > /etc/fail2ban/jail.d/01_sshd.conf
[sshd]
enabled = true
port = 22
filter = sshd
backend = systemd
maxretry = 3
findtime = 2d
bantime = 1h
EOF

    cat <<EOF > /etc/fail2ban/jail.d/02_proxmox.conf
[proxmox]
enabled = true
port = https,http,8006
filter = proxmox
backend = systemd
maxretry = 3
findtime = 2d
bantime = 1h 
EOF

    cat <<EOF > /etc/fail2ban/filter.d/proxmox.conf
[Definition]
failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*
ignoreregex =
journalmatch = _SYSTEMD_UNIT=pvedaemon.service
EOF

    rm /etc/fail2ban/jail.d/defaults-debian.conf
    systemctl enable --now fail2ban.service

    # disabling unused services
    systemctl disable --now \
        zfs-mount.service \
        zfs-share.service \
        zfs-volume-wait.service \
        zfs-zed.service \
        zfs-import.target \
        zfs-volumes.target \
        zfs.target \
        ceph-fuse.target \
        ceph.target \
        spiceproxy
    systemctl mask --now ceph.target

    # enforcing strong kernel tcp parameters
    cat <<EOF > /etc/sysctl.d/80-tcp-hardening.conf
## TCP/IP stack hardening

# Disable IPv6 protocol
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Timeout broken connections faster (amount of time to wait for FIN).
# Sets how many seconds to wait for a final FIN packet before the socket
# is forcibly closed. This is strictly a violation of the TCP specification,
# but required to prevent denial-of-service attacks.
# https://sysctl-explorer.net/net/ipv4/tcp_fin_timeout/
# Value in SECONDS.
net.ipv4.tcp_fin_timeout = 10

# IP loose spoofing protection or source route verification.
# Complements the rule set in /usr/lib/sysctl.d/pve-firewall.conf for all interfaces.
# Set to "loose" (2) to avoid unexpected networking problems in usual scenarios.
net.ipv4.conf.default.rp_filter = 2

# Ignore ICMP echo requests, or pings.
# Commented by default since Proxmox VE or any other monitoring tool might
# need to do pings to this host.
# Uncomment only if you're sure that your system won't need to respond to pings.
# net.ipv4.icmp_echo_ignore_all = 1
# net.ipv6.icmp.echo_ignore_all = 1

# Disable source packet routing; this system is not a router.
net.ipv4.conf.default.accept_source_route = 0

# Ignore send redirects; this system is not a router.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Do not accept ICMP redirects; prevents MITM attacks.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Protection against tcp time-wait assassination hazards,
# drop RST packets for sockets in the time-wait state.
net.ipv4.tcp_rfc1337 = 1

# Only retry creating TCP connections twice.
# Minimize the time it takes for a connection attempt to fail.
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_orphan_retries = 2

# For intranets or low latency users, SACK is not worth it.
# Also can become a performance and security issue.
net.ipv4.tcp_sack = 0

# A martian packet is an IP packet which specifies a source or destination
# address that is reserved for special-use by Internet Assigned Numbers Authority
# (IANA).
# To monitor 'martian' packets in your logs, enable the lines below.
# Be aware that this can fill up your logs with a lot of information,
# so use these options only if you really need to do some checking or diagnostics.
# net.ipv4.conf.all.log_martians = 1
# net.ipv4.conf.default.log_martians = 1
EOF
    # removing ipv6 from chrony daemon
    cp /etc/default/chrony /etc/default/chrony.orig
    sed -i 's/^DAEMON_OPTS=".*"/OPTIONS="-F -4 1"/' /etc/default/chrony
    systemctl restart chronyd.service
}

function harden_proxmox_web() {
    # enforcing TLS 1.2+ and disabling weak ciphers
    cat <<EOF > /etc/default/pveproxy
CIPHERS="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
HONOR_CIPHER_ORDER="1"
TLS_PROTOCOLS="TLSv1.2 TLSv1.3"
DENY_FROM="all"
ALLOW_FROM="192.168.10.0/24,192.168.20.0/24,192.168.1.0/24"
POLICY="allow"
EOF
    systemctl restart pveproxy.service
}

function harden_proxmox_cluster() {
    if [[ "$(hostname)" == "pve1" ]]; then
        ## create cluster
        pvecm create homelab

        ## creating pve non-root admin group
        pveum groupadd pvemgrs -comment "PVE System Managers"
        pveum aclmod / -group pvemgrs -role Administrator
        pveum user add mfx@pam -group pvemgrs -email "support@masonfox.me" -comment "PVE System Manager"

        ## creating pve cluster firewall rules and groups
        cat <<EOF > /etc/pve/firewall/cluster.fw
[OPTIONS]

enable: 1

[ALIASES]

internal-clients 192.168.20.0/24 # vlan 10 trusted clients on home internet
k3sagent01_net0 192.168.10.31
k3sagent01_net1 172.16.15.31
k3sagent02_net0 192.168.10.32
k3sagent02_net1 172.16.15.32
k3sserver01_net0 192.168.10.21
k3sserver01_net1 172.16.15.21
k3sserver02_net0 192.168.10.22
k3sserver02_net1 172.16.15.22
k3sserver03_net0 192.168.10.23
k3sserver03_net1 172.16.15.23
kube-api 192.168.10.20
openvpn-clients 192.168.1.0/24 # trusted clients on home openvpn server
tailscale-clients 100.0.0.0/8 # trusted clients on tailscale net

[IPSET admins] # homelab admin IPs

dc/internal-clients
dc/openvpn-clients
dc/tailscale-clients

[IPSET k3s-backplane] # k3s_svrs_net1_ips

dc/k3sserver01_net1
dc/k3sserver02_net1
dc/k3sserver03_net1

[IPSET k3s_nodes_net0_ips]

dc/k3sagent01_net0
dc/k3sagent02_net0
dc/k3sserver01_net0
dc/k3sserver02_net0
dc/k3sserver03_net0

[IPSET k8s-nodes]

192.168.10.21 # ctrl-01
192.168.10.22 # ctrl-02
192.168.10.23 # ctrl-03
192.168.10.31 # work-01
192.168.10.32 # work-02
192.168.10.33 # work-03

[IPSET pve-hosts] # homelab pve servers

192.168.10.11
192.168.10.12
192.168.10.13

[RULES]

GROUP pve-hosts-mgmt-in -i vmbr0 # rules to allow basic management traffic to pve hosts

[group k3s-agnts-net0-in] # rules for traffic coming into k3s-agents

IN Ping(ACCEPT) -dest +dc/k3s_nodes_net0_ips -log nolog
IN HTTPS(ACCEPT) -dest +dc/k3s_nodes_net0_ips -log nolog # HTTPS standard port open for entire local network
IN SSH(ACCEPT) -source +dc/admins -dest +dc/k3s_nodes_net0_ips -log nolog # SSH standard port open for entire local network

[group k3s-nodes-net1-in] # rules for traffic between k3s-servers on encrypted vxlan backplane

IN ACCEPT -source +dc/k3s-backplane -dest +dc/k3s-backplane -log nolog # allow all between k3s server nodes

[group k3s-svrs-net0-in] # rules for traffic coming into k3s-servers

IN Ping(ACCEPT) -dest +dc/k3s_nodes_net0_ips -log nolog
IN SSH(ACCEPT) -source +dc/admins -dest +dc/k3s_nodes_net0_ips -log nolog # SSH standard port open for entire local network
IN SSH(ACCEPT) -source +dc/k3s_nodes_net0_ips -dest +dc/k3s_nodes_net0_ips -log nolog

[group pve-hosts-mgmt-in] # rules for traffic coming into pve hosts

IN IPsecnat(ACCEPT) -source +dc/pve-hosts -dest +dc/pve-hosts -log nolog # permitting ipsec traffic between hosts
IN ACCEPT -source +dc/pve-hosts -dest +dc/pve-hosts -p udp -dport 4789 -log nolog # allow vxlan traffic between pve nodes
IN ACCEPT -source +dc/admins -dest +dc/pve-hosts -p tcp -dport 8006 -log nolog
IN Ping(ACCEPT) -dest +dc/pve-hosts -log nolog
IN SSH(ACCEPT) -source +dc/pve-hosts -dest +dc/pve-hosts -log nolog # allowing pve hosts to ssh to each other
IN SSH(ACCEPT) -source +dc/admins -dest +dc/pve-hosts -log nolog
EOF

    # set up SDN parameters
    cat <<EOF > /etc/pve/sdn/zones.cfg
vxlan: vxkube
        peers 192.168.10.11,192.168.10.12,192.168.10.13
        ipam pve
        mtu 8870
EOF

    cat <<EOF > /etc/pve/sdn/vnets.cfg
vnet: vkubenet
        zone vxkube
        alias k3s-backplane
        tag 15
EOF

    cat <<EOF > /etc/pve/sdn/subnets.cfg
subnet: kubebkpl-172.16.15.0-24
        vnet vkubenet
        gateway 172.16.15.1
EOF
    chmod 640 /etc/pve/sdn/zones.cfg /etc/pve/sdn/vnets.cfg /etc/pve/sdn/subnets.cfg /etc/pve/firewall/cluster.fw
    chown root:www-data /etc/pve/sdn/zones.cfg /etc/pve/sdn/vnets.cfg /etc/pve/sdn/subnets.cfg /etc/pve/firewall/cluster.fw
    pvesh set /cluster/sdn
    fi
}

function harden_proxmox_firewall() {
    apt install netfilter-persistent
    cat <<'EOF' > /usr/share/netfilter-persistent/plugins.d/35-ebtables
#!/bin/sh

# This file is part of netfilter-persistent
# (was iptables-persistent)
# Copyright (C) 2009, Simon Richter <sjr@debian.org>
# Copyright (C) 2010, 2014 Jonathan Wiltshire <jmw@debian.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.

set -e

rc=0
done=0

TABLES="filter nat broute"

for i in $TABLES; do
    modprobe -q ebtable_$i
done

RULES=/etc/ebtables/rules

if [ -x ebtables ]; then
    echo "Warning: ebtables binary not available"
    exit
fi

load_rules()
{
    #load ebtables rules
    for i in $TABLES; do
        done=1
        if [ -f $RULES.$i ]; then
            ebtables -t $i --atomic-file $RULES.$i --atomic-commit
            if [ $? -ne 0 ]; then
                rc=1
            fi
        fi
    done
    if [ "x$done" = "x0" ]; then
        echo "Warning: skipping ebtables (no rules to load)"
    fi
}

save_rules()
{
    #save ebtables rules
    for i in $TABLES; do
        ebtables -t $i --atomic-file $RULES.$i --atomic-save
        # zero the counters
        ebtables -t $i --atomic-file $RULES.$i -Z
    done
}

flush_rules()
{
    for i in $TABLES; do
        ebtables -t $i --init-table
    done
}

case "$1" in
start|restart|reload|force-reload)
    load_rules
    ;;
save)
    save_rules
    ;;
stop)
    # Why? because if stop is used, the firewall gets flushed for a variable
    # amount of time during package upgrades, leaving the machine vulnerable
    # It's also not always desirable to flush during purge
    echo "Automatic flushing disabled, use \"flush\" instead of \"stop\""
    ;;
flush)
    flush_rules
    ;;
*)
    echo "Usage: $0 {start|restart|reload|force-reload|save|flush}" >&2
    exit 1
    ;;
esac

exit $rc
EOF

    chmod 544 /usr/share/netfilter-persistent/plugins.d/35-ebtables
    mkdir -p /etc/ebtables
    /usr/share/netfilter-persistent/plugins.d/35-ebtables save
    
    # Add ebtables rule to drop all incoming unknown traffic
    ebtables -A INPUT -p fe68 -j DROP
    netfilter-persistent save

    # Add firewall rules for Proxmox hosts
    cat <<EOF > /etc/pve/nodes/$(hostname)/host.fw 
[OPTIONS]

enable: 1
log_level_in: info
ndp: 0
tcpflags: 1
nf_conntrack_tcp_timeout_established: 7875
protection_synflood: 1
protection_synflood_burst: 1000
protection_synflood_rate: 200
EOF
    chmod 640 /etc/pve/nodes/$(hostname)/host.fw
    chown root:www-data /etc/pve/nodes/$(hostname)/host.fw

    pve-firewall restart
}

function qol_proxmox() {
    ## Disable the warning about no valid subscription
    sed -Ezi.bkp "s/(Ext.Msg.show\(\{\s+title: gettext\('No valid sub)/void\(\{ \/\/\1/g" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js \
    && systemctl restart pveproxy.service

    ## enable powersave cpu target
    echo 'GOVERNOR="powersave"' > /etc/default/cpufrequtils
}

function optimize_proxmox() {
    # enable kernel parameters to optimize memory, tcp, and other settings
    cat <<EOF > /etc/sysctl.d/85-kernel-optimization.conf
## Kernel optimizations

# Controls whether unprivileged users can load eBPF programs.
# For most scenarios this is recommended to be set as 1 (enabled).
# This is a kernel hardening concern rather than a optimization one, but
# is left here since its just this value. 
kernel.unprivileged_bpf_disabled=1

# Process Scheduler related settings
#
# Determines how long a migrated process has to be running before the kernel
# will consider migrating it again to another core. So, a higher value makes
# the kernel take longer before migrating again an already migrated process.
# Value in MILLISECONDS.
kernel.sched_migration_cost_ns = 5000000
#
# This setting groups tasks by TTY, to improve perceived responsiveness on an
# interactive system. On a server with a long running forking daemon, this will
# tend to keep child processes from migrating away as soon as they should.
# So in a server it's better to leave it disabled.
kernel.sched_autogroup_enabled = 0
EOF

    cat <<EOF > /etc/sysctl.d/85-memory-optimization.conf
## Memory optimizations

# Define how aggressive the kernel will swap memory pages.
# The value represents the percentage of the free memory remaining
# in the system's RAM before activating swap.
# https://sysctl-explorer.net/vm/swappiness/
# Value is a PERCENTAGE.
vm.swappiness = 2

# Allow application request allocation of virtual memory
# more than real RAM size (or OpenVZ/LXC limits).
# https://sysctl-explorer.net/vm/overcommit_memory/
vm.overcommit_memory = 1

# Controls the tendency of the kernel to reclaim the memory
# which is used for caching of directory and inode objects.
# Adjusting this value higher than the default one (100) should
# help in keeping the caches down to a reasonable level.
# Value is a PERCENTAGE.
# https://sysctl-explorer.net/vm/vfs_cache_pressure/
vm.vfs_cache_pressure = 500

# How the kernel will deal with old data on memory.

# The kernel flusher threads will periodically wake up and write
# 'old’ data out to disk.
# Value in CENTISECS (100 points = 1 second)
# https://sysctl-explorer.net/vm/dirty_writeback_centisecs/
vm.dirty_writeback_centisecs = 3000
#
# Define when dirty data is old enough to be eligible for
# writeout by the kernel flusher threads.
# https://sysctl-explorer.net/vm/dirty_expire_centisecs/
# Value in CENTISECS (100 points = 1 second)
vm.dirty_expire_centisecs = 18000

# Adjustment of vfs cache to decrease dirty cache, aiming for a faster flush on disk.
# 
# Percentage of system memory that can be filled with “dirty” pages
# — memory pages that still need to be written to disk — before the
# pdflush/flush/kdmflush background processes kick in to write it to disk.
# https://sysctl-explorer.net/vm/dirty_background_ratio/
# Value is a PERCENTAGE.
vm.dirty_background_ratio = 5
#
# Absolute maximum percentage amount of system memory that can be filled with
# dirty pages before everything must get committed to disk.
# https://sysctl-explorer.net/vm/dirty_ratio/
# Value is a PERCENTAGE.
vm.dirty_ratio = 10

# Indicates the current number of "persistent" huge pages in the
# kernel's huge page pool.
# https://sysctl-explorer.net/vm/nr_hugepages/
# https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt
vm.nr_hugepages = 1
EOF

    cat <<EOF > /etc/sysctl.d/85-network-optimization.conf
## NETWORK optimizations

# TCP Fast Open is an extension to the transmission control protocol (TCP)
# that helps reduce network latency by enabling data to be exchanged during
# the sender’s initial TCP SYN [3]. Using the value 3 instead of the default 1
# allows TCP Fast Open for both incoming and outgoing connections.
net.ipv4.tcp_fastopen = 3

# Wait a maximum of 5 * 2 = 10 seconds in the TIME_WAIT state after a FIN,
# to handle any remaining packets in the network.
# Load module nf_conntrack if needed.
# BEWARE: this parameter won't be available if the firewall hasn't been enabled first!
# Value is an INTEGER.
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 5

# Keepalive optimizations
#
# TCP keepalive is a mechanism for TCP connections that help to determine whether
# the other end has stopped responding or not. TCP will send the keepalive probe
# that contains null data to the network peer several times after a period of idle
# time. If the peer does not respond, the socket will be closed automatically.
#
# By default, the keepalive routines wait for two hours (7200 secs)
# before sending the first keepalive probe, and then resend it every 75 seconds.
# If no ACK response is received for 9 consecutive times, the connection
# is marked as broken. As long as there is TCP/IP socket communications going on
# and active, no keepalive packets are needed.
#
# The default values are:
# tcp_keepalive_time = 7200, tcp_keepalive_intvl = 75, tcp_keepalive_probes = 9
#
# We would decrease the default values for tcp_keepalive_* params as follow:
#
# Disconnect dead TCP connections after 10 minutes
# https://sysctl-explorer.net/net/ipv4/tcp_keepalive_time/
# Value in SECONDS.
net.ipv4.tcp_keepalive_time = 600
#
# Determines the wait time between isAlive interval probes.
# https://sysctl-explorer.net/net/ipv4/tcp_keepalive_intvl/
# Value in SECONDS.
net.ipv4.tcp_keepalive_intvl = 10
#
# Determines the number of probes before timing out.
# https://sysctl-explorer.net/net/ipv4/tcp_keepalive_probes/
net.ipv4.tcp_keepalive_probes = 6

# The longer the maximum transmission unit (MTU) the better for performance,
# but the worse for reliability. This is because a lost packet means more data
# to be retransmitted and because many routers on the Internet cannot deliver
# very long packets.
net.ipv4.tcp_mtu_probing = 1

# Maximum number of connections that can be queued for acceptance.
net.core.somaxconn = 256000

# How many half-open connections for which the client has not yet
# sent an ACK response can be kept in the queue or, in other words,
# the maximum queue length of pending connections 'Waiting Acknowledgment'.
# SYN cookies only kick in when this number of remembered connections is surpassed.
# Handle SYN floods and large numbers of valid HTTPS connections.
net.ipv4.tcp_max_syn_backlog = 40000

# Maximal number of packets in the receive queue that passed through the network
# interface and are waiting to be processed by the kernel.
# Increase the length of the network device input queue.
net.core.netdev_max_backlog = 50000

# Huge improve Linux network performance by change TCP congestion control to BBR
# (Bottleneck Bandwidth and RTT).
# BBR congestion control computes the sending rate based on the delivery
# rate (throughput) estimated from ACKs.
# https://djangocas.dev/blog/huge-improve-network-performance-by-change-tcp-congestion-control-to-bbr/
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Increase ephemeral IP ports available for outgoing connections.
# The ephemeral port is typically used by the Transmission Control Protocol (TCP),
# User Datagram Protocol (UDP), or the Stream Control Transmission Protocol (SCTP)
# as the port assignment for the client end of a client–server communication.
# https://www.cyberciti.biz/tips/linux-increase-outgoing-network-sockets-range.html
net.ipv4.ip_local_port_range = 30000 65535

# This is a setting for large networks (more than 128 hosts), and this includes
# having many virtual machines or containers running in the Proxmox VE platform.
# https://www.serveradminblog.com/2011/02/neighbour-table-overflow-sysctl-conf-tunning/
net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.neigh.default.gc_thresh2 = 4096
# The gc_thresh3 is already set at /usr/lib/sysctl.d/10-pve-ct-inotify-limits.conf

# Limits number of Challenge ACK sent per second, as recommended in RFC 5961.
# Improves TCP’s Robustness to Blind In-Window Attacks.
# https://sysctl-explorer.net/net/ipv4/tcp_challenge_ack_limit/
net.ipv4.tcp_challenge_ack_limit = 9999

# Sets whether TCP should start at the default window size only for new connections
# or also for existing connections that have been idle for too long.
# This setting kills persistent single connection performance and could be turned off.
# https://sysctl-explorer.net/net/ipv4/tcp_slow_start_after_idle/
# https://github.com/ton31337/tools/wiki/tcp_slow_start_after_idle---tcp_no_metrics_save-performance
#net.ipv4.tcp_slow_start_after_idle = 0

# Maximal number of sockets in TIME_WAIT state held by the system simultaneously.
# After reaching this number, the system will start destroying the sockets
# that are in this state. Increase this number to prevent simple DOS attacks.
# https://sysctl-explorer.net/net/ipv4/tcp_max_tw_buckets/
net.ipv4.tcp_max_tw_buckets = 500000

# Sets whether TCP should reuse an existing connection in the TIME-WAIT state
# for a new outgoing connection, if the new timestamp is strictly bigger than
# the most recent timestamp recorded for the previous connection.
# This helps avoid from running out of available network sockets
# https://sysctl-explorer.net/net/ipv4/tcp_tw_reuse/
net.ipv4.tcp_tw_reuse = 1

# Increase Linux autotuning TCP buffer limits.
# The default the Linux network stack is not configured for high speed large
# file transfer across WAN links (i.e. handle more network packets) and setting
# the correct values may save memory resources.
# Values in BYTES.
net.core.rmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_default = 1048576
net.core.wmem_max = 16777216
net.core.optmem_max = 65536
net.ipv4.tcp_rmem = 4096 1048576 2097152
net.ipv4.tcp_wmem = 4096 65536 16777216

# In case UDP connections are used, these limits should also be raised.
# Values in BYTES.
# https://sysctl-explorer.net/net/ipv4/udp_rmem_min/
net.ipv4.udp_rmem_min = 8192
# https://sysctl-explorer.net/net/ipv4/udp_wmem_min/
net.ipv4.udp_wmem_min = 8192

# The maximum length of dgram socket receive queue.
net.unix.max_dgram_qlen = 1024
EOF

    # disabling transparent_hugepages
    cp /etc/default/grub /etc/default/grub.orig
    sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 transparent_hugepage=never"/' /etc/default/grub

    # enforce iommu and vfio-pci for passthrough devices
    if lspci | grep -i 'VGA' | grep -q 'Intel'; then
        echo "Intel integrated GPU detected."
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/&intel_iommu=on iommu=pt /' /etc/default/grub
        echo "blacklist i915" >> /etc/modprobe.d/blacklist.conf
    elif lspci | grep -i 'VGA' | grep -q 'AMD'; then
        echo "AMD integrated GPU detected."
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/&iommu=pt amd_iommu=full_flush pcie_acs_override=downstream,multifunction /' /etc/default/grub
        echo -e "blacklist amdgpu\nblacklist radeon" > /etc/modprobe.d/blacklist-amdgpu.conf
    else
        echo "No Intel or AMD integrated GPU detected."
    fi

    # Automatically configure vfio-pci for detected VGA and Audio devices
    # Perform lspci to find VGA and Audio devices
    pci_ids=$(lspci -nn \
    | egrep -i "VGA|Audio" \
    | grep -Eo '[[:xdigit:]]{4}:[[:xdigit:]]{4}' \
    | paste -sd ',' -)

    # Check if any PCI IDs were found
    if [[ -n "$pci_ids" ]]; then
        echo "Detected PCI IDs: $pci_ids"
        echo "options vfio-pci ids=$pci_ids" > /etc/modprobe.d/vfio.conf
        echo "VFIO configuration written to /etc/modprobe.d/vfio.conf"
        update-initramfs -uk all
    else
        echo "No VGA or Audio devices detected."
    fi

    update-grub
}

function configure_networking() {
    # Ensure pve1, pve2, and pve3 are present in /etc/hosts
    declare -A PVE_HOSTS=(
        [pve1]="192.168.10.11"
        [pve2]="192.168.10.12"
        [pve3]="192.168.10.13"
    )

    for host in "${!PVE_HOSTS[@]}"; do
        ip="${PVE_HOSTS[$host]}"
        if ! grep -qE "^\s*${ip}\s+${host}(\s|$)" /etc/hosts && ! grep -qE "\s${host}(\s|$)" /etc/hosts; then
            echo "${ip} ${host} ${host}.dev.masonfox.me" >> /etc/hosts
        fi
    done

    # backup first
    cp /etc/network/interfaces /etc/network/interfaces.bak

    # for each iface (excluding lo), insert the mtu if missing
    grep -Po '(?<=^iface )\S+' /etc/network/interfaces \
    | grep -v '^lo$' \
    | while read -r IF; do
        # skip if it already has an mtu line
        if grep -qE "^\\s*mtu\\s+9000" <<<"$(sed -n "/^iface $IF /,/^iface /p" /etc/network/interfaces)"; then
            continue
        fi

        # insert after the iface line (indented)
        sed -i "/^iface $IF /a \    mtu 9000" /etc/network/interfaces
    done

    systemctl restart networking.service

    apt install strongswan -y
    cat <<EOF > /etc/ipsec.conf
conn %default
    ike=aes256-sha1-modp1024!  # the fastest, but reasonably secure cipher on modern HW
    esp=aes256-sha1!
    leftfirewall=yes           # this is necessary when using Proxmox VE firewall rules

conn output
    rightsubnet=%dynamic[udp/4789]
    right=%any
    type=transport
    authby=psk
    auto=route

conn input
    leftsubnet=%dynamic[udp/4789]
    type=transport
    authby=psk
    auto=route
EOF

    if [[ "$(hostname)" == "pve1" ]]; then
        VXLAN_PSK=$(openssl rand -base64 128 | tr -d '\n')
        echo "192.168.10.11 192.168.10.12 192.168.10.13 : PSK $VXLAN_PSK" > /etc/ipsec.secrets
        chmod 600 /etc/ipsec.secrets
    else
        scp pve1:/etc/ipsec.secrets /etc/ipsec.secrets
        chmod 600 /etc/ipsec.secrets
    fi

    systemctl enable --now ipsec.service
}

function main() {
    # Check if the script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root. Please use 'sudo' or switch to the root user."
        exit 1
    fi

    {
        # Perform apt actions
        apt_actions
        apt-get update && apt-get -y upgrade

        # Harden SSH configuration
        harden_ssh

        # Harden OS settings
        harden_os

        # Harden Proxmox settings
        harden_proxmox_cluster
        harden_proxmox_firewall
        harden_proxmox_admin

        optimize_proxmox

        # Quality of Life improvements for Proxmox
        qol_proxmox

        configure_networking

        echo "Proxmox setup and hardening completed successfully!"
        reboot
    } || {
        status=$?
        echo "An error occurred during setup (exit code $status)."
        echo "Check the output above for details."
        exit $status
    }
}

# Execute the main function
main