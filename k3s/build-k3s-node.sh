#!/bin/bash

function build_vars() {
    if [[ -f ./.k3s-build-status ]]; then
        source ./.k3s-build-status
        if [[ -n "$HOSTNAME" && -n "$IP_ADDRESS" ]]; then
            echo "Found previous configuration:"
            echo "  HOSTNAME: $HOSTNAME"
            echo "  IP_ADDRESS: $IP_ADDRESS"
            read -p "Reuse these values? [y/N]: " REUSE
            if [[ "$REUSE" =~ ^[Yy]$ ]]; then
                return
            fi
        fi
    fi
    while true; do
        read -p "Enter desired hostname (k3sserver01, k3sagent02, etc.): " HOSTNAME
        if [[ $HOSTNAME =~ ^k3s(server|agent)0[0-9]+$ ]]; then
            break
        else
            echo "Invalid hostname. Please use the format: k3sserver01, k3sagent02, etc."
        fi
    done
    while true; do
        read -p "Enter desired IP address: " IP_ADDRESS
        if [[ ${IP_ADDRESS:-} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            # Check each octet is <= 255
            VALID=1
            IFS='.' read -ra OCTETS <<< "$IP_ADDRESS"
            for OCTET in "${OCTETS[@]}"; do
                if (( OCTET < 0 || OCTET > 255 )); then
                    VALID=0
                    break
                fi
            done
            if (( VALID )); then
                break
            fi
        fi
        echo "Invalid IP address. Please enter a valid IPv4 address."
    done

    echo "HOSTNAME=$HOSTNAME" > ./.k3s-build-status
    echo "IP_ADDRESS=$IP_ADDRESS" >> ./.k3s-build-status
}

function configure_network() {
    CURRENT_HOSTNAME=$(hostname)
    CURRENT_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$HOSTNAME" ] || [ -z "$IP_ADDRESS" ]; then
        echo "Hostname or IP address not set. Exiting."
        exit 1
    elif [[ "$CURRENT_HOSTNAME" == "$HOSTNAME" && "$CURRENT_IP" == "$IP_ADDRESS" ]]; then
        echo "Hostname and IP address already match the desired values. Skipping network configuration."
        return
    else
        echo "Configuring network settings..."

        # Ensure k3snodes are present in /etc/hosts
        declare -A K3S_NODES=(
            [k3sserver01]="192.168.10.21"
            [k3sserver02]="192.168.10.22"
            [k3sserver03]="192.168.10.23"
            [k3sagent01]="192.168.10.31"
            [k3sagent02]="192.168.10.32"
            [k3sagent03]="192.168.10.33"
        )

        for host in "${!K3S_NODES[@]}"; do
            ip="${K3S_NODES[$host]}"
            if ! grep -qE "^\s*${ip}\s+${host}(\s|$)" /etc/hosts && ! grep -qE "\s${host}(\s|$)" /etc/hosts; then
                echo "${ip} ${host} ${host}.vextech.dev" >> /etc/hosts
            fi
        done

        # Set hostname
        hostnamectl set-hostname "$HOSTNAME"

        # Replace k3s-tmplt with the provided hostname in /etc/hosts
        if grep -q "k3s-tmplt" /etc/hosts; then
            sed -i "s/k3s-tmplt/$HOSTNAME/g" /etc/hosts
            echo "Replaced k3s-tmplt with $HOSTNAME in /etc/hosts"
        else
            echo "k3s-tmplt not found in /etc/hosts"
        fi

        # Replace old IP with new IP in /etc/network/interfaces or relevant config file
        if grep -q "192.168.10.30" /etc/network/interfaces; then
            sed -i "s/192\.168\.10\.30/$IP_ADDRESS/g" /etc/network/interfaces
            echo "Replaced 192.168.10.30 with $IP_ADDRESS in /etc/network/interfaces"
        else
            echo "192.168.10.30 not found in /etc/network/interfaces"
        fi

        # Parse the last octet from the provided IP address
        LAST_OCTET=$(echo "$IP_ADDRESS" | awk -F. '{print $4}')
        if [ -z "$LAST_OCTET" ]; then
            echo "Failed to parse last octet from IP address. Exiting."
            exit 1
        fi

        # Replace the last octet in 172.16.15.30 with the parsed value
        NEW_IP="172.16.15.$LAST_OCTET"
        if grep -q "172.16.15.30" /etc/network/interfaces; then
            sed -i "s/172\.16\.15\.30/$NEW_IP/g" /etc/network/interfaces
            echo "Replaced 172.16.15.30 with $NEW_IP in /etc/network/interfaces"
        else
            echo "172.16.15.30 not found in /etc/network/interfaces"
        fi

        ifdown --force --ignore-errors ens18 ens19
        ifup --force --ignore-errors ens18 ens19
        echo "Network configuration updated. Hostname set to $HOSTNAME and IP address set to $IP_ADDRESS."

        echo "BACKPLANE_IP=172.16.15.$LAST_OCTET" >> ./.k3s-build-status
        echo "LAST_CONFIGURE_NETWORK_RUN=$(date '+%Y-%m-%d')" >> ./.k3s-build-status
        reboot
    fi
}

function configure_ssh() {
    if [[ -f ./.k3s-build-status ]] && grep -q '^LAST_CONFIGURE_SSH_RUN=' ./.k3s-build-status; then
        echo "SSH configuration already run. Skipping."
        return
    fi
    echo "SSH configuration has already run. Proceeding with reconfiguration."

    rm -rfd /home/mfx/.ssh /etc/ssh/ssh_host_*
    mkdir -p /home/mfx/.ssh
    chmod 700 /home/mfx/.ssh
    echo -e \
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFdYOGLLAr1GZP+dDo7uBuv/ANIWGmosW4wgaVN807T9 mfx@bluefin' \
    > /home/mfx/.ssh/authorized_keys
    echo -e \
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfhx9qe60Kr4L1FQ0sUdI90+1KdWuEuWKe4qS0upqb71OD6z6LEmaZa/LfUTiuOplbF8nWoqZqMyqLYOjtY+5nDG3iTwxbC7n6j7he/vN2Nuhmf9w88sYXKcPLBu9l50xnwb9pwN0/msvxLBeAlSg5CivJxObBCjnHJ7ZSC662dYhkwbvbTD3Fmk5he57n+V9Xr2lSK0ZJPM9NUtU0ZgMLHutzCuSuaCbV9zMvzpUR/fzGM8mFmlYdEa5KDaln2U8zSf/RinznTtdOo6HTG/hC4YdZDWfnAXVRAk5rvAHITMLghxZFLRd+iQwA/bDXRVd0L1UBBltdgGfuWtKnmdjr3FhoSw40VwXr+HFFGWyUsfIVWtF4Iy2wJnLmHQGYWRjE//BObTOnEv9wsB0ZDK4uz2XBevvt8oXhxjDP7zDDjU1qk6D+arJAcU2606HsNasPglsEjUz5/geVIcefv7o6PXWCIJlbDAsDn28NEN9YAomL7d7AV/d/cuMZtEy1ay0= mfx@bluefin' \
    >> /home/mfx/.ssh/authorized_keys
    chmod 600 /home/mfx/.ssh/authorized_keys
    chown -R mfx:mfx /home/mfx/.ssh

    # generate new SSH keys for user mfx
    su mfx -c "ssh-keygen -t rsa -b 4096 -C \"mfx@$(echo $(hostname --fqdn))\" -f /home/mfx/.ssh/id_rsa -N \"\""
    cat /home/mfx/.ssh/id_rsa.pub
    echo -e "\nAdd the above public key to k3sserver01's authorized_keys file.\n"
    read -p "Press [Enter] to continue..."

    if [[ "$(hostname)" == "k3sserver01" ]]; then
        google-authenticator -t -d -f -r 3 -R 30 -w 3 -Q UTF8 -i $(echo $(hostname --fqdn)) -l mfx@$HOSTNAME -s /home/mfx/.ssh/google_authenticator
    else
        scp -i /home/mfx/.ssh/id_rsa mfx@k3sserver01.vextech.dev:/home/mfx/.ssh/google_authenticator /home/mfx/.ssh/google_authenticator
    fi
    chmod 400 /home/mfx/.ssh/google_authenticator
    chown -R mfx:mfx /home/mfx/.ssh

    # genereate new SSH host keys
    ssh-keygen -A

    sed -i "s/^#\?ListenAddress.* 0.0.0.0/ListenAddress $(hostname -I | awk '{print $1}')/" /etc/ssh/sshd_config
    sed -i '/^#\?ListenAddress.* ::/d' /etc/ssh/sshd_config

    systemctl restart sshd.service
    echo "SSH configuration updated. Authorized keys and host keys set."

    echo "LAST_CONFIGURE_SSH_RUN=$(date '+%Y-%m-%d')" >> ./.k3s-build-status
}

function apt_actions() {
    apt update && apt upgrade -y

    apt install curl open-iscsi parted nfs-common -y
    systemctl enable --now iscsid.service
}

function configure_k3s() {
    if [[ -f ./.k3s-build-status ]] && grep -q '^LAST_CONFIGURE_K3S_RUN=' ./.k3s-build-status; then
        echo "K3s configuration already run. Skipping."
        return
    fi

    # create necessary k3s configuration directories
    mkdir -p /etc/rancher/k3s/ /etc/rancher/k3s.config.d/
    # enable graceful shutdown for k3s and symlink configuration to k3s dir
        cat <<EOF > /etc/rancher/k3s.config.d/kubelet.config
# Kubelet configuration
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration

shutdownGracePeriod: 30s
shutdownGracePeriodCriticalPods: 10s
EOF
        ln -fs /etc/rancher/k3s.config.d/kubelet.config /etc/rancher/k3s/kubelet.config

        # create and install systemd service to cleanup k3s on shutdown
        cat <<EOF > /lib/systemd/system/k3s-cleanup.service
[Unit]
Description=k3s-cleanup
StartLimitInterval=200
StartLimitBurst=5
Wants=k3s.service

[Service]
Type=oneshot
ExecStart=kubectl delete pods --field-selector status.phase=Failed -A --ignore-not-found=true
RemainAfterExit=true
User=root
StandardOutput=journal
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

    if [[ "$(hostname)" == "k3sserver01" ]]; then
        # generate k3s configuration file
        cat <<EOF > /etc/rancher/k3s.config.d/config.yaml
tls-san:
  - "$HOSTNAME.vextech.dev"
  - "$IP_ADDRESS"

https-listen-port: 6443
advertise-address: "$BACKPLANE_IP"
advertise-port: 6443
node-ip: "$BACKPLANE_IP"
node-external-ip: "$IP_ADDRESS"
flannel-backend: "none"

node-taint:
  - "node-role.kubernetes.io/control-plane=true:NoSchedule"

log: "/var/log/k3s.log"

kubelet-arg:
  - "config=/etc/rancher/k3s/kubelet.config"
  - "node-labels=bgp=65020"

disable:
  - metrics-server
  - servicelb
  - traefik
  - flannel
  - network-policy
  - local-storage
  - cloud-controller
  - kube-proxy

protect-kernel-defaults: true
secrets-encryption: true

agent-token: "MijyGqAIes2pMmR0dZXHsUalnIRPzW"

cluster-init: true
EOF
        ln -fs /etc/rancher/k3s.config.d/config.yaml /etc/rancher/k3s/config.yaml
        # install k3s
        curl -sfL https://get.k3s.io | sh -s - server
        sleep 5
        systemctl enable --now k3s-cleanup.service
        touch /usr/share/bash-completion/completions/kubectl
        kubectl completion bash | sudo tee /usr/share/bash-completion/completions/kubectl
        source ~/.bashrc

    elif [[ "$(hostname)" =~ ^k3sserver0[2-3]$ ]]; then
        read -p "Enter the K3S_TOKEN for this server (from k3sserver01:/var/lib/rancher/k3s/server/token): " K3S_TOKEN

        # building additional data location
        if [ -b /dev/sdb1 ]; then
            echo "/dev/sdb1 already exists, skipping partition and filesystem creation."
        else
            # Create a new GPT and one partition that fills the disk
            parted --script /dev/sdb \
                mklabel gpt \
                mkpart primary ext4 0% 100%
            mkfs.ext4 -L data /dev/sdb1
            mkdir -p /data
            UUID=$(blkid -s UUID -o value /dev/sdb1)
            echo "UUID=$UUID /data ext4 defaults,noatime 0 2" >> /etc/fstab
            systemctl daemon-reload
            mount -a
        fi

        # generate k3s configuration file
        cat <<EOF > /etc/rancher/k3s.config.d/config.yaml
cluster-domain: "vextech.cluster.io"

tls-san:
  - "$HOSTNAME.vextech.dev"
  - "$IP_ADDRESS"

https-listen-port: 6443
advertise-address: "$BACKPLANE_IP"
advertise-port: 6443
node-ip: "$BACKPLANE_IP"
node-external-ip: "$IP_ADDRESS"
flannel-backend: "none"

node-taint:
  - "node-role.kubernetes.io/control-plane=true:NoSchedule"

log: "/var/log/k3s.log"

kubelet-arg:
  - "config=/etc/rancher/k3s/kubelet.config"
  - "node-labels=bgp=65020"

disable:
  - metrics-server
  - servicelb
  - traefik
  - flannel
  - network-policy
  - local-storage
  - cloud-controller
  - kube-proxy

protect-kernel-defaults: true
secrets-encryption: true

agent-token: "MijyGqAIes2pMmR0dZXHsUalnIRPzW"

server: "https://k3sserver01.vextech.dev:6443"
token: "$K3S_TOKEN"
EOF
        ln -fs /etc/rancher/k3s.config.d/config.yaml /etc/rancher/k3s/config.yaml

        # install k3s
        wget -qO - https://get.k3s.io | sh -s - server
        echo "Sleeping for 120 seconds to allow k3s to start..."
        sleep 120
        systemctl enable --now k3s-cleanup.service
        touch /usr/share/bash-completion/completions/kubectl
        kubectl completion bash | sudo tee /usr/share/bash-completion/completions/kubectl
        source ~/.bashrc

    elif [[ "$(hostname)" =~ ^k3sagent0[1-3]$ ]]; then
        read -p "Enter the K3S_TOKEN for this server (from k3sserver01:/var/lib/rancher/k3s/server/agent-token): " K3S_TOKEN

        cat <<EOF > /etc/rancher/k3s.config.d/config.yaml
node-ip: "$BACKPLANE_IP"
node-external-ip: "$IP_ADDRESS"
server: "https://k3sserver01.vextech.dev:6443"
token: "$K3S_TOKEN"

log: "/var/log/k3s.log"
kubelet-arg: "config=/etc/rancher/k3s/kubelet.config"

protect-kernel-defaults: true
EOF
        ln -fs /etc/rancher/k3s.config.d/config.yaml /etc/rancher/k3s/config.yaml

        wget -qO - https://get.k3s.io | sh -s - agent
        echo "Sleeping for 120 seconds to allow k3s to start..."
        sleep 120
    fi

    cat <<EOF > /etc/logrotate.d/k3s
/var/log/k3s.log {
    daily
    rotate 5
    missingok
    notifempty
    dateext
    compress
    delaycompress
}
EOF

    cat <<EOF > /etc/logrotate.d/k3s-containerd
/var/lib/rancher/k3s/agent/containerd/containerd.log {
    daily
    rotate 5
    missingok
    notifempty
    dateext
    compress
    delaycompress
}
EOF

    echo "LAST_CONFIGURE_K3S_RUN=$(date '+%Y-%m-%d')" >> ./.k3s-build-status
    echo "K3s configuration complete."
}

function cleanup() {
    if [[ ! -f ./.k3s-build-status ]]; then
        echo "No build status file found. Nothing to clean up."
        return
    elif ! grep -q '^LAST_CONFIGURE_NETWORK_RUN=' ./.k3s-build-status || \
        ! grep -q '^LAST_CONFIGURE_SSH_RUN=' ./.k3s-build-status || \
        ! grep -q '^LAST_CONFIGURE_K3S_RUN=' ./.k3s-build-status; then
        echo "Required configuration run markers not found. Skipping cleanup."
        return
    else
        echo "Cleaning up temporary files..."
        rm -f ./.k3s-build-status
        echo "Cleanup complete."
        reboot
    fi
}

function main() {
    set -e
    trap 'echo "An error occurred. Exiting."; exit 1' ERR

    # Check if the script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root. Please use 'sudo' or switch to the root user."
        exit 1
    fi

    build_vars
    configure_network

    apt_actions &> /dev/null

    configure_ssh

    echo "System configuration complete."

    configure_k3s
    #cleanup
    #sleep 3
}

main
