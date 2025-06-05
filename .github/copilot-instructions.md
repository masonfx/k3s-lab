# GitHub Copilot Instructions – K3s Homelab (Debian 12 VMs on Proxmox)

---

## Environment
- Cluster: **K3s** on **Debian 12 VMs** hosted in **Proxmox**
- Hardware / topology

  | Node   | vCPU       | RAM    | Role                                           |
  |--------|------------|--------|------------------------------------------------|
  | Node A | 8 C / 16 T | 32 GiB | Control-plane **and** workloads                |
  | Node B | 8 C / 16 T | 32 GiB | Control-plane **and** workloads                |
  | Node C | 4 C / 4 T  | 16 GiB | Control-plane (primary) & light system pods    |

  > **All three nodes host the control-plane for high availability.**
  > Schedule heavy workloads to Nodes A & B.

---

## Networking
- **CNI:** **Cilium**
- **Load balancing:** use **LoadBalancer Services** that preserve client IPs (Cilium-LB or MetalLB, L2 mode) and rely on **ClusterIP** routing internally for HA
- **DNS:** manage records with **external-dns** → **Ubiquiti Dream Machine**

---

## GitOps Workflow
- Declarative manifests live in Git and are synchronized by **Argo CD**
- Embed Helm charts in Kustomize using `helmCharts:` or `helmValues:` blocks
- Prefer applying manifests via **Kustomize with Helm enabled**; suggest raw `helm install` only when explicitly requested
- Preferred deployment command:
   ```bash
   kustomize build --enable-helm /path/to/dir | kubectl apply -f -
    ```
---

## Secrets Management
1. Use **External-Secrets** with **Bitwarden** backend
2. Provide a **`ClusterSecretStore`** named `bitwarden-backend`
3. Show **`ExternalSecret`** objects mapping Bitwarden UUIDs → Kubernetes Secrets
4. Note that the SecretStore must report **Ready** before ExternalSecrets reconcile

---

## Namespace Strategy
- **One namespace per application** (e.g. `namespace: mediawiki`)
- Avoid a shared “homelab” namespace

---

## Resource-Sizing Defaults

| Workload type        | `requests`                   | `limits`                       | Preferred nodes |
|----------------------|------------------------------|--------------------------------|-----------------|
| Light stateless pod  | `cpu: 250m`, `memory: 256Mi` | `cpu: 2`,   `memory: 2Gi`      | Any             |
| CPU-heavy workload   | `cpu: 2`,   `memory: 1Gi`    | `cpu: 8`,   `memory: 6Gi`      | Nodes A / B     |
| Controller / system  | `cpu: 50m`, `memory: 128Mi`  | `cpu: 500m`, `memory: 512Mi`   | Any             |

> Adjust when the user overrides.

---

## YAML Conventions
- Target **Kubernetes v1.32** APIs (`apps/v1`, `networking.k8s.io/v1`, etc.)
- Include concise, beginner-friendly comments for key fields
- Assume bare-metal; avoid cloud-provider annotations

---

## Optional Add-ons *(describe only when asked)*
- **metrics-server**, **MetalLB**, **Traefik**, **cert-manager** via Helm + Kustomize, with steps to disable K3s built-ins where necessary

---

## Troubleshooting Guidance
- Commands: `kubectl get pods -A`, `kubectl top nodes`, `cilium status`, `argocd app list`
- Logs: `journalctl -u k3s`, `journalctl -u cilium-agent`
- Paths: `/var/lib/rancher/k3s/...`, `/etc/rancher/k3s/config.yaml`
- Link common errors (CrashLoopBackOff, certificate issues, External-Secrets “Store not ready”) to actionable fixes
