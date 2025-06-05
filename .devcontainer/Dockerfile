FROM debian:bookworm-slim

# ── Install dependencies ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
   git \
   curl \
   && rm -rf /var/lib/apt/lists/*

# ── Set up non-root user ────────────────────────────────────────────────────
RUN groupadd -g 1000 devfx && useradd -m -u 1000 -g devfx devfx

# ── Fetch latest kubectl and kustomize ──────────────────────────────────────
RUN KUBECTL_VER="$(curl -fsSL https://dl.k8s.io/release/stable.txt)" && \
   curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VER}/bin/linux/amd64/kubectl" \
   -o /usr/local/bin/kubectl && \
   chmod +x /usr/local/bin/kubectl

RUN curl -s https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh | bash \
   && mv kustomize /usr/local/bin/ \
   && chmod +x /usr/local/bin/kustomize

# ── Fetch latest Argo CD CLI ────────────────────────────────────────────────
RUN curl -fsSL \
   "https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64" \
   -o /usr/local/bin/argocd && \
   chmod +x /usr/local/bin/argocd

# Cilium CLI
RUN CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt) \
   && curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz \
   && tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin \
   && rm cilium-linux-amd64.tar.gz

# ── Fetch latest Helm ─────────────────────────────────────────────────
RUN curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Kubeconform
RUN curl -L https://github.com/yannh/kubeconform/releases/latest/download/kubeconform-linux-amd64.tar.gz | tar xvzf - \
   && mv kubeconform /usr/local/bin/ \
   && chmod +x /usr/local/bin/kubeconform

# Cert-manager CLI
RUN curl -fsSL -o cmctl https://github.com/cert-manager/cmctl/releases/latest/download/cmctl_linux_amd64 \
   && chmod +x cmctl \
   && mv cmctl /usr/local/bin/cmctl

# Hubble cli
RUN HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt) \
   && HUBBLE_ARCH=amd64 \
   && curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-${HUBBLE_ARCH}.tar.gz \
   && tar xzvfC hubble-linux-${HUBBLE_ARCH}.tar.gz /usr/local/bin \
   && rm hubble-linux-${HUBBLE_ARCH}.tar.gz
