#!/usr/bin/env bash
set -euo pipefail

# This runner creates an isolated, disposable cluster only on GitHub Actions.
# Never use the current operator kubeconfig for a version-upgrade rehearsal.
if [[ ${GITHUB_ACTIONS:-false} != true ]]; then
  echo "Run the upgrade matrix in GitHub Actions, not against a local/current cluster." >&2
  exit 1
fi
: "${SOURCE_VERSION:?SOURCE_VERSION is required}"
: "${IP_FAMILY:?IP_FAMILY is required}"
case "$SOURCE_VERSION" in
  v1.15.28) source_commit=6c918a528001daf6cd46d610d4211f6ad296b4ce ;;
  v1.16.10) source_commit=cb4076adc7176a594989d5f25b343f2f06cdc612 ;;
  *) echo "Unsupported legacy source $SOURCE_VERSION" >&2; exit 1 ;;
esac
case "$IP_FAMILY" in
  ipv4|ipv6|dual) ;;
  *) echo "Unsupported IP family $IP_FAMILY" >&2; exit 1 ;;
esac

pipx install jinjanator
make "kind-init-$IP_FAMILY" K8S_VERSION=v1.35.0
make untaint-control-plane
kubectl config use-context kind-kube-ovn
kubectl apply -f pkg/cnp/crds/legacy.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.8/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.8/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml

# v1.15 has the same DNSNameResolver API and RBAC but does not ship its CRD in
# install.sh. Use the fixed v1.16.10 schema for this optional DNS-enabled fixture.
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/kubeovn/kube-ovn/cb4076adc7176a594989d5f25b343f2f06cdc612/dist/images/install.sh \
  -o dns-crd-source.sh
python - <<'PY' > dns-name-resolver.yaml
from pathlib import Path
blocks = Path("dns-crd-source.sh").read_text().split("\n---\n")
matches = [block for block in blocks if "\n  name: dnsnameresolvers.kubeovn.io\n" in block]
if len(matches) != 1:
    raise SystemExit("Expected exactly one pinned DNSNameResolver CRD")
print(matches[0])
PY
kubectl apply -f dns-name-resolver.yaml
kubectl wait --for=condition=Established crd/dnsnameresolvers.kubeovn.io --timeout=60s

curl --fail --silent --show-error --location \
  "https://raw.githubusercontent.com/kubeovn/kube-ovn/$source_commit/dist/images/install.sh" \
  -o legacy-install.sh
case "$IP_FAMILY" in
  ipv4) export IPV6=false DUAL_STACK=false ;;
  ipv6) export IPV6=true DUAL_STACK=false ;;
  dual) export IPV6=false DUAL_STACK=true ;;
esac
ENABLE_ANP=true ENABLE_DNS_NAME_RESOLVER=true DEL_NON_HOST_NET_POD=false bash legacy-install.sh
kubectl rollout status deployment/kube-ovn-controller -n kube-system --timeout=300s
kubectl rollout status daemonset/kube-ovn-cni -n kube-system --timeout=300s

# Publishing only to a disposable registry gives the test controller a real
# manifest digest without public registry credentials or permission changes.
docker load --input cnp-upgrade.tar
docker run -d --restart=always -p 127.0.0.1:5001:5000 --name cnp-registry registry:2
docker network connect kind cnp-registry
docker tag cnp-upgrade:candidate localhost:5001/cnp-upgrade:candidate
docker push localhost:5001/cnp-upgrade:candidate
target_digest=$(docker image inspect localhost:5001/cnp-upgrade:candidate --format '{{json .RepoDigests}}' |
  jq -er 'map(select(startswith("localhost:5001/cnp-upgrade@sha256:"))) |
    if length == 1 then .[0] else error("Expected one local registry manifest digest") end')
for node in $(kind get nodes --name kube-ovn); do
  docker exec "$node" mkdir -p /etc/containerd/certs.d/localhost:5001
  docker exec -i "$node" tee /etc/containerd/certs.d/localhost:5001/hosts.toml >/dev/null <<'EOF'
[host."http://cnp-registry:5000"]
  capabilities = ["pull", "resolve"]
EOF
done
echo "CNP_UPGRADE_TARGET_IMAGE=$target_digest" >> "$GITHUB_ENV"
