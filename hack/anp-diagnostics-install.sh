#!/usr/bin/env bash
set -euo pipefail

[[ ${GITHUB_ACTIONS:-false} == true ]]
: "${SOURCE_VERSION:?SOURCE_VERSION is required}"
: "${IP_FAMILY:?IP_FAMILY is required}"
case "$SOURCE_VERSION" in
  v1.15.28) source_commit=6c918a528001daf6cd46d610d4211f6ad296b4ce ;;
  v1.16.10) source_commit=cb4076adc7176a594989d5f25b343f2f06cdc612 ;;
  *) echo "Unsupported source $SOURCE_VERSION" >&2; exit 1 ;;
esac
case "$IP_FAMILY" in
  ipv4) export IPV6=false DUAL_STACK=false ;;
  ipv6) export IPV6=true DUAL_STACK=false ;;
  dual) export IPV6=false DUAL_STACK=true ;;
  *) echo "Unsupported IP family $IP_FAMILY" >&2; exit 1 ;;
esac

mkdir -p anp-diagnostics
# Use the existing kind audit mount, with a policy scoped to this experiment.
cp hack/anp-diagnostics-audit.yaml yamls/audit-policy.yaml
pipx install jinjanator
KIND_AUDITING=true make "kind-init-$IP_FAMILY" K8S_VERSION=v1.35.0
make untaint-control-plane
kubectl config use-context kind-kube-ovn

for resource in adminnetworkpolicies baselineadminnetworkpolicies clusternetworkpolicies; do
  curl --fail --silent --show-error --location \
    "https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.8/config/crd/experimental/policy.networking.k8s.io_${resource}.yaml" \
    -o "anp-diagnostics/${resource}.yaml"
  kubectl apply -f "anp-diagnostics/${resource}.yaml"
done

# v1.15 exposes DNSNameResolver but its installer does not ship the CRD.
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/kubeovn/kube-ovn/cb4076adc7176a594989d5f25b343f2f06cdc612/dist/images/install.sh \
  -o anp-diagnostics/dns-source-install.sh
python - <<'PY' > anp-diagnostics/dns-name-resolver.yaml
from pathlib import Path
blocks = Path('anp-diagnostics/dns-source-install.sh').read_text().split('\n---\n')
matches = [block for block in blocks if '\n  name: dnsnameresolvers.kubeovn.io\n' in block]
if len(matches) != 1:
    raise SystemExit('Expected one pinned DNSNameResolver CRD')
print(matches[0])
PY
kubectl apply -f anp-diagnostics/dns-name-resolver.yaml
curl --fail --silent --show-error --location \
  "https://raw.githubusercontent.com/kubeovn/kube-ovn/$source_commit/dist/images/install.sh" \
  -o anp-diagnostics/legacy-install.sh
ENABLE_ANP=true ENABLE_DNS_NAME_RESOLVER=true DEL_NON_HOST_NET_POD=false \
  bash anp-diagnostics/legacy-install.sh
kubectl rollout status deployment/kube-ovn-controller -n kube-system --timeout=300s
kubectl rollout status daemonset/kube-ovn-cni -n kube-system --timeout=300s
kubectl rollout status daemonset/ovs-ovn -n kube-system --timeout=300s

SOURCE_COMMIT="$source_commit" python - <<'PY'
import json, os, subprocess
from pathlib import Path
pods = json.loads(subprocess.check_output(['kubectl', 'get', 'pods', '-n', 'kube-system', '-o', 'json']))
components = []
for pod in pods['items']:
    if pod['metadata'].get('labels', {}).get('app') not in {'kube-ovn-controller', 'kube-ovn-cni', 'ovs', 'ovn-central'}:
        continue
    components.append({'name': pod['metadata']['name'], 'node': pod['spec'].get('nodeName'),
                       'images': [c['image'] for c in pod['spec']['containers']],
                       'imageIDs': [c['imageID'] for c in pod['status'].get('containerStatuses', [])]})
expected = 'docker.io/kubeovn/kube-ovn:' + os.environ['SOURCE_VERSION']
controllers = [p for p in pods['items'] if p['metadata'].get('labels', {}).get('app') == 'kube-ovn-controller']
if not controllers or any(c['image'] != expected for p in controllers for c in p['spec']['containers']):
    raise SystemExit('Historical controller image must match the pinned source')
record = {k: os.environ.get(k) for k in ['SOURCE_VERSION', 'SOURCE_COMMIT', 'IP_FAMILY', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']}
record['components'] = components
Path('anp-diagnostics/install.json').write_text(json.dumps(record, indent=2) + '\n')
PY
