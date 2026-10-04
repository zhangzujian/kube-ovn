#!/usr/bin/env bash
set -euo pipefail

# Run only in CI's disposable Docker runner, never against a caller's cluster.
api_cluster="ipsec-api-${GITHUB_RUN_ID:?requires an isolated CI runner}-${GITHUB_RUN_ATTEMPT:-1}"
api_kubeconfig=$(mktemp)
chmod 600 "$api_kubeconfig"
export KUBECONFIG="$api_kubeconfig"
api_created=false
cleanup() {
  if [[ "$api_created" == true ]]; then
    kind delete cluster --name "$api_cluster"
  fi
  rm -f "$api_kubeconfig"
}
trap cleanup EXIT

kind create cluster --name "$api_cluster" --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5 --kubeconfig "$api_kubeconfig" --wait 120s
api_created=true
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager \
  --version v1.21.2 --namespace cert-manager --create-namespace \
  --set crds.enabled=true --wait --timeout 180s
export KUBE_OVN_IPSEC_API_TEST=true
go test ./pkg/controller -run '^TestIPsecAPIServerSigningContract$' -count=1 -v -timeout 8m
