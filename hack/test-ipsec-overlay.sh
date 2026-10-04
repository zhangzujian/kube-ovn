#!/usr/bin/env bash
# Variables in remote bash snippets must be expanded inside the container.
# shellcheck disable=SC2016
set -euo pipefail

# Run against a disposable, two-node Kind cluster on CI's Docker runner.
# Capture the actual underlay interface, not the decrypted pod interface.
overlay_image=${1:?candidate image is required}
overlay_cluster="ipsec-overlay-${GITHUB_RUN_ID:?requires an isolated CI runner}-${GITHUB_RUN_ATTEMPT:-1}"
overlay_kubeconfig=$(mktemp)
overlay_config=$(mktemp)
chmod 600 "$overlay_kubeconfig"
export KUBECONFIG="$overlay_kubeconfig"
overlay_created=false
diagnose() {
  kubectl get pods -A -o wide || true
  kubectl get events -A --sort-by=.lastTimestamp | tail -60 || true
  for component in ovs kube-ovn-controller kube-ovn-cni; do
    while read -r pod; do
      [[ -n "$pod" ]] || continue
      if [[ "$component" == kube-ovn-cni ]]; then
        kubectl -n kube-system logs "$pod" -c cni-server --tail=80 || true
        kubectl -n kube-system logs "$pod" -c ipsec --tail=80 || true
      else
        kubectl -n kube-system logs "$pod" --tail=80 || true
      fi
    done < <(kubectl -n kube-system get pods -l "app=$component" -o name)
  done
}
cleanup() {
  overlay_status=$?
  if [[ "$overlay_created" == true ]]; then
    if [[ "$overlay_status" != 0 ]]; then
      diagnose
    fi
    kind delete cluster --name "$overlay_cluster"
  fi
  rm -f "$overlay_kubeconfig" "$overlay_config"
  exit "$overlay_status"
}
trap cleanup EXIT
cat >"$overlay_config" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 10.16.0.0/16
  serviceSubnet: 10.96.0.0/12
nodes:
  - role: control-plane
  - role: worker
EOF
kind create cluster --name "$overlay_cluster" --config "$overlay_config" \
  --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5 \
  --kubeconfig "$overlay_kubeconfig" --wait 120s
overlay_created=true
kind load docker-image --name "$overlay_cluster" "$overlay_image"
overlay_control_plane="$overlay_cluster-control-plane"
overlay_worker="$overlay_cluster-worker"
kubectl label node "$overlay_control_plane" kube-ovn/role=master
kubectl taint node "$overlay_control_plane" node-role.kubernetes.io/control-plane:NoSchedule-
helm install kube-ovn charts/kube-ovn-v2 --namespace kube-system \
  --set-string global.registry.address= \
  --set-string "global.images.kubeovn.repository=${overlay_image%:*}" \
  --set-string "global.images.kubeovn.tag=${overlay_image##*:}" \
  --set image.pullPolicy=Never --set features.enableOvnIpsec=true \
  --set ovsOvn.disableModulesManagement=true
kubectl -n kube-system rollout status deployment/ovn-central --timeout=240s
kubectl -n kube-system rollout status deployment/kube-ovn-controller --timeout=240s
kubectl -n kube-system rollout status daemonset/ovs-ovn --timeout=240s
kubectl -n kube-system rollout status daemonset/kube-ovn-cni --timeout=300s
kubectl create namespace ipsec-overlay
for role in control-plane worker; do
  kubectl -n ipsec-overlay run "$role" --image="$overlay_image" --image-pull-policy=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$overlay_cluster-$role\"}}" --command -- sleep 600
done
kubectl -n ipsec-overlay wait pod --all --for=condition=Ready --timeout=180s
overlay_peer=$(kubectl get node "$overlay_worker" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
overlay_ovs=$(kubectl -n kube-system get pod -l app=ovs --field-selector "spec.nodeName=$overlay_control_plane" -o name)
kubectl -n kube-system exec "$overlay_ovs" -- bash -c '
  set -euo pipefail
  tcpdump -Z root -i eth0 -p -n -U -w /tmp/ipsec-overlay.pcap \
    "host $1 and (udp port 6081 or udp port 4789 or udp port 4500 or ip proto 50)" >/tmp/ipsec-overlay-capture.log 2>&1 &
  overlay_capture_pid=$!
  echo "$overlay_capture_pid" >/tmp/ipsec-overlay-capture.pid
  wait "$overlay_capture_pid"
  touch /tmp/ipsec-overlay-capture-complete
' overlay-capture "$overlay_peer" &
overlay_capture_client=$!
for attempt in {1..30}; do
  if kubectl -n kube-system exec "$overlay_ovs" -- bash -c 'grep -q "listening on eth0" /tmp/ipsec-overlay-capture.log && kill -0 "$(cat /tmp/ipsec-overlay-capture.pid)"'; then
    break
  fi
  if [[ "$attempt" == 30 ]]; then
    echo 'Underlay packet capture did not start' >&2
    exit 1
  fi
  sleep 0.1
done
for direction in control-plane worker; do
  destination=control-plane
  if [[ "$direction" == control-plane ]]; then
    destination=worker
  fi
  overlay_pod_ip=$(kubectl -n ipsec-overlay get pod "$destination" -o jsonpath='{.status.podIP}')
  kubectl -n ipsec-overlay exec "$direction" -- ping -c 20 -W 2 "$overlay_pod_ip"
done
kubectl -n kube-system exec "$overlay_ovs" -- bash -c '
  kill -INT "$(cat /tmp/ipsec-overlay-capture.pid)"
  for attempt in {1..30}; do
    if test -f /tmp/ipsec-overlay-capture-complete; then
      exit 0
    fi
    sleep 0.1
  done
  exit 1
'
wait "$overlay_capture_client"
overlay_esp=$(kubectl -n kube-system exec "$overlay_ovs" -- bash -c 'tcpdump -n -r /tmp/ipsec-overlay.pcap "ip proto 50" 2>/dev/null | wc -l')
overlay_plaintext=$(kubectl -n kube-system exec "$overlay_ovs" -- bash -c 'tcpdump -n -r /tmp/ipsec-overlay.pcap "udp port 6081 or udp port 4789" 2>/dev/null | wc -l')
echo "Actual cross-node OVN pods: ESP packets=$overlay_esp plaintext transport packets=$overlay_plaintext"
if [[ "$overlay_esp" == 0 || "$overlay_plaintext" != 0 ]]; then
  echo 'The actual OVN overlay did not prove encryption without plaintext' >&2
  exit 1
fi
