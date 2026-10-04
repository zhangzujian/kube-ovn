#!/usr/bin/env bash
# Variables in remote bash snippets must be expanded inside the container.
# shellcheck disable=SC2016
set -euo pipefail

# Run against a disposable, two-node Kind cluster on CI's Docker runner.
# Capture the actual underlay interface, not the decrypted pod interface.
overlay_image=${1:?candidate image is required}
overlay_protection=${IPSEC_PROTECTION_PROTOTYPE:-false}
overlay_family=${IPSEC_OVERLAY_FAMILY:-IPv4}
overlay_tunnel=${IPSEC_OVERLAY_TUNNEL:-geneve}
case "$overlay_family" in
  IPv4) overlay_kind_family=ipv4; overlay_pods=10.16.0.0/16; overlay_services=10.96.0.0/12; overlay_wildcard=0.0.0.0/0 ;;
  IPv6) overlay_kind_family=ipv6; overlay_pods=fd00:10:16::/56; overlay_services=fd00:10:96::/112; overlay_wildcard=::/0 ;;
  *) echo 'Unsupported overlay IP family' >&2; exit 1 ;;
esac
case "$overlay_tunnel" in
  geneve|vxlan) ;;
  *) echo 'Unsupported overlay tunnel type' >&2; exit 1 ;;
esac
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
cat >"$overlay_config" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  ipFamily: $overlay_kind_family
  podSubnet: $overlay_pods
  serviceSubnet: $overlay_services
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
  --set ovsOvn.disableModulesManagement=true \
  --set-string "networking.stack=$overlay_family" --set-string "networking.tunnelType=$overlay_tunnel"
kubectl -n kube-system rollout status deployment/ovn-central --timeout=240s
kubectl -n kube-system rollout status deployment/kube-ovn-controller --timeout=240s
kubectl -n kube-system rollout status daemonset/ovs-ovn --timeout=240s
kubectl -n kube-system rollout status daemonset/kube-ovn-cni --timeout=300s
# Confirm the requested privilege/priority split in the deployed processes,
# beyond rendered manifests and the isolated runtime fixture.
for node in "$overlay_control_plane" "$overlay_worker"; do
  cni_pod=$(kubectl -n kube-system get pod -l app=kube-ovn-cni --field-selector "spec.nodeName=$node" -o name)
  kubectl -n kube-system exec "$cni_pod" -c cni-server -- python3 -c '
import os,subprocess
pids=subprocess.check_output(["pidof","kube-ovn-daemon"],text=True).split()
assert len(pids)==1, "expected one node CNI process"
pid=int(pids[0])
with open(f"/proc/{pid}/status") as f:
    status=dict(line.split(":",1) for line in f if ":" in line)
assert status["Uid"].split()[1]=="65534", "CNI must remain non-root"
assert int(status["CapBnd"],16)&(1<<23)==0, "CNI must not retain SYS_NICE in its bounding set"
assert int(status["CapEff"],16)&(1<<23)==0, "CNI must not have effective SYS_NICE"
assert os.getpriority(os.PRIO_PROCESS,pid)==0, "CNI must use normal process priority"
print("Deployed CNI: UID 65534, nice 0, SYS_NICE absent")'
  kubectl -n kube-system exec "$cni_pod" -c ipsec -- python3 -c '
import os,subprocess
pids=subprocess.check_output(["pidof","charon"],text=True).split()
assert len(pids)==1, "expected one owned IKE process"
pid=int(pids[0])
with open(f"/proc/{pid}/status") as f:
    status=dict(line.split(":",1) for line in f if ":" in line)
assert status["Uid"].split()[1]=="0", "IKE must use the validated root runtime"
assert int(status["CapEff"],16)&~((1<<12)|(1<<10)|(1<<23))==0, "IKE must stay within the three production capabilities"
assert os.getpriority(os.PRIO_PROCESS,pid)==-5, "IPsec must own the configured process priority"
print("Deployed IPsec: IKE nice -5, effective capabilities restricted")'
done
# This synthetic reservation is confined to disposable Kind node namespaces.
# It is not a production allocator, activation coordinator or ownership ledger.
if [[ "$overlay_protection" == true ]]; then
  for node in "$overlay_control_plane" "$overlay_worker"; do
    docker exec "$node" ip xfrm policy add src "$overlay_wildcard" dst "$overlay_wildcard" \
      dir out priority 2147483647 index 759833 action block mark 759815 mask 0xffffffff
    ovs_pod=$(kubectl -n kube-system get pod -l app=ovs --field-selector "spec.nodeName=$node" -o name)
    kubectl -n kube-system exec "$ovs_pod" -- ovs-vsctl set Open_vSwitch . \
      external_ids:ovn-ipsec-protection-mark=759815 \
      external_ids:ovn-ipsec-protection-reqid=759815
    for attempt in {1..60}; do
      if kubectl -n kube-system exec "$ovs_pod" -- ovs-vsctl --format=json --columns=options find Interface "type=$overlay_tunnel" | \
          python3 -c 'import json,sys; rows=json.load(sys.stdin)["data"]; expected={"egress_pkt_mark":"759815","ipsec_mark_out":"759815/0xffffffff","ipsec_reqid":"759815"}; sys.exit(not rows or not all(expected.items() <= dict(row[0][1]).items() for row in rows))'; then
        break
      fi
      if [[ "$attempt" == 60 ]]; then
        echo 'OVN did not generate the owned output mark and IKE selectors' >&2
        exit 1
      fi
      sleep 1
    done
  done
fi
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
    "host $1 and (udp port 6081 or udp port 4789 or udp port 4500 or ip proto 50 or ip6 proto 50)" >/tmp/ipsec-overlay-capture.log 2>&1 &
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
overlay_esp=$(kubectl -n kube-system exec "$overlay_ovs" -- bash -o pipefail -c 'tcpdump -Z root -n -r /tmp/ipsec-overlay.pcap | awk "/ESP\\(spi=/{count++} END{print count+0}"')
overlay_plaintext=$(kubectl -n kube-system exec "$overlay_ovs" -- bash -o pipefail -c 'tcpdump -Z root -n -r /tmp/ipsec-overlay.pcap "udp port 6081 or udp port 4789" | wc -l')
echo "Actual cross-node OVN $overlay_family $overlay_tunnel pods: ESP packets=$overlay_esp plaintext transport packets=$overlay_plaintext"
if [[ "$overlay_esp" == 0 || "$overlay_plaintext" != 0 ]]; then
  echo 'The actual OVN overlay did not prove encryption without plaintext' >&2
  exit 1
fi

if [[ "$overlay_protection" == true ]]; then
  for node in "$overlay_control_plane" "$overlay_worker"; do
    # Do not dump XFRM key material; print only the counted owned reqid headers.
    owned_states=$(docker exec "$node" bash -o pipefail -c 'ip xfrm state | awk "/reqid 759815 /{n++} END{print n+0}"')
    if [[ "$owned_states" == 0 ]]; then
      echo 'No ESP SA uses the prototype ownership reservation' >&2
      exit 1
    fi
    echo "OVN-generated marked $overlay_family $overlay_tunnel tunnel on $node: owned ESP states=$owned_states"
  done
fi

if [[ "$overlay_protection" == true ]]; then
  # Freeze kubelet recovery only in disposable Kind nodes. CRI exec continues
  # to exercise existing containers without depending on the stopped kubelet.
  for node in "$overlay_control_plane" "$overlay_worker"; do
    docker exec "$node" systemctl stop kubelet
    ipsec_id=$(docker exec "$node" crictl ps --name '^ipsec$' -q)
    [[ -n "$ipsec_id" && "$ipsec_id" != *$'\n'* ]]
    docker exec "$node" crictl stop --timeout 10 "$ipsec_id"
    for attempt in {1..30}; do
      owned_states=$(docker exec "$node" bash -o pipefail -c 'ip xfrm state | awk "/reqid 759815 /{n++} END{print n+0}"')
      if [[ "$owned_states" == 0 ]]; then
        break
      fi
      if [[ "$attempt" == 30 ]]; then
        echo 'Stopped IKE runtime retained owned prototype ESP SAs' >&2
        exit 1
      fi
      sleep 1
    done
    docker exec "$node" bash -o pipefail -c 'ip xfrm policy get index 759833 dir out mark 759815 mask 0xffffffff | grep -q "action block"'
  done
  central_id=$(docker exec "$overlay_control_plane" crictl ps --name '^ovn-central$' -q)
  [[ -n "$central_id" && "$central_id" != *$'\n'* ]]
  docker exec "$overlay_control_plane" crictl exec "$central_id" ovn-nbctl set NB_Global . ipsec=false
  ovs_id=$(docker exec "$overlay_control_plane" crictl ps --name '^openvswitch$' -q)
  [[ -n "$ovs_id" && "$ovs_id" != *$'\n'* ]]
  for attempt in {1..30}; do
    if docker exec "$overlay_control_plane" crictl exec "$ovs_id" ovs-vsctl --format=json --columns=options find Interface "type=$overlay_tunnel" | \
        python3 -c 'import json,sys; rows=json.load(sys.stdin)["data"]; options=[dict(row[0][1]) for row in rows]; sys.exit(not options or not all(o.get("egress_pkt_mark")=="759815" and "remote_name" not in o for o in options))'; then
      break
    fi
    if [[ "$attempt" == 30 ]]; then
      echo 'OVN did not retain the protection mark with SB encryption disabled' >&2
      exit 1
    fi
    sleep 1
  done
  docker exec "$overlay_control_plane" crictl exec "$ovs_id" bash -c '
    set -euo pipefail
    tcpdump -Z root -i eth0 -p -n -U -w /tmp/ipsec-protected.pcap \
      "host $1 and (udp port 6081 or udp port 4789)" >/tmp/ipsec-protected.log 2>&1 &
    echo "$!" >/tmp/ipsec-protected.pid
    wait "$!"
  ' protected-capture "$overlay_peer" &
  protected_capture_client=$!
  for attempt in {1..30}; do
    if docker exec "$overlay_control_plane" crictl exec "$ovs_id" bash -c 'grep -q "listening on eth0" /tmp/ipsec-protected.log'; then
      break
    fi
    if [[ "$attempt" == 30 ]]; then
      echo 'Protected-output capture did not start' >&2
      exit 1
    fi
    sleep 0.1
  done
  pod_id=$(docker exec "$overlay_control_plane" crictl ps --name '^control-plane$' -q)
  [[ -n "$pod_id" && "$pod_id" != *$'\n'* ]]
  overlay_pod_ip=$(kubectl -n ipsec-overlay get pod worker -o jsonpath='{.status.podIP}')
  if docker exec "$overlay_control_plane" crictl exec "$pod_id" ping -c 5 -W 1 "$overlay_pod_ip"; then
    echo 'Protected cross-node traffic was delivered with IKE stopped and SB encryption disabled' >&2
    exit 1
  fi
  # These upstream paths have no per-peer IKE identity. They are unsupported
  # encryption modes and must retain the output guard, including existing ports.
  for node in "$overlay_control_plane" "$overlay_worker"; do
    node_ovs_id=$(docker exec "$node" crictl ps --name '^openvswitch$' -q)
    [[ -n "$node_ovs_id" && "$node_ovs_id" != *$'\n'* ]]
    docker exec "$node" crictl exec "$node_ovs_id" ovs-vsctl set Open_vSwitch . \
      external_ids:ovn-enable-flow-based-tunnels=true \
      external_ids:ovn-evpn-vxlan-ports=4789
    for expected_mark in 759815 759816; do
      if [[ "$expected_mark" == 759816 ]]; then
        # Install the replacement fixture guard before publishing its mark.
        docker exec "$node" ip xfrm policy add src "$overlay_wildcard" dst "$overlay_wildcard" \
          dir out priority 2147483647 index 759841 action block mark 759816 mask 0xffffffff
        docker exec "$node" crictl exec "$node_ovs_id" ovs-vsctl set Open_vSwitch . \
          external_ids:ovn-ipsec-protection-mark=759816
      fi
      for attempt in {1..30}; do
        if docker exec "$node" crictl exec "$node_ovs_id" ovs-vsctl --format=json --columns=name,options list Interface | \
            python3 -c 'import json,sys; rows=json.load(sys.stdin)["data"]; ports=[(name,dict(options[1])) for name,options in rows if name.startswith("ovn") and dict(options[1]).get("remote_ip")=="flow"]; sys.exit(not any("-evpn-" in name for name,_ in ports) or not any("-evpn-" not in name for name,_ in ports) or not all(o.get("egress_pkt_mark")==sys.argv[1] and "remote_name" not in o and "ipsec_mark_out" not in o and "ipsec_reqid" not in o for _,o in ports))' "$expected_mark"; then
          break
        fi
        if [[ "$attempt" == 30 ]]; then
          echo "OVN did not reconcile flow-based/EVPN output mark $expected_mark on $node" >&2
          exit 1
        fi
        sleep 1
      done
    done
  done
  if docker exec "$overlay_control_plane" crictl exec "$pod_id" ping -c 5 -W 1 "$overlay_pod_ip"; then
    echo 'Unsupported flow-based output bypassed the armed protection' >&2
    exit 1
  fi
  docker exec "$overlay_control_plane" crictl exec "$ovs_id" bash -c 'kill -INT "$(cat /tmp/ipsec-protected.pid)"'
  wait "$protected_capture_client"
  protected_plaintext=$(docker exec "$overlay_control_plane" crictl exec "$ovs_id" bash -o pipefail -c 'tcpdump -Z root -n -r /tmp/ipsec-protected.pcap | wc -l')
  echo "OVN $overlay_family $overlay_tunnel retained-mark protection after IKE stop/SB disable: plaintext transport packets=$protected_plaintext"
  [[ "$protected_plaintext" == 0 ]]
fi
