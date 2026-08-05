#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE ONLY: validate the Linux VRF data-path premise proposed in issue #7130.
# Every mutable network object lives in an anonymous process-owned network namespace.

declare -A ns_pid=()
declare -a holder_pids=()
declare -a server_pids=()
scratch_dir=

cleanup() {
  local status=$?
  local pid
  for pid in "${server_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${holder_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [[ -n "$scratch_dir" && -d "$scratch_dir" ]]; then
    rm -rf -- "$scratch_dir"
  fi
  return "$status"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'PASS: %s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

root_network_fingerprint() {
  {
    ip -o link show
    ip -o address show
    ip route show table all
    ip rule show
    nft list ruleset | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter packets N bytes N/g'
    sysctl -n net.ipv4.ip_forward
  } | sha256sum | awk '{print $1}'
}

start_namespace() {
  local name=$1
  local root_netns
  local current_netns

  root_netns=$(readlink /proc/self/ns/net)
  unshare --net -- sleep infinity &
  local pid=$!
  holder_pids+=("$pid")

  for _ in $(seq 1 100); do
    if [[ -r /proc/$pid/ns/net ]]; then
      current_netns=$(readlink "/proc/$pid/ns/net")
      if [[ "$current_netns" != "$root_netns" ]]; then
        ns_pid["$name"]=$pid
        ns "$name" ip link set lo up
        return
      fi
    fi
    sleep 0.01
  done
  fail "network namespace $name did not start"
}

ns() {
  local name=$1
  shift
  nsenter --target "${ns_pid[$name]}" --net -- "$@"
}

add_cross_namespace_veth() {
  local left_ns=$1
  local left_if=$2
  local right_ns=$3
  local right_if=$4

  ip link add name "$left_if" netns "${ns_pid[$left_ns]}" \
    type veth peer name "$right_if" netns "${ns_pid[$right_ns]}"
  ns "$left_ns" ip link set "$left_if" up
  ns "$right_ns" ip link set "$right_if" up
}

disable_rp_filter() {
  local name=$1
  local interface

  ns "$name" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ns "$name" sysctl -qw net.ipv4.conf.default.rp_filter=0
  while read -r interface; do
    ns "$name" sysctl -qw "net.ipv4.conf.$interface.rp_filter=0"
  done < <(ns "$name" ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1)
}

start_echo_server() {
  local name=$1
  local address=$2
  local port=$3
  local connections=$4
  local log_file=$5

  nsenter --target "${ns_pid[$name]}" --net -- \
    python3 -u -c '
import socket
import sys

address = sys.argv[1]
port = int(sys.argv[2])
connections = int(sys.argv[3])
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen()
    for _ in range(connections):
        connection, peer = listener.accept()
        with connection:
            connection.sendall((peer[0] + "\n").encode())
' "$address" "$port" "$connections" >"$log_file" 2>&1 &
  server_pids+=("$!")
}

tcp_peer() {
  local name=$1
  local address=$2
  local port=$3

  ns "$name" python3 -c '
import socket
import sys
import time

address = sys.argv[1]
port = int(sys.argv[2])
last_error = None
for _ in range(50):
    try:
        with socket.create_connection((address, port), timeout=1) as connection:
            print(connection.recv(128).decode().strip())
            raise SystemExit(0)
    except OSError as error:
        last_error = error
        time.sleep(0.05)
raise SystemExit(f"connection failed: {last_error}")
' "$address" "$port"
}

tcp_peer_in_vrf() {
  local name=$1
  local vrf=$2
  local address=$3
  local port=$4

  ns "$name" ip vrf exec "$vrf" python3 -c '
import socket
import sys
import time

address = sys.argv[1]
port = int(sys.argv[2])
last_error = None
for _ in range(50):
    try:
        with socket.create_connection((address, port), timeout=1) as connection:
            print(connection.recv(128).decode().strip())
            raise SystemExit(0)
    except OSError as error:
        last_error = error
        time.sleep(0.05)
raise SystemExit(f"connection failed: {last_error}")
' "$address" "$port"
}

assert_equal() {
  local actual=$1
  local expected=$2
  local description=$3
  [[ "$actual" == "$expected" ]] || fail "$description: expected $expected, got $actual"
  pass "$description ($actual)"
}

for command in ip nft nsenter unshare python3 ping sha256sum sysctl; do
  require_command "$command"
done
[[ $(id -u) -eq 0 ]] || fail "this prototype must run as root"

root_before=$(root_network_fingerprint)
scratch_dir=$(mktemp -d)

printf 'Creating isolated topology...\n'
for name in host vpc1 vpc2 pod1 pod2 external; do
  start_namespace "$name"
done

add_cross_namespace_veth pod1 p1eth vpc1 v1pod
add_cross_namespace_veth vpc1 v1host host h1vpc
add_cross_namespace_veth pod2 p2eth vpc2 v2pod
add_cross_namespace_veth vpc2 v2host host h2vpc
add_cross_namespace_veth host uplink0 external ext0

ns host ip link add vrf1 type vrf table 1001
ns host ip link add vrf2 type vrf table 1002
ns host ip link set vrf1 up
ns host ip link set vrf2 up
ns host ip link set h1vpc master vrf1
ns host ip link set h2vpc master vrf2

ns pod1 ip address add 10.10.1.2/24 dev p1eth
ns pod1 ip route add default via 10.10.1.1
ns vpc1 ip address add 10.10.1.1/24 dev v1pod
ns vpc1 ip address add 172.31.1.1/30 dev v1host
ns vpc1 ip route add default via 172.31.1.2

ns pod2 ip address add 10.10.2.2/24 dev p2eth
ns pod2 ip route add default via 10.10.2.1
ns vpc2 ip address add 10.10.2.1/24 dev v2pod
ns vpc2 ip address add 172.31.2.1/30 dev v2host
ns vpc2 ip route add default via 172.31.2.2

ns host ip address add 172.31.1.2/30 dev h1vpc
ns host ip route add table 1001 10.10.1.0/24 via 172.31.1.1 dev h1vpc
ns host ip route add table 1001 unreachable default metric 4278198272

ns host ip address add 172.31.2.2/30 dev h2vpc
ns host ip route add table 1002 10.10.2.0/24 via 172.31.2.1 dev h2vpc
ns host ip route add table 1002 unreachable default metric 4278198272

ns host ip address add 203.0.113.1/24 dev uplink0
ns external ip address add 203.0.113.2/24 dev ext0
ns external ip route add 10.10.1.0/24 via 203.0.113.1
ns external ip route add 10.10.2.0/24 via 203.0.113.1

# The narrow egress rules run first. The ingress guards then keep every other
# packet from a VPC in its original table, before the destination rules make
# Pod CIDRs reachable to locally generated host traffic and external returns.
ns host ip rule add priority 40 from 10.10.1.0/24 to 203.0.113.0/24 lookup main
ns host ip rule add priority 41 from 10.10.2.0/24 to 203.0.113.0/24 lookup main
ns host ip rule add priority 50 iif h1vpc lookup 1001
ns host ip rule add priority 51 iif h2vpc lookup 1002
ns host ip rule add priority 100 to 10.10.1.0/24 lookup 1001
ns host ip rule add priority 101 to 10.10.2.0/24 lookup 1002

for name in host vpc1 vpc2 external; do
  ns "$name" sysctl -qw net.ipv4.ip_forward=1
  disable_rp_filter "$name"
done
ns host sysctl -qw net.ipv4.tcp_l3mdev_accept=0

printf '\nSimulated host state:\n'
ns host ip -brief link show
printf '\nVRF routes:\n'
ns host ip route show table 1001
ns host ip route show table 1002
printf '\nMain-table routes and policy rules:\n'
ns host ip route show table main
ns host ip rule show

printf '\nValidating Pod/host connectivity...\n'
ns pod1 ping -q -c 2 -W 1 172.31.1.2 >/dev/null
pass "VPC 1 Pod reaches its host-transit address"
ns pod2 ping -q -c 2 -W 1 172.31.2.2 >/dev/null
pass "VPC 2 Pod reaches its host-transit address"
ns pod1 ping -q -c 2 -W 1 203.0.113.1 >/dev/null
pass "VPC 1 Pod reaches a main-domain host-local address through the local table"
ns pod2 ping -q -c 2 -W 1 203.0.113.1 >/dev/null
pass "VPC 2 Pod reaches a main-domain host-local address through the local table"

start_echo_server host 0.0.0.0 18081 1 "$scratch_dir/host.log"
if peer=$(tcp_peer pod1 172.31.1.2 18081 2>/dev/null); then
  fail "plain host listener unexpectedly accepted VRF traffic while tcp_l3mdev_accept=0 from $peer"
fi
pass "tcp_l3mdev_accept=0 keeps a plain wildcard listener outside the VPC VRFs"
kill "${server_pids[-1]}" 2>/dev/null || true
wait "${server_pids[-1]}" 2>/dev/null || true

start_echo_server pod1 10.10.1.2 18091 1 "$scratch_dir/pod1.log"
start_echo_server pod2 10.10.2.2 18092 1 "$scratch_dir/pod2.log"
ns host ip route get 10.10.1.2
ns host ip route get 10.10.2.2
ns host ping -q -c 2 -W 1 10.10.1.2 >/dev/null
pass "an ordinary host ICMP socket reaches VPC 1 Pod through the destination policy rule"
ns host ping -q -c 2 -W 1 10.10.2.2 >/dev/null
pass "an ordinary host ICMP socket reaches VPC 2 Pod through the destination policy rule"
if peer=$(tcp_peer host 10.10.1.2 18091 2>/dev/null); then
  fail "a VRF-unaware host TCP socket unexpectedly reached VPC 1 Pod from $peer"
fi
pass "a VRF-unaware host TCP socket remains isolated from VPC 1 while tcp_l3mdev_accept=0"
if peer=$(tcp_peer host 10.10.2.2 18092 2>/dev/null); then
  fail "a VRF-unaware host TCP socket unexpectedly reached VPC 2 Pod from $peer"
fi
pass "a VRF-unaware host TCP socket remains isolated from VPC 2 while tcp_l3mdev_accept=0"
assert_equal "$(tcp_peer_in_vrf host vrf1 10.10.1.2 18091)" "172.31.1.2" \
  "a VRF-scoped host TCP socket reaches VPC 1 Pod"
assert_equal "$(tcp_peer_in_vrf host vrf2 10.10.2.2 18092)" "172.31.2.2" \
  "a VRF-scoped host TCP socket reaches VPC 2 Pod"

if ns pod1 ping -q -c 1 -W 1 10.10.2.2 >/dev/null 2>&1; then
  fail "VPC 1 unexpectedly reached VPC 2"
fi
pass "the VPC 1 ingress guard and unreachable default block traffic to VPC 2"
if ns pod2 ping -q -c 1 -W 1 10.10.1.2 >/dev/null 2>&1; then
  fail "VPC 2 unexpectedly reached VPC 1"
fi
pass "the VPC 2 ingress guard and unreachable default block traffic to VPC 1"

printf '\nValidating routed external egress...\n'
start_echo_server external 203.0.113.2 18080 2 "$scratch_dir/external.log"
assert_equal "$(tcp_peer pod1 203.0.113.2 18080)" "10.10.1.2" \
  "VPC 1 routed egress preserves the Pod source"
assert_equal "$(tcp_peer pod2 203.0.113.2 18080)" "10.10.2.2" \
  "VPC 2 routed egress preserves the Pod source"

root_after=$(root_network_fingerprint)
assert_equal "$root_after" "$root_before" "root network namespace remains unchanged"
assert_equal "$(ns host sysctl -n net.ipv4.tcp_l3mdev_accept)" "0" \
  "the simulated host keeps tcp_l3mdev_accept disabled"

printf '\nVERDICT: policy rules replace the leak veths for ICMP and routed forwarding without consuming extra addresses.\n'
printf 'With tcp_l3mdev_accept disabled, transparent host TCP sockets remain unavailable; an explicitly VRF-scoped client works.\n'
