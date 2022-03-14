#!/bin/bash

set -exo pipefail

bridge="vpc-nat-gw-br0"
bridge_addr="172.20.0.1/24"

ip link add $bridge type bridge
kubectl get node --no-headers -o custom-columns=NAME:.metadata.name | while read node; do
    port=$(echo ${node##kube-ovn-} | sed 's/control-plane/master/')
    peer=${port}-peer
    ip link add name $port type veth peer name $peer
    ip link set dev $port master $bridge
    ip link set dev $port up
    netns=$(docker inspect $node -f '{{json .NetworkSettings.SandboxKey}}' | tr -d '"')
    ip link set $peer netns $netns
    nsenter --net=$netns ip link set $peer name eth1
    nsenter --net=$netns ip link set eth1 up
done

ip link set $bridge up
ip addr add $bridge_addr dev $bridge
