#!/usr/bin/env bash
set -euo pipefail

repoRoot="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixtureDir="$(mktemp -d)"
trap 'rm -rf "$fixtureDir"' EXIT
chartArgs=(template distributed "$repoRoot/charts/kube-ovn" --set MASTER_NODES=127.0.0.1
  --set distributed.sharedSubnet=true --set func.ENABLE_IC=true
  --set distributed.externalInterconnect=true --set distributed.gatewayOwner=node-a
  --set distributed.nbEndpoint=tcp:127.0.0.1:6641
  --set distributed.sbEndpoint=tcp:127.0.0.1:6642
  --set distributed.icNbEndpoint=tcp:192.0.2.1:6645)
helm "${chartArgs[@]}" > "$fixtureDir/rendered.yaml"
for field in nbEndpoint sbEndpoint icNbEndpoint gatewayOwner; do
  if helm "${chartArgs[@]}" --set "distributed.$field=" > "$fixtureDir/error" 2>&1; then
    echo "Missing distributed.$field unexpectedly succeeded" >&2
    exit 1
  fi
  rg -q "requires distributed.$field" "$fixtureDir/error"
done
for setting in externalInterconnect=false zone=custom; do
  if helm "${chartArgs[@]}" --set "distributed.$setting" > "$fixtureDir/error" 2>&1; then
    echo "Unsupported distributed.$setting unexpectedly succeeded" >&2
    exit 1
  fi
done
helm template default "$repoRoot/charts/kube-ovn" --set MASTER_NODES=127.0.0.1 > "$fixtureDir/default.yaml"
python3 - "$fixtureDir/rendered.yaml" "$fixtureDir/default.yaml" <<'PYCHART'
import sys

import yaml


def controller(path):
    with open(path, encoding="utf-8") as rendered:
        documents = list(yaml.safe_load_all(rendered))
    selected = [doc for doc in documents if doc and doc.get("metadata", {}).get("name") == "kube-ovn-controller" and doc.get("kind") in {"Deployment", "DaemonSet"}]
    assert len(selected) == 1, "Expected exactly one kube-ovn-controller workload"
    workload = selected[0]
    containers = workload["spec"]["template"]["spec"]["containers"]
    selected_container = [container for container in containers if container["name"] == "kube-ovn-controller"]
    assert len(selected_container) == 1, "Expected exactly one controller container"
    return documents, workload, selected_container[0]


documents, distributed, container = controller(sys.argv[1])
assert distributed["kind"] == "DaemonSet", "Distributed controller must be a DaemonSet"
assert not any(doc and doc.get("metadata", {}).get("name") == "ovn-ic-controller" for doc in documents), "Legacy IC controller must be omitted"
environment = {item["name"]: item for item in container["env"]}
assert environment["OVN_NB_ADDR"]["value"] == "tcp:127.0.0.1:6641"
assert environment["OVN_SB_ADDR"]["value"] == "tcp:127.0.0.1:6642"
assert environment["NODE_NAME"]["valueFrom"]["fieldRef"]["fieldPath"] == "spec.nodeName"
assert "OVN_DB_IPS" not in environment, "Distributed controller must not discover central databases"
arguments = container["args"]
for argument in ("--distributed-shared-subnet=true", "--distributed-gateway-owner=node-a", "--ovn-ic-nb-addr=tcp:192.0.2.1:6645"):
    assert argument in arguments, f"Missing controller argument {argument}"
assert not any(argument.startswith("--distributed-zone=") for argument in arguments)
_, default, container = controller(sys.argv[2])
assert default["kind"] == "Deployment", "Default controller must be a Deployment"
assert not any(argument.startswith("--distributed-shared-subnet=") for argument in container["args"])
PYCHART
echo 'Distributed chart: 8 checks passed'
