#!/usr/bin/env python3
"""Replay the unchanged NP suite with selective API/OVN timing evidence."""

import datetime
import json
import os
import pathlib
import re
import subprocess
import threading
import time


RESULTS = pathlib.Path("comparison-results")
CLI = str(RESULTS / "kubectl-ko")
STOP = threading.Event()
PREFIX = re.compile(r"(?:netpol|udp.network.policy|sctp.network.policy)[.-]")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def execute(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=35)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} exited {result.returncode}: {result.stderr[:1000]}")
    return result.stdout


def ovsdb(role, table, columns, conditions=None):
    argv = [CLI, "--timeout", "25s", "exec", role + "ctl", "--",
            "--format=json", "--data=json", "--columns=" + columns]
    argv += ["find", table, *(conditions or [])] if conditions else ["list", table]
    data = json.loads(execute(argv))
    return [dict(zip(data["headings"], row)) for row in data["data"]]


def selected_row(row):
    return bool(PREFIX.search(json.dumps(row)))


def objects():
    data = json.loads(execute([
        "kubectl", "--request-timeout=15s", "get", "pods,networkpolicies",
        "--all-namespaces", "-o", "json",
    ]))
    selected = []
    for item in data["items"]:
        metadata = item["metadata"]
        if not PREFIX.search(metadata.get("namespace", "")):
            continue
        result = {
            "kind": item["kind"], "namespace": metadata["namespace"],
            "name": metadata["name"], "uid": metadata["uid"],
            "createdAt": metadata["creationTimestamp"],
            "generation": metadata.get("generation"),
            "resourceVersion": metadata["resourceVersion"],
            "labels": metadata.get("labels", {}),
            "deletingAt": metadata.get("deletionTimestamp"),
        }
        if item["kind"] == "NetworkPolicy":
            result["policy"] = item["spec"]
        else:
            result["node"] = item["spec"].get("nodeName")
            result["phase"] = item.get("status", {}).get("phase")
            result["ips"] = item.get("status", {}).get("podIPs", [])
            result["conditions"] = [{"type": c["type"], "status": c["status"],
                                     "changedAt": c["lastTransitionTime"]}
                                    for c in item.get("status", {}).get("conditions", [])]
        selected.append(result)
    return selected


def collect():
    snapshots = 0
    errors = []
    with (RESULTS / "policy-timeline.jsonl").open("w") as output:
        while not STOP.is_set():
            snapshot = {"startedAt": now(), "queries": {}}
            operations = {
                "api": objects,
                "nbACL": lambda: [r for r in ovsdb(
                    "nb", "ACL", "_uuid,name,match,action,priority,tier,direction,external_ids")
                    if selected_row(r)],
                "nbPortGroup": lambda: [r for r in ovsdb(
                    "nb", "Port_Group", "_uuid,name,ports,acls,external_ids") if selected_row(r)],
                "nbAddressSet": lambda: [r for r in ovsdb(
                    "nb", "Address_Set", "_uuid,name,addresses,external_ids") if selected_row(r)],
                "sbBindings": lambda: [r for r in ovsdb(
                    "sb", "Port_Binding", "_uuid,logical_port,chassis,up,mac") if selected_row(r)],
                "sbIngressACL": lambda: ovsdb(
                    "sb", "Logical_Flow",
                    "_uuid,logical_datapath,pipeline,table_id,priority,match,actions,external_ids",
                    ["external_ids:stage-name=ls_in_acl_eval"]),
                "sbEgressACL": lambda: ovsdb(
                    "sb", "Logical_Flow",
                    "_uuid,logical_datapath,pipeline,table_id,priority,match,actions,external_ids",
                    ["external_ids:stage-name=ls_out_acl_eval"]),
                "controller": lambda: [line for line in execute([
                    "kubectl", "--request-timeout=15s", "-n", "kube-system", "logs",
                    "deployment/kube-ovn-controller", "--timestamps", "--since=10s",
                    "--tail=300",
                ]).splitlines() if PREFIX.search(line) or "handleUpdateNetworkPolicy" in line],
            }
            for key, operation in operations.items():
                if STOP.is_set():
                    break
                started = time.monotonic()
                record = {"startedAt": now()}
                try:
                    record["data"] = operation()
                except (RuntimeError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
                    record["error"] = str(error)[:1500]
                    errors.append({"query": key, "at": now(), "error": record["error"]})
                record["completedAt"] = now()
                record["seconds"] = time.monotonic() - started
                snapshot["queries"][key] = record
            snapshot["completedAt"] = now()
            output.write(json.dumps(snapshot) + "\n")
            output.flush()
            snapshots += 1
            STOP.wait(3)
    (RESULTS / "collector.json").write_text(json.dumps({
        "snapshots": snapshots, "errors": errors, "stopped": True,
        "boundary": "Non-atomic sequential snapshots with added API/agent query load. "
                    "No assertions, retries, deadlines or runtime source changed. "
                    "Missing/late snapshots do not prove earlier policy or data-plane state.",
    }, indent=2) + "\n")


def main():
    seed = int(os.environ["FIXED_SEED"])
    thread = threading.Thread(target=collect)
    thread.start()
    try:
        with (RESULTS / "e2e.log").open("w") as output:
            result = subprocess.run([
                "make", "k8s-netpol-e2e",
                "GINKGO_E2E_RUN=go tool github.com/onsi/ginkgo/v2/ginkgo run "
                f"--github-output --silence-skips --randomize-all -v --seed={seed}",
            ], stdout=output, stderr=subprocess.STDOUT)
    finally:
        STOP.set()
        thread.join()
    print((RESULTS / "e2e.log").read_text())
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
