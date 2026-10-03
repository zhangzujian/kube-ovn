#!/usr/bin/env python3
"""Replay immutable HA suites and retain selected, credential-free metadata."""

import datetime
import json
from pathlib import Path
import subprocess
import threading


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "diagnostics-results"
CANDIDATE = ROOT / "candidate"
CLI = RESULTS / "kubectl-ko"
STOP = threading.Event()
COLLECTOR_ERRORS = []


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def query(argv):
    started = now()
    try:
        result = subprocess.run(argv, capture_output=True, timeout=10, check=False)
        if result.returncode:
            return {"startedAt": started, "completedAt": now(), "exit": result.returncode}, None
        return {"startedAt": started, "completedAt": now(), "exit": 0}, json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        return {"startedAt": started, "completedAt": now(), "errorType": type(error).__name__}, None


def pod_metadata(pod):
    metadata, spec, status = pod["metadata"], pod["spec"], pod.get("status", {})
    return {
        "name": metadata["name"], "uid": metadata["uid"],
        "createdAt": metadata.get("creationTimestamp"),
        "deletingAt": metadata.get("deletionTimestamp"), "node": spec.get("nodeName"),
        "phase": status.get("phase"), "podIPs": status.get("podIPs", []),
        "networkAnnotations": {key: value for key, value in metadata.get("annotations", {}).items()
                               if key in {"ovn.kubernetes.io/allocated", "ovn.kubernetes.io/routed", "ovn.kubernetes.io/ip_address"}},
        "conditions": [{key: condition.get(key) for key in ("type", "status", "reason", "lastTransitionTime")}
                       for condition in status.get("conditions", [])],
        "containers": [{"name": container["name"], "ready": container.get("ready"),
                        "restarts": container.get("restartCount"),
                        "state": {kind: {key: value.get(key) for key in ("reason", "exitCode", "startedAt", "finishedAt")}
                                  for kind, value in container.get("state", {}).items()}}
                       for container in status.get("containerStatuses", [])],
    }


def selected_name(name):
    return name.startswith(("ko-", "kube-ovn-", "ovn-central-", "ovs-ovn-"))


def collect():
    with (RESULTS / "timeline.jsonl").open("w") as output:
        while not STOP.is_set():
            snapshot = {"at": now(), "queries": {}, "pods": [], "events": [], "workloads": []}
            info, objects = query(["kubectl", "-n", "kube-system", "get", "pods", "-o", "json"])
            snapshot["queries"]["pods"] = info
            if objects:
                snapshot["pods"] = [pod_metadata(pod) for pod in objects["items"]
                                    if selected_name(pod["metadata"]["name"])]
            info, objects = query(["kubectl", "-n", "kube-system", "get", "events", "-o", "json"])
            snapshot["queries"]["events"] = info
            if objects:
                snapshot["events"] = [{"name": event["involvedObject"]["name"],
                                       "uid": event["involvedObject"].get("uid"),
                                       "reason": event.get("reason"), "type": event.get("type"),
                                       "count": event.get("count"), "firstAt": event.get("firstTimestamp"),
                                       "lastAt": event.get("lastTimestamp"), "eventTime": event.get("eventTime")}
                                      for event in objects["items"] if selected_name(event["involvedObject"]["name"])]
            info, objects = query(["kubectl", "-n", "kube-system", "get", "deployment,daemonset", "-o", "json"])
            snapshot["queries"]["workloads"] = info
            if objects:
                snapshot["workloads"] = [{"kind": obj["kind"], "name": obj["metadata"]["name"],
                                          "generation": obj["metadata"]["generation"],
                                          "status": {key: value for key, value in obj.get("status", {}).items()
                                                     if isinstance(value, (int, bool))}}
                                         for obj in objects["items"] if selected_name(obj["metadata"]["name"])]
            for tool, table, columns, name_column in [
                ("nbctl", "Logical_Switch_Port", "name,up,addresses", "name"),
                ("sbctl", "Port_Binding", "logical_port,chassis,up", "logical_port"),
            ]:
                info, objects = query([str(CLI), "--timeout", "8s", "exec", tool, "--", "--timeout=5",
                                       "--format=json", "--columns=" + columns, "list", table])
                snapshot["queries"][table] = info
                if objects:
                    index = objects["headings"].index(name_column)
                    snapshot[table] = {"headings": objects["headings"],
                                       "data": [row for row in objects["data"] if selected_name(row[index])]}
            output.write(json.dumps(snapshot) + "\n")
            output.flush()
            STOP.wait(5)


def collect_safely():
    try:
        collect()
    except Exception as error:
        COLLECTOR_ERRORS.append({"at": now(), "errorType": type(error).__name__})


def main():
    RESULTS.mkdir(exist_ok=True)
    collector = threading.Thread(target=collect_safely)
    collector.start()
    reports = []
    try:
        for suite, seed, target in [("security", 1791044104, "kube-ovn-security-e2e"),
                                    ("ha", 1791044325, "kube-ovn-ha-e2e")]:
            report = {"suite": suite, "seed": seed, "startedAt": now()}
            # The Make target still builds and runs the original suite, with its
            # unchanged arguments, assertions and timeouts. Only the seed is pinned.
            argv = ["make", target,
                    f"GINKGO_E2E_RUN=go tool github.com/onsi/ginkgo/v2/ginkgo run --github-output --silence-skips --randomize-all -v --seed={seed}"]
            with (RESULTS / (suite + ".log")).open("w") as output:
                result = subprocess.run(argv, cwd=CANDIDATE, stdout=output, stderr=subprocess.STDOUT, check=False)
            report.update({"completedAt": now(), "exit": result.returncode})
            reports.append(report)
            if result.returncode:
                break
    finally:
        STOP.set()
        collector.join(timeout=60)
        if collector.is_alive():
            raise RuntimeError("diagnostic collector did not stop")
        (RESULTS / "summary.json").write_text(json.dumps({"head": "100a48deaf2de5ac17b2a64ac1443b7a0416bbaf",
                                                          "originalRun": 37131618946, "originalJob": 111231733695,
                                                          "suites": reports, "collectorStopped": True,
                                                          "collectorErrors": COLLECTOR_ERRORS,
                                                          "boundary": "Sequential non-atomic snapshots; collection adds API/OVSDB load. Original assertions retained."}, indent=2) + "\n")
    return next((report["exit"] for report in reports if report["exit"]), int(bool(COLLECTOR_ERRORS)))


if __name__ == "__main__":
    raise SystemExit(main())
