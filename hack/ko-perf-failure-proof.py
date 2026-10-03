#!/usr/bin/env python3
"""Prove cleanup after a real perf readiness timeout using the fixed CLI."""

import json
import pathlib
import subprocess
import time


RESULTS = pathlib.Path("diagnostics-results")
CLI = str(RESULTS / "kubectl-ko")
SELECTOR = "app=kubectl-ko-probe"


def command(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60).stdout


def kubernetes(resource, selector):
    return json.loads(command([
        "kubectl", "--request-timeout=10s", "-n", "kube-system", "get", resource,
        "-l", selector, "-o", "json",
    ]))["items"]


def probes():
    return [{
        "kind": item["kind"], "name": item["metadata"]["name"],
        "uid": item["metadata"]["uid"],
        "run": item["metadata"]["labels"]["kubeovn.io/ko-run"],
        "phase": item.get("status", {}).get("phase"),
        "deleting": bool(item["metadata"].get("deletionTimestamp")),
        "ready": any(c["type"] == "Ready" and c["status"] == "True"
                     for c in item.get("status", {}).get("conditions", [])),
        "waiting": [c["state"]["waiting"]["reason"]
                    for c in item.get("status", {}).get("containerStatuses", [])
                    if "waiting" in c.get("state", {})],
    } for item in kubernetes("pods,services,daemonsets", SELECTOR)]


def components():
    result = {}
    for selector in ["app=kubectl-ko-node-agent", "app=ovn-central"]:
        for item in kubernetes("pods", selector):
            result[item["metadata"]["name"]] = {
                "uid": item["metadata"]["uid"],
                "restarts": {c["name"]: c["restartCount"]
                             for c in item.get("status", {}).get("containerStatuses", [])},
            }
    assert result, "No component pods observed"
    return result


def performance_lbs():
    data = json.loads(command([
        CLI, "--timeout", "30s", "exec", "nbctl", "--",
        "--format=json", "--data=json", "--columns=name", "list", "Load_Balancer",
    ]))
    return sorted(row[0] for row in data["data"]
                  if isinstance(row[0], str) and row[0].startswith("ko-perf-"))


def main():
    before = probes()
    assert not before, "Fresh verification cluster already contains ko probe resources"
    before_components = components()
    before_lbs = performance_lbs()
    report = {"before": before, "beforeComponents": before_components,
              "beforePerformanceLBs": before_lbs, "cases": []}
    (RESULTS / "failure-cleanup.json").write_text(json.dumps(report, indent=2) + "\n")

    # An invalid image reference prevents container startup without relying on
    # registry availability. The unchanged CLI creates all four real Pods and
    # waits for readiness before its overall context expires.
    for iteration in range(2):
        started = time.monotonic()
        observed = {}
        with (RESULTS / f"perf-failure-{iteration}.stdout.log").open("w") as out, \
             (RESULTS / f"perf-failure-{iteration}.stderr.log").open("w") as err:
            process = subprocess.Popen([
                CLI, "--timeout", "20s", "perf", "run", "--duration", "1s",
                "--image", "INVALID_REFERENCE", "--bandwidth", "10M",
            ], stdout=out, stderr=err)
            try:
                while process.poll() is None:
                    for item in probes():
                        observed[item["uid"]] = item
                    assert time.monotonic() - started < 90, "CLI did not finish bounded cleanup"
                    time.sleep(0.25)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
        error = (RESULTS / f"perf-failure-{iteration}.stderr.log").read_text()
        output = (RESULTS / f"perf-failure-{iteration}.stdout.log").read_text()
        case = {"iteration": iteration, "exitCode": process.returncode,
                "durationSeconds": time.monotonic() - started,
                "observed": list(observed.values()), "stderr": error}
        report["cases"].append(case)
        (RESULTS / "failure-cleanup.json").write_text(json.dumps(report, indent=2) + "\n")
        assert process.returncode != 0 and "context deadline exceeded" in error, error
        assert "cleanup " not in error, "CLI reported cleanup failure"
        assert output == "", "Traffic measurements unexpectedly started"
        assert len(observed) == 4, "Failure must follow creation of all four real probe Pods"
        assert len({item["run"] for item in observed.values()}) == 1
        assert all(item["kind"] == "Pod" and not item["ready"] for item in observed.values())
        assert any("InvalidImageName" in item["waiting"] for item in observed.values()), \
            "Image-reference readiness failure was not observed"
        deadline = time.monotonic() + 90
        while probes():
            assert time.monotonic() < deadline, "Temporary resources remained after failed invocation"
            time.sleep(1)
        case["after"] = probes()
        case["afterPerformanceLBs"] = performance_lbs()
        assert case["afterPerformanceLBs"] == before_lbs
        case["afterComponents"] = components()
        assert case["afterComponents"] == before_components, "Failure disrupted agents or central leaders"
        (RESULTS / "failure-cleanup.json").write_text(json.dumps(report, indent=2) + "\n")

    command([CLI, "--timeout", "30s", "db", "health"])
    report["subsequentDBHealth"] = "success"
    report["verdict"] = "success"
    report["boundary"] = (
        "Controlled current-candidate readiness failure, not a reconstruction of the original "
        "failed HA invocation. Original failure and its missing cleanup snapshot remain retained."
    )
    (RESULTS / "failure-cleanup.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Two real readiness failures cleaned eight probe Pods; LB/leader/agent state preserved.")


if __name__ == "__main__":
    main()
