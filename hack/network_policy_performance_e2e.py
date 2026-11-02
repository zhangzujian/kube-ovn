#!/usr/bin/env python3
"""Run a controlled NetworkPolicy event storm and collect controller evidence."""

import argparse
import json
import os
import pathlib
import subprocess
import time
import urllib.request
import re


ROOT = pathlib.Path(os.environ.get("PERF_OUTPUT", "network-policy-performance"))
NAMESPACES = 20
PODS = 20
NETWORK_POLICIES = 100
ADMIN_POLICIES = 10
STORM_ROUNDS = 3


def run(*args, input_text=None, check=True, capture=False):
    return subprocess.run(
        args,
        input=input_text,
        text=True,
        check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def yaml_labels(labels, indent="    "):
	return "".join(f"{indent}{key}: {value}\n" for key, value in labels.items())


def policy_selector(tenant, state="old"):
    return f"        matchLabels:\n          tenant: {tenant}\n          event-state: {state}\n"


def build_manifests():
    documents = []
    for index in range(NAMESPACES):
        tenant = f"t{index}"
        documents.append(
            "\n".join(
                [
                    "apiVersion: v1",
                    "kind: Namespace",
                    "metadata:",
                    f"  name: perf-{index}",
                    "  labels:",
                    yaml_labels({"perf-suite": "network-policy", "tenant": tenant, "event-state": "old"}).rstrip(),
                ]
            )
        )
    for index in range(PODS):
        tenant = f"t{index}"
        documents.append(
            "\n".join(
                [
                    "apiVersion: v1",
                    "kind: Pod",
                    "metadata:",
                    f"  name: perf-pod-{index}",
                    f"  namespace: perf-{index}",
                    "  labels:",
                    yaml_labels({"perf-suite": "network-policy", "tenant": tenant, "policy-id": f"p{index}", "event-state": "old"}),
                    "spec:",
                    "  containers:",
                    "  - name: pause",
                    "    image: registry.k8s.io/e2e-test-images/agnhost:2.45",
                    "    command: [\"/agnhost\", \"pause\"]",
                ]
            )
        )
    for index in range(NETWORK_POLICIES):
        tenant = f"t{index % NAMESPACES}"
        policy_id = f"p{index % PODS}"
        documents.append(
            "\n".join(
                [
                    "apiVersion: networking.k8s.io/v1",
                    "kind: NetworkPolicy",
                    "metadata:",
                    f"  name: perf-np-{index}",
                    "  namespace: perf-0",
                    "spec:",
                    "  podSelector:",
                    "    matchLabels:",
                    f"      policy-id: {policy_id}",
                    "  policyTypes: [Ingress]",
                    "  ingress:",
                    "  - from:",
                    "    - namespaceSelector:",
                    "        matchLabels:",
                    f"          tenant: {tenant}",
                    "          event-state: old",
                ]
            )
        )
    for kind in ("AdminNetworkPolicy", "BaselineAdminNetworkPolicy", "ClusterNetworkPolicy"):
        for index in range(ADMIN_POLICIES):
            tenant = f"t{index}"
            if kind == "ClusterNetworkPolicy":
                documents.append(
                    "\n".join(
                        [
                            "apiVersion: policy.networking.k8s.io/v1alpha2",
                            "kind: ClusterNetworkPolicy",
                            "metadata:",
                            f"  name: perf-cnp-{index}",
                            "spec:",
                            "  tier: Admin",
                            f"  priority: {100 + index}",
                            "  subject:",
                            "    namespaces:",
                            policy_selector(tenant).rstrip(),
                            "  ingress:",
                            "  - name: ingress",
                            "    action: Accept",
                            "    from:",
                            "    - namespaces:",
                            policy_selector(tenant).rstrip(),
                        ]
                    )
                )
                continue
            api_version = "policy.networking.k8s.io/v1alpha1"
            action = "Allow" if kind == "AdminNetworkPolicy" else "Deny"
            prefix = "anp" if kind == "AdminNetworkPolicy" else "banp"
            documents.append(
                "\n".join(
                    [
                        f"apiVersion: {api_version}",
                        f"kind: {kind}",
                        "metadata:",
                        f"  name: perf-{prefix}-{index}",
                        "spec:",
                        f"  priority: {100 + index}",
                        "  subject:",
                        "    namespaces:",
                        policy_selector(tenant).rstrip(),
                        "  ingress:",
                        "  - name: ingress",
                        f"    action: {action}",
                        "    from:",
                        "    - namespaces:",
                        policy_selector(tenant).rstrip(),
                    ]
                )
            )
    return "\n---\n".join(documents) + "\n"


def start_port_forward():
    process = subprocess.Popen(
        ["kubectl", "-n", "kube-system", "port-forward", "svc/kube-ovn-controller", "18080:10660"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(30):
        try:
            urllib.request.urlopen("http://127.0.0.1:18080/readyz", timeout=2).close()
            return process
        except Exception:
            time.sleep(1)
    process.terminate()
    raise RuntimeError("controller metrics port-forward did not become ready")


def metrics_snapshot(path):
    data = urllib.request.urlopen("http://127.0.0.1:18080/metrics", timeout=10).read()
    pathlib.Path(path).write_bytes(data)


def parse_prometheus(path):
    samples = {}
    pattern = re.compile(r"^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^}]*)\})?\s+([-+0-9.eE]+)$")
    label_pattern = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:\\.|[^"\\])*)"')
    for line in pathlib.Path(path).read_text().splitlines():
        match = pattern.match(line)
        if not match:
            continue
        labels = tuple(sorted(label_pattern.findall(match.group(2) or "")))
        samples[(match.group(1), labels)] = float(match.group(3))
    return samples


def metric_totals(samples, name):
    return {
        labels: value
        for (sample_name, labels), value in samples.items()
        if sample_name == name
    }


def phase_summary(name):
    before = parse_prometheus(ROOT / f"{name}-before.prom")
    after = parse_prometheus(ROOT / f"{name}-after.prom")

    def delta(metric):
        before_values = metric_totals(before, metric)
        after_values = metric_totals(after, metric)
        keys = set(before_values) | set(after_values)
        return {
            "{" + ",".join(f"{key}={value}" for key, value in sorted(dict(labels).items())) + "}": after_values.get(labels, 0) - before_values.get(labels, 0)
            for labels in keys
        }

    def value(metric):
        return sum(metric_totals(after, metric).values())

    queue_depth = metric_totals(after, "workqueue_depth")
    summary = {
        "mode": name,
        "selector_matches_delta": delta("network_policy_selector_matches_total"),
        "candidate_evaluations_delta": delta("network_policy_candidate_evaluations_total"),
        "address_set_updates_delta": delta("network_policy_address_set_updates_total"),
        "workqueue_adds_delta": delta("workqueue_adds_total"),
        "workqueue_queue_duration_count_delta": delta("workqueue_queue_duration_seconds_count"),
        "workqueue_queue_duration_sum_delta": delta("workqueue_queue_duration_seconds_sum"),
        "workqueue_work_duration_count_delta": delta("workqueue_work_duration_seconds_count"),
        "workqueue_work_duration_sum_delta": delta("workqueue_work_duration_seconds_sum"),
        "workqueue_depth_after": {str(dict(labels)): value for labels, value in queue_depth.items()},
        "ovsdb_request_count_delta": delta("ovs_client_request_latency_milliseconds_count"),
        "process_cpu_seconds_delta": value("process_cpu_seconds_total") - sum(metric_totals(before, "process_cpu_seconds_total").values()),
    }
    (ROOT / f"{name}-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def run_storm(state):
    for _ in range(STORM_ROUNDS):
        run("kubectl", "label", "pods", "-A", "-l", "perf-suite=network-policy", f"event-state={state}", "--overwrite")
        run("kubectl", "label", "namespace", "-l", "perf-suite=network-policy", f"event-state={state}", "--overwrite")
        time.sleep(3)
    time.sleep(20)


def collect_runtime(name):
    target = run("kubectl", "-n", "kube-system", "get", "pod", "-l", "app=kube-ovn-controller", "-o", "jsonpath={.items[0].metadata.name}", capture=True).stdout.strip()
    log = run("kubectl", "-n", "kube-system", "logs", target, "--since=5m", capture=True, check=False).stdout
    (ROOT / f"{name}-controller.log").write_text(log)
    cgroup = run("kubectl", "-n", "kube-system", "exec", target, "--", "cat", "/sys/fs/cgroup/cpu.stat", capture=True, check=False).stdout
    (ROOT / f"{name}-cpu.stat").write_text(cgroup)
    central = run("kubectl", "-n", "kube-system", "get", "pod", "-l", "app=ovn-central", "-o", "jsonpath={.items[0].metadata.name}", capture=True, check=False).stdout.strip()
    if central:
        nb = run("kubectl", "-n", "kube-system", "exec", central, "--", "ovn-nbctl", "--format=csv", "--no-heading", "--columns=name,addresses", "list", "address_set", capture=True, check=False).stdout
        (ROOT / f"{name}-address-sets.csv").write_text(nb)
    return target


def restart_controller(disable_index):
    value = "--disable-policy-event-index"
    if disable_index:
        run("kubectl", "-n", "kube-system", "patch", "deployment", "kube-ovn-controller", "--type=json", "-p", json.dumps([{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": value}]))
    else:
        run("kubectl", "-n", "kube-system", "patch", "deployment", "kube-ovn-controller", "--type=json", "-p", json.dumps([{"op": "remove", "path": "/spec/template/spec/containers/0/args/-"}]), check=False)
    run("kubectl", "-n", "kube-system", "rollout", "status", "deployment/kube-ovn-controller", "--timeout=180s")


def main():
    global ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT))
    args = parser.parse_args()
    ROOT = pathlib.Path(args.output)
    ROOT.mkdir(parents=True, exist_ok=True)
    manifest = ROOT / "workload.yaml"
    manifest.write_text(build_manifests())
    run("kubectl", "apply", "-f", str(manifest))
    run("kubectl", "wait", "--for=condition=Ready", "pod", "-A", "-l", "perf-suite=network-policy", "--timeout=180s")
    run("kubectl", "-n", "kube-system", "patch", "deployment", "kube-ovn-controller", "--type=json", "-p", json.dumps([
        {"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--enable-pprof"},
        {"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--v=4"},
    ]))
    run("kubectl", "-n", "kube-system", "rollout", "status", "deployment/kube-ovn-controller", "--timeout=180s")
    for disable_index, name in ((False, "indexed"), (True, "full-scan")):
        if disable_index:
            restart_controller(True)
        forward = start_port_forward()
        metrics_snapshot(ROOT / f"{name}-before.prom")
        run_storm("new" if not disable_index else "old")
        metrics_snapshot(ROOT / f"{name}-after.prom")
        phase_summary(name)
        target = collect_runtime(name)
        profile = urllib.request.urlopen("http://127.0.0.1:18080/debug/pprof/profile?seconds=10", timeout=20).read()
        (ROOT / f"{name}-profile.pb.gz").write_bytes(profile)
        forward.terminate()
        forward.wait(timeout=10)
        (ROOT / f"{name}-controller-pod.txt").write_text(target + "\n")

    run("kubectl", "get", "networkpolicies", "-A", "-o", "yaml", capture=False, check=False)
    run("kubectl", "get", "pods", "-A", "-o", "yaml", capture=False, check=False)


if __name__ == "__main__":
    main()
