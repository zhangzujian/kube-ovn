#!/usr/bin/env python3
"""Record historical ANP/BANP failures without changing the suite's verdict."""

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def command(args, timeout=8):
    started = time.monotonic()
    result = {"argv": args, "started": timestamp(), "monotonic_ns": time.monotonic_ns()}
    try:
        proc = subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
        result.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except (subprocess.TimeoutExpired, OSError) as err:
        result.update(returncode=-1, stdout="", stderr=str(err))
    result.update(finished=timestamp(), elapsed_seconds=time.monotonic() - started)
    return result


def kubectl(*args):
    return ["kubectl", "--request-timeout=5s", *args]


def pod_summary(raw):
    """Exclude environment variables, projected credentials and unrelated Pods."""
    items = []
    for pod in json.loads(raw)["items"]:
        metadata = pod["metadata"]
        if not metadata["namespace"].startswith("network-policy-conformance-") and metadata.get("labels", {}).get("app") not in {"ovs", "ovn-central", "kube-ovn-controller", "kube-ovn-cni"}:
            continue
        items.append({"name": metadata["name"], "namespace": metadata["namespace"], "uid": metadata["uid"],
                      "node": pod["spec"].get("nodeName"), "labels": metadata.get("labels", {}),
                      "status": pod.get("status", {}),
                      "containers": [{"name": c["name"], "image": c["image"]} for c in pod["spec"]["containers"]]})
    return {"items": items}


def parse_probe(command_line, expected_line):
    match = re.search(r"FAILED Command was \[(.+)\]", command_line)
    client = re.search(r"Expected connection to (fail|succeed|be dropped) from ([a-z0-9-]+)/([a-z0-9-]+) to", expected_line)
    if not match or not client:
        return None
    try:
        args = shlex.split(match[1])
    except ValueError:
        return None
    if len(args) != 5 or args[:2] != ["/agnhost", "connect"]:
        return None
    if not re.fullmatch(r"--timeout=\d+(?:\.\d+)?s", args[2]) or args[3] not in {"--protocol=tcp", "--protocol=udp", "--protocol=sctp"}:
        return None
    try:
        target, port = args[4].rsplit(":", 1)
        address = ipaddress.ip_address(target.strip("[]"))
        if not 1 <= int(port) <= 65535:
            return None
    except ValueError:
        return None
    return {"namespace": client[2], "pod": client[3], "container": client[3][:-1] + "client",
            "expected_connect": client[1] == "succeed", "protocol": args[3].split("=")[1],
            "target": str(address), "port": int(port), "command": args,
            "original_command_line": command_line.strip(), "original_expected_line": expected_line.strip()}


def probe_outcome(result):
    if result["returncode"] == 0 and not result["stdout"] and not result["stderr"]:
        return "connected"
    if result["returncode"] == 1 and result["stderr"].splitlines()[:1] == ["TIMEOUT"]:
        return "dropped"
    return "command_error_or_other_rejection"


class Recorder:
    def __init__(self, output, interval, window=8, max_incidents=12):
        self.output = output
        self.interval = interval
        self.window = window
        self.max_incidents = max_incidents
        self.stop = threading.Event()
        self.audit_ready = threading.Event()
        self.lock = threading.Lock()
        self.ring = []
        self.sequence = 0
        self.failures = []
        self.workers = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.futures = []
        self.audit_count = 0
        self.snapshot_count = 0
        self.complete_snapshots = 0
        self.errors = []
        self.output.mkdir(parents=True, exist_ok=True)
        inventory = command(kubectl("get", "pods", "-n", "kube-system", "-l", "app=ovs", "-o", "json"))
        if inventory["returncode"] != 0:
            raise RuntimeError("Cannot discover the historical OVS Pods: " + inventory["stderr"])
        self.ovs = [(p["metadata"]["name"], p["spec"]["nodeName"], p["spec"]["containers"][0]["name"]) for p in json.loads(inventory["stdout"])["items"]]
        if len(self.ovs) < 2:
            raise RuntimeError("Expected OVS Pods on both kind nodes")

    def snapshot_commands(self):
        commands = {"policies": kubectl("get", "anp,banp,networkpolicies", "-A", "-o", "json"),
                    "pods": kubectl("get", "pods", "-A", "-o", "json")}
        tables = [
            ("nb-global", "ovn-nbctl", "nb_cfg,sb_cfg,hv_cfg", "NB_Global"),
            ("nb-acl", "ovn-nbctl", "_uuid,priority,direction,match,action,tier,external_ids", "ACL"),
            ("nb-port-groups", "ovn-nbctl", "_uuid,name,ports,acls,external_ids", "Port_Group"),
            ("nb-address-sets", "ovn-nbctl", "_uuid,name,addresses,external_ids", "Address_Set"),
            ("sb-global", "ovn-sbctl", "nb_cfg", "SB_Global"),
            ("sb-chassis", "ovn-sbctl", "name,nb_cfg", "Chassis_Private"),
            ("sb-ports", "ovn-sbctl", "logical_port,datapath,chassis,up,mac,type,options", "Port_Binding"),
            ("sb-logical-flows", "ovn-sbctl", "logical_datapath,pipeline,table_id,priority,match,actions,external_ids", "Logical_Flow"),
        ]
        for name, executable, columns, table in tables:
            commands[name] = kubectl("exec", "-n", "kube-system", "deployment/ovn-central", "--", executable,
                                    "--timeout=3", "--format=json", "--columns=" + columns, "list", table)
        for pod, node, container in self.ovs:
            commands[node + "-openflow"] = kubectl("exec", "-n", "kube-system", pod, "-c", container, "--", "ovs-ofctl", "-O", "OpenFlow15", "dump-flows", "br-int")
        return commands

    def snapshot(self, destination):
        destination.mkdir(parents=True, exist_ok=True)
        started = timestamp()
        failed = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = {name: pool.submit(command, argv) for name, argv in self.snapshot_commands().items()}
            for name, future in results.items():
                result = future.result()
                if name == "pods" and result["returncode"] == 0:
                    try:
                        result["stdout"] = json.dumps(pod_summary(result["stdout"]))
                    except (KeyError, ValueError) as err:
                        result.update(returncode=-1, stdout="", stderr=str(err))
                write_json(destination / (name + ".json"), result)
                if result["returncode"] != 0:
                    failed.append(name)
        write_json(destination / "snapshot.json", {"started": started, "finished": timestamp(), "failed_commands": failed})
        with self.lock:
            self.snapshot_count += 1
            if not failed:
                self.complete_snapshots += 1

    def rolling_snapshots(self):
        try:
            while not self.stop.is_set():
                self.sequence += 1
                destination = self.output / "rolling" / ("sample-%05d" % self.sequence)
                self.snapshot(destination)
                with self.lock:
                    self.ring.append(destination)
                    if len(self.ring) > self.window:
                        expired = self.ring.pop(0)
                        if expired != self.output / "initial":
                            shutil.rmtree(expired)
                self.stop.wait(self.interval)
        except Exception as err:
            self.errors.append("rolling collector: " + str(err))

    def audit(self):
        args = ["docker", "exec", "kube-ovn-control-plane", "tail", "-n", "+1", "-F", "/var/log/kubernetes/kube-apiserver-audit.log"]
        try:
            with (self.output / "audit-errors.log").open("w") as errors:
                self.audit_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=errors, text=True)
                self.audit_ready.set()
                with (self.output / "audit.jsonl").open("w") as output:
                    for line in self.audit_proc.stdout:
                        try:
                            event = json.loads(line)
                        except ValueError:
                            continue
                        fields = {key: event[key] for key in ["auditID", "stage", "verb", "objectRef", "requestURI", "requestReceivedTimestamp", "stageTimestamp", "responseStatus", "requestObject", "responseObject"] if key in event}
                        fields["observed"] = timestamp()
                        output.write(json.dumps(fields) + "\n")
                        output.flush()
                        self.audit_count += 1
                self.audit_proc.stdout.close()
                self.audit_proc.wait()
                if not self.stop.is_set():
                    self.errors.append("audit stream ended unexpectedly")
        except Exception as err:
            self.errors.append("audit collector: " + str(err))
        finally:
            self.audit_ready.set()

    def incident(self, probe, destination, observed):
        try:
            write_json(destination / "probe.json", {"observed": observed, **probe})
            self.snapshot(destination / "immediate")
            results = []
            probe_start = time.monotonic()
            for delay in [0, 1, 5]:
                time.sleep(max(0, probe_start + delay - time.monotonic()))
                result = command(kubectl("exec", "-n", probe["namespace"], probe["pod"], "-c", probe["container"], "--", *probe["command"]), timeout=10)
                result["outcome"] = probe_outcome(result)
                result["scheduled_seconds_after_immediate_snapshot"] = delay
                results.append(result)
                write_json(destination / "additional-probes.json", results)
            self.snapshot(destination / "after-probes")
            self.conntrack(probe, destination)
        except Exception as err:
            self.errors.append("incident collector: " + str(err))

    def conntrack(self, probe, destination):
        pod = command(kubectl("get", "pod", "-n", probe["namespace"], probe["pod"], "-o", "json"))
        if pod["returncode"] != 0:
            write_json(destination / "conntrack-client-error.json", pod)
            return
        target_family = ipaddress.ip_address(probe["target"]).version
        client = json.loads(pod["stdout"])
        addresses = [entry["ip"] for entry in client["status"].get("podIPs", []) if ipaddress.ip_address(entry["ip"]).version == target_family]
        if not addresses:
            return
        for ovs_pod, node, container in self.ovs:
            args = kubectl("exec", "-n", "kube-system", ovs_pod, "-c", container, "--", "conntrack", "-L", "-f", "ipv%d" % target_family,
                           "-p", probe["protocol"], "-s", addresses[0], "-d", probe["target"], "--dport", str(probe["port"]))
            write_json(destination / (node + "-conntrack.json"), command(args))

    def observe_failure(self, probe):
        observed = timestamp()
        self.failures.append({"observed": observed, "probe": probe})
        if len(self.failures) > self.max_incidents:
            return
        destination = self.output / "incidents" / ("failure-%03d" % len(self.failures))
        destination.mkdir(parents=True, exist_ok=True)
        with self.lock:
            for sample in self.ring:
                shutil.copytree(sample, destination / "before" / sample.name)
        self.futures.append(self.workers.submit(self.incident, probe, destination, observed))

    def run(self, args):
        rolling = threading.Thread(target=self.rolling_snapshots)
        audit = threading.Thread(target=self.audit)
        # Complete one baseline snapshot before the first policy probe.
        self.snapshot(self.output / "initial")
        with self.lock:
            self.ring.append(self.output / "initial")
        rolling.start()
        audit.start()
        self.audit_ready.wait(timeout=10)
        pending = ""
        cases = []
        returncode = 125
        process = None
        try:
            with (self.output / "suite.log").open("w") as output:
                process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                for line in process.stdout:
                    output.write(timestamp() + " " + line)
                    output.flush()
                    print(line, end="", flush=True)
                    execution_error = re.search(r"FAILED to execute command (\[.+\]) on pod ([a-z0-9-]+)/([a-z0-9-]+):", line)
                    if execution_error:
                        probe = parse_probe("FAILED Command was " + execution_error[1], "Expected connection to fail from " + execution_error[2] + "/" + execution_error[3] + " to")
                        if probe:
                            probe.update(expected_connect=None, original_execution_error=line.strip())
                            try:
                                self.observe_failure(probe)
                            except Exception as err:
                                self.errors.append("execution failure capture: " + str(err))
                        else:
                            self.errors.append("unrecognized execution failure: " + line.strip())
                    if "FAILED Command was [" in line:
                        pending = line
                    if "Expected connection to " in line and pending:
                        probe = parse_probe(pending, line)
                        if probe:
                            try:
                                self.observe_failure(probe)
                            except Exception as err:
                                self.errors.append("failure capture: " + str(err))
                        else:
                            self.errors.append("unrecognized failed probe: " + pending.strip())
                        pending = ""
                    match = re.search(r"--- (PASS|FAIL|SKIP): TestAdminNetworkPolicyConformance/([^/\s]+) \(", line)
                    if match:
                        cases.append({"name": match[2], "result": match[1]})
                returncode = process.wait()
        except Exception as err:
            self.errors.append("suite runner: " + str(err))
            if process is not None:
                process.terminate()
                try:
                    returncode = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    returncode = process.wait()
        finally:
            # Finish incident probes while their Pods still exist where possible.
            if process is not None and process.stdout is not None:
                process.stdout.close()
            self.workers.shutdown(wait=True)
            self.stop.set()
            rolling.join()
            if hasattr(self, "audit_proc") and self.audit_proc.poll() is None:
                self.audit_proc.terminate()
                try:
                    self.audit_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.audit_proc.kill()
                    self.audit_proc.wait()
                    self.errors.append("audit stream required SIGKILL")
            audit.join()
        healthy = self.complete_snapshots > 0 and self.audit_count > 0 and len(cases) == 18 and not self.errors
        summary = {"diagnostics_healthy": healthy, "command": args, "suite_returncode": returncode, "cases": cases, "failures": self.failures,
                   "snapshots": self.snapshot_count, "complete_snapshots": self.complete_snapshots,
                   "audit_events": self.audit_count, "collector_errors": self.errors,
                   "detailed_incident_limit": self.max_incidents, "finished": timestamp()}
        write_json(self.output / "summary.json", summary)
        if returncode != 0:
            return returncode if returncode >= 0 else 128 - returncode
        return 0 if healthy else 2


def final_logs(output):
    output.mkdir(parents=True, exist_ok=True)
    inventory = command(kubectl("get", "pods", "-A", "-o", "json"))
    raw = inventory["stdout"]
    if inventory["returncode"] == 0:
        inventory["stdout"] = json.dumps(pod_summary(raw))
    write_json(output / "pods.json", inventory)
    write_json(output / "events.json", command(kubectl("get", "events", "-A", "-o", "json")))
    if inventory["returncode"] != 0:
        return
    for pod in json.loads(raw)["items"]:
        meta = pod["metadata"]
        if meta.get("labels", {}).get("app") not in {"ovs", "ovn-central", "kube-ovn-controller", "kube-ovn-cni"} and not meta["namespace"].startswith("network-policy-conformance-"):
            continue
        for container in pod["spec"]["containers"]:
            for previous in [False, True]:
                args = kubectl("logs", "-n", meta["namespace"], meta["name"], "-c", container["name"], "--timestamps=true", "--tail=5000")
                if previous:
                    args.append("--previous=true")
                name = meta["namespace"] + "-" + meta["name"] + "-" + container["name"] + ("-previous" if previous else "")
                write_json(output / (name + ".json"), command(args))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--final-logs", action="store_true")
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--max-incidents", type=int, default=12)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    args = options.command
    if args and args[0] == "--":
        args = args[1:]
    if (not args and not options.final_logs) or not 1 <= options.interval <= 30 or not 1 <= options.max_incidents <= 30:
        parser.error("Supply a command, interval 1–30 seconds and incident limit 1–30")
    if os.environ.get("GITHUB_ACTIONS") != "true" or command(kubectl("config", "current-context"))["stdout"].strip() != "kind-kube-ovn":
        parser.error("This collector only runs in the disposable GitHub Actions kind-kube-ovn cluster")
    if options.final_logs:
        final_logs(options.output)
        return 0
    recorder = Recorder(options.output, options.interval, max_incidents=options.max_incidents)
    return recorder.run(args)


if __name__ == "__main__":
    sys.exit(main())
