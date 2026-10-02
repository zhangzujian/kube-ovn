#!/usr/bin/env python3
"""Prepare component prerequisites in the isolated CNP upgrade CI cluster."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess


ROLES = ("system:ovn", "system:kube-ovn-cni")


def documents(path, kind):
    return [
        block for block in path.read_text().split("\n---\n")
        if re.search(rf"(?m)^kind: {re.escape(kind)}$", block)
    ]


def role_document(path, name):
    matches = [
        block for block in documents(path, "ClusterRole")
        if re.search(rf"(?m)^  name: {re.escape(name)}$", block)
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one ClusterRole {name} in {path}")
    return matches[0]


def permissions(role):
    return {
        (group, resource, verb)
        for rule in role["rules"]
        for group in rule.get("apiGroups", [])
        for resource in rule.get("resources", [])
        for verb in rule["verbs"]
    }


def grants(existing, requested):
    group, resource, verb = requested
    subresource = resource.partition("/")[2]
    return any(
        old_group in ("*", group)
        and old_verb in ("*", verb)
        and (old_resource in ("*", resource) or (subresource and old_resource == "*/" + subresource))
        for old_group, old_resource, old_verb in existing
    )


def role_patch(source, target, live):
    name = source["metadata"]["name"]
    if name not in ROLES or target["metadata"]["name"] != name or live["metadata"]["name"] != name:
        raise ValueError("Unexpected role identity")
    if live["rules"] != source["rules"]:
        raise ValueError(f"ClusterRole {name} differs from the pinned source installer")
    if any(rule.get("nonResourceURLs") for rule in target["rules"]):
        raise ValueError("Non-resource permissions are outside the reviewed upgrade scope")
    existing = permissions(source)
    missing = {}
    for group, resource, verb in sorted(permissions(target)):
        if not grants(existing, (group, resource, verb)):
            missing.setdefault((group, resource), []).append(verb)
    if not missing:
        return []
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": live["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": live["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/rules", "value": live["rules"]},
    ]
    patch.extend(
        {"op": "add", "path": "/rules/-", "value": {"apiGroups": [group], "resources": [resource], "verbs": verbs}}
        for (group, resource), verbs in missing.items()
    )
    return patch


def kubectl(*args, stdin=None):
    result = subprocess.run(
        ["kubectl", "--context=kind-kube-ovn", *args],
        input=stdin, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"kubectl {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def as_json(document):
    return json.loads(kubectl("create", "--dry-run=client", "--validate=false", "-f", "-", "-o", "json", stdin=document))


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Component preparation is restricted to the isolated GitHub Actions cluster")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-installer", type=Path, required=True)
    parser.add_argument("--target-installer", type=Path, default=Path("dist/images/install.sh"))
    parser.add_argument("--output", type=Path, default=Path("cnp-component-prerequisites"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    patches = []
    for name in ROLES:
        source = as_json(role_document(args.source_installer, name))
        target = as_json(role_document(args.target_installer, name))
        live = json.loads(kubectl("get", "clusterrole", name, "-o", "json"))
        patch = role_patch(source, target, live)
        if patch:
            path = args.output / (name.removeprefix("system:") + ".json")
            path.write_text(json.dumps(patch, indent=2) + "\n")
            patches.append((name, path))

    existing_crds = {
        item["metadata"]["name"]
        for item in json.loads(kubectl("get", "crd", "-o", "json"))["items"]
    }
    crds = []
    for block in documents(args.target_installer, "CustomResourceDefinition"):
        match = re.search(r"(?m)^  name: ([-a-z0-9]+\.kubeovn\.io)$", block)
        if match and match[1] not in existing_crds:
            document = as_json(block)
            if document["spec"]["group"] != "kubeovn.io":
                raise ValueError("Component CRD has an unexpected API group")
            path = args.output / (match[1] + ".json")
            path.write_text(json.dumps(document, indent=2) + "\n")
            crds.append((match[1], path))

    # Validate every change before granting permissions or creating missing CRDs.
    # Existing CRDs, policy schemas, bindings and accounts are never replaced.
    for name, path in patches:
        kubectl("patch", "clusterrole", name, "--type=json", "--patch-file", str(path), "--dry-run=server")
    for _, path in crds:
        kubectl("create", "-f", str(path), "--dry-run=server")
    for name, path in patches:
        print(f"Appending target component permissions to {name}", flush=True)
        kubectl("patch", "clusterrole", name, "--type=json", "--patch-file", str(path))
    for name, path in crds:
        print(f"Creating missing target component CRD {name}", flush=True)
        kubectl("create", "-f", str(path))
        kubectl("wait", "--for=condition=Established", "crd/" + name, "--timeout=60s")


if __name__ == "__main__":
    main()
