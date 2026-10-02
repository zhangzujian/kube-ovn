import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import cnp_upgrade_prerequisites as prerequisites


class ComponentPrerequisitesTest(unittest.TestCase):
    def setUp(self):
        self.source = {
            "metadata": {"name": "system:kube-ovn-cni"},
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}],
        }
        self.target = copy.deepcopy(self.source)
        self.target["rules"].append({
            "apiGroups": ["networking.k8s.io"], "resources": ["servicecidrs"], "verbs": ["get", "list", "watch"],
        })
        self.live = copy.deepcopy(self.source)
        self.live["metadata"].update(uid="source-role", resourceVersion="17")

    def test_only_missing_permissions_are_appended_with_identity_guards(self):
        patch = prerequisites.role_patch(self.source, self.target, self.live)
        self.assertEqual(patch[:3], [
            {"op": "test", "path": "/metadata/uid", "value": "source-role"},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "17"},
            {"op": "test", "path": "/rules", "value": self.source["rules"]},
        ])
        self.assertEqual(patch[3:], [{"op": "add", "path": "/rules/-", "value": self.target["rules"][-1]}])
        self.assertEqual(self.live["rules"], self.source["rules"])

    def test_unknown_live_permissions_are_not_replaced(self):
        self.live["rules"][0]["verbs"].append("delete")
        with self.assertRaisesRegex(ValueError, "differs from the pinned source"):
            prerequisites.role_patch(self.source, self.target, self.live)

    def test_unreviewed_role_and_non_resource_permissions_are_rejected(self):
        self.target["metadata"]["name"] = "cluster-admin"
        with self.assertRaisesRegex(ValueError, "role identity"):
            prerequisites.role_patch(self.source, self.target, self.live)
        self.target["metadata"]["name"] = self.source["metadata"]["name"]
        self.target["rules"].append({"nonResourceURLs": ["/*"], "verbs": ["get"]})
        with self.assertRaisesRegex(ValueError, "outside the reviewed"):
            prerequisites.role_patch(self.source, self.target, self.live)

    def test_existing_wildcard_and_subresource_grants_need_no_additions(self):
        existing = {("*", "*", "*")}
        self.assertTrue(prerequisites.grants(existing, ("networking.k8s.io", "servicecidrs", "list")))
        self.assertTrue(prerequisites.grants({("apps", "*/scale", "patch")}, ("apps", "deployments/scale", "patch")))
        self.assertFalse(prerequisites.grants({("apps", "deployments", "patch")}, ("apps", "deployments/scale", "patch")))
        self.assertEqual(prerequisites.role_patch(self.source, self.source, self.live), [])

    def test_target_installer_contains_exact_component_roles(self):
        installer = Path(__file__).resolve().parents[1] / "dist/images/install.sh"
        for name in prerequisites.ROLES:
            document = prerequisites.role_document(installer, name)
            self.assertIn("\n      - servicecidrs\n", document)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            prerequisites.role_document(installer, "cluster-admin")

    def test_non_ci_execution_stops_before_accessing_a_cluster(self):
        with mock.patch.dict(prerequisites.os.environ, {"GITHUB_ACTIONS": "false"}), mock.patch.object(prerequisites, "kubectl") as command:
            with self.assertRaisesRegex(SystemExit, "restricted"):
                prerequisites.main()
            command.assert_not_called()

    def test_existing_component_crds_are_preserved(self):
        calls = []

        def convert(document):
            name = prerequisites.re.search(r"(?m)^  name: (.+)$", document)[1]
            if "kind: CustomResourceDefinition" in document:
                return {"kind": "CustomResourceDefinition", "metadata": {"name": name}, "spec": {"group": "kubeovn.io"}}
            role = copy.deepcopy(self.source)
            role["metadata"]["name"] = name
            return role

        existing = ["subnets.kubeovn.io", "vpcs.kubeovn.io"]

        def command(*args, stdin=None):
            calls.append(args)
            if args[:2] == ("get", "clusterrole"):
                live = copy.deepcopy(self.live)
                live["metadata"]["name"] = args[2]
                return json.dumps(live)
            if args[:2] == ("get", "crd"):
                if args[-1] == "json":
                    return json.dumps({"items": [{"metadata": {"name": name}} for name in existing]})
                # Reproduce kubectl's output for the previous escaped JSONPath.
                return "\\n".join(existing) + "\\n"
            return ""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            roles = "\n---\n".join("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: " + name + "\n" for name in prerequisites.ROLES)
            (root / "source.sh").write_text(roles)
            target = roles
            for name in [*existing, "router-lb-rules.kubeovn.io"]:
                target += "\n---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: " + name + "\n"
            (root / "target.sh").write_text(target)
            argv = ["prerequisites", "--source-installer", str(root / "source.sh"), "--target-installer", str(root / "target.sh"), "--output", str(root / "plan")]
            with mock.patch.dict(prerequisites.os.environ, {"GITHUB_ACTIONS": "true"}), mock.patch("sys.argv", argv), mock.patch.object(prerequisites, "as_json", side_effect=convert), mock.patch.object(prerequisites, "kubectl", side_effect=command):
                prerequisites.main()
            self.assertEqual([path.name for path in (root / "plan").glob("*.json")], ["router-lb-rules.kubeovn.io.json"])
            created = [Path(args[2]).name for args in calls if args[0] == "create"]
            self.assertEqual(created, ["router-lb-rules.kubeovn.io.json"] * 2)

    def test_crd_preflight_failure_does_not_grant_permissions(self):
        calls = []

        def convert(document):
            if "kind: CustomResourceDefinition" in document:
                return {"kind": "CustomResourceDefinition", "metadata": {"name": "router-lb-rules.kubeovn.io"}, "spec": {"group": "kubeovn.io"}}
            name = prerequisites.re.search(r"(?m)^  name: (.+)$", document)[1]
            role = copy.deepcopy(self.target if "target" in document else self.source)
            role["metadata"]["name"] = name
            return role

        def command(*args, stdin=None):
            calls.append(args)
            if args[:2] == ("get", "clusterrole"):
                live = copy.deepcopy(self.live)
                live["metadata"]["name"] = args[2]
                return json.dumps(live)
            if args[:2] == ("get", "crd"):
                return json.dumps({"items": []})
            if args[0] == "create" and "--dry-run=server" in args:
                raise ValueError("CRD preflight rejected")
            return ""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            roles = "\n---\n".join("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: " + name + "\n" for name in prerequisites.ROLES)
            (root / "source.sh").write_text(roles)
            (root / "target.sh").write_text(roles.replace("apiVersion:", "# target\napiVersion:") + "\n---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: router-lb-rules.kubeovn.io\n\n---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: clusternetworkpolicies.policy.networking.k8s.io\n")
            argv = ["prerequisites", "--source-installer", str(root / "source.sh"), "--target-installer", str(root / "target.sh"), "--output", str(root / "plan")]
            with mock.patch.dict(prerequisites.os.environ, {"GITHUB_ACTIONS": "true"}), mock.patch("sys.argv", argv), mock.patch.object(prerequisites, "as_json", side_effect=convert), mock.patch.object(prerequisites, "kubectl", side_effect=command):
                with self.assertRaisesRegex(ValueError, "CRD preflight rejected"):
                    prerequisites.main()

            mutations = [args for args in calls if args[0] in ("patch", "create") and "--dry-run=server" not in args]
            self.assertEqual(mutations, [])
            self.assertEqual(len(list((root / "plan").glob("*.json"))), 3)
            self.assertFalse((root / "plan" / "clusternetworkpolicies.policy.networking.k8s.io.json").exists())


if __name__ == "__main__":
    unittest.main()
