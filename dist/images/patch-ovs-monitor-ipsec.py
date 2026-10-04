#!/usr/bin/env python3
"""Apply the small IPsec extensions to the base image's OVS monitor.

Keep these adaptations explicit and fail image construction on source drift.
The monitor still owns connection generation and refresh; this does not create
a second implementation of its tunnel state machine.
"""

from pathlib import Path
import sys


def patch(path):
    source = path.read_text()
    replacements = [
        ('import re\n', 'import re\nimport hashlib\nimport json\n'),
        ('m = re.search(r"CN=(.+?),", pout.strip())',
         'm = re.search(r"(?:^subject=\\s*|,)CN=([^,]+)(?:,|$)", pout.strip())'),
        ('        self.tunnels = {}\n',
         '        self.tunnels = {}\n        self.ovn_owned_only = args.ovn_owned_only\n        self.applied_pki = None\n'),
        ('''        run_command([self.IPSEC, "update"],
                    "update StrongSwan's configuration")
        run_command([self.IPSEC, "rereadsecrets"], "re-read secrets")
''', '''        monitor.applied_pki = None
        ret, _, _ = run_command([self.IPSEC, "update"],
                               "update StrongSwan's configuration")
        if ret:
            raise RuntimeError("StrongSwan configuration update failed")
        ret, _, _ = run_command([self.IPSEC, "rereadsecrets"], "re-read secrets")
        if ret:
            raise RuntimeError("StrongSwan secret reload failed")
        pki = monitor.conf_in_use["pki"]
        if pki["certificate"] and pki["ca_cert"]:
            # Snapshot public content after successful refresh. Never read,
            # return or hash a private key through the diagnostic endpoint.
            with open(pki["certificate"], "rb") as cert_file:
                certificate = hashlib.sha256(cert_file.read()).hexdigest()
            with open(pki["ca_cert"], "rb") as trust_file:
                trust = hashlib.sha256(trust_file.read()).hexdigest()
            monitor.applied_pki = {"certificate": certificate, "trust": trust}
'''),
        ('def unixctl_refresh(conn, unused_argv, unused_aux):\n', '''def unixctl_configuration(conn, unused_argv, unused_aux):
    if monitor.applied_pki is None:
        conn.reply_error("IPsec configuration has not been refreshed")
    else:
        conn.reply(json.dumps(monitor.applied_pki))


def unixctl_refresh(conn, unused_argv, unused_aux):
'''),
        ('    ovs.unixctl.command_register("refresh", "", 0, 0, unixctl_refresh, None)\n', '''    ovs.unixctl.command_register("configuration/get", "", 0, 0,
                                 unixctl_configuration, None)
    ovs.unixctl.command_register("refresh", "", 0, 0, unixctl_refresh, None)
'''),
        ('        for row in data["Interface"].rows.values():\n',
         '''        owned = set()
        if self.ovn_owned_only:
            for port in data["Port"].rows.values():
                if port.external_ids.get("ovn-chassis-id"):
                    owned.update(interface.uuid for interface in port.interfaces)

        for row in data["Interface"].rows.values():
            if self.ovn_owned_only and row.uuid not in owned:
                continue
'''),
        ('    ovs.vlog.add_args(parser)\n',
         '''    parser.add_argument("--ovn-owned-only", action="store_true",
                        help="Manage only interfaces belonging to an OVN tunnel port.")
    ovs.vlog.add_args(parser)
'''),
        ('    schema_helper.register_columns("Open_vSwitch", ["other_config"])\n',
         '''    schema_helper.register_columns("Open_vSwitch", ["other_config"])
    if args.ovn_owned_only:
        schema_helper.register_columns("Port", ["interfaces", "external_ids"])
'''),
    ]
    for original, updated in replacements:
        if source.count(original) != 1:
            raise RuntimeError(f"unsupported OVS IPsec monitor source: {original!r}")
        source = source.replace(original, updated, 1)
    compile(source, str(path), "exec")
    path.write_text(source)


if __name__ == "__main__":
    patch(Path(sys.argv[1]))
