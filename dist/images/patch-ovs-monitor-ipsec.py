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
        ('m = re.search(r"CN=(.+?),", pout.strip())',
         'm = re.search(r"(?:^subject=\\s*|,)CN=([^,]+)(?:,|$)", pout.strip())'),
        ('        self.tunnels = {}\n',
         '        self.tunnels = {}\n        self.ovn_owned_only = args.ovn_owned_only\n'),
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
