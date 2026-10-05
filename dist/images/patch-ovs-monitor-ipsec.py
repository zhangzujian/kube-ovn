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
        ('import re\n', 'import re\nimport hashlib\nimport json\nimport tempfile\n'),
        ('m = re.search(r"CN=(.+?),", pout.strip())',
         'm = re.search(r"(?:^subject=\\s*|,)CN=([^,]+)(?:,|$)", pout.strip())'),
        ('        self.tunnels = {}\n',
         '''        self.tunnels = {}
        self.ovn_owned_only = args.ovn_owned_only
        self.applied_pki = None
        self.connection_prefix = args.connection_prefix
        self.connection_intent_file = args.connection_intent
        self.connection_intent = {}
        self.connection_owner = {"version": 1,
                                 "nodeUID": args.connection_owner_node_uid,
                                 "lease": args.connection_owner_lease,
                                 "mark": args.connection_owner_mark,
                                 "reqid": args.connection_owner_reqid,
                                 "prefix": args.connection_prefix}
'''),
        ('''        run_command([self.IPSEC, "update"],
                    "update StrongSwan's configuration")
        run_command([self.IPSEC, "rereadsecrets"], "re-read secrets")
''', '''        monitor.applied_pki = None
        monitor.persist_connection_intent()
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
    parser.add_argument("--connection-prefix", default="")
    parser.add_argument("--connection-intent")
    parser.add_argument("--connection-owner-node-uid")
    parser.add_argument("--connection-owner-lease")
    parser.add_argument("--connection-owner-mark", type=int, default=0)
    parser.add_argument("--connection-owner-reqid", type=int, default=0)
    ovs.vlog.add_args(parser)
'''),
        ('    args = parser.parse_args()\n', '''    args = parser.parse_args()
    if args.ovn_owned_only:
        if (args.ike_daemon != "strongswan"
                or not re.fullmatch(r"ko[A-Za-z0-9]{20,64}-", args.connection_prefix)
                or not args.connection_intent or not args.connection_owner_node_uid
                or not args.connection_owner_lease
                or not 0 < args.connection_owner_mark < (1 << 32)
                or not 0 < args.connection_owner_reqid < (1 << 31)):
            parser.error("owned IPsec requires a persistent connection namespace")
    elif args.connection_prefix or args.connection_intent:
        parser.error("connection intent requires --ovn-owned-only")
'''),
        ('        new_conf = {\n            "ifname": self.name,\n',
         '''        new_conf = {
            "ifname": self.name,
            "interface_uuid": str(row.uuid),
'''),
        ('    def read_ovsdb(self, data):\n', '''    def record_connection_intent(self, tunnel):
        if not self.ovn_owned_only:
            return
        options = tunnel.conf["custom_options"]
        reqid = int(options.get("reqid", "0"))
        mark = options.get("mark_out", "")
        if (tunnel.conf["tunnel_type"] not in ("geneve", "vxlan")
                or reqid != self.connection_owner["reqid"]
                or mark != "%d/0xffffffff" % self.connection_owner["mark"]):
            raise RuntimeError("owned connection lacks protection selectors")
        ipaddress.ip_address(tunnel.conf["local_ip"])
        ipaddress.ip_address(tunnel.conf["remote_ip"])
        # Retain obsolete versions: IKE deletion is asynchronous. These are
        # configuration claims only, never private keys or SA deletion proof.
        for direction in ("in", "out"):
            name = "%s%s-%s-%d" % (self.connection_prefix, tunnel.name,
                                     direction, tunnel.version)
            self.connection_intent[name] = {
                "interfaceUUID": tunnel.conf["interface_uuid"],
                "localIP": tunnel.conf["local_ip"],
                "remoteIP": tunnel.conf["remote_ip"],
                "reqid": reqid, "markOut": mark,
                "tunnelType": tunnel.conf["tunnel_type"]}

    def persist_connection_intent(self):
        if not self.ovn_owned_only:
            return
        parent = os.path.dirname(self.connection_intent_file)
        fd, temporary = tempfile.mkstemp(prefix=".intent-", dir=parent)
        try:
            with os.fdopen(fd, "w") as intent:
                data = dict(self.connection_owner)
                data["connections"] = self.connection_intent
                json.dump(data, intent, sort_keys=True)
                intent.flush()
                os.fsync(intent.fileno())
            os.replace(temporary, self.connection_intent_file)
            directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def read_ovsdb(self, data):
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
    # Scope the adaptation to strongSwan; both upstream backends contain
    # similar connection-generation and status-parsing blocks.
    start = source.index("class StrongSwanHelper(object):")
    end = source.index("class LibreSwanHelper(object):")
    strongswan = source[start:end]
    for original, updated in [
        ('r"(.*)(-in-\\d+|-out-\\d+|-\\d+).*"',
         'r"(.+?)(-in-\\d+|-out-\\d+|-\\d+)(?:\\[\\d+\\]|\\{\\d+\\})?$"'),
        ('            ifname = m.group(1)\n', '''            ifname = m.group(1)
            if monitor.connection_prefix:
                if not ifname.startswith(monitor.connection_prefix):
                    continue
                ifname = ifname[len(monitor.connection_prefix):]
'''),
        ('        vals["version"] = tunnel.version\n', '''        vals["version"] = tunnel.version
        vals["ifname"] = monitor.connection_prefix + tunnel.name
        monitor.record_connection_intent(tunnel)
'''),
        ('                if not conn.startswith(ifname):\n', '''                stem = monitor.connection_prefix + ifname
                if not conn.startswith(stem):
'''),
        ("conn[len(ifname):]", "conn[len(stem):]"),
    ]:
        if strongswan.count(original) != 1:
            raise RuntimeError(f"unsupported strongSwan monitor source: {original!r}")
        strongswan = strongswan.replace(original, updated, 1)
    source = source[:start] + strongswan + source[end:]
    compile(source, str(path), "exec")
    path.write_text(source)


if __name__ == "__main__":
    patch(Path(sys.argv[1]))
