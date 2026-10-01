# kubectl-ko

`kubectl-ko` is a standalone Go kubectl plugin for operating and diagnosing
Kube-OVN. It talks to the Kubernetes API and executes the OVN/OVS tools shipped
in the cluster. No local Bash, OVN, OVS, tar, or kubectl subprocess is required.
`kubectl` itself is only needed to invoke the plugin as `kubectl ko`.

## Installation

Kube-OVN images and the CNI installer install the binary at the existing
`/usr/local/bin/kubectl-ko` path. For a separate workstation, download the
`kubectl-ko-<os>-<arch>.tar.gz` (Linux/macOS) or
`kubectl-ko-windows-<arch>.zip` asset and `kubectl-ko-checksums.txt` from the
matching Kube-OVN GitHub release, verify its SHA256, and put the extracted
`kubectl-ko` on PATH. Linux, macOS and Windows, each on amd64 and arm64, are
built independently. Do not copy a Linux pod binary to a macOS or Windows
workstation. The Kubernetes nodes and remote OVN/OVS tools remain Linux-based.

On Windows, use the ZIP matching the workstation architecture. Verify its
SHA256 with `Get-FileHash`, extract it with `Expand-Archive`, and place
`kubectl-ko.exe` in a directory on PATH alongside the existing `kubectl.exe`
installation. PowerShell can also run it directly:

```powershell
Get-FileHash .\kubectl-ko-windows-arm64.zip -Algorithm SHA256
Expand-Archive .\kubectl-ko-windows-arm64.zip .\kubectl-ko-windows-arm64
.\kubectl-ko-windows-arm64\kubectl-ko.exe version
.\kubectl-ko-windows-arm64\kubectl-ko.exe --context staging nbctl show
```

Use the amd64 archive instead on x64 Windows. `kubectl ko version` and
`kubectl plugin list` confirm discovery once its directory is on PATH. WSL,
Bash and local OVN/OVS installations are not required. Use PowerShell 7.4 or
later (or cmd.exe) when redirecting binary stdout such as `tcpdump -w -`;
older PowerShell versions can decode and corrupt native command output.

For a source checkout, run `make build-kubectl-ko`; the result is
`dist/images/kubectl-ko`. The module uses replacements, so installing release
binaries is preferred to `go install ...@version`.
On Windows, build from the checkout with
`go build -o kubectl-ko.exe ./cmd/kubectl-ko`. Cross-builds via
`GOOS=windows GOARCH=amd64 make build-kubectl-ko` produce
`dist/images/kubectl-ko.exe`; substitute `arm64` for Windows on ARM.

Use `kubectl plugin list` to detect older copies shadowing the new binary.
`kubectl ko version` prints the local build without accessing a cluster.

## Configuration and argument boundaries

Global flags go **after `ko` and before the subcommand**:

```console
kubectl ko --context staging --kube-ovn-namespace ovn-system nbctl show
kubectl ko --namespace app tcpdump web -w - > capture.pcap
kubectl ko --timeout 30s trace app/web 10.0.0.8 tcp 443
kubectl ko nbctl --format=json --columns=name list Logical_Switch
kubectl ko nbctl -- ls-add example -- lsp-add example example-port
```

The standard kubeconfig loader supports `--kubeconfig`, `KUBECONFIG`, context,
TLS, authentication plugins and impersonation. Workload namespace selection is
`namespace/pod`, then `--namespace`, then kubeconfig namespace, then `default`.
The Kube-OVN deployment namespace is independently selected by
`--kube-ovn-namespace`, `KUBE_OVN_NS`, then `kube-system`.

The eight `*ctl` commands and `tcpdump` preserve remote arguments verbatim,
including `--help`, `--timeout`, `-n`, `-c`, whitespace and OVN transaction `--`
separators. Use `kubectl ko help nbctl` for plugin help; `nbctl --help` invokes
the remote tool help. Do not add an extra separator intended for the plugin:
all tokens after a passthrough command (and its required target) belong to the
remote tool.

Exec uses WebSocket with SPDY fallback only for supported handshake failures.
Remote exit codes propagate to the caller; a failed command is never replayed.
Output is streamed without TTY transformations, including `tcpdump -w -` and
backups. `--timeout` bounds the entire invocation; zero allows continuous
capture/listen until cancellation. Closing an exec connection does not promise
to kill independently backgrounded remote processes.

## Commands

| Command | Behavior |
| --- | --- |
| `nbctl`, `sbctl` | Execute the corresponding OVN tool on its own database leader. |
| `icnbctl`, `icsbctl` | Execute the interconnection database tools on their leaders. |
| `vsctl NODE`, `ofctl NODE`, `dpctl NODE`, `appctl NODE` | Execute the OVS tool in the node openvswitch container. |
| `nb status`, `sb status` | Show database cluster and storage status. |
| `nb dbstatus`, `sb dbstatus` | Inspect NB and SB storage on all running central containers, even without a leader. |
| `nb kick ID`, `sb kick ID` | Remove a stale member; `--dry-run` prints the selected target and command. |
| `nb backup`, `sb backup` | Download a standalone database, validate DB name and SHA256, then publish without overwriting an existing backup. `--output FILE` selects the destination. A JSON sidecar records its origin and checksum. |
| `nb restore --source-node NODE --yes` | Rebuild the central database cluster from an existing node NB database; see recovery below. `sb restore` is not supported. |
| `tcpdump POD ...` | Capture hostNetwork or pod netns traffic; internal-port and VM-backed logical port lookup are supported. A remote `-w PATH` is still a remote path; `-w -` streams locally. |
| `trace SOURCE IP [MAC] PROTOCOL [PORT/OP]` | Execute OVN trace, followed by OVS ofproto trace. |
| `ovn-trace SOURCE IP [MAC] PROTOCOL [PORT/OP]` | Execute only OVN trace. SOURCE accepts `namespace/pod`, a bare pod, or `node//NODE`; protocols are icmp, tcp, udp and IPv4 arp request/reply. |
| `diagnose [all/node NODE/subnet SUBNET/IPPorts TARGETS]` | Check components and actively probe with pinger. `--read-only` skips probe resource creation and traffic. |
| `env-check` | Execute the image environment checker on each CNI container. |
| `log kube-ovn/ovn/ovs/linux/all` | Collect files, container logs and node state, with bounded concurrency and a manifest of partial failures. |
| `reload` | Restart and wait for central, OVS, controller, CNI, pinger and monitor in order. |
| `perf [IMAGE]` | Measure pod/host/Service unicast and multicast performance. `--include-disruption` additionally deletes central leader pods to measure recovery. |
| `acl-sample decode COOKIE` | Decode through the existing NB helper. |
| `acl-sample listen --node NODE` | Stream cookies from the node helper and decode with bounded backpressure; output remains YAML documents. |

`WITHOUT_KUBE_PROXY`, `TCP_CONN_CHECK_PORT` and `UDP_CONN_CHECK_PORT` retain their
existing meanings. `perf` defaults to `docker.io/kubeovn/test:v1.13.0`; pass an
internal image for disconnected installations. Traffic duration and offered UDP
bandwidth are controlled by `--duration` (seconds) and `--bandwidth`.

## Logs and recovery

`log` keeps the `kubectl-ko-log/<node>/{kube-ovn,ovn,openvswitch,linux}` layout.
Central files on the same node occupy an `ovn/central-<pod>` child directory.
`manifest.json` records every item and failure. `--concurrency`, `--item-timeout`
and `--max-bytes` limit each run; the byte limit is per item. Use `--strict` to
make any failed item fail the command. Archives cannot write outside their
collection root. On Unix, extracted files use private permissions. On Windows,
use a destination directory protected by your user ACL; Unix permission bits
do not configure Windows ACLs. Backup destinations must support hard links
(for example, NTFS) for atomic publication without overwriting existing files.
XFRM state is collected with
`nokeys`. Treat database and network diagnostics as sensitive local artifacts.

`nb restore` preserves the old operation meaning: reconstruct from a database
already on a node, not import an arbitrary local backup. It requires an explicit
source node and confirmation; the source must be the first `NODE_IPS` member,
which the image startup script uses to bootstrap the cluster. Recovery supports only the standard central Deployment
with literal `NODE_IPS` membership and matching writable hostPath mounts in
central and OVS. Run `--dry-run` first. All central pods must stop before file
changes begin. Original files remain in a unique directory on every member;
a private local JSON record tracks the last recovery stage. An error stops the
procedure and reports this record, the remote directory and original replica
count. It does not guess whether it is safe to undo a partially completed
recovery. Retain these files for a deliberate recovery or rollback.

Probe resources have unique names and a run identity. Cleanup uses saved UIDs,
not broad label deletion. A cleanup failure reports the exact remaining object
without hiding the original error. `reload`, raw OVN/OVS commands, recovery and
explicit performance disruption can change live cluster state.

## Compatibility and migration

The supported starting point is a matching CLI and Kube-OVN release. Remote
image tools determine feature availability. There is no direct database
connection or new diagnostic agent. Existing kubeconfig authorization applies:
resource discovery requires get/list, exec needs the applicable pods/exec
GET/POST authorization, logs need pods/log, probes need create/delete, and
rollout/recovery need workload patch/scale permissions. Exec access is not a
read-only database permission.

Intentional changes from Bash are: bare pod names honor kubeconfig namespace;
multiple ready leaders fail instead of picking an arbitrary pod; failures retain
nonzero exit codes; performance tests no longer delete leaders unless requested;
recovery requires an explicit source/confirmation; binary streams do not use a
TTY. UDP offered bandwidth defaults to 1G rather than the old 1000G.

The original script is retained as `kubectl-ko-legacy` for explicit rollback.
It is never selected automatically after a new command fails. The Go binary
replaces the default entrypoint; build scripts and CI must invoke it directly,
not with `bash`. The legacy script retains its previous dependencies and risks.

## Development checks

```console
go test -race ./pkg/ko/... ./cmd/kubectl-ko/...
make build-kubectl-ko
make lint
```

The dedicated workflow tests real exec streams, builds all six workstation
platforms and runs file/streaming tests natively on Windows amd64 and arm64.
Existing `[group:kubectl-ko]` E2E exercises trace, capture, logs,
diagnostics and backup against a cluster. Recovery, rollout and disruption
validation belong in disposable test clusters, never in the production CI
control plane. New CLI paths select the existing full E2E matrix.
