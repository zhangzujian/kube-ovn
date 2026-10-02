# Historical ANP/BANP diagnostics

The `Historical ANP and BANP Diagnostics` workflow runs the retained
`network-policy-api v0.1.8` conformance suite against **v1.15.28 and v1.16.10**,
each in **IPv4, IPv6 and dual-stack** disposable two-node kind clusters. It tests
historical components without upgrading their controller, CRDs or host CNI to a
candidate release. The historical v1alpha2 CNP informer prerequisite is installed
from upstream commit `3910463a5686`, rather than the v0.1.8 release tag which does
not contain that CRD. The optional v1.15 DNSNameResolver CRD uses the pinned
v1.16.10 installer schema, matching the reference fixture. The only conformance harness correction is preserving `https://`
in the base manifest URL; policy assertions and the upstream single-shot probes
are unchanged.

The reference run is [37000479576](https://github.com/zhangzujian/kube-ovn/actions/runs/37000479576).
Both IPv4 jobs passed. Both dual-stack jobs failed, including initial TCP deny
connections after policy changes and SCTP allow timeouts. These observations
establish that the symptoms also occur with historical releases; they do not
establish whether the cause is controller processing, OVN/OVS convergence,
connection tracking, or test timing. That reference run did not test IPv6 alone.

## Trigger and results

Relevant pull requests run all six combinations once. The workflow can also be
dispatched on a branch containing this workflow, with `rounds` (1–3),
`snapshot_interval` (1–30 seconds, default 2), and `max_incidents` (1–30, default 12).
Each round runs the full ANP/BANP suite, including cross-profile Priority and
Integration cases. There are 18 executed cases and six optional NamedPort/NodePeers
definitions that the unchanged standard profiles log as SKIP. A read-only namespace deletion wait separates rounds; the
harness does not remove finalizers. A failed round remains failed even if later
rounds or additional diagnostic probes succeed. Matrix fail-fast is disabled.

The original suite's nonzero exit code takes precedence. When the suite passes,
the job still fails if diagnostics are unhealthy: no complete snapshot, no API
audit events, collector errors, or missing, skipped, duplicated or unexpected executed standard cases.
`summary.json` records every case, the executed subset and coverage completeness,
and records the suite return code separately from diagnostic health.
A red job can therefore represent a successfully captured historical failure.
Read the summaries and logs before interpreting the workflow conclusion.

## Evidence layout

Each attempt uploads a distinct artifact for each source/family, retained for
14 days. Download artifacts before expiry to preserve investigation evidence.

| Path under `anp-diagnostics/` | Content |
| --- | --- |
| `install.json` | Installer commit, workflow revision/run/attempt, family, installed component images and actual image IDs |
| `round-N/suite.log` | Original Go output with collector UTC observation timestamps |
| `round-N/summary.json` | All Go case results (18 executed standard cases plus optional skips), original suite exit code, every parsed failed probe, collection health/errors |
| `round-N/anp-test-report.yaml` | Native profile report; use the Go case list as well because this report omits cross-profile cases |
| `round-N/audit.jsonl` | Policy writes at RequestReceived/ResponseComplete and Pod exec metadata; audit IDs and API-server timestamps |
| `round-N/traces/` | Continuous NB ACL/Address_Set/Port_Group and SB Logical_Flow updates, both nodes’ OpenFlow changes and TCP port 80 packet timestamps; per-stream errors/health |
| `round-N/initial/`, `rolling/` | Initial snapshot and the last eight completed rolling snapshots |
| `round-N/incidents/failure-NNN/before/` | Preserved completed snapshots preceding detection |
| `round-N/incidents/failure-NNN/immediate/` | Snapshot collected when an incident worker handles the failure |
| `round-N/incidents/failure-NNN/additional-probes.json` | Three later probes using the original client Pod/container and command |
| `round-N/incidents/failure-NNN/after-probes/` | Snapshot after the later probes |
| `round-N/incidents/failure-NNN/*conntrack*.json` | Filtered conntrack entries on both nodes, or command errors |
| `final-logs/` | Component/conformance container logs, previous-container logs, events and sanitized Pod status |

Snapshots include policy objects, conformance/system Pod status, NB ACLs,
Port_Groups, Address_Sets and NB_Global convergence counters, SB_Global,
Chassis_Private, Port_Binding and Logical_Flow, plus both nodes' br-int OpenFlow.
Each command records its argv, UTC start/end, monotonic start, elapsed time,
exit code and error. Missing tools/columns or timeout errors remain visible.
Current/previous logs are bounded to 5,000 lines per container. Requests exclude
credentials and unrelated Pod specifications; API auditing is restricted to
ANP/BANP/NetworkPolicy writes and Pod exec metadata.

## Interpret a failure

Correlate the policy write's audit ID and resourceVersion with controller logs,
NB rule/Port_Group changes, `nb_cfg/sb_cfg/hv_cfg`, SB and chassis counters, logical
flows and each node's OpenFlow. The original exec audit record helps locate the
probe relative to the policy write. Policy ResponseComplete means the API server
accepted the write; it does not mean packet processing has converged.

Additional probes preserve the exact `/agnhost connect` command, target family,
protocol, port and client container used upstream. Their desired scheduling is
0, 1 and 5 seconds **after the immediate snapshot finishes**, rather than after
the original failure. Each probe is synchronous and can push later probes past
their desired deadline; actual start/end timestamps are authoritative. `connected`
requires successful exec with empty output; `dropped` requires agnhost's TIMEOUT
result. Exec errors, missing/cleaned-up Pods and other rejections are reported
separately. Additional probes never change the original assertion or suite result.

A later successful deny is consistent with subsequent convergence but cannot
prove the original failure's root cause. The suite continues changing policies
while incident workers run. Correlate those intervening writes as well. Snapshots
are concurrent and **not atomic**; their start/end intervals matter. Two incident
workers queue detailed captures up to the configured limit; detection time and
capture time can differ. Failures beyond the limit remain listed in the summary.
An initial snapshot is guaranteed before suite execution, but a slow rolling
capture can leave no recent completed snapshot at the exact failed probe time.

Audit, DB reads, OpenFlow dumps and extra connection probes add load and can alter
connection tracking or failure frequency. This workflow is a diagnostic
experiment, not proof that an uninstrumented run is stable. It does not suppress
failures, add retries to the original suite, or fix historical runtime behavior.

Continuous tracing adds passive subscriptions before the suite starts. Each stream
records its command, observation timestamps, original tool timestamps, stderr,
exit/cleanup status and a 20 MiB output limit. Early termination, absent output
or exceeding the limit makes trace health false. Trace processes are terminated
by their own recorded remote PID at round completion. TCP traces decode headers
without payload dumps and are restricted to port 80 in the conformance Pod CIDRs.
Original SYN timestamps and source ports distinguish new probes from preceding
connections. OVS flow updates and NB/SB row UUIDs can locate rule replacement
relative to those packets. Stream observation time includes transport delay;
use original packet/tool timestamps where available.

The historical Kube-OVN libovsdb writer does not increment `NB_Global.nb_cfg` for
these policy changes. In the reference artifacts `nb_cfg`, `sb_cfg`, `hv_cfg` and
chassis counters all remain zero. Equal zero counters are **not** a convergence
barrier. Correlate actual ACL, logical-flow and OpenFlow changes instead.
