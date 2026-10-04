# Node IPsec container refactor

This branch builds on kubeovn/kube-ovn#7593. When IPsec is enabled, the
`kube-ovn-cni` Pod runs an additional `ipsec` container using the same image.
The container runs `/kube-ovn/kube-ovn-ipsec`; CNI no longer watches the CA
Secret, issues certificates, starts IPsec services, or flushes host XFRM state.

The new container owns the persistent key directory and needs `NET_ADMIN`,
`NET_BIND_SERVICE`, and `SYS_NICE`. Its subprocesses run with a configurable
nice priority, defaulting to -5. CNI explicitly drops `SYS_NICE` and uses the
unprivileged service user even with IPsec enabled. Installer debug mode retains
its existing CNI root exception. Pod-level host networking, host PID namespace,
and the ServiceAccount remain shared; this is not a separate security identity.
Both Charts and the installer explicitly use a zero-surge CNI DaemonSet rollout;
the persistent node owner lock additionally excludes concurrent new writers.

The node module persists pending private keys, watches Kubernetes CSR results,
validates the returned identity, and
activates complete key/certificate/trust generations through a single OVSDB
map mutation. Other `other_config` entries are preserved. Failed renewals keep
an existing valid identity. The monitor and strongSwan starter run as supervised
foreground processes with private monitor pid/control paths. The monitor does
not restart the IKE daemon itself.

Renewals use a stable per-node/certificate schedule between 40% and 60% of the
leaf lifetime, so simultaneously installed nodes do not all renew at the midpoint.
Repeated runtime startup failures back off from one to thirty seconds; a runtime
that remained up for a minute resets that delay before recovery.

The image applies small, checked adaptations to the upstream OVS monitor:
accept CN at the end of an RFC2253 subject, optionally filter interfaces by
their owning Port's `ovn-chassis-id`, and report public configuration digests
through `configuration/get` after successful strongSwan update/secret reload.
The IPsec entrypoint enables the filter. Readiness waits for the current
certificate/trust digest acknowledgement as well as responsive processes;
changed public content invalidates the previous acknowledgement. This confirms
configuration refresh, not replacement of every established peer SA or a
cluster CA rotation acknowledgement.
Image construction fails if the pinned monitor source no longer matches the
adaptation points. Connection generation and refresh remain in OVS. The filter
does not prove ownership of orphaned kernel SAs after a crash.

The built-in signer checks the CSR signature, bound Pod identity, live
DaemonSet ownership, Node UID, and the requested chassis CN/SAN. A shared
ServiceAccount or a request name alone is not sufficient. Clusters that do not
populate the bound Pod authentication fields must not silently fall back to
name-based approval. The node's remaining Kubernetes privileges and chassis
registration still need to be included in the threat model.

Both Charts use an `ipsec` configuration section for the backend, issuer,
duration, timeout, priority, and resource limits. Existing IPsec feature switches
remain in place. The controller selects the signing backend with
`--cert-manager-ipsec-cert` and `--cert-manager-issuer-name`. Nodes always submit
a Kubernetes CSR, including when cert-manager signs the certificate. The
controller validates the bound identity before forwarding an approved CSR to
cert-manager and checks the returned certificate before publishing it. CNI's
ServiceAccount cannot create CertificateRequests; that permission belongs only
to the controller and is restricted to its namespace.

The IPsec entrypoint owns `--ovn-ipsec-cert-duration`, `--request-timeout`, and
`--priority`, rather than `kube-ovn-daemon`.

The external ClusterIssuer and public `ovn-ipsec-ca` trust bundle must be
provisioned consistently. The issuer must be dedicated to Kube-OVN IPsec.
Installation creates a fail-closed ValidatingAdmissionPolicy and binding that
restrict requests to this ClusterIssuer across all namespaces to the controller
ServiceAccount in its configured namespace. Kubernetes >= 1.30 is required for
this backend. Metadata-only updates are allowed; other requesters cannot change
the authorized request's spec. Before forwarding, the controller checks the
policy scope, observed generation and unconditional Deny binding. Missing or
weakened policy is retryable and never forwards a request. Generic cert-manager
auto-approval cannot admit a different requester past this policy.
Policy installation propagation still requires cluster acceptance testing
before this draft is ready.

The disposable API test has passed the bound-token and issuer rejection/issuance
contract. This does not establish installation safety across API Server replicas:
`observedGeneration` confirms policy processing, not that every instance already
enforces a newly created binding. The admission barrier must be established before
the dedicated issuer is made available. That rollout barrier remains incomplete
in this draft; a later immediate rejection check returned an accepted request after policy
status convergence. The test now waits for an actual unauthorized dry-run
rejection before provisioning its disposable issuer. This does not implement
a production barrier across API Server instances.

`hack/test-ipsec-runtime.sh` validates the real candidate's startup, private
endpoints, priority/capability inheritance, monitor crash recovery, and shutdown.
`hack/test-ipsec-traffic.sh` runs two private network namespaces with synthetic
certificate identities and UDP payloads on Geneve/VXLAN ports, for IPv4 and IPv6.
A separate fixture captures the outer interface and requires ESP packets with
zero plaintext transport packets. The isolated test also prototypes a
low-priority XFRM block policy before starting IKE and confirms it survives
runtime shutdown. Production does not install this policy: its selector would
reserve an underlay address/UDP port, so ownership and conflicts must be resolved
before adoption. This verifies synthetic Linux transport/IKE; it does not run
`ovn-controller` or Pod overlays, or establish production protection during
faults and rollout.

`hack/test-ipsec-api.sh` uses a disposable CI cluster with real cert-manager to
check bound Pod authentication fields, built-in signing, rendered issuer
admission and controller forwarding. It intentionally grants its test CNI
CertificateRequest privileges to verify admission independently of RBAC;
production CNI does not have those privileges. The test also checks namespace
restriction, unrelated issuers and metadata-only updates. This is an API
contract test, not a full Kube-OVN deployment or migration test.

`hack/test-ipsec-overlay.sh` installs the candidate in a disposable two-node
Kind cluster, exchanges actual cross-node Pod traffic in both directions, and
checks the underlay capture for ESP and absence of plaintext tunnel packets.
Its outcome must be recorded against the tested image and revision; the harness
itself is not evidence of a successful deployment or fault-safe migration.

Local probes use the private status socket with `--check=livez` or
`--check=readyz`. Readiness includes an unexpired active certificate and runtime
health; API outages do not directly fail liveness. An IPsec readiness failure
still makes the whole Pod unready, although its CNI container is not restarted.

Before the trust informer synchronizes, cold startup may restore the last
committed generation. Recovery requires the same Node name, namespace and local
OVS chassis, a recorded Node UID, intact content digest, matching key/certificate
and an unexpired identity under its last committed trust. It does not import
legacy files or submit a CSR offline. Status reports `Restored`; this represents
the last verified binding, not a new live Node UID or a CA rotation acknowledgement.
After API synchronization, online identity and trust checks take precedence.
Older generations without the name/namespace binding need one successful online
reconciliation before they can recover offline.

This draft is still under implementation. Activation protection, disable
cleanup and compatibility migration must be completed and
verified before enabling the refactor in a supported release. A populated
OVSDB `ipsec_skb_mark` does not alone prove that a drop policy is installed.
The candidate image must prove startup/restart behavior and actual encrypted
traffic on the host kernel; package tests and rendered capabilities do not
substitute for that verification.

The built-in CA is generated in Go and stored in the controller-only
`ovn-ipsec-signer` Secret. `ovn-ipsec-ca` publishes only `cacert` on fresh
installations. During an upgrade the original root and key are copied before
publishing trust; the legacy `cakey` field is removed only when every live
controller Pod acknowledges the new format. The controller's Secret get/update
permissions are restricted to named Secrets in its namespace. This transition
does not revoke existing node access until controller compatibility is confirmed.
Rolling back to an old controller after finalization requires restoring its
supported Secret schema through a deliberate migration.

The node imports an existing legacy certificate/key pair only from referenced
files in its key directory, after checking the key, chassis, trust and expiry.
Requests also include the current Pod UID and signing parameters in their name,
so a rebuilt Pod can retain its pending private key without waiting on a CSR
authenticated as a deleted Pod. Storage rejects symlink entries. Reconciliation
reuses the reconnecting native OVSDB client, and probes check responsive local
IKE/monitor endpoints and a bounded reconciliation heartbeat.

The IPsec switch no longer changes the UID of OVS, the controller, or other ordinary containers. The agent runs as UID 0 with GID 65534 to access the non-root OVSDB socket without DAC capabilities. The shell installer retains its existing debug-wrapper UID/GID 0 exception for the shared socket. CNI DaemonSet rollouts explicitly use `maxSurge: 0` and `maxUnavailable: 1`.

The source-path prototype rebuilds only `ovn-controller` from pinned OVN/OVS
sources in `Dockerfile.ipsec-ovn`. A small candidate patch generates
`egress_pkt_mark`, `ipsec_mark_out`, and `ipsec_reqid` from paired local
`ovn-ipsec-protection-mark`/`ovn-ipsec-protection-reqid` external IDs. The output
mark remains configured when the SB IPsec switch is off, so a future activation
coordinator can protect the transition. The normal base image and production
agent do not use this prototype. The disposable Kind harness reserves its own
synthetic mark/reqid, installs an independent guard before setting the external
IDs, verifies actual OVN-generated options, and requires marked encrypted Pod
traffic and ESP SAs using that reservation. It then stops IKE, changes the SB
switch to plaintext mode, and requires the retained output mark/guard to block
Pod probes with zero plaintext transport packets. This still needs an actual CI pass
and is not a production allocator, reboot gate or cleanup ledger.
