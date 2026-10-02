# ClusterNetworkPolicy v0.2.0 upgrade and rollback

The first compatible Kube-OVN controller reads both legacy `ports` and v0.2.0
`protocols` using a raw dynamic informer. Both forms use the same `v1alpha2` API
version. Installing the upstream v0.2.0 CRD over legacy objects can prune their
port restrictions. Updating the Go dependency alone is therefore unsafe.

Controller/image upgrades and policy representation migration are separate
operations. An ordinary upgrade ends with a compatible controller and legacy
objects. No Helm hook migrates policies, and the policy CRDs remain independent
of the Helm release. ANP/BANP and their v1alpha1 objects are retained.

## Scope and prerequisites

This process handles CNP compatibility. Follow the target Kube-OVN release's
normal Kubernetes, OVN/OVS, database, CNI and daemon upgrade requirements first.
The format change adds no OVN database migration and keeps existing policy
ownership, names, tiers and priority limits. Source controllers include the
legacy CNP implementations in v1.15.28 and v1.16.10. Their full component upgrade
paths still need release-specific validation.

The tool recognizes the exact experimental legacy schema at `3910463a5686`,
the upstream v0.2.0 experimental schema at
`a17adecd0316b8ff1c3f83939ec0441d68cd6cce`, and the generated transition schemas.
It rejects unknown schemas. Investigate and review a different source schema
before adopting it; do not force-replace an unknown CRD or restore missing fields
from an unverified backup. Experimental DNS and node selectors are retained.

Numeric TCP/UDP/SCTP ports, ranges and unrestricted rules are supported. Named
ports are explicitly unsupported: transition CRDs reject them, the controller
reports an application error before changing existing policy resources, and
migration/rollback preflight rejects them. Upstream native CRDs allow the field,
so successful admission does not mean Kube-OVN can implement it. New invalid
policies have no successful application receipt. Fix an invalid update promptly;
retaining the last successful policy does not enforce the invalid desired spec.

Keep `--enable-anp=true` throughout the process. Disabling it is not a policy
freeze: the controller may garbage-collect ANP/BANP/CNP resources. Preserve DNS,
NP and all other effective flags. The legacy chart uses `func.ENABLE_ANP`; v2 uses
`features.ENABLE_ANP`. Preserve the namespace and leader Lease configuration.

## Schemas and artifacts

| Artifact | Fields accepted | Purpose |
| --- | --- | --- |
| `yamls/cnp/legacy-only.yaml` | `ports`; CEL rejects `protocols` | Mixed legacy/compatible controller rollout |
| `yamls/cnp/dual.yaml` | Either field per rule, never both | Migration and rollback observation |
| `yamls/cnp/native.yaml` | `protocols` | New installations or explicit finalization |

All transition fields are structural and validated. No unknown-field
preservation or annotation-based policy storage is used. Regenerate artifacts
with `go run ./cmd/cnp-upgrade crd`; tests check their pinned source and schema.
ANP/BANP CRD URLs remain pinned separately because v0.2.0 does not ship them.

The versioned `cnp-upgrade` binary is built into the Kube-OVN image. It can also
be built with `go build ./cmd/cnp-upgrade`. Run it from an upgrade host with an
existing kubeconfig authorized for the policy CRD, CNP metadata/spec, controller
Deployment/ReplicaSet/Pod/Lease reads and ConfigMaps in the controller namespace.
It never changes RBAC, credentials, deployments or OVN directly.

For this capability gate, pin the controller to an architecture-specific manifest
digest and use the same architecture for the controller replicas. A multi-arch
index whose resolved imageID differs from that digest, or an opaque runtime
imageID, is rejected rather than guessed. Other node components can follow the
release's existing multi-architecture deployment procedure independently.

## Upgrade an existing cluster

1. Export raw policy manifests, CRD and effective deployment values into your
   controlled backup store. Coordinate CRD ownership with GitOps. Run
   `cnp-upgrade plan` and inspect every conversion. Unknown or invalid objects
   block progress. The plan contains UID/resourceVersion/generation, semantic
   digest and guarded JSON Patch operations; it is an inventory, not a reusable
   patch against future objects.
2. Run `cnp-upgrade prepare`. It validates all stored policies against the
   transition schema with Kubernetes pruning, defaulting, OpenAPI and CEL
   validators, dry-runs the CRD update, and installs `legacy-only`. Both fields
   are declared, but `protocols` is rejected while an old controller may run.
3. Upgrade components and controllers to the compatible release using the
   normal release procedure. Pin the controller image by its published manifest
   digest. For at least two replicas, the charts default to `maxSurge: 0` and
   `maxUnavailable: 1`; verify leader handover for each batch. A single replica
   needs a schedulable surge replica with `maxSurge: 1, maxUnavailable: 0` or an
   explicit maintenance window. Existing anti-affinity can prevent surge
   scheduling. The install-script rollout strategy is independently configured.
4. Run `cnp-upgrade verify-controller --controller-image "$CNP_IMAGE"`, followed
   by `cnp-upgrade verify --controller-image "$CNP_IMAGE"`. The gate checks the
   desired template, active ReplicaSets, every owned Pod including terminating
   Pods, resolved image digests, effective policy flag and current leader
   capability. Verification requests fresh application evidence for each CNP.
   This is the default endpoint of the first compatible image upgrade.
5. Before opening native writes, freeze all CNP and schema writers, migrate
   GitOps declarations and external clients, coordinate SSA field ownership,
   and disable every automatic/manual CD path that could deploy a legacy
   image. A scaled-down ReplicaSet alone does not prevent resurrection. These
   external conditions cannot be discovered or fenced by Kubernetes; the tool
   requires explicit acknowledgements and rechecks the fleet/schema per object.
6. Run the independent native migration below, with continuous positive and
   negative **new-connection** probes. Keep the controller compatible during
   migration and observation. Release-specific full-stack and traffic validation
   is required before claiming support for an upgrade path.

```bash
export CNP_IMAGE='registry/repository@sha256:<verified-compatible-manifest-digest>'
cnp-upgrade open --controller-image "$CNP_IMAGE" --writers-frozen --rollback-guarded
cnp-upgrade migrate --controller-image "$CNP_IMAGE" --writers-frozen --rollback-guarded \
  --journal /controlled-backup/cnp-migration.jsonl
cnp-upgrade verify --controller-image "$CNP_IMAGE"
```

`open` installs `dual` only after successful takeover verification. `migrate`
uses a single JSON Patch per object: tests UID, resourceVersion and original spec,
then adds `protocols` and removes `ports`. It retains rule/peer order and UID.
Conflicts stop the operation; rerun from current live objects after investigation.
Completed objects stay migrated. Deleted/recreated objects are separate UIDs;
the tool never resurrects a deleted policy or overwrites a new spec with a backup.
Both intent and read-back are flushed to the append-only journal. The namespace
ConfigMap `kube-ovn-cnp-upgrade` records the last completed stage/object.

Verification checks raw format, semantic digest, generation and fresh leader
application evidence. A representation-only change can reuse the successful
NB state only after its complete PG/ACL/AS digest is unchanged within the same
leader session. Other changes reconcile normally. Ingress and egress still use
separate transactions; this does not promise policy-wide atomicity. Receipts
confirm NB transaction success/read-back, not southbound convergence or end-to-end
traffic. Continuous probes are a separate mandatory release gate.

The controller uses its existing ConfigMap permissions for evidence. Evidence
is bound to the policy UID, generation, semantic digest, leader Pod UID, resolved
image digest, session and verification nonce. It is not CNP status or a readiness
signal. Failure to publish evidence blocks migration while enforcement continues.
Evidence is owned by its corresponding CNP or controller Pod and is garbage
collected with that owner. No additional account or permission is needed.

## Rollback

Before native writes, legacy rollback is possible under the original full-stack
rollback constraints, with legacy representations, `legacy-only` and all flags
preserved. After any native write, the default rollback target must support both
representations. Never use a normal `helm rollback` to deploy a legacy image
after migration. Historical Helm revisions do not run new capability checks.

To return to a legacy controller, keep the compatible controller running, review
the **current** policy semantics, freeze writers and rewrite declaration sources
to legacy. Then run:

```bash
cnp-upgrade rollback-plan
cnp-upgrade rollback --controller-image "$CNP_IMAGE" --writers-frozen --rollback-guarded \
  --journal /controlled-backup/cnp-rollback.jsonl
```

For native schema, `rollback` first restores `dual`, then performs guarded reverse
conversion on current objects. It rejects unsupported semantics, fills the legacy
required empty namespace selector, verifies the new generation on the compatible
controller and installs `legacy-only` only when no native fields remain. Only
then may the external component/Helm rollback deploy the legacy controller.
Partial rollback leaves the compatible controller in place. No CRD/object deletion,
global policy cleanup or whole-database restore is part of this process.

## Finalization and release validation

After an actual validated upgrade/rollback observation period, confirm every
declaration/client is native and freeze writers. `cnp-upgrade finalize
--controller-image "$CNP_IMAGE" --writers-frozen --rollback-guarded` rechecks the
inventory, leader and application evidence before installing native schema. It
is an explicit operation, never an ordinary upgrade hook. Keep this release's
dual-read controller for rollback; removal of legacy decoding belongs to a later
release with a documented minimum upgrade source.

CI covers schema compilation, OpenAPI/CEL/pruning/defaulting, real API-server
round-trips and guarded patching, numeric ACLs, invalid conditions, legacy
ReplicaSet/Pod gates, chart strategies and the two independent Go modules.
The upgrade job creates disposable kind clusters from the pinned v1.15.28 and
v1.16.10 installers for IPv4, IPv6 and dual stack. It upgrades central/OVS/node
components, exercises both mixed leader arrangements, migrates both tiers and
directions, resurrects a legacy standby to test the gate, finalizes/reverses
schema and objects, and rolls back the controller while continuously probing
new connections to allowed and denied ports. It then runs native CNP conformance.
The test image is pinned through a disposable local registry; no public registry
credentials are needed. Run `bash hack/cnp-upgrade-e2e.sh` only in that isolated CI
job. Component database downgrade remains subject to the release's normal rules;
the test's rollback returns the controller while preserving upgraded components.
The release gate additionally requires isolated cluster runs from both supported
legacy versions, mixed leaders and failures, IPv4/IPv6, both tiers/directions,
DNS/nodes, ANP/BANP and NP regression, partial migration, concurrent GitOps/spec
updates, same-name recreation, restart/recovery, old ReplicaSet resurrection,
Helm failure/rollback and sustained positive/negative new-connection probes.
Do not treat compile checks, Pod Ready or NB receipts as substitutes for those runs.
