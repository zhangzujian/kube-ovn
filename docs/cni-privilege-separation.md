# CNI privilege separation

Kube-OVN now supports a two-phase CNI path. The daemon resolves Kubernetes state and returns a typed network plan. The CNI binary, started by the container runtime, applies the host and Pod network changes and then commits the observed result to the daemon.

```text
CNI ADD -> daemon: prepare plan
CNI ADD -> local executor: veth/VF, OVS, netns, routes, QoS
CNI ADD -> daemon: commit observed result
```

The plan contains network intent and validated resource identifiers. It does not contain shell commands, arbitrary paths, OVS transactions, or a namespace path chosen by the daemon. The executor validates the plan again and uses the runtime-provided network namespace for the operation.

The same sequence is used for DEL. DEL obtains a deletion plan before removing an interface, so a missing Pod or a missing namespace does not make the executor guess which host object to remove. The local executor owns host networking cleanup; the daemon commit handles Kubernetes and egress bookkeeping.

The daemon rejects old daemon-side ADD and DEL execution when the chart passes `--disable-legacy-cni-execution=true`. The v1/v2 charts and `install.sh` enable this mode by default. Set the corresponding chart or installer option to `false` only while rolling back to an older CNI binary.

In the new mode, the CNI server runs with the chart's unprivileged service user (root is retained when IPsec requires it), keeps the capabilities needed by its continuous node work, and drops the legacy CNI `SYS_ADMIN` and `SYS_PTRACE` capabilities. The compatibility mode restores the root user and the legacy capability set. This change moves Pod attachment privileges out of the `kube-ovn-daemon` CNI server; node gateway reconciliation, ProviderNetwork updates, netfilter, IPsec, TProxy, and other continuous node work remain in the node daemon until their own execution mode is migrated. Deployments that still enable a feature requiring daemon-side namespace creation or switching must keep compatibility mode enabled until that feature is migrated.

## Upgrade and rollback

The installer publishes `kube-ovn` as an atomic symlink to an immutable execution
bundle under the CNI bin directory. Each bundle includes `ovs-vsctl`, `ethtool`,
their ELF loader, and shared libraries from the image. CNI resolves tools beside
its actual executable and does not require these packages on the node. The tools
run in the CNI process environment with the runtime's privileges; no daemon RPC
executes their commands. Installation verifies both tools with `--version` before
publishing the bundle. Previous bundles are retained for running invocations and
rollback; operators may retire them after those invocations have exited and the
rollback window has closed.

1. Install the new image and CNI binary on a node.
2. Verify the CNI binary can reach the daemon socket and that a test ADD receives a plan.
3. Enable `--disable-legacy-cni-execution=true` only after the new CNI binary is present on every node in the rollout.
4. During rollback, disable the flag before restoring an older CNI binary. Existing new-path attachments must be deleted by the new binary or by an explicit cleanup operation before the old binary becomes the sole owner.

The v1 request and response types remain wire-compatible for clients that do not set `prepare_only`; the compatibility flag is the enforcement switch for deployments that want to prevent daemon-side host changes.
