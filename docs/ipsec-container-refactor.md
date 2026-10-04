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

The node module persists pending private keys, watches both Kubernetes CSR and
cert-manager CertificateRequest results, validates the returned identity, and
activates complete key/certificate/trust generations through a single OVSDB
map mutation. Other `other_config` entries are preserved. Failed renewals keep
an existing valid identity. The monitor and strongSwan starter run as supervised
foreground processes with private monitor pid/control paths. The monitor does
not restart the IKE daemon itself.

The built-in signer checks the CSR signature, bound Pod identity, live
DaemonSet ownership, Node UID, and the requested chassis CN/SAN. A shared
ServiceAccount or a request name alone is not sufficient. Clusters that do not
populate the bound Pod authentication fields must not silently fall back to
name-based approval. The node's remaining Kubernetes privileges and chassis
registration still need to be included in the threat model.

Both Charts use an `ipsec` configuration section for the backend, issuer,
duration, timeout, priority, and resource limits. Existing IPsec feature switches
remain in place. These arguments now belong to the IPsec entrypoint, rather
than `kube-ovn-daemon`:

- `--cert-manager-ipsec-cert`
- `--cert-manager-issuer-name`
- `--ovn-ipsec-cert-duration`

Local probes use the private status socket with `--check=livez` or
`--check=readyz`. Readiness includes an unexpired active certificate and runtime
health; API outages do not directly fail liveness. An IPsec readiness failure
still makes the whole Pod unready, although its CNI container is not restarted.

This draft is still under implementation. Activation protection, disable
cleanup, CA-key isolation and compatibility migration must be completed and
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
