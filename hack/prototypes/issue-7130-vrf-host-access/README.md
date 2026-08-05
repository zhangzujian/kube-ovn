# Issue #7130 VRF host-access prototype

This is a throwaway prototype for [issue #7130](https://github.com/kubeovn/kube-ovn/issues/7130). It answers one question: for non-overlapping IPv4 overlay VPCs, which host/Pod and routed-egress paths remain available when ingress-scoped policy rules replace per-VPC leak veths and `tcp_l3mdev_accept` stays disabled?

The prototype creates six anonymous, process-owned network namespaces. The real root network namespace receives no interfaces, addresses, routes, rules, sysctls, or netfilter rules. All simulated network state disappears when the script exits.

```text
 pod1          VPC router 1          simulated host               external
10.10.1.2 -- 10.10.1.1/172.31.1.1 -- h1vpc[vrf1/table 1001]
                                             |
                                      policy rules -- uplink0 -- 203.0.113.2
                                             |
10.10.2.2 -- 10.10.2.1/172.31.2.1 -- h2vpc[vrf2/table 1002]
 pod2          VPC router 2
```

Each VRF table contains its Pod route plus an unreachable default. Narrow rules scoped by both the Pod source CIDR and the allowed external destination select the main table first. Per-VPC ingress guards then keep every other packet arriving on `h1vpc` or `h2vpc` in its original VRF table. Lower-priority destination rules make each Pod CIDR reachable to ordinary host sockets and external returns without allowing one VPC to select another VPC's table.

Run it as root with:

```bash
bash hack/prototypes/issue-7130-vrf-host-access/run.sh
```

The script validates:

- Pod-to-host ICMP for both the VRF transit address and a main-domain local address;
- expected rejection of a plain host wildcard TCP listener while `tcp_l3mdev_accept=0`;
- ordinary host ICMP sockets reaching both Pods through destination policy rules;
- expected failure of VRF-unaware host TCP sockets despite correct FIB selection;
- explicitly VRF-scoped host TCP sockets reaching both Pods;
- routed external egress with Pod sources preserved and explicit external return routes;
- denial of traffic between the two VPCs;
- absence of leak veths, leak addresses, netfilter rules, NAT, and conntrack zones;
- unchanged root network namespace state before and after the run;
- `tcp_l3mdev_accept=0` at the end of the run.

The result is intentionally narrower than transparent host access: policy rules are sufficient for ICMP and routed forwarding, but they do not associate a default-domain TCP socket with a VPC VRF. An unmodified kubelet TCP/HTTP/gRPC probe path is therefore not proven by this variant. The prototype also does not model OVN logical flows, OVS internal ports, Kubernetes lifecycle, dual stack, failure withdrawal, SNAT, or host-service proxies.
