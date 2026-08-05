# Issue #7130 VRF host-access prototype

This is a throwaway prototype for [issue #7130](https://github.com/kubeovn/kube-ovn/issues/7130). It answers one question: for non-overlapping IPv4 overlay VPCs, can a per-VPC Linux VRF provide bidirectional Pod/host connectivity and an explicit path from Pods through the host network to an external network without leaking traffic between VPCs?

The prototype creates six anonymous, process-owned network namespaces. The real root network namespace receives no interfaces, addresses, routes, rules, sysctls, or netfilter rules. All simulated network state disappears when the script exits.

```text
 pod1          VPC router 1          simulated host                external
10.10.1.2 -- 10.10.1.1/172.31.1.1 -- h1vpc[vrf1/table 1001]
                                             |
                                      leak1v -- leak1m --+
                                                         +-- uplink0 -- 203.0.113.2
                                      leak2v -- leak2m --+
                                             |
10.10.2.2 -- 10.10.2.1/172.31.2.1 -- h2vpc[vrf2/table 1002]
 pod2          VPC router 2
```

`leak*v` is enslaved to its VPC VRF and `leak*m` stays in the simulated host's main routing table. The veth pair is the explicit route-leak boundary. Each VRF only has a route for the selected external prefix, not a default route, so the first-stage prototype uses only VRFs and routes while keeping the VPC routes disconnected.

Host-initiated checks run in the corresponding VRF and use that VRF's route table. The prototype deliberately installs no `ip rule` beyond the l3mdev rule that Linux creates with a VRF.

Run it as root with:

```bash
bash hack/prototypes/issue-7130-vrf-host-access/run.sh
```

The script validates:

- Pod-to-host ICMP and a plain TCP service listening on `0.0.0.0:<port>` with no service-specific VRF or device argument;
- the default rejection of that plain listener when `tcp_l3mdev_accept=0`, followed by success after the simulated host opts in with `tcp_l3mdev_accept=1`;
- host-to-Pod traffic initiated from the corresponding VRF;
- routed external egress with the Pod source preserved and explicit return routes;
- denial of Pod traffic from one VPC to the other;
- unchanged root network namespace state before and after the run.

This prototype intentionally does not model OVN logical flows, OVS internal ports, Kubernetes lifecycle, dual stack, failure withdrawal, kubelet probes, SNAT, or netfilter isolation. It validates the first-stage Linux VRF and routed data-path premise, not a production implementation.
