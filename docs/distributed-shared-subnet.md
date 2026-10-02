# Distributed VPC routing with shared overlay subnets

The distributed mode keeps the Kubernetes-facing `Subnet` CIDR global while
sharding its OVN objects by zone. A subnet is represented by one leaf logical
switch in each zone NB and one transit logical switch for that subnet. The
leaf keeps the existing Kubernetes subnet name because logical switch names
are scoped to each zone NB. Transit switches are deliberately separate:
putting two user subnets on one transit switch would bridge them into the same
broadcast domain.

All subnets belonging to a VPC are attached to the VPC logical router through
their own logical router port. The port network is the subnet gateway address
and prefix, for example:

```text
VPC LR: ovn-vpc-1
  LRP subnet-a: 10.10.0.1/24
  LRP subnet-b: 10.20.0.1/24
```

OVN then installs connected routes for both CIDRs. A packet from
`10.10.0.10` to `10.20.0.10` follows this path:

```text
pod-a -> leaf LS-a -> TS-a -> subnet-a LRP -> VPC LR
      -> subnet-b LRP -> TS-b -> leaf LS-b -> pod-b
```

The same route intent is rendered into every local NB/SB zone. The gateway
owner is explicit in the first implementation, so only one zone owns the
VPC router gateway state at a time. Internal interconnect `/31` addresses are
transport addresses and are not taken from a user subnet CIDR.

The planner in `pkg/controller/distributed` enforces the invariants needed for
this model:

* every subnet belongs to the requested VPC and has a unique stable identity;
* all subnet CIDRs are canonical and non-overlapping;
* every gateway address belongs to its subnet;
* switch and router-port names are deterministic across controller restarts;
* zones receive a stable, sorted identity list.

The Helm gate is `distributed.sharedSubnet=true`. It renders the controller as
a DaemonSet. Leave `distributed.zone` empty to derive the zone identity from
the node name, set `distributed.gatewayOwner` to the node that owns the VPC
gateway, and provide local `distributed.nbEndpoint`/
`distributed.sbEndpoint` plus the shared `distributed.icNbEndpoint`. The
controller creates the per-subnet `Transit_Switch` in the IC NB and then
creates reciprocal `type=switch` ports in the local NB.

IP allocation remains global. A per-zone controller must never independently
allocate from the same pool, or two pods can receive the same address. Service
load-balancer, NetworkPolicy, NAT, and gateway failover need additional
distributed renderers because the existing Kube-OVN implementations assume
that all logical switch ports are visible in one NB database.
