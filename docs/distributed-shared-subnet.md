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

The leaf topology is rendered into every local NB/SB zone. The gateway
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

This is an experimental per-node topology. `distributed.zone` must remain
empty; arbitrary zone-to-node mappings are unsupported. Every controller's
zone and the local `NB_Global.name` must equal its Kubernetes node name.
The controller validates this identity before its first NB write and refuses
to rename a shared central NB.

Set `distributed.externalInterconnect=true` only after provisioning independent
NB/SB databases, `ovn-northd`, and `ovn-ic` on every node, plus the shared IC
NB/SB databases and their interconnect connectivity. This chart does not
provision that infrastructure. Local endpoints must resolve to the database
of the current node (for example a loopback address), never a shared Service.
All NB/SB/IC NB endpoints and the gateway owner are required. The legacy
central `ovn-ic-controller` is omitted in distributed mode.

Distributed transit switches carry a dedicated vendor and `distributed-cidr`
marker instead of the gateway transport `subnet` field. The legacy IC gateway
renderer cannot allocate transport addresses from the user's Pod CIDR.
Garbage collection preserves transit switches derived from live VPC/Subnet
identities.

The owner allocates all Pod and node join addresses and writes shared
annotations and IP CRs. Each zone materializes only ports for its own node;
remote endpoints remain managed by OVN-IC. Fully allocated local Pods are
reconciled again after restart to rebuild lost local NB ports. DHCP rows are
always resolved in the local NB; followers never publish their UUIDs into
shared Subnet status. Router ports, RA and routed subnet ACLs run only on the
owner; followers reconcile their local switches, DHCP and ordinary ACLs.
Per-pod legacy centralized routing is bypassed in favor of connected VPC
routes. Hotplug and custom per-Pod north gateways are not supported in this
experimental topology.

IP allocation remains global. A per-zone controller must never independently
allocate from the same pool, or two pods can receive the same address. Service
load-balancer, NetworkPolicy, NAT, and gateway failover need additional
distributed renderers because the existing Kube-OVN implementations assume
that all logical switch ports are visible in one NB database.
