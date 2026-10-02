// Package distributed contains the topology planning primitives used by the
// distributed controller. Planning is deliberately independent of an OVN
// database client so every zone can render the same names and route intent.
package distributed

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

var (
	// ErrMissingIdentity indicates that a VPC, router, or gateway owner is absent.
	ErrMissingIdentity = errors.New("distributed network identity is required")
	// ErrOverlappingCIDR indicates that two subnets cannot be routed safely.
	ErrOverlappingCIDR = errors.New("subnet CIDRs overlap")
	// ErrInvalidRequest indicates that the topology request has no usable resources.
	ErrInvalidRequest = errors.New("invalid distributed network request")
)

// Subnet describes the user-visible network that is materialized in each
// zone. CIDR is the pod address space; it must not be reused for transit links.
type Subnet struct {
	Name       string
	VPCUID     string
	SubnetUID  string
	CIDR       string
	GatewayIP  string
	GatewayMAC string
}

// Request contains the stable identities needed to construct a VPC topology.
type Request struct {
	VPCUID       string
	RouterName   string
	GatewayOwner string
	Subnets      []Subnet
	Zones        []string
}

// Plan is the complete route intent for one VPC. Each subnet has its own
// transit switch, so attaching two subnets never creates an accidental L2
// broadcast domain. The router ports provide the L3 boundary between them.
type Plan struct {
	VPCUID       string
	RouterName   string
	GatewayOwner string
	Subnets      []SubnetPlan
	Zones        []string
}

// SubnetPlan names the logical resources that every zone renderer must use.
type SubnetPlan struct {
	SubnetUID         string
	CIDR              string
	TransitSwitchName string
	RouterPortName    string
	RouterPortNetwork string
	GatewayIP         string
	GatewayMAC        string
	Zones             []ZoneSubnetPlan
}

// ZoneSubnetPlan is the local materialization of a subnet in one zone. The
// transit switch name is shared by all zones; the leaf switch is zone-local.
type ZoneSubnetPlan struct {
	ZoneUID           string
	LeafSwitchName    string
	TransitSwitchName string
	LeafToTransitPort string
	TransitToLeafPort string
}

// BuildPlan validates a VPC's subnet set and returns deterministic OVN names.
// Connected routes are represented by one router port per subnet. OVN's
// logical router then routes between all non-overlapping connected CIDRs.
func BuildPlan(request Request) (Plan, error) {
	if request.VPCUID == "" || request.RouterName == "" || request.GatewayOwner == "" {
		return Plan{}, ErrMissingIdentity
	}
	if len(request.Subnets) == 0 || len(request.Zones) == 0 {
		return Plan{}, fmt.Errorf("%w: at least one subnet and zone are required", ErrInvalidRequest)
	}

	zones := append([]string(nil), request.Zones...)
	slices.Sort(zones)
	for i := 1; i < len(zones); i++ {
		if zones[i] == zones[i-1] || zones[i] == "" {
			return Plan{}, fmt.Errorf("invalid zone identity %q", zones[i])
		}
	}
	if zones[0] == "" {
		return Plan{}, fmt.Errorf("invalid zone identity %q", zones[0])
	}

	subnets := append([]Subnet(nil), request.Subnets...)
	slices.SortFunc(subnets, func(a, b Subnet) int {
		return cmp.Compare(a.SubnetUID, b.SubnetUID)
	})
	planned := make([]SubnetPlan, 0, len(subnets))
	prefixes := make([]netip.Prefix, 0, len(subnets))
	seen := make(map[string]struct{}, len(subnets))
	for _, subnet := range subnets {
		if subnet.VPCUID != request.VPCUID || subnet.SubnetUID == "" || subnet.CIDR == "" {
			return Plan{}, fmt.Errorf("invalid subnet identity %q", subnet.SubnetUID)
		}
		if _, ok := seen[subnet.SubnetUID]; ok {
			return Plan{}, fmt.Errorf("duplicate subnet %q", subnet.SubnetUID)
		}
		seen[subnet.SubnetUID] = struct{}{}
		cidrs := strings.Split(subnet.CIDR, ",")
		gateways := strings.Split(subnet.GatewayIP, ",")
		if len(cidrs) != len(gateways) || len(cidrs) == 0 {
			return Plan{}, fmt.Errorf("subnet %q must have one gateway per CIDR", subnet.SubnetUID)
		}
		canonicalCIDRs := make([]string, 0, len(cidrs))
		gatewayNetworks := make([]string, 0, len(gateways))
		canonicalGateways := make([]string, 0, len(gateways))
		for i, cidr := range cidrs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				return Plan{}, fmt.Errorf("parse subnet %q CIDR %q: %w", subnet.SubnetUID, cidr, err)
			}
			prefix = prefix.Masked()
			for _, other := range prefixes {
				if prefix.Overlaps(other) {
					return Plan{}, fmt.Errorf("%w: %q overlaps %q", ErrOverlappingCIDR, prefix, other)
				}
			}
			gateway, err := netip.ParseAddr(strings.TrimSpace(gateways[i]))
			if err != nil || !prefix.Contains(gateway) {
				return Plan{}, fmt.Errorf("gateway %q is outside subnet %q", gateways[i], prefix)
			}
			prefixes = append(prefixes, prefix)
			canonicalCIDRs = append(canonicalCIDRs, prefix.String())
			canonicalGateways = append(canonicalGateways, gateway.String())
			gatewayNetworks = append(gatewayNetworks, gateway.String()+"/"+strconv.Itoa(prefix.Bits()))
		}
		canonicalCIDR := strings.Join(canonicalCIDRs, ",")
		canonicalGateway := strings.Join(canonicalGateways, ",")
		key := stableKey(request.VPCUID, subnet.SubnetUID)
		leafSwitchName := "dist-ls-" + key
		if subnet.Name != "" {
			// A logical switch name is scoped to a zone NB. Keeping the
			// Kubernetes subnet name here preserves existing CNI annotations
			// while each zone still owns a separate database row.
			leafSwitchName = subnet.Name
		}
		transitSwitchName := "dist-ts-" + key
		zonePlans := make([]ZoneSubnetPlan, 0, len(zones))
		for _, zone := range zones {
			zonePlans = append(zonePlans, ZoneSubnetPlan{
				ZoneUID:           zone,
				LeafSwitchName:    leafSwitchName,
				TransitSwitchName: transitSwitchName,
				LeafToTransitPort: fmt.Sprintf("%s-to-%s", leafSwitchName, stableKey(request.VPCUID, subnet.SubnetUID, zone)),
				TransitToLeafPort: fmt.Sprintf("%s-to-%s", transitSwitchName, stableKey(request.VPCUID, subnet.SubnetUID, zone)),
			})
		}
		planned = append(planned, SubnetPlan{
			SubnetUID:         subnet.SubnetUID,
			CIDR:              canonicalCIDR,
			TransitSwitchName: transitSwitchName,
			RouterPortName:    request.RouterName + "-" + leafSwitchName,
			RouterPortNetwork: strings.Join(gatewayNetworks, ","),
			GatewayIP:         canonicalGateway,
			GatewayMAC:        subnet.GatewayMAC,
			Zones:             zonePlans,
		})
	}

	return Plan{
		VPCUID:       request.VPCUID,
		RouterName:   request.RouterName,
		GatewayOwner: request.GatewayOwner,
		Subnets:      planned,
		Zones:        zones,
	}, nil
}

func stableKey(values ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(digest[:])[:16]
}
