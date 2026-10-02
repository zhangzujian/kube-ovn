package distributed

import (
	"errors"
	"fmt"
)

// SwitchLinkClient is the small OVN surface needed to render a subnet's
// leaf-to-transit link. Keeping this interface narrow makes the renderer
// testable without an OVSDB server.
type SwitchLinkClient interface {
	CreateLogicalSwitchSwitchPort(lsName, lspName, peerName string) error
}

// RenderZone connects every planned subnet leaf in zoneUID to its dedicated
// transit switch. The transit switch itself is created in the OVN IC database
// and synchronized into each zone NB; only its local switch ports are written
// here.
func RenderZone(client SwitchLinkClient, plan Plan, zoneUID string) error {
	if client == nil {
		return errors.New("distributed switch link client is nil")
	}
	if zoneUID == "" {
		return errors.New("distributed zone identity is required")
	}

	for _, subnet := range plan.Subnets {
		zone, found := findZone(subnet.Zones, zoneUID)
		if !found {
			return fmt.Errorf("subnet %q has no zone %q", subnet.SubnetUID, zoneUID)
		}
		leafPort := zone.LeafToTransitPort
		transitPort := zone.TransitToLeafPort
		if err := client.CreateLogicalSwitchSwitchPort(zone.LeafSwitchName, leafPort, transitPort); err != nil {
			return fmt.Errorf("connect subnet %q leaf to transit switch: %w", subnet.SubnetUID, err)
		}
		if err := client.CreateLogicalSwitchSwitchPort(zone.TransitSwitchName, transitPort, leafPort); err != nil {
			return fmt.Errorf("connect subnet %q transit switch to leaf: %w", subnet.SubnetUID, err)
		}
	}
	return nil
}

func findZone(zones []ZoneSubnetPlan, zoneUID string) (ZoneSubnetPlan, bool) {
	for _, zone := range zones {
		if zone.ZoneUID == zoneUID {
			return zone, true
		}
	}
	return ZoneSubnetPlan{}, false
}
