package controller

import (
	"testing"

	kubeovnv1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	"github.com/kubeovn/kube-ovn/pkg/ovs"
)

func TestLocalSubnetDHCPOptionsUUIDsUsesZoneLocalRows(t *testing.T) {
	subnet := &kubeovnv1.Subnet{}
	subnet.Name = "subnet-a"
	subnet.Status.DHCPv4OptionsUUID = "shared-status-v4"
	subnet.Status.DHCPv6OptionsUUID = "shared-status-v6"

	c := &Controller{
		config: &Configuration{EnableDistributedSharedSubnet: true},
		distributedDHCPOptions: map[string]ovs.DHCPOptionsUUIDs{
			"subnet-a": {DHCPv4OptionsUUID: "local-v4", DHCPv6OptionsUUID: "local-v6"},
		},
	}
	got := c.localSubnetDHCPOptionsUUIDs(subnet)
	if got.DHCPv4OptionsUUID != "local-v4" || got.DHCPv6OptionsUUID != "local-v6" {
		t.Fatalf("local DHCP options = %#v, want zone-local UUIDs", got)
	}
}

func TestLocalSubnetDHCPOptionsUUIDsFallsBackToStatus(t *testing.T) {
	subnet := &kubeovnv1.Subnet{}
	subnet.Name = "subnet-a"
	subnet.Status.DHCPv4OptionsUUID = "status-v4"
	subnet.Status.DHCPv6OptionsUUID = "status-v6"

	c := &Controller{config: &Configuration{EnableDistributedSharedSubnet: true}}
	got := c.localSubnetDHCPOptionsUUIDs(subnet)
	if got.DHCPv4OptionsUUID != "status-v4" || got.DHCPv6OptionsUUID != "status-v6" {
		t.Fatalf("fallback DHCP options = %#v, want status UUIDs", got)
	}
}
