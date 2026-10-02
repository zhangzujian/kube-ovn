package distributed

import (
	"errors"
	"testing"
)

type switchLinkCall struct {
	lsName   string
	portName string
	peerName string
}

type fakeSwitchLinkClient struct {
	calls []switchLinkCall
}

func (f *fakeSwitchLinkClient) CreateLogicalSwitchSwitchPort(lsName, lspName, peerName string) error {
	f.calls = append(f.calls, switchLinkCall{lsName: lsName, portName: lspName, peerName: peerName})
	return nil
}

func TestBuildPlanCreatesSeparateTransitDomainsAndRouterPorts(t *testing.T) {
	request := Request{
		VPCUID:       "vpc-1",
		RouterName:   "ovn-vpc-1",
		GatewayOwner: "zone-a",
		Zones:        []string{"zone-b", "zone-a"},
		Subnets: []Subnet{
			{Name: "subnet-b", VPCUID: "vpc-1", SubnetUID: "subnet-b", CIDR: "10.20.0.0/24", GatewayIP: "10.20.0.1", GatewayMAC: "00:00:00:20:00:01"},
			{Name: "subnet-a", VPCUID: "vpc-1", SubnetUID: "subnet-a", CIDR: "10.10.0.0/24", GatewayIP: "10.10.0.1", GatewayMAC: "00:00:00:10:00:01"},
		},
	}

	plan, err := BuildPlan(request)
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if got, want := plan.Zones[0], "zone-a"; got != want {
		t.Fatalf("zones are not deterministic: got %q, want %q", got, want)
	}
	if len(plan.Subnets) != 2 {
		t.Fatalf("subnet plan count = %d, want 2", len(plan.Subnets))
	}
	if plan.Subnets[0].SubnetUID != "subnet-a" || plan.Subnets[1].SubnetUID != "subnet-b" {
		t.Fatalf("subnets are not deterministic: %#v", plan.Subnets)
	}
	if plan.Subnets[0].TransitSwitchName == plan.Subnets[1].TransitSwitchName {
		t.Fatal("different subnets must not share a transit switch")
	}
	if len(plan.Subnets[0].Zones) != 2 || plan.Subnets[0].Zones[0].LeafSwitchName != "subnet-a" || plan.Subnets[0].Zones[1].LeafSwitchName != "subnet-a" {
		t.Fatal("each zone must materialize the stable subnet leaf switch name")
	}
	if plan.Subnets[0].Zones[0].TransitSwitchName != plan.Subnets[0].Zones[1].TransitSwitchName {
		t.Fatal("all zones of one subnet must use the same transit switch")
	}
	if plan.Subnets[0].Zones[0].LeafToTransitPort == plan.Subnets[0].Zones[1].LeafToTransitPort {
		t.Fatal("switch port names must be unique per zone")
	}
	if plan.Subnets[0].RouterPortName == plan.Subnets[1].RouterPortName {
		t.Fatal("different subnets must have different router ports")
	}
	if got, want := plan.Subnets[0].RouterPortNetwork, "10.10.0.1/24"; got != want {
		t.Fatalf("router port network = %q, want %q", got, want)
	}
}

func TestBuildPlanRejectsOverlappingCIDRs(t *testing.T) {
	_, err := BuildPlan(Request{
		VPCUID:       "vpc-1",
		RouterName:   "ovn-vpc-1",
		GatewayOwner: "zone-a",
		Zones:        []string{"zone-a"},
		Subnets: []Subnet{
			{VPCUID: "vpc-1", SubnetUID: "a", CIDR: "10.0.0.0/24", GatewayIP: "10.0.0.1"},
			{VPCUID: "vpc-1", SubnetUID: "b", CIDR: "10.0.0.128/25", GatewayIP: "10.0.0.129"},
		},
	})
	if !errors.Is(err, ErrOverlappingCIDR) {
		t.Fatalf("BuildPlan() error = %v, want ErrOverlappingCIDR", err)
	}
}

func TestBuildPlanRejectsGatewayOutsideCIDR(t *testing.T) {
	_, err := BuildPlan(Request{
		VPCUID:       "vpc-1",
		RouterName:   "ovn-vpc-1",
		GatewayOwner: "zone-a",
		Zones:        []string{"zone-a"},
		Subnets: []Subnet{
			{VPCUID: "vpc-1", SubnetUID: "a", CIDR: "10.0.0.0/24", GatewayIP: "10.1.0.1"},
		},
	})
	if err == nil {
		t.Fatal("BuildPlan() succeeded with a gateway outside the subnet")
	}
}

func TestBuildPlanRejectsSubnetFromAnotherVPC(t *testing.T) {
	_, err := BuildPlan(Request{
		VPCUID:       "vpc-1",
		RouterName:   "ovn-vpc-1",
		GatewayOwner: "zone-a",
		Zones:        []string{"zone-a"},
		Subnets: []Subnet{
			{VPCUID: "vpc-2", SubnetUID: "a", CIDR: "10.0.0.0/24", GatewayIP: "10.0.0.1"},
		},
	})
	if err == nil {
		t.Fatal("BuildPlan() succeeded with a subnet from another VPC")
	}
}

func TestBuildPlanSupportsDualStackSubnet(t *testing.T) {
	plan, err := BuildPlan(Request{
		VPCUID:       "vpc-1",
		RouterName:   "ovn-vpc-1",
		GatewayOwner: "zone-a",
		Zones:        []string{"zone-a"},
		Subnets: []Subnet{
			{Name: "subnet-a", VPCUID: "vpc-1", SubnetUID: "subnet-a", CIDR: "10.10.0.0/24,fd00:10::/64", GatewayIP: "10.10.0.1,fd00:10::1"},
		},
	})
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if got, want := plan.Subnets[0].RouterPortNetwork, "10.10.0.1/24,fd00:10::1/64"; got != want {
		t.Fatalf("router port network = %q, want %q", got, want)
	}
}

func TestRenderZoneCreatesBothSwitchPortPeers(t *testing.T) {
	plan, err := BuildPlan(Request{
		VPCUID:       "vpc-1",
		RouterName:   "ovn-vpc-1",
		GatewayOwner: "zone-a",
		Zones:        []string{"zone-a", "zone-b"},
		Subnets: []Subnet{
			{Name: "subnet-a", VPCUID: "vpc-1", SubnetUID: "subnet-a", CIDR: "10.10.0.0/24", GatewayIP: "10.10.0.1"},
		},
	})
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}

	client := new(fakeSwitchLinkClient)
	if err := RenderZone(client, plan, "zone-a"); err != nil {
		t.Fatalf("RenderZone() error = %v", err)
	}
	if len(client.calls) != 2 {
		t.Fatalf("switch link operation count = %d, want 2", len(client.calls))
	}
	if client.calls[0].peerName != client.calls[1].portName || client.calls[1].peerName != client.calls[0].portName {
		t.Fatalf("switch peers are not reciprocal: %#v", client.calls)
	}
}
