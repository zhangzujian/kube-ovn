package ovs

import (
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
	"github.com/ovn-org/libovsdb/ovsdb"
)

type NbGlobal interface {
	UpdateNbGlobal(nbGlobal *ovnnb.NBGlobal, fields ...interface{}) error
	SetAzName(azName string) error
	SetUseCtInvMatch() error
	SetICAutoRoute(enable bool, blackList []string) error
	SetLBCIDR(serviceCIDR string) error
	GetNbGlobal() (*ovnnb.NBGlobal, error)
}

type LogicalRouter interface {
	CreateLogicalRouter(lrName string) error
	DeleteLogicalRouter(lrName string) error
	GetLogicalRouter(lrName string, ignoreNotFound bool) (*ovnnb.LogicalRouter, error)
	ListLogicalRouter(needVendorFilter bool) ([]ovnnb.LogicalRouter, error)
	LogicalRouterExists(name string) (bool, error)
}

type LogicalRouterPort interface {
	CreatePeerRouterPort(localRouter, remoteRouter, localRouterPortIP string) error
	DeleteLogicalRouterPort(lrpName string) error
	DeleteLogicalRouterPorts(externalIDs map[string]string, filter func(lrp *ovnnb.LogicalRouterPort) bool) error
	GetLogicalRouterPort(lrpName string, ignoreNotFound bool) (*ovnnb.LogicalRouterPort, error)
	ListLogicalRouterPorts(externalIDs map[string]string, filter func(lrp *ovnnb.LogicalRouterPort) bool) ([]ovnnb.LogicalRouterPort, error)
	LogicalRouterPortExists(lrpName string) (bool, error)
}

type LogicalSwitch interface {
	CreateLogicalSwitch(lsName, lrName, cidrBlock, gateway string, needRouter bool) error
	CreateBareLogicalSwitch(lsName string) error
	LogicalSwitchUpdateLoadBalancers(lsName string, op ovsdb.Mutator, lbNames ...string) error
	DeleteLogicalSwitch(lsName string) error
	ListLogicalSwitch(needVendorFilter bool) ([]ovnnb.LogicalSwitch, error)
	LogicalSwitchExists(lsName string) (bool, error)
}

type LogicalSwitchPort interface {
	CreateLogicalSwitchPort(lsName, lspName, ip, mac, podName, namespace string, portSecurity bool, securityGroups string, vips string, enableDHCP bool, dhcpOptions *DHCPOptionsUUIDs, vpc string) error
	CreateBareLogicalSwitchPort(lsName, lspName, ip, mac string) error
	CreateLocalnetLogicalSwitchPort(lsName, lspName, provider string, vlanID int) error
	CreateVirtualLogicalSwitchPorts(lsName string, ips ...string) error
	SetLogicalSwitchPortSecurity(portSecurity bool, lspName, mac, ips, vips string) error
	SetLogicalSwitchPortVirtualParents(lsName, parents string, ips ...string) error
	SetLogicalSwitchPortExternalIds(lspName string, externalIds map[string]string) error
	SetLogicalSwitchPortVlanTag(lspName string, vlanID int) error
	EnablePortLayer2forward(lspName string) error
	DeleteLogicalSwitchPort(lspName string) error
	ListLogicalSwitchPorts(needVendorFilter bool, externalIDs map[string]string) ([]ovnnb.LogicalSwitchPort, error)
	ListVirtualTypeLogicalSwitchPorts(lsName string) ([]ovnnb.LogicalSwitchPort, error)
	ListRemoteTypeLogicalSwitchPorts() ([]ovnnb.LogicalSwitchPort, error)
	GetLogicalSwitchPort(lspName string, ignoreNotFound bool) (*ovnnb.LogicalSwitchPort, error)
	LogicalSwitchPortExists(name string) (bool, error)
}

type LoadBalancer interface {
}

type PortGroup interface {
	PortGroupUpdatePorts(pgName string, op ovsdb.Mutator, lspNames ...string) error
	PortGroupExists(pgName string) (bool, error)
	PortGroupRemovePorts(pgName string, lspNames ...string) error
}

type LogicalRouterStaticRoute interface {
	GetLogicalRouterRouteByOpts(key, value string) ([]ovnnb.LogicalRouterStaticRoute, error)
	ListLogicalRouterStaticRoutes(externalIDs map[string]string) ([]ovnnb.LogicalRouterStaticRoute, error)
}

type LogicalRouterPolicy interface {
	AddLogicalRouterPolicy(lrName string, priority int, match, action string, nextHops []string, externalIDs map[string]string) error
	DeleteLogicalRouterPolicy(lrName string, priority int, match string) error
	DeleteRouterPolicy(lr *ovnnb.LogicalRouter, uuid string) error
	ListLogicalRouterPolicies(externalIDs map[string]string) ([]ovnnb.LogicalRouterPolicy, error)
}

type NAT interface {
	UpdateSnat(lrName, externalIP, logicalIP string) error
	UpdateDnatAndSnat(lrName, externalIP, logicalIP, lspName, externalMac, gatewayType string) error
	DeleteNats(lrName, natType, logicalIP string) error
}

type OvnClient interface {
	NbGlobal
	LogicalRouter
	LogicalRouterPort
	LogicalSwitch
	LogicalSwitchPort
	LoadBalancer
	PortGroup
	LogicalRouterStaticRoute
	LogicalRouterPolicy
	NAT
	CreateGatewayLogicalSwitch(lsName, lrName, provider, ip, mac string, vlanID int, chassises ...string) error
	CreateRouterPort(lsName, lrName, lspName, lrpName, ip, mac string, chassises ...string) error
	RemoveRouterPort(lspName, lrpName string) error
	DeleteLogicalGatewaySwitch(lsName, lrName string) error
}
