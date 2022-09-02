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
	DeleteLogicalRouterPort(lrpName string) error
	DeleteLogicalRouterPorts(externalIDs map[string]string, filter func(lrp *ovnnb.LogicalRouterPort) bool) error
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
	ListLogicalSwitchPorts(needVendorFilter bool, externalIDs map[string]string) ([]ovnnb.LogicalSwitchPort, error)
	GetLogicalSwitchPort(lspName string, ignoreNotFound bool) (*ovnnb.LogicalSwitchPort, error)
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
	CreateRouterPort(lsName, lrName, lspName, lrpName, ip, mac string, chassises ...string) error
}
