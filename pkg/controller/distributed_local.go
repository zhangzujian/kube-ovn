package controller

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	kubeovnv1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	"github.com/kubeovn/kube-ovn/pkg/controller/distributed"
	"github.com/kubeovn/kube-ovn/pkg/ovs"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

// ownsGlobalState serializes shared Kubernetes and IPAM writes in one zone.
func (c *Controller) ownsGlobalState() bool {
	return c.config == nil || !c.config.EnableDistributedSharedSubnet || c.config.DistributedZone == c.config.DistributedGatewayOwner
}

func (c *Controller) isLocalNode(node string) bool {
	return c.config == nil || !c.config.EnableDistributedSharedSubnet || node == c.config.DistributedZone
}

func (c *Controller) validateDistributedNB() error {
	if !c.config.EnableDistributedSharedSubnet {
		return nil
	}
	global, err := c.OVNNbClient.GetNbGlobal()
	if err != nil {
		return fmt.Errorf("read distributed NB identity: %w", err)
	}
	if global == nil || global.Name != c.config.DistributedZone {
		return fmt.Errorf("local NB_Global.name must equal distributed zone %q", c.config.DistributedZone)
	}
	return nil
}

// reconcileDistributedFollowerSubnet only writes the local NB. Shared status,
// allocations, namespaces and router state belong to the gateway owner.
func (c *Controller) reconcileDistributedFollowerSubnet(subnet *kubeovnv1.Subnet) error {
	if err := c.ipam.AddOrUpdateSubnet(subnet.Name, subnet.Spec.CIDRBlock, subnet.Spec.Gateway, subnet.Spec.ExcludeIps); err != nil {
		return fmt.Errorf("restore local IPAM subnet %s: %w", subnet.Name, err)
	}
	if !isOvnSubnet(subnet) {
		return nil
	}
	vpc, err := c.vpcsLister.Get(subnet.Spec.Vpc)
	if err != nil {
		return err
	}
	if err := c.prepareDistributedSubnet(subnet, vpc, subnet.Spec.Gateway, "", false); err != nil {
		return err
	}
	if err := c.updateSubnetDHCPOption(subnet, false); err != nil {
		return err
	}
	if err := c.reconcileSubnetBaseACLs(subnet, vpc.Status.Router); err != nil {
		return err
	}
	acls := subnet.Spec.Acls
	if subnet.Spec.Routed {
		acls = nil
	}
	return c.OVNNbClient.UpdateLogicalSwitchACL(subnet.Name, subnet.Spec.CIDRBlock, acls, subnet.Spec.AllowEWTraffic && !subnet.Spec.Routed)
}

// Connected VPC routes carry distributed traffic. The legacy per-pod route
// path also mutates ports in a centralized NB, so it must not run here.
func (c *Controller) distributedPodRoutePatch(pod *corev1.Pod, nets []*kubeovnNet) util.KVPatch {
	patch := util.KVPatch{}
	for _, n := range nets {
		if isOvnSubnet(n.Subnet) && pod.Spec.NodeName != "" {
			patch[fmt.Sprintf(util.RoutedAnnotationTemplate, n.ProviderName)] = "true"
		}
	}
	return patch
}

func (c *Controller) distributedTransitSwitches(subnets []*kubeovnv1.Subnet) (map[string]bool, error) {
	names := make(map[string]bool)
	if !c.config.EnableDistributedSharedSubnet {
		return names, nil
	}
	for _, subnet := range subnets {
		if !isOvnSubnet(subnet) || subnet.Spec.Vlan != "" || subnet.Spec.CIDRBlock == "" {
			continue
		}
		vpc, err := c.vpcsLister.Get(subnet.Spec.Vpc)
		if err != nil {
			return nil, err
		}
		vpcUID := string(vpc.UID)
		if vpcUID == "" {
			vpcUID = vpc.Name
		}
		subnetUID := string(subnet.UID)
		if subnetUID == "" {
			subnetUID = subnet.Name
		}
		names[distributed.TransitSwitchName(vpcUID, subnetUID)] = true
	}
	return names, nil
}

// reconcileSubnetDHCPRows shares one critical section between Pod and Subnet
// workers: the NB lookup/create/lookup sequence must not create duplicate rows.
func (c *Controller) reconcileSubnetDHCPRows(subnet *kubeovnv1.Subnet) (*ovs.DHCPOptionsUUIDs, error) {
	mtu, err := c.getSubnetMTU(subnet)
	if err != nil {
		return nil, err
	}
	if c.config != nil && c.config.EnableDistributedSharedSubnet {
		c.distributedDHCPOptionsMu.Lock()
		defer c.distributedDHCPOptionsMu.Unlock()
	}
	return c.OVNNbClient.UpdateDHCPOptions(subnet, mtu)
}
