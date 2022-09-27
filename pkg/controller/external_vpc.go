package controller

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	v1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

func (c *Controller) syncExternalVpc() {
	lrTols, err := c.getExternalLogicalRoutersLogicalSwitchs()
	if err != nil {
		klog.Errorf("get external logical routers: %v", err)
		return
	}

	klog.V(4).Infof("sync external vpc %v", lrTols)

	vpcs, err := c.vpcsLister.List(labels.SelectorFromSet(labels.Set{util.VpcExternalLabel: "true"}))
	if err != nil {
		klog.Errorf("list external vpcs: %v", err)
		return
	}

	vpcMaps := make(map[string]*v1.Vpc)
	for _, vpc := range vpcs {
		vpcMaps[vpc.Name] = vpc.DeepCopy()
	}

	for vpcName, vpc := range vpcMaps {
		if lss, ok := lrTols[vpcName]; ok {
			vpc.Status.Subnets = lss

			_, err = c.config.KubeOvnClient.KubeovnV1().Vpcs().UpdateStatus(context.Background(), vpc, metav1.UpdateOptions{})
			if err != nil {
				klog.V(4).Infof("update vpc %s status", vpcName)
				continue
			}

			delete(lrTols, vpcName)
			klog.V(4).Infof("patch vpc %s", vpcName)
		} else {
			err = c.config.KubeOvnClient.KubeovnV1().Vpcs().Delete(context.Background(), vpcName, metav1.DeleteOptions{})
			if err != nil {
				klog.V(4).Infof("delete vpc %s failed", vpcName)
				continue
			}
			klog.V(4).Infof("delete vpc %s ", vpcName)
		}
	}

	if len(lrTols) == 0 { // no new logical router
		return
	}

	for lr, lss := range lrTols {
		klog.V(4).Infof("add vpc %s", lr)

		vpc := &v1.Vpc{
			ObjectMeta: metav1.ObjectMeta{
				Name:   lr,
				Labels: map[string]string{util.VpcExternalLabel: "true"},
			},
		}

		vpc, err = c.config.KubeOvnClient.KubeovnV1().Vpcs().Create(context.Background(), vpc, metav1.CreateOptions{})
		if err != nil {
			klog.Errorf("init vpc %s: %v", lr, err)
			return
		}

		vpc.Status.Subnets = lss
		vpc.Status.DefaultLogicalSwitch = ""
		vpc.Status.Router = lr
		vpc.Status.Standby = true
		vpc.Status.Default = false

		_, err = c.config.KubeOvnClient.KubeovnV1().Vpcs().UpdateStatus(context.Background(), vpc, metav1.UpdateOptions{})
		if err != nil {
			klog.Errorf("update vpc %s status %v", lr, err)
			return
		}
	}
}

// getExternalLogicalRoutersLogicalSwitchs get logical switchs in external logical router,
// result is map with key is logical router name and value is logical switchs name
func (c *Controller) getExternalLogicalRoutersLogicalSwitchs() (result map[string][]string, err error) {
	result = make(map[string][]string)

	lrToLrps, err := c.getLogicalRoutersPorts()
	if err != nil {
		return nil, fmt.Errorf("get logical router ports: %v", err)
	}

	if len(lrToLrps) == 0 {
		return nil, nil // no external logical router
	}

	lrpToLs, err := c.getLogicalSwitchsPatchPorts()
	if err != nil {
		return nil, fmt.Errorf("get logical switch patch port: %v", err)
	}

	for lr, lrps := range lrToLrps {
		result[lr] = getlogicalRouterLogicalSwitchs(lrps, lrpToLs)
	}

	return result, nil
}

// getLogicalRoutersPorts get ports name which belongs to lrs,
// result is map with key is lrName and value is port name
func (c *Controller) getLogicalRoutersPorts() (result map[string][]string, err error) {
	result = make(map[string][]string)

	lrs, err := c.ovnClient.ListLogicalRouter(false, func(lr *ovnnb.LogicalRouter) bool {
		return len(lr.ExternalIDs) == 0 || lr.ExternalIDs["vendor"] != util.CniTypeName
	})
	if err != nil {
		return nil, fmt.Errorf("list external logical routers: %v", err)
	}

	for _, lr := range lrs {
		ports, err := c.getLogicalRouterPorts(&lr)
		if err != nil {
			return nil, fmt.Errorf("get logical router %s ports: %v", lr.Name, err)
		}
		result[lr.Name] = ports
	}

	return result, nil
}

// getLogicalSwitchsPatchPorts get ports name which belongs to lss and type is router
// result is map with key is peer logical router port name and value is lsName
func (c *Controller) getLogicalSwitchsPatchPorts() (result map[string]string, err error) {
	result = make(map[string]string)

	lss, err := c.ovnClient.ListLogicalSwitch(false, func(ls *ovnnb.LogicalSwitch) bool {
		return len(ls.ExternalIDs) == 0 || ls.ExternalIDs["vendor"] != util.CniTypeName
	})
	if err != nil {
		return nil, fmt.Errorf("list external logical switchs: %v", err)
	}

	for _, ls := range lss {
		peerPort, err := c.getLogicalSwitchPatchPorts(&ls)
		if err != nil {
			return nil, fmt.Errorf("get logical switch %s peer router port: %v", ls.Name, err)
		}
		result[peerPort] = ls.Name
	}

	return result, nil
}

// getlogicalRouterLogicalSwitchs get logical switchs in logical router
func getlogicalRouterLogicalSwitchs(lrps []string, lrpToLs map[string]string) (result []string) {
	result = make([]string, 0, len(lrps))

	for _, lrp := range lrps {
		if ls, ok := lrpToLs[lrp]; ok {
			result = append(result, ls)
		}
	}

	return result
}

// getLogicalRouterPorts get ports name which belongs to lr
func (c *Controller) getLogicalRouterPorts(lr *ovnnb.LogicalRouter) (result []string, err error) {
	if lr == nil {
		return nil, fmt.Errorf("logical router is nil")
	}

	if lr == nil || len(lr.Ports) == 0 {
		return nil, fmt.Errorf("logical router %s has no ports", lr.Name)
	}

	lrpNames := make([]string, 0, len(lr.Ports))
	for _, portUUID := range lr.Ports {
		lrp := &ovnnb.LogicalRouterPort{UUID: portUUID}
		if err := c.ovnClient.GetEntityInfo(lrp); err != nil {
			return nil, fmt.Errorf("get logical router port name by UUID: %v", err)
		}

		lrpNames = append(lrpNames, lrp.Name)
	}

	return lrpNames, nil
}

// getLogicalSwitchPorts get ports name which belongs to ls and type is router
func (c *Controller) getLogicalSwitchPatchPorts(ls *ovnnb.LogicalSwitch) (string, error) {
	if ls == nil {
		return "", fmt.Errorf("logical switch is nil")
	}

	if ls == nil || len(ls.Ports) == 0 {
		return "", fmt.Errorf("logical switch %s has no ports", ls.Name)
	}

	for _, portUUID := range ls.Ports {
		lsp := &ovnnb.LogicalSwitchPort{UUID: portUUID}
		if err := c.ovnClient.GetEntityInfo(lsp); err != nil {
			return "", fmt.Errorf("get logical router port name by UUID: %v", err)
		}

		if lsp.Type == "router" && len(lsp.Options) != 0 && len(lsp.Options["router-port"]) != 0 {
			return lsp.Options["router-port"], nil // one logical switch has only one patch port
		}
	}

	return "", nil
}
