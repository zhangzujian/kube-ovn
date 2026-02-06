package ovs

import (
	"context"
	"fmt"

	"k8s.io/klog/v2"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/vswitch"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

// ListBridge lists ovs bridges
func (c *VswitchClient) ListBridge(needVendorFilter bool, filter func(sw *vswitch.Bridge) bool) ([]vswitch.Bridge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	var swList []vswitch.Bridge
	if err := c.ovsDbClient.WhereCache(func(sw *vswitch.Bridge) bool {
		if needVendorFilter && (len(sw.ExternalIDs) == 0 || sw.ExternalIDs[ExternalIDVendor] != util.CniTypeName) {
			return false
		}

		if filter != nil {
			return filter(sw)
		}

		return true
	}).List(ctx, &swList); err != nil {
		klog.Error(err)
		return nil, fmt.Errorf("failed to list bridge: %w", err)
	}

	return swList, nil
}
