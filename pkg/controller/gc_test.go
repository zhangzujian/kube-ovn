package controller

import (
	"fmt"
	"testing"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
	"github.com/stretchr/testify/require"
)

func newLogicalRouterPort(lrName, lrpName, mac string, networks []string) *ovnnb.LogicalRouterPort {
	return &ovnnb.LogicalRouterPort{
		Name:     lrpName,
		MAC:      mac,
		Networks: networks,
		ExternalIDs: map[string]string{
			"lr": lrName,
		},
	}
}

func Test_logicalRouterPortFilter(t *testing.T) {
	t.Parallel()

	exceptPeerPorts := map[string]struct{}{
		"except-lrp-0": {},
		"except-lrp-1": {},
	}

	lrpNames := []string{"other-0", "other-1", "other-2", "except-lrp-0", "except-lrp-1"}
	lrps := make([]*ovnnb.LogicalRouterPort, 0)
	for _, lrpName := range lrpNames {
		lrp := newLogicalRouterPort("", lrpName, "", nil)
		peer := fmt.Sprintf("%s-peer", lrpName)
		lrp.Peer = &peer
		lrps = append(lrps, lrp)
	}

	filterFunc := logicalRouterPortFilter(exceptPeerPorts)

	for _, lrp := range lrps {
		if _, ok := exceptPeerPorts[lrp.Name]; ok {
			require.False(t, filterFunc(lrp))
		} else {
			require.True(t, filterFunc(lrp))
		}
	}
}

func Test_deleteServiceNonExistVips(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient
	lbNamePrefix := "del-svc-non-existent-vips"

	mocklb := func(lbName string, vips map[string]string) *ovnnb.LoadBalancer {
		return &ovnnb.LoadBalancer{
			Name: lbName,
			Vips: vips,
		}
	}

	lbs := []*ovnnb.LoadBalancer{
		mocklb(lbNamePrefix+"-0", map[string]string{
			"10.100.185.113:10660": "192.168.20.4:10660",
			"10.96.0.10:53":        "10.244.0.7:53,10.244.0.8:53",
			"10.96.0.100:53":       "10.244.0.99:53,10.244.0.100:53",
		}),
		mocklb(lbNamePrefix+"-1", map[string]string{
			"10.96.0.1:443":       "192.168.20.3:6443",
			"10.110.41.165:10661": "192.168.20.3:10661",
			"10.110.41.201:10661": "192.168.20.3:10663",
		}),
	}

	t.Run("normal gc lbs", func(t *testing.T) {
		lbNames := make([]string, 0, 2)

		servicVips := map[string]struct{}{
			"10.100.185.113:10660": {},
			"10.96.0.10:53":        {},
			"10.96.0.1:443":        {},
			"10.110.41.165:10661":  {},
		}

		for _, lb := range lbs {
			lbNames = append(lbNames, lb.Name)
			mockOvnClient.EXPECT().GetLoadBalancer(lb.Name, false).Return(lb, nil)

			deleteVips := make(map[string]struct{}, 0)
			for vip := range lb.Vips {
				if _, ok := servicVips[vip]; ok {
					continue // ignore
				}

				deleteVips[vip] = struct{}{}
			}
			mockOvnClient.EXPECT().LoadBalancerDeleteVips(lb.Name, deleteVips).Return(nil)
		}

		err := ctrl.deleteServiceNonExistVips(lbNames, servicVips)
		require.NoError(t, err)
	})

	t.Run("no lbs need to be deleted", func(t *testing.T) {
		lbNames := make([]string, 0, 2)

		servicVips := map[string]struct{}{
			"10.100.185.113:10660": {},
			"10.96.0.10:53":        {},
			"10.96.0.1:443":        {},
			"10.110.41.165:10661":  {},
			"10.96.0.100:53":       {},
			"10.110.41.201:10661":  {},
		}

		for _, lb := range lbs {
			lbNames = append(lbNames, lb.Name)
			mockOvnClient.EXPECT().GetLoadBalancer(lb.Name, false).Return(lb, nil)
		}

		err := ctrl.deleteServiceNonExistVips(lbNames, servicVips)
		require.NoError(t, err)
	})
}
