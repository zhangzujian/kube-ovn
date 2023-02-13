package controller

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/kubeovn/kube-ovn/pkg/ipam"
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

func Test_deletePolicyRouteByNexthop(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient

	ctrl.config = &Configuration{
		ClusterRouter: "ovn-cluster",
	}

	addresses := []*ipam.SubnetAddress{
		{
			Ip: "100.64.0.2",
		},
		{
			Ip: "fd00:100:64::2",
		},
	}

	policies := []ovnnb.LogicalRouterPolicy{
		{
			Priority: util.NodeRouterPolicyPriority,
			Match:    "ip4.dst == 192.168.20.5",
			Nexthops: []string{
				"100.64.0.2",
			},
		},
		{
			Priority: util.NodeRouterPolicyPriority,
			Match:    "ip6.dst == fc00::af4:5",
			Nexthops: []string{
				"fd00:100:64::2",
			},
		},
		{
			Priority: util.NodeRouterPolicyPriority,
			Match:    "ip4.dst == 192.168.20.6",
			Nexthops: []string{
				"100.64.0.3",
			},
		},
	}

	mockOvnClient.EXPECT().ListLogicalRouterPolicies(util.NodeRouterPolicyPriority, gomock.Any()).Return(policies, nil)
	mockOvnClient.EXPECT().DeleteLogicalRouterPolicy("ovn-cluster", util.NodeRouterPolicyPriority, "ip4.dst == 192.168.20.5").Return(nil)
	mockOvnClient.EXPECT().DeleteLogicalRouterPolicy("ovn-cluster", util.NodeRouterPolicyPriority, "ip6.dst == fc00::af4:5").Return(nil)

	err := ctrl.deletePolicyRouteByNexthop(addresses)
	require.NoError(t, err)
}
