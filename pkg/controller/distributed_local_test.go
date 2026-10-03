package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/puzpuzpuz/xsync/v4"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/keymutex"

	kubeovnv1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	"github.com/kubeovn/kube-ovn/pkg/controller/distributed"
	"github.com/kubeovn/kube-ovn/pkg/ovs"
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

func distributedController(t *testing.T, opts *FakeControllerOptions, zone string) *fakeController {
	t.Helper()
	fc, err := newFakeControllerWithOptions(t, opts)
	require.NoError(t, err)
	fc.fakeController.config.EnableDistributedSharedSubnet = true
	fc.fakeController.config.DistributedZone = zone
	fc.fakeController.config.DistributedGatewayOwner = "owner"
	return fc
}

func TestDistributedRemotePodNeverTouchesLocalPorts(t *testing.T) {
	for _, zone := range []string{"owner", "follower"} {
		t.Run(zone, func(t *testing.T) {
			pod := &corev1.Pod{Name: "pod", Namespace: "default", Spec: corev1.PodSpec{NodeName: "remote"}, Annotations: map[string]string{
				util.AllocatedAnnotation: "true", util.IPAddressAnnotation: "10.0.0.2", util.MacAddressAnnotation: "02:00:00:00:00:02",
			}}
			nets := []*kubeovnNet{{Type: providerTypeOriginal, ProviderName: util.OvnProvider, Subnet: &kubeovnv1.Subnet{Name: "subnet", Spec: kubeovnv1.SubnetSpec{Mtu: 1500}}}}
			fc := distributedController(t, nil, zone)
			c := fc.fakeController
			require.NoError(t, c.reconcileDistributedExistingPodPorts(pod, nets))
			require.NoError(t, c.reconcilePodDHCPOptions(pod, nets))
			got, details, err := c.syncKubeOvnNet(pod, nets)
			require.NoError(t, err)
			require.Same(t, pod, got)
			require.Empty(t, details)
		})
	}
}

func TestDistributedLocalPodRestartRebuildsPortsInEveryZone(t *testing.T) {
	for _, zone := range []string{"owner", "follower"} {
		for _, prior := range []string{"missing", "normal", "remote"} {
			t.Run(zone+"/"+prior, func(t *testing.T) {
				subnet := &kubeovnv1.Subnet{Name: "subnet", Spec: kubeovnv1.SubnetSpec{Provider: util.OvnProvider, Mtu: 1500}}
				pod := &corev1.Pod{Name: "pod", Namespace: "default", Spec: corev1.PodSpec{NodeName: zone}, Annotations: map[string]string{
					util.AllocatedAnnotation: "true", util.RoutedAnnotation: "true", util.IPAddressAnnotation: "10.0.0.2", util.MacAddressAnnotation: "02:00:00:00:00:02",
				}}
				fc := distributedController(t, nil, zone)
				c := fc.fakeController
				need, err := c.podNeedSync(pod)
				require.NoError(t, err)
				require.True(t, need)
				port := ovs.PodNameToPortName(pod.Name, pod.Namespace, util.OvnProvider)
				var existing *ovnnb.LogicalSwitchPort
				if prior != "missing" {
					existing = &ovnnb.LogicalSwitchPort{Name: port}
					if prior == "remote" {
						existing.Type = "remote"
						fc.mockOvnClient.EXPECT().DeleteLogicalSwitchPort(port).Return(nil)
					}
				}
				fc.mockOvnClient.EXPECT().GetLogicalSwitchPort(port, true).Return(existing, nil)
				options := &ovs.DHCPOptionsUUIDs{}
				fc.mockOvnClient.EXPECT().UpdateDHCPOptions(subnet, 1500).Return(options, nil)
				fc.mockOvnClient.EXPECT().ReconcilePortDHCPOptions("subnet", port, options, "", "", "", "", 1500).Return(options, false, nil)
				fc.mockOvnClient.EXPECT().CreateLogicalSwitchPort("subnet", port, "10.0.0.2", "02:00:00:00:00:02", "pod", "default", false, "", "", false, options, "").Return(nil)
				require.NoError(t, c.reconcileDistributedExistingPodPorts(pod, []*kubeovnNet{{Type: providerTypeOriginal, ProviderName: util.OvnProvider, Subnet: subnet}}))
			})
		}
	}
}

func TestDistributedFollowerWaitsForNodeAllocation(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "join", Spec: kubeovnv1.SubnetSpec{CIDRBlock: "10.0.0.0/24", Gateway: "10.0.0.1"}}
	fc := distributedController(t, &FakeControllerOptions{Subnets: []*kubeovnv1.Subnet{subnet}}, "follower")
	c := fc.fakeController
	require.NoError(t, c.ipam.AddOrUpdateSubnet("join", subnet.Spec.CIDRBlock, subnet.Spec.Gateway, nil))
	_, err := c.ensureNodeJoinNetwork(&corev1.Node{Name: "follower"})
	require.ErrorContains(t, err, "waiting for gateway owner")
	require.Empty(t, c.ipam.GetPodAddress(util.NodeLspName("follower")))
}

func TestDistributedOwnerAllocatesRemoteNodeWithoutLocalPort(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "join", Spec: kubeovnv1.SubnetSpec{CIDRBlock: "10.0.0.0/24", Gateway: "10.0.0.1"}}
	fc := distributedController(t, &FakeControllerOptions{Subnets: []*kubeovnv1.Subnet{subnet}}, "owner")
	c := fc.fakeController
	require.NoError(t, c.ipam.AddOrUpdateSubnet("join", subnet.Spec.CIDRBlock, subnet.Spec.Gateway, nil))
	join, err := c.ensureNodeJoinNetwork(&corev1.Node{Name: "remote"})
	require.NoError(t, err)
	require.NotEmpty(t, join.ip)
	require.Len(t, c.ipam.GetPodAddress(util.NodeLspName("remote")), 1)
}

func TestDistributedGCProtectsOnlyLiveTransitSwitches(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "subnet", UID: "subnet-uid", Spec: kubeovnv1.SubnetSpec{Vpc: "vpc", CIDRBlock: "10.0.0.0/24"}}
	vpc := &kubeovnv1.Vpc{Name: "vpc", UID: "vpc-uid"}
	fc := distributedController(t, &FakeControllerOptions{Subnets: []*kubeovnv1.Subnet{subnet}, Vpcs: []*kubeovnv1.Vpc{vpc}}, "owner")
	ts := distributed.TransitSwitchName(string(vpc.UID), string(subnet.UID))
	stale := distributed.TransitSwitchName(string(vpc.UID), "deleted-subnet")
	fc.mockOvnClient.EXPECT().ListLogicalSwitchNames(false, nil).Return([]string{"subnet", ts, stale}, nil)
	fc.mockOvnClient.EXPECT().LogicalSwitchExists(stale).Return(false, nil)
	require.NoError(t, fc.fakeController.gcLogicalSwitch())
}

func TestDistributedRejectsForeignNBIdentityBeforeWrites(t *testing.T) {
	fc := distributedController(t, nil, "follower")
	fc.mockOvnClient.EXPECT().GetNbGlobal().Return(&ovnnb.NBGlobal{Name: "central"}, nil)
	require.ErrorContains(t, fc.fakeController.validateDistributedNB(), "must equal distributed zone")
}

func TestDistributedNodeKeepSetContainsOnlyLocalPorts(t *testing.T) {
	fc := distributedController(t, nil, "follower")
	nodes := []*corev1.Node{{Name: "follower", Annotations: map[string]string{util.AllocatedAnnotation: "true"}}, {Name: "remote", Annotations: map[string]string{util.AllocatedAnnotation: "true"}}}
	kept := fc.fakeController.keepNodeLSPs(nodes, strset.New())
	require.Equal(t, map[string]string{util.NodeLspName("follower"): "follower"}, kept)
}

func TestDistributedOwnerDeletesRemotePodGlobalAllocationWithoutLocalPort(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "subnet", Spec: kubeovnv1.SubnetSpec{Vpc: "vpc", CIDRBlock: "10.0.0.0/24", Provider: util.OvnProvider}}
	pod := &corev1.Pod{Name: "pod", Namespace: "default", Spec: corev1.PodSpec{NodeName: "remote"}, Annotations: map[string]string{util.LogicalSwitchAnnotation: "subnet", util.AllocatedAnnotation: "true", util.IPAddressAnnotation: "10.0.0.2", util.MacAddressAnnotation: "02:00:00:00:00:02"}}
	port := ovs.PodNameToPortName("pod", "default", util.OvnProvider)
	ip := &kubeovnv1.IP{Name: port, Spec: kubeovnv1.IPSpec{PodName: "pod", Namespace: "default", NodeName: "remote", Subnet: "subnet", IPAddress: "10.0.0.2"}}
	fc := distributedController(t, &FakeControllerOptions{Subnets: []*kubeovnv1.Subnet{subnet}, IPs: []*kubeovnv1.IP{ip}}, "owner")
	c := fc.fakeController
	c.podKeyMutex = keymutex.NewHashed(0)
	c.deletingPodObjMap = xsync.NewMap[string, *corev1.Pod]()
	require.NoError(t, c.ipam.AddOrUpdateSubnet("subnet", subnet.Spec.CIDRBlock, "10.0.0.1", nil))
	mac := pod.Annotations[util.MacAddressAnnotation]
	_, _, _, err := c.ipam.GetStaticAddress("default/pod", port, "10.0.0.2", &mac, "subnet", true)
	require.NoError(t, err)
	c.deletingPodObjMap.Store("default/pod", pod)
	fc.mockOvnClient.EXPECT().ListNormalLogicalSwitchPorts(true, gomock.Any()).Return(nil, nil)
	require.NoError(t, c.handleDeletePod("default/pod"))
	require.Empty(t, c.ipam.GetPodAddress("default/pod"))
	_, err = c.config.KubeOvnClient.KubeovnV1().IPs().Get(context.Background(), port, metav1.GetOptions{})
	require.Error(t, err)
}

func TestDistributedOwnerAllocatesRemotePodWithoutLocalPort(t *testing.T) {
	pod, subnet := podEventFixture()
	pod.Spec.NodeName = "remote"
	fc := distributedController(t, &FakeControllerOptions{Pods: []*corev1.Pod{pod}, Subnets: []*kubeovnv1.Subnet{subnet}}, "owner")
	c := fc.fakeController
	require.NoError(t, c.ipam.AddOrUpdateSubnet(subnet.Name, subnet.Spec.CIDRBlock, subnet.Spec.Gateway, nil))
	allocated, err := c.reconcileAllocateSubnets(pod, []*kubeovnNet{{Type: providerTypeOriginal, ProviderName: util.OvnProvider, Subnet: subnet, IsDefault: true}})
	require.NoError(t, err)
	require.Equal(t, "true", allocated.Annotations[util.AllocatedAnnotation])
	require.NotEmpty(t, allocated.Annotations[util.IPAddressAnnotation])
	port := ovs.PodNameToPortName(pod.Name, pod.Namespace, util.OvnProvider)
	ip, err := c.config.KubeOvnClient.KubeovnV1().IPs().Get(context.Background(), port, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, allocated.Annotations[util.IPAddressAnnotation], ip.Spec.IPAddress)
}

func TestDistributedFollowerSubnetHandlerOnlyRendersLocalState(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "subnet", UID: "subnet-uid", Spec: kubeovnv1.SubnetSpec{Vpc: "vpc", CIDRBlock: "10.0.0.0/24", Gateway: "10.0.0.1", Mtu: 1500, Routed: true, EnableIPv6RA: true}}
	vpc := &kubeovnv1.Vpc{Name: "vpc", UID: "vpc-uid", Status: kubeovnv1.VpcStatus{Router: "vpc"}}
	fc := distributedController(t, &FakeControllerOptions{Subnets: []*kubeovnv1.Subnet{subnet}, Vpcs: []*kubeovnv1.Vpc{vpc}}, "follower")
	c := fc.fakeController
	c.subnetKeyMutex = keymutex.NewHashed(0)
	fixture := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(fixture, ovs.OVNIcNbCtl), []byte("#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n"), 0o700))
	t.Setenv("PATH", fixture+string(os.PathListSeparator)+os.Getenv("PATH"))
	c.distributedICClient = &ovs.LegacyClient{OvnTimeout: 1, OvnICNbAddress: "tcp:127.0.0.1:16641"}
	fc.mockOvnClient.EXPECT().CreateBareLogicalSwitch("subnet").Return(nil).Times(2)
	fc.mockOvnClient.EXPECT().CreateLogicalSwitchSwitchPort(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(2)
	fc.mockOvnClient.EXPECT().UpdateDHCPOptions(gomock.Any(), 1500).Return(&ovs.DHCPOptionsUUIDs{DHCPv4OptionsUUID: "local-row"}, nil)
	fc.mockOvnClient.EXPECT().UpdateLogicalSwitchACL("subnet", "10.0.0.0/24", nil, false).Return(nil)
	require.NoError(t, c.handleAddOrUpdateSubnet("subnet"))
}

func TestDistributedPodInspectionPreservesGlobalAllocation(t *testing.T) {
	for _, tc := range []struct {
		zone, node, portType string
		local                bool
	}{
		{zone: "owner", node: "remote"},
		{zone: "follower", node: "follower", local: true},
		{zone: "owner", node: "owner", local: true},
		{zone: "follower", node: "follower", portType: "remote", local: true},
	} {
		t.Run(tc.zone+"/"+tc.node+"/"+tc.portType, func(t *testing.T) {
			subnet := &kubeovnv1.Subnet{Name: "subnet", Spec: kubeovnv1.SubnetSpec{Provider: util.OvnProvider}}
			pod := &corev1.Pod{Name: "pod", Namespace: "default", Spec: corev1.PodSpec{NodeName: tc.node}, Annotations: map[string]string{
				util.LogicalSwitchAnnotation: "subnet", util.AllocatedAnnotation: "true", util.RoutedAnnotation: "true", util.IPAddressAnnotation: "10.0.0.2", util.MacAddressAnnotation: "02:00:00:00:00:02",
			}}
			fc := distributedController(t, &FakeControllerOptions{Pods: []*corev1.Pod{pod}, Subnets: []*kubeovnv1.Subnet{subnet}}, tc.zone)
			queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
			fc.fakeController.addOrUpdatePodQueue = queue
			t.Cleanup(queue.ShutDown)
			if tc.local {
				var port *ovnnb.LogicalSwitchPort
				if tc.portType != "" {
					port = &ovnnb.LogicalSwitchPort{Type: tc.portType}
				}
				fc.mockOvnClient.EXPECT().GetLogicalSwitchPort(ovs.PodNameToPortName("pod", "default", util.OvnProvider), true).Return(port, nil)
			}
			require.NoError(t, fc.fakeController.inspectPod())
			require.Equal(t, map[bool]int{false: 0, true: 1}[tc.local], fc.fakeController.addOrUpdatePodQueue.Len())
			current, err := fc.kubeClient.CoreV1().Pods("default").Get(t.Context(), "pod", metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, pod.Annotations, current.Annotations)
			for _, action := range fc.kubeClient.Actions() {
				require.NotEqual(t, "patch", action.GetVerb())
			}
		})
	}
}

func TestDistributedFollowerLearnsJoinSubnetBeforeStaticNodeRestore(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "join", UID: "join-uid", Spec: kubeovnv1.SubnetSpec{Vpc: "vpc", CIDRBlock: "10.0.0.0/24", Gateway: "10.0.0.1", ExcludeIps: []string{"10.0.0.1"}, Mtu: 1500, Routed: true}}
	vpc := &kubeovnv1.Vpc{Name: "vpc", UID: "vpc-uid", Status: kubeovnv1.VpcStatus{Router: "vpc"}}
	fc := distributedController(t, &FakeControllerOptions{Subnets: []*kubeovnv1.Subnet{subnet}, Vpcs: []*kubeovnv1.Vpc{vpc}}, "follower")
	c := fc.fakeController
	c.subnetKeyMutex = keymutex.NewHashed(0)
	fixture := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(fixture, ovs.OVNIcNbCtl), []byte("#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n"), 0o700))
	t.Setenv("PATH", fixture+string(os.PathListSeparator)+os.Getenv("PATH"))
	c.distributedICClient = &ovs.LegacyClient{OvnTimeout: 1, OvnICNbAddress: "tcp:127.0.0.1:16641"}
	require.Empty(t, c.ipam.Subnets)
	node := &corev1.Node{Name: "follower", Annotations: map[string]string{util.AllocatedAnnotation: "true", util.LogicalSwitchAnnotation: "join", util.IPAddressAnnotation: "10.0.0.2", util.MacAddressAnnotation: "02:00:00:00:00:02"}}
	_, err := c.ensureNodeJoinNetwork(node)
	require.ErrorContains(t, err, "NoSubnet")
	fc.mockOvnClient.EXPECT().CreateBareLogicalSwitch("join").Return(nil).Times(2)
	fc.mockOvnClient.EXPECT().CreateLogicalSwitchSwitchPort(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(2)
	fc.mockOvnClient.EXPECT().UpdateDHCPOptions(gomock.Any(), 1500).Return(&ovs.DHCPOptionsUUIDs{}, nil)
	fc.mockOvnClient.EXPECT().UpdateLogicalSwitchACL("join", "10.0.0.0/24", nil, false).Return(nil)
	require.NoError(t, c.handleAddOrUpdateSubnet("join"))
	fc.mockOvnClient.EXPECT().CreateBareLogicalSwitchPort("join", util.NodeLspName("follower"), "10.0.0.2", "02:00:00:00:00:02").Return(nil)
	network, err := c.ensureNodeJoinNetwork(node)
	require.NoError(t, err)
	require.Equal(t, "10.0.0.2", network.ip)
	require.Equal(t, "02:00:00:00:00:02", network.mac)
	require.Len(t, c.ipam.GetPodAddress(util.NodeLspName("follower")), 1)
}
