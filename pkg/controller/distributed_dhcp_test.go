package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kubeovnv1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	"github.com/kubeovn/kube-ovn/pkg/ovs"
)

func TestLocalSubnetDHCPOptionsUUIDsUsesZoneLocalRows(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "subnet-a", Spec: kubeovnv1.SubnetSpec{Mtu: 1500}}
	subnet.Status.DHCPv4OptionsUUID = "foreign-v4"
	fc := newFakeController(t)
	c := fc.fakeController
	c.config.EnableDistributedSharedSubnet = true
	local := &ovs.DHCPOptionsUUIDs{DHCPv4OptionsUUID: "local-v4"}
	fc.mockOvnClient.EXPECT().UpdateDHCPOptions(subnet, 1500).Return(local, nil)
	got, err := c.localSubnetDHCPOptionsUUIDs(subnet)
	require.NoError(t, err)
	require.Equal(t, local, got)
}

func TestLocalSubnetDHCPOptionsUUIDsNeverFallsBackToForeignStatus(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "subnet-a", Spec: kubeovnv1.SubnetSpec{Mtu: 1500}}
	subnet.Status.DHCPv4OptionsUUID = "foreign-v4"
	fc := newFakeController(t)
	c := fc.fakeController
	c.config.EnableDistributedSharedSubnet = true
	failure := errors.New("local NB unavailable")
	fc.mockOvnClient.EXPECT().UpdateDHCPOptions(subnet, 1500).Return(nil, failure)
	got, err := c.localSubnetDHCPOptionsUUIDs(subnet)
	require.ErrorIs(t, err, failure)
	require.Nil(t, got)
}

func TestDistributedFollowerDHCPDoesNotAccessLRPOrPublishStatus(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "subnet-a", Spec: kubeovnv1.SubnetSpec{Mtu: 1500, EnableIPv6RA: true}}
	subnet.Status.DHCPv4OptionsUUID = "foreign-v4"
	fc := newFakeController(t)
	c := fc.fakeController
	c.config.EnableDistributedSharedSubnet = true
	c.config.DistributedZone, c.config.DistributedGatewayOwner = "follower", "owner"
	fc.mockOvnClient.EXPECT().UpdateDHCPOptions(subnet, 1500).Return(&ovs.DHCPOptionsUUIDs{DHCPv4OptionsUUID: "local-v4"}, nil)
	require.NoError(t, c.updateSubnetDHCPOption(subnet, true))
	require.Equal(t, "foreign-v4", subnet.Status.DHCPv4OptionsUUID)
	require.NoError(t, c.reconcileSubnetBaseACLs(&kubeovnv1.Subnet{Spec: kubeovnv1.SubnetSpec{Routed: true}}, "router"))
}

func TestDistributedPodAndSubnetShareUniqueDHCPRows(t *testing.T) {
	subnet := &kubeovnv1.Subnet{Name: "subnet", Spec: kubeovnv1.SubnetSpec{Mtu: 1500}}
	fc := distributedController(t, nil, "follower")
	c := fc.fakeController
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	firstRead, releaseFirst, secondRead := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Uint32
	var fixtureMu sync.Mutex
	rows := 0
	fc.mockOvnClient.EXPECT().UpdateDHCPOptions(subnet, 1500).DoAndReturn(func(*kubeovnv1.Subnet, int) (*ovs.DHCPOptionsUUIDs, error) {
		call := calls.Add(1)
		fixtureMu.Lock()
		missing := rows == 0
		fixtureMu.Unlock()
		if call == 1 {
			close(firstRead)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			close(secondRead)
		}
		fixtureMu.Lock()
		defer fixtureMu.Unlock()
		if missing {
			rows++
		}
		if rows != 1 {
			return nil, fmt.Errorf("lookup found %d DHCP rows", rows)
		}
		return &ovs.DHCPOptionsUUIDs{DHCPv4OptionsUUID: "unique-local-row"}, nil
	}).Times(2)
	results := make(chan error, 2)
	go func() {
		options, err := c.localSubnetDHCPOptionsUUIDs(subnet)
		if err == nil && options.DHCPv4OptionsUUID != "unique-local-row" {
			err = errors.New("Pod attached an unexpected DHCP row")
		}
		results <- err
	}()
	select {
	case <-firstRead:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	subnetStarted := make(chan struct{})
	go func() { close(subnetStarted); results <- c.updateSubnetDHCPOption(subnet, false) }()
	<-subnetStarted
	select {
	case <-secondRead:
		t.Error("Subnet worker entered lookup/create before the Pod worker committed its row")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	for range 2 {
		select {
		case err := <-results:
			require.NoError(t, err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	fixtureMu.Lock()
	defer fixtureMu.Unlock()
	require.Equal(t, 1, rows)
}
