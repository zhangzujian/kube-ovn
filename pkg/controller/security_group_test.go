package controller

import (
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/kubeovn/kube-ovn/pkg/ovs"
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
)

func Test_getPortSg(t *testing.T) {
	mockLsp := func() *ovnnb.LogicalSwitchPort {
		return &ovnnb.LogicalSwitchPort{
			ExternalIDs: map[string]string{
				"associated_sg_default-securitygroup": "false",
				"associated_sg_sg":                    "true",
				"security_groups":                     "sg",
			},
		}
	}

	t.Run("only have one sg", func(t *testing.T) {
		port := mockLsp()
		out, err := getPortSg(port)
		require.NoError(t, err)
		require.Equal(t, []string{"sg"}, out)
	})

	t.Run("have two and more sgs", func(t *testing.T) {
		port := mockLsp()
		port.ExternalIDs["associated_sg_default-securitygroup"] = "true"
		out, err := getPortSg(port)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"sg", "default-securitygroup"}, out)
	})
}

func Test_securityGroupALLNotExist(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient

	sgName := "sg"
	pgName := ovs.GetSgPortGroupName(sgName)

	t.Run("should return false when some port group exist", func(t *testing.T) {
		mockOvnClient.EXPECT().PortGroupExists(pgName).Return(true, nil)

		allNotExist, err := ctrl.securityGroupALLNotExist([]string{sgName, "sg1", "sg2", "sg3"})
		require.NoError(t, err)
		require.False(t, allNotExist)
	})

	t.Run("should return true when all port group does't exist", func(t *testing.T) {
		mockOvnClient.EXPECT().PortGroupExists(gomock.Any()).Return(false, nil).Times(3)

		allNotExist, err := ctrl.securityGroupALLNotExist([]string{"sg1", "sg2", "sg3"})
		require.NoError(t, err)
		require.True(t, allNotExist)
	})

	t.Run("should return true when sgs is empty", func(t *testing.T) {
		allNotExist, err := ctrl.securityGroupALLNotExist([]string{})
		require.NoError(t, err)
		require.True(t, allNotExist)
	})
}

func Test_getSecurityGroupPortsInfo(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient

	sgName := "sg"
	lspNamePrefix := "get-sg-port-info-lsp"

	mockLsp := func(lspName string, addresses []string) ovnnb.LogicalSwitchPort {
		return ovnnb.LogicalSwitchPort{
			Name:         lspName,
			PortSecurity: []string{strings.Join(addresses, " ")},
			ExternalIDs: map[string]string{
				fmt.Sprintf("%s%s", associatedSgKeyPrefix, sgName): "true",
				sgsKey: sgName,
			},
		}
	}

	lsps := []ovnnb.LogicalSwitchPort{
		mockLsp(lspNamePrefix+"-0", []string{"00:00:00:15:3F:16", "10.244.0.8", "fc00::af4:8"}),
		mockLsp(lspNamePrefix+"-1", []string{"00:00:00:44:CD:CA", "192.168.200.2"}),
		mockLsp(lspNamePrefix+"-2", []string{"00:00:00:22:4C:35", "fd00::af4:8"}),
		mockLsp(lspNamePrefix+"-3", []string{"00:00:00:11:22:33"}),
	}

	mockOvnClient.EXPECT().ListNormalLogicalSwitchPorts(true, map[string]string{
		fmt.Sprintf("%s%s", associatedSgKeyPrefix, sgName): "true",
	}).Return(lsps, nil)

	out, err := ctrl.getSecurityGroupPortsInfo(sgName)
	require.NoError(t, err)
	require.Equal(t, &portsInfo{
		[]string{lspNamePrefix + "-0", lspNamePrefix + "-1", lspNamePrefix + "-2"},
		[]string{"10.244.0.8", "192.168.200.2"},
		[]string{"fc00::af4:8", "fd00::af4:8"},
	}, out)
}
