package ovs

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/stretchr/testify/require"

	ovsclient "github.com/kubeovn/kube-ovn/pkg/ovsdb/client"
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

func (suite *OvnClientTestSuite) testCreateLogicalSwitchPort() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	failedNbClient := suite.faiedOvnNBClient
	lsName := "test-create-lsp-ls"
	ips := "10.244.0.37,fc00::af4:25"
	mac := "00:00:00:AB:B4:65"
	vips := "10.244.0.110,10.244.0.112"
	podName := "test-create-lsp-pod"
	podNamespace := "test-create-lsp-ns"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateDHCPOptions(lsName, "10.244.0.0/16", "")
	require.NoError(t, err)
	err = nbClient.CreateDHCPOptions(lsName, "fc00::/64", "")
	require.NoError(t, err)
	dhcpOptions, err := nbClient.ListDHCPOptions(true, map[string]string{logicalSwitchKey: lsName})
	require.NoError(t, err)
	require.Len(t, dhcpOptions, 2)

	dhcpUUIDs := &DHCPOptionsUUIDs{
		DHCPv4OptionsUUID: dhcpOptions[0].UUID,
		DHCPv6OptionsUUID: dhcpOptions[1].UUID,
	}

	t.Run("create logical switch port", func(t *testing.T) {
		lspName := "test-create-lsp-lsp"
		sgs := "sg,sg1"
		vpcName := "test-vpc"

		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, true, sgs, vips, true, dhcpUUIDs, vpcName)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25"}, lsp.Addresses)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25 10.244.0.110 10.244.0.112"}, lsp.PortSecurity)
		require.Equal(t, map[string]string{
			sgsKey:              strings.ReplaceAll(sgs, ",", "/"),
			"associated_sg_sg":  "true",
			"associated_sg_sg1": "true",
			"associated_sg_" + util.DefaultSecurityGroupName: "false",
			"vips":        vips,
			"attach-vips": "true",
			"pod":         fmt.Sprintf("%s/%s", podNamespace, podName),
			"ls":          lsName,
			"vendor":      util.CniTypeName,
		}, lsp.ExternalIDs)
		require.Equal(t, dhcpUUIDs.DHCPv4OptionsUUID, *lsp.Dhcpv4Options)
		require.Equal(t, dhcpUUIDs.DHCPv6OptionsUUID, *lsp.Dhcpv6Options)
	})

	t.Run("create logical switch port without vips", func(t *testing.T) {
		lspName := "test-create-lsp-lsp-no-vip"
		sgs := "sg,sg1"
		vpcName := "test-vpc"

		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, true, sgs, "", true, dhcpUUIDs, vpcName)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25"}, lsp.Addresses)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25"}, lsp.PortSecurity)
		require.Equal(t, map[string]string{
			sgsKey:              strings.ReplaceAll(sgs, ",", "/"),
			"associated_sg_sg":  "true",
			"associated_sg_sg1": "true",
			"associated_sg_" + util.DefaultSecurityGroupName: "false",
			"pod":    fmt.Sprintf("%s/%s", podNamespace, podName),
			"ls":     lsName,
			"vendor": util.CniTypeName,
		}, lsp.ExternalIDs)
		require.Equal(t, dhcpUUIDs.DHCPv4OptionsUUID, *lsp.Dhcpv4Options)
		require.Equal(t, dhcpUUIDs.DHCPv6OptionsUUID, *lsp.Dhcpv6Options)
	})

	t.Run("create logical switch port with default-securitygroup", func(t *testing.T) {
		lspName := "test-create-lsp-lsp-default-sg"
		sgs := "sg,sg1,default-securitygroup"
		vpcName := "test-vpc"

		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, true, sgs, vips, true, dhcpUUIDs, vpcName)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25"}, lsp.Addresses)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25 10.244.0.110 10.244.0.112"}, lsp.PortSecurity)
		require.Equal(t, map[string]string{
			sgsKey:              strings.ReplaceAll(sgs, ",", "/"),
			"associated_sg_sg":  "true",
			"associated_sg_sg1": "true",
			"associated_sg_" + util.DefaultSecurityGroupName: "true",
			"pod":         fmt.Sprintf("%s/%s", podNamespace, podName),
			"ls":          lsName,
			"vendor":      util.CniTypeName,
			"vips":        vips,
			"attach-vips": "true",
		}, lsp.ExternalIDs)
		require.Equal(t, dhcpUUIDs.DHCPv4OptionsUUID, *lsp.Dhcpv4Options)
		require.Equal(t, dhcpUUIDs.DHCPv6OptionsUUID, *lsp.Dhcpv6Options)
	})

	t.Run("create logical switch port in default vpc with sg", func(t *testing.T) {
		lspName := "test-create-lsp-lsp-in-default-vpc-with-sg"
		sgs := "sg,sg1"
		vpcName := "ovn-cluster"

		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, true, sgs, vips, true, dhcpUUIDs, vpcName)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25"}, lsp.Addresses)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25 10.244.0.110 10.244.0.112"}, lsp.PortSecurity)
		require.Equal(t, map[string]string{
			sgsKey:              strings.ReplaceAll(sgs, ",", "/"),
			"associated_sg_sg":  "true",
			"associated_sg_sg1": "true",
			"pod":               fmt.Sprintf("%s/%s", podNamespace, podName),
			"ls":                lsName,
			"vendor":            util.CniTypeName,
			"vips":              vips,
			"attach-vips":       "true",
		}, lsp.ExternalIDs)
		require.Equal(t, dhcpUUIDs.DHCPv4OptionsUUID, *lsp.Dhcpv4Options)
		require.Equal(t, dhcpUUIDs.DHCPv6OptionsUUID, *lsp.Dhcpv6Options)
	})

	t.Run("create logical switch port with portSecurity=false and sg", func(t *testing.T) {
		lspName := "test-create-lsp-lsp-no-port-security"
		sgs := "sg,sg1"
		vpcName := "test-vpc"

		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, false, sgs, vips, true, dhcpUUIDs, vpcName)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25"}, lsp.Addresses)
		require.Equal(t, map[string]string{
			"associated_sg_" + util.DefaultSecurityGroupName: "false",
			"associated_sg_sg":  "true",
			"associated_sg_sg1": "true",
			"pod":               fmt.Sprintf("%s/%s", podNamespace, podName),
			"security_groups":   "sg/sg1",
			"ls":                lsName,
			"vendor":            util.CniTypeName,
			"vips":              vips,
			"attach-vips":       "true",
		}, lsp.ExternalIDs)
		require.Equal(t, dhcpUUIDs.DHCPv4OptionsUUID, *lsp.Dhcpv4Options)
		require.Equal(t, dhcpUUIDs.DHCPv6OptionsUUID, *lsp.Dhcpv6Options)
	})

	t.Run("create logical switch port without dhcp options", func(t *testing.T) {
		lspName := "test-create-lsp-lsp-no-dhcp-options"
		sgs := "sg,sg1"
		vpcName := "test-vpc"

		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, true, sgs, vips, true, nil, vpcName)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25"}, lsp.Addresses)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25 10.244.0.110 10.244.0.112"}, lsp.PortSecurity)
		require.Equal(t, map[string]string{
			sgsKey:              strings.ReplaceAll(sgs, ",", "/"),
			"associated_sg_sg":  "true",
			"associated_sg_sg1": "true",
			"associated_sg_" + util.DefaultSecurityGroupName: "false",
			"vips":        vips,
			"attach-vips": "true",
			"pod":         fmt.Sprintf("%s/%s", podNamespace, podName),
			"ls":          lsName,
			"vendor":      util.CniTypeName,
		}, lsp.ExternalIDs)
		require.Empty(t, lsp.Dhcpv4Options)
		require.Empty(t, lsp.Dhcpv6Options)
	})

	t.Run("create existing logical switch port in one logical switch", func(t *testing.T) {
		lspName := "test-create-lsp-lsp-exist"
		sgs := "sg,sg1,default-securitygroup"
		vpcName := "test-vpc"

		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, true, sgs, vips, true, dhcpUUIDs, vpcName)
		require.NoError(t, err)
		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, true, sgs, vips, true, dhcpUUIDs, vpcName)
		require.NoError(t, err)
	})

	t.Run("create existing logical switch port in other logical switch", func(t *testing.T) {
		lsName2 := "test-create-lsp-ls2"
		err := nbClient.CreateBareLogicalSwitch(lsName2)
		require.NoError(t, err)

		lspName := "test-create-lsp-lsp-default-sg"
		sgs := "sg,sg1,default-securitygroup"
		vpcName := "test-vpc"

		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, true, sgs, vips, true, dhcpUUIDs, vpcName)
		require.NoError(t, err)
		err = nbClient.CreateLogicalSwitchPort(lsName2, lspName, ips, mac, podName, podNamespace, true, sgs, vips, true, dhcpUUIDs, vpcName)
		require.NoError(t, err)
	})

	t.Run("create logical switch port op error", func(t *testing.T) {
		lspName := "create logical switch port op"
		sgs := "sg,sg1"
		vpcName := "test-vpc"

		err = failedNbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, podName, podNamespace, true, sgs, vips, true, nil, vpcName)
		require.Error(t, err)
	})
}

func (suite *OvnClientTestSuite) testCreateLocalnetLogicalSwitchPort() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lspName := "test-create-localnet-port-lsp"
	lsName := "test-create-localnet-port-ls"
	provider := "external"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	t.Run("create localnet logical switch port with vlan id", func(t *testing.T) {
		err = nbClient.CreateLocalnetLogicalSwitchPort(lsName, lspName, provider, "192.168.0.0/24,fd00::/120", 200)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.Equal(t, lspName, lsp.Name)
		require.Equal(t, "localnet", lsp.Type)
		require.ElementsMatch(t, []string{"unknown"}, lsp.Addresses)
		require.Equal(t, map[string]string{
			"network_name": provider,
		}, lsp.Options)
		require.Equal(t, "192.168.0.0/24", lsp.ExternalIDs["ipv4_network"])
		require.Equal(t, "fd00::/120", lsp.ExternalIDs["ipv6_network"])
		require.NotNil(t, lsp.Tag)
		require.Equal(t, 200, *lsp.Tag)
	})

	t.Run("create localnet logical switch port without vlan id", func(t *testing.T) {
		lspName := "test-create-localnet-port-lsp-no-vlan-id"
		err = nbClient.CreateLocalnetLogicalSwitchPort(lsName, lspName, provider, "192.168.1.0/24,fd01::/120", 0)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.Equal(t, lspName, lsp.Name)
		require.Equal(t, "localnet", lsp.Type)
		require.ElementsMatch(t, []string{"unknown"}, lsp.Addresses)
		require.Equal(t, map[string]string{
			"network_name": provider,
		}, lsp.Options)
		require.Equal(t, "192.168.1.0/24", lsp.ExternalIDs["ipv4_network"])
		require.Equal(t, "fd01::/120", lsp.ExternalIDs["ipv6_network"])
		require.Nil(t, lsp.Tag)
	})

	t.Run("should no err when create logical switch port repeatedly", func(t *testing.T) {
		err = nbClient.CreateLocalnetLogicalSwitchPort(lsName, lspName, "external", "192.168.2.0/24,fd02::/120", 0)
		require.NoError(t, err)
	})

	t.Run("should print err log when logical switch does not exist", func(t *testing.T) {
		err = nbClient.CreateLocalnetLogicalSwitchPort("", "", "", "", 0)
		require.Error(t, err)
	})
}

func (suite *OvnClientTestSuite) testCreateVirtualLogicalSwitchPorts() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-create-virtual-port-ls"
	vips := []string{"192.168.33.10", "192.168.33.12"}

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	t.Run("create virtual logical switch port", func(t *testing.T) {
		err = nbClient.CreateVirtualLogicalSwitchPorts(lsName, vips...)
		require.NoError(t, err)
		for _, ip := range vips {
			lspName := fmt.Sprintf("%s-vip-%s", lsName, ip)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.Equal(t, lspName, lsp.Name)
			require.Equal(t, "virtual", lsp.Type)
			require.Equal(t, map[string]string{
				"virtual-ip": ip,
			}, lsp.Options)
		}
	})

	t.Run("should no err when create logical switch port repeatedly", func(t *testing.T) {
		err = nbClient.CreateVirtualLogicalSwitchPorts(lsName, vips...)
		require.NoError(t, err)
		err = nbClient.CreateVirtualLogicalSwitchPorts(lsName, vips...)
		require.NoError(t, err)
	})

	t.Run("should print err log when logical switch does not exist", func(t *testing.T) {
		err = nbClient.CreateVirtualLogicalSwitchPorts("", vips...)
		require.Error(t, err)
	})
}

func (suite *OvnClientTestSuite) testCreateVirtualLogicalSwitchPort() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lspName := "test-create-one-virtual-port-lsp"
	lsName := "test-create-one-virtual-port-ls"
	lsName2 := "test-create-one-virtual-port-ls2"
	vip := "192.168.33.10"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)
	err = nbClient.CreateBareLogicalSwitch(lsName2)
	require.NoError(t, err)

	t.Run("create virtual logical switch port", func(t *testing.T) {
		err = nbClient.CreateVirtualLogicalSwitchPort(lspName, lsName, vip)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.Equal(t, lspName, lsp.Name)
		require.Equal(t, "virtual", lsp.Type)
		require.Equal(t, map[string]string{
			"virtual-ip": vip,
		}, lsp.Options)
	})

	t.Run("should no err when create logical switch port repeatedly", func(t *testing.T) {
		err = nbClient.CreateVirtualLogicalSwitchPort(lspName, lsName, vip)
		require.NoError(t, err)
		err = nbClient.CreateVirtualLogicalSwitchPort(lspName, "test-create-virtual-port-ls2", vip)
		require.NoError(t, err)
	})

	t.Run("should print err log when logical switch port does not exit", func(t *testing.T) {
		err = nbClient.CreateVirtualLogicalSwitchPort("", "", "")
		require.Error(t, err)
	})
}

func (suite *OvnClientTestSuite) testCreateBareLogicalSwitchPort() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-create-bare-port-ls"
	lspName := "test-create-bare-port-lsp"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	t.Run("create bare logic switch port", func(t *testing.T) {
		err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "100.64.0.4,fd00:100:64::4", "00:00:00:C9:4E:EE")
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"00:00:00:C9:4E:EE 100.64.0.4 fd00:100:64::4"}, lsp.Addresses)

		ls, err := nbClient.GetLogicalSwitch(lsName, false)
		require.NoError(t, err)

		require.Contains(t, ls.Ports, lsp.UUID)
	})

	t.Run("create bare logic switch port repeatedly", func(t *testing.T) {
		err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "100.64.0.4,fd00:100:64::4", "00:00:00:C9:4E:EE")
		require.NoError(t, err)
		err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "100.64.0.4,fd00:100:64::4", "00:00:00:C9:4E:EE")
		require.NoError(t, err)
	})

	t.Run("should print err log when logical switch does not exist", func(t *testing.T) {
		err = nbClient.CreateBareLogicalSwitchPort("", "", "100.64.0.4,fd00:100:64::4", "00:00:00:C9:4E:EE")
		require.Error(t, err)
	})
}

func (suite *OvnClientTestSuite) testSetLogicalSwitchPortVirtualParents() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-update-port-virt-parents-ls"
	ips := []string{"192.168.211.31", "192.168.211.32"}

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateVirtualLogicalSwitchPorts(lsName, ips...)
	require.NoError(t, err)

	t.Run("set virtual-parents option", func(t *testing.T) {
		err = nbClient.SetLogicalSwitchPortVirtualParents(lsName, "virt-parents-ls-1,virt-parents-ls-2", ips...)
		require.NoError(t, err)
		for _, ip := range ips {
			lspName := fmt.Sprintf("%s-vip-%s", lsName, ip)
			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.Equal(t, "virt-parents-ls-1,virt-parents-ls-2", lsp.Options["virtual-parents"])
		}
	})

	t.Run("clear virtual-parents option", func(t *testing.T) {
		err = nbClient.SetLogicalSwitchPortVirtualParents(lsName, "", ips...)
		require.NoError(t, err)
		for _, ip := range ips {
			lspName := fmt.Sprintf("%s-vip-%s", lsName, ip)
			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.Empty(t, lsp.Options["virtual-parents"])
		}
	})
}

func (suite *OvnClientTestSuite) testSetVirtualLogicalSwitchPortVirtualParents() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-update-virtual-port-virt-parents-ls"
	ip := "192.168.211.31"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateVirtualLogicalSwitchPorts(lsName, ip)
	require.NoError(t, err)

	lspName := fmt.Sprintf("%s-vip-%s", lsName, ip)

	t.Run("set virtual-parents option", func(t *testing.T) {
		parents := "virt-parents-ls-1,virt-parents-ls-2"
		err = nbClient.SetVirtualLogicalSwitchPortVirtualParents(lspName, parents)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.Equal(t, parents, lsp.Options["virtual-parents"])
	})

	t.Run("clear virtual-parents option", func(t *testing.T) {
		parents := ""
		err = nbClient.SetVirtualLogicalSwitchPortVirtualParents(lspName, parents)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		_, exists := lsp.Options["virtual-parents"]
		require.False(t, exists)
	})
}

func (suite *OvnClientTestSuite) testSetLogicalSwitchPortArpProxy() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-set-lsp-arp-proxy-ls"
	ips := "10.244.0.37,fc00::af4:25"
	mac := "00:00:00:AB:B4:65"
	podNamespace := "test-ns"
	vpcName := "test-vpc"
	lspName := "test-set-lsp-arp-proxy-lsp"
	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	t.Run("create logical switch port", func(t *testing.T) {
		err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ips, mac, lspName, podNamespace, true, "", "", false, nil, vpcName)
		require.NoError(t, err)
	})

	t.Run("set arp_proxy option", func(t *testing.T) {
		enableArpProxy := true
		err = nbClient.SetLogicalSwitchPortArpProxy(lspName, enableArpProxy)
		require.NoError(t, err)
		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.Equal(t, "true", lsp.Options["arp_proxy"])
	})

	t.Run("clear arp_proxy option", func(t *testing.T) {
		enableArpProxy := false
		err = nbClient.SetLogicalSwitchPortArpProxy(lspName, enableArpProxy)
		require.NoError(t, err)
		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.Empty(t, lsp.Options["arp_proxy"])
	})
}

func (suite *OvnClientTestSuite) testSetLogicalSwitchPortSecurity() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-update-port-security-ls"
	lspName := "test-update-port-security-lsp"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
	require.NoError(t, err)

	t.Run("update port_security and external_ids", func(t *testing.T) {
		err = nbClient.SetLogicalSwitchPortSecurity(true, lspName, "00:00:00:AB:B4:65", "10.244.0.37,fc00::af4:25", "10.244.100.10,10.244.100.11")
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25 10.244.100.10 10.244.100.11"}, lsp.PortSecurity)
		require.Equal(t, map[string]string{
			"vendor":         util.CniTypeName,
			logicalSwitchKey: lsName,
			"vips":           "10.244.100.10,10.244.100.11",
			"attach-vips":    "true",
		}, lsp.ExternalIDs)
	})

	t.Run("clear port_security and external_ids", func(t *testing.T) {
		err = nbClient.SetLogicalSwitchPortSecurity(false, lspName, "00:00:00:AB:B4:65", "10.244.0.37,fc00::af4:25", "")
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.NotNil(t, lsp)
		require.Empty(t, lsp.PortSecurity)
		require.Equal(t, map[string]string{
			"vendor":         util.CniTypeName,
			logicalSwitchKey: lsName,
		}, lsp.ExternalIDs)
	})

	t.Run("update port_security and external_ids when lsp.ExternalIDs is nil and vips is not nil", func(t *testing.T) {
		lspName := "test-update-port-security-lsp-nil-eid"

		err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
		require.NoError(t, err)

		err = nbClient.SetLogicalSwitchPortSecurity(true, lspName, "00:00:00:AB:B4:65", "10.244.0.37,fc00::af4:25", "10.244.100.10,10.244.100.11")
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.NotNil(t, lsp)
		require.ElementsMatch(t, []string{"00:00:00:AB:B4:65 10.244.0.37 fc00::af4:25 10.244.100.10 10.244.100.11"}, lsp.PortSecurity)
		require.Equal(t, map[string]string{
			"vendor":         util.CniTypeName,
			logicalSwitchKey: lsName,
			"vips":           "10.244.100.10,10.244.100.11",
			"attach-vips":    "true",
		}, lsp.ExternalIDs)
	})
}

func (suite *OvnClientTestSuite) testSetSetLogicalSwitchPortExternalIDs() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-set-lsp-ext-id-ls"
	lspName := "test-set-lsp-ext-id-lsp"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
	require.NoError(t, err)

	lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
	require.NoError(t, err)
	require.NotNil(t, lsp)
	require.NotEmpty(t, lsp.ExternalIDs)
	require.Equal(t, util.CniTypeName, lsp.ExternalIDs["vendor"])

	err = nbClient.SetLogicalSwitchPortExternalIDs(lspName, map[string]string{"k1": "v1"})
	require.NoError(t, err)

	lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
	require.NoError(t, err)
	require.NotNil(t, lsp)
	require.NotEmpty(t, lsp.ExternalIDs)
	require.Equal(t, util.CniTypeName, lsp.ExternalIDs["vendor"])
	require.Equal(t, "v1", lsp.ExternalIDs["k1"])

	err = nbClient.SetLogicalSwitchPortExternalIDs(lspName, map[string]string{"k1": "v2"})
	require.NoError(t, err)

	lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
	require.NoError(t, err)
	require.NotNil(t, lsp)
	require.NotEmpty(t, lsp.ExternalIDs)
	require.Equal(t, util.CniTypeName, lsp.ExternalIDs["vendor"])
	require.Equal(t, "v2", lsp.ExternalIDs["k1"])
}

func (suite *OvnClientTestSuite) testSetLogicalSwitchPortSecurityGroup() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-set-sg-ls"
	lspNamePrefix := "test-set-sg-lsp"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	addOpExpect := func(lsp *ovnnb.LogicalSwitchPort, sgs []string) {
		for _, sg := range sgs {
			require.Equalf(t, "true", lsp.ExternalIDs[associatedSgKeyPrefix+sg], "%s should exist", sg)
		}

		sgList := strings.Split(lsp.ExternalIDs[sgsKey], "/")
		require.ElementsMatch(t, sgs, sgList)
	}

	removeOpExpect := func(lsp *ovnnb.LogicalSwitchPort, sgs []string) {
		for _, sg := range sgs {
			require.Equalf(t, "false", lsp.ExternalIDs[associatedSgKeyPrefix+sg], "%s should't exist", sg)
		}

		sgList := strings.Split(lsp.ExternalIDs[sgsKey], "/")
		require.NotSubset(t, sgList, sgs)
	}

	t.Run("add operation", func(t *testing.T) {
		t.Parallel()

		lspNamePrefix := lspNamePrefix + "-add"
		op := "add"

		t.Run("new sgs is completely different old sgs", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-complete"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "true"
			lsp.ExternalIDs[sgsKey] = "sg1"
			err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
			require.NoError(t, err)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg3")
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"sg2", "sg3"}, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			addOpExpect(lsp, []string{"sg2", "sg1", "sg3"})
		})

		t.Run("old sg is subset of new sgs", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-old-subset"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"] = "true"
			lsp.ExternalIDs[sgsKey] = "sg1/sg2"
			err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
			require.NoError(t, err)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg3", "sg4", "sg1")
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"sg4", "sg3"}, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			addOpExpect(lsp, []string{"sg2", "sg1", "sg3", "sg4"})
		})

		t.Run("new sg is subset of old sgs", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-new-subset"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg3"] = "true"
			lsp.ExternalIDs[sgsKey] = "sg1/sg2/sg3"
			err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
			require.NoError(t, err)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg1")
			require.NoError(t, err)
			require.Empty(t, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			addOpExpect(lsp, []string{"sg2", "sg1", "sg3"})
		})

		t.Run("new sgs is partially different old sgs", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-partial"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg3"] = "true"
			lsp.ExternalIDs[sgsKey] = "sg1/sg2/sg3"
			err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
			require.NoError(t, err)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg3", "sg4")
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"sg4"}, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			addOpExpect(lsp, []string{"sg2", "sg1", "sg3", "sg4"})
		})

		t.Run("new sgs is empty", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-new-empty"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg3"] = "true"
			lsp.ExternalIDs[sgsKey] = "sg1/sg2/sg3"
			err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
			require.NoError(t, err)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op)
			require.NoError(t, err)
			require.Empty(t, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			addOpExpect(lsp, []string{"sg2", "sg1", "sg3"})
		})

		t.Run("old sgs is empty", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-old-empty"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg1")
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"sg1", "sg2"}, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			addOpExpect(lsp, []string{"sg2", "sg1"})
		})
	})

	t.Run("remove operation", func(t *testing.T) {
		t.Parallel()

		lspNamePrefix := lspNamePrefix + "-remove"
		op := "remove"

		t.Run("new sgs is completely different old sgs", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-complete"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "true"
			lsp.ExternalIDs[sgsKey] = "sg1"
			err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
			require.NoError(t, err)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg3")
			require.NoError(t, err)
			require.Empty(t, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			addOpExpect(lsp, []string{"sg1"})
		})

		t.Run("old sg is subset of new sgs", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-old-subset"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"] = "true"
			lsp.ExternalIDs[sgsKey] = "sg1/sg2"
			err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
			require.NoError(t, err)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg3", "sg4", "sg1")
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"sg1", "sg2"}, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			removeOpExpect(lsp, []string{"sg2", "sg1"})
		})

		t.Run("new sg is subset of old sgs", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-new-subset"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg3"] = "true"
			lsp.ExternalIDs[sgsKey] = "sg1/sg2/sg3"
			err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
			require.NoError(t, err)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg1")
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"sg2", "sg1"}, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			addOpExpect(lsp, []string{"sg3"})
			removeOpExpect(lsp, []string{"sg2", "sg1"})
		})

		t.Run("new sgs is partially different old sgs", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-partial"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"] = "true"
			lsp.ExternalIDs[associatedSgKeyPrefix+"sg3"] = "true"
			lsp.ExternalIDs[sgsKey] = "sg1/sg2/sg3"
			err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
			require.NoError(t, err)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg3", "sg4")
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"sg3", "sg2"}, diffSgs)

			lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			addOpExpect(lsp, []string{"sg1"})
			removeOpExpect(lsp, []string{"sg2", "sg3"})
		})

		t.Run("old sgs is empty", func(t *testing.T) {
			t.Parallel()

			lspName := lspNamePrefix + "-old-empty"
			err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
			require.NoError(t, err)

			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)

			diffSgs, err := nbClient.SetLogicalSwitchPortSecurityGroup(lsp, op, "sg2", "sg1")
			require.NoError(t, err)
			require.Empty(t, diffSgs)
		})
	})
}

func (suite *OvnClientTestSuite) testSetLogicalSwitchPortsSecurityGroup() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-set-sgs-ls"
	lspNamePrefix := "test-set-sgs-lsp"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		lspName := fmt.Sprintf("%s-%d", lspNamePrefix, i)
		err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.NotNil(t, lsp)

		lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"] = "false"
		lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"] = "false"
		err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs)
		require.NoError(t, err)
	}

	t.Run("add sg to lsp", func(t *testing.T) {
		err := nbClient.SetLogicalSwitchPortsSecurityGroup("sg2", "add")
		require.NoError(t, err)

		for i := 0; i < 3; i++ {
			lspName := fmt.Sprintf("%s-%d", lspNamePrefix, i)
			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)
			require.NotEmpty(t, lsp.ExternalIDs)
			require.Equal(t, "false", lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"])
			require.Equal(t, "true", lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"])

			sgList := strings.Split(lsp.ExternalIDs[sgsKey], "/")
			require.ElementsMatch(t, []string{"sg2"}, sgList)
		}
	})

	t.Run("remove sg from lsp", func(t *testing.T) {
		err := nbClient.SetLogicalSwitchPortsSecurityGroup("sg2", "remove")
		require.NoError(t, err)

		for i := 0; i < 3; i++ {
			lspName := fmt.Sprintf("%s-%d", lspNamePrefix, i)
			lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
			require.NoError(t, err)
			require.NotNil(t, lsp)
			require.NotEmpty(t, lsp.ExternalIDs)
			require.Equal(t, "false", lsp.ExternalIDs[associatedSgKeyPrefix+"sg1"])
			require.Equal(t, "false", lsp.ExternalIDs[associatedSgKeyPrefix+"sg2"])
			require.Empty(t, lsp.ExternalIDs[sgsKey])
		}
	})

	t.Run("invalid op", func(t *testing.T) {
		err := nbClient.SetLogicalSwitchPortsSecurityGroup("sg2", "del")
		require.ErrorContains(t, err, "op must be 'add' or 'remove'")
	})
}

func (suite *OvnClientTestSuite) testEnablePortLayer2forward() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-enable-port-l2-ls"
	lspName := "test-enable-port-l2-lsp"
	ns := "test-enable-port-l2-ns"
	pod := "test-enable-port-l2-pod"
	ip := util.GenerateRandomIP("192.168.1.0/24")
	mac := util.GenerateMac()

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateLogicalSwitchPort(lsName, lspName, ip, mac, pod, ns, false, "", "", false, nil, "")
	require.NoError(t, err)

	lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
	require.NoError(t, err)
	require.NotNil(t, lsp)
	require.NotEmpty(t, lsp.ExternalIDs)
	require.Equal(t, util.CniTypeName, lsp.ExternalIDs["vendor"])

	err = nbClient.EnablePortLayer2forward(lspName)
	require.NoError(t, err)

	lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
	require.NoError(t, err)
	require.NotNil(t, lsp)
	require.Contains(t, lsp.Addresses, "unknown")
}

func (suite *OvnClientTestSuite) testSetLogicalSwitchPortVlanTag() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-set-port-vlan-tag-ls"
	lspName := "test-set-port-vlan-tag-lsp"
	vlanID := 100

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateLocalnetLogicalSwitchPort(lsName, lspName, "provider", "192.168.3.0/24,fd03::/120", vlanID)
	require.NoError(t, err)

	lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
	require.NoError(t, err)
	require.NotNil(t, lsp)
	require.NotNil(t, lsp.Tag)
	require.Equal(t, vlanID, *lsp.Tag)
	require.NotEmpty(t, lsp.ExternalIDs)
	require.Equal(t, util.CniTypeName, lsp.ExternalIDs["vendor"])
	require.Equal(t, "192.168.3.0/24", lsp.ExternalIDs["ipv4_network"])
	require.Equal(t, "fd03::/120", lsp.ExternalIDs["ipv6_network"])

	t.Run("clear logical switch port vlan id", func(t *testing.T) {
		err = nbClient.SetLogicalSwitchPortVlanTag(lspName, 0)
		require.NoError(t, err)

		lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.NotNil(t, lsp)
		require.Nil(t, lsp.Tag)
	})

	t.Run("set logical switch port vlan id", func(t *testing.T) {
		vlanID := 10
		err = nbClient.SetLogicalSwitchPortVlanTag(lspName, vlanID)
		require.NoError(t, err)

		lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.NotNil(t, lsp)
		require.NotNil(t, lsp.Tag)
		require.Equal(t, vlanID, *lsp.Tag)

		// no error when set the same vlan id
		err = nbClient.SetLogicalSwitchPortVlanTag(lspName, vlanID)
		require.NoError(t, err)

		lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.NotNil(t, lsp)
		require.NotNil(t, lsp.Tag)
		require.Equal(t, vlanID, *lsp.Tag)
	})

	t.Run("invalid vlan id", func(t *testing.T) {
		err = nbClient.SetLogicalSwitchPortVlanTag(lspName, -1)
		require.ErrorContains(t, err, "invalid vlan id")

		err = nbClient.SetLogicalSwitchPortVlanTag(lspName, 4096)
		require.ErrorContains(t, err, "invalid vlan id")
	})
}

func (suite *OvnClientTestSuite) testUpdateLogicalSwitchPort() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-update-lsp-ls"
	lspName := "test-update-lsp-lsp"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
	require.NoError(t, err)

	lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
	require.NoError(t, err)
	require.NotNil(t, lsp)
	require.NotEmpty(t, lsp.ExternalIDs)
	require.Equal(t, util.CniTypeName, lsp.ExternalIDs["vendor"])

	t.Run("update external-ids & options", func(t *testing.T) {
		lsp.ExternalIDs["liveMigration"] = "0"
		if lsp.Options == nil {
			lsp.Options = make(map[string]string, 1)
		}
		lsp.Options["virtual-parents"] = "test-virtual-parents"
		err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs, &lsp.Options)
		require.NoError(t, err)

		lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.NotNil(t, lsp)
		require.NotEmpty(t, lsp.ExternalIDs)
		require.NotEmpty(t, lsp.Options)
		require.Equal(t, "0", lsp.ExternalIDs["liveMigration"])
		require.Equal(t, "test-virtual-parents", lsp.Options["virtual-parents"])
	})

	t.Run("remove external-ids & options", func(t *testing.T) {
		delete(lsp.ExternalIDs, "liveMigration")
		delete(lsp.Options, "virtual-parents")

		err = nbClient.UpdateLogicalSwitchPort(lsp, &lsp.ExternalIDs, &lsp.Options)
		require.NoError(t, err)

		lsp, err = nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.NotNil(t, lsp)
		require.NotEmpty(t, lsp.ExternalIDs)
		require.NotContains(t, lsp.ExternalIDs, "liveMigration")
		require.Empty(t, lsp.Options)
	})

	t.Run("update nil logical switch port", func(t *testing.T) {
		err := nbClient.UpdateLogicalSwitchPort(nil, &map[string]string{}, &map[string]string{})

		require.Error(t, err)
		require.Contains(t, err.Error(), "logical switch port is nil")
	})
}

func (suite *OvnClientTestSuite) testListLogicalSwitchPorts() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient

	lsName := "test-list-lsp-ls"
	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	t.Run("normal lsp", func(t *testing.T) {
		t.Parallel()

		// normal lsp
		lspName := "test-list-normal-lsp"
		err := nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
		require.NoError(t, err)

		out, err := nbClient.ListLogicalSwitchPorts(true, map[string]string{logicalSwitchKey: lsName}, func(lsp *ovnnb.LogicalSwitchPort) bool {
			return lsp.Type == ""
		})
		require.NoError(t, err)
		require.Len(t, out, 1)
		require.Equal(t, lspName, out[0].Name)
	})

	t.Run("patch lsp", func(t *testing.T) {
		t.Parallel()

		// patch lsp
		lrName := "test-list-patch-lsp-lr"
		lspName := "test-list-patch-lsp-lsp"
		lrpName := "test-list-patch-lsp-lrp"

		err := nbClient.CreateLogicalRouter(lrName)
		require.NoError(t, err)

		err = nbClient.CreateLogicalPatchPort(lsName, lrName, lspName, lrpName, "10.19.100.1/24", "")
		require.NoError(t, err)

		out, err := nbClient.ListLogicalSwitchPorts(true, map[string]string{logicalSwitchKey: lsName}, func(lsp *ovnnb.LogicalSwitchPort) bool {
			return lsp.Type == "router" && len(lsp.Options) != 0 && lsp.Options["router-port"] == lrpName
		})
		require.NoError(t, err)
		require.Len(t, out, 1)
		require.Equal(t, lspName, out[0].Name)
	})

	t.Run("virtual lsp", func(t *testing.T) {
		t.Parallel()

		// virtual lsp
		lspName := "test-list-virtual-lsp"
		err := nbClient.CreateVirtualLogicalSwitchPort(lspName, lsName, "unknown")
		require.NoError(t, err)

		out, err := nbClient.ListLogicalSwitchPorts(true, map[string]string{logicalSwitchKey: lsName}, func(lsp *ovnnb.LogicalSwitchPort) bool {
			return lsp.Type == "virtual"
		})
		require.NoError(t, err)
		require.Len(t, out, 1)
		require.Equal(t, lspName, out[0].Name)
	})
}

func (suite *OvnClientTestSuite) testDeleteLogicalSwitchPort() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lspName := "test-delete-port-lsp"
	lsName := "test-delete-port-ls"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
	require.NoError(t, err)

	t.Run("no err when delete existent logical switch port", func(t *testing.T) {
		ls, err := nbClient.GetLogicalSwitch(lsName, false)
		require.NoError(t, err)

		lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.NoError(t, err)
		require.Contains(t, ls.Ports, lsp.UUID)

		err = nbClient.DeleteLogicalSwitchPort(lspName)
		require.NoError(t, err)

		ls, err = nbClient.GetLogicalSwitch(lsName, false)
		require.NoError(t, err)
		require.NotContains(t, ls.Ports, lsp.UUID)
	})

	t.Run("no err when delete non-existent logical switch port", func(t *testing.T) {
		err := nbClient.DeleteLogicalSwitchPort("test-delete-lrp-non-existent")
		require.NoError(t, err)
	})
}

func (suite *OvnClientTestSuite) testCreateLogicalSwitchPortOp() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lspName := "test-create-op-lsp"
	lsName := "test-create-op-ls"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	t.Run("merge ExternalIDs when exist ExternalIDs", func(t *testing.T) {
		lsp := &ovnnb.LogicalSwitchPort{
			UUID: ovsclient.NamedUUID(),
			Name: lspName,
			ExternalIDs: map[string]string{
				"pod": lspName,
			},
		}

		ops, err := nbClient.CreateLogicalSwitchPortOp(lsp, lsName)
		require.NoError(t, err)
		require.Len(t, ops, 2)

		require.Equal(t, ovsdb.OvsMap{
			GoMap: map[interface{}]interface{}{
				logicalSwitchKey: lsName,
				"pod":            lspName,
				"vendor":         "kube-ovn",
			},
		}, ops[0].Row["external_ids"])

		require.Equal(t, []ovsdb.Mutation{
			{
				Column:  "ports",
				Mutator: ovsdb.MutateOperationInsert,
				Value: ovsdb.OvsSet{
					GoSet: []interface{}{
						ovsdb.UUID{
							GoUUID: lsp.UUID,
						},
					},
				},
			},
		}, ops[1].Mutations)
	})

	t.Run("attach ExternalIDs when does't exist ExternalIDs", func(t *testing.T) {
		lspName := "test-create-op-lsp-none-ext-id"

		lsp := &ovnnb.LogicalSwitchPort{
			UUID: ovsclient.NamedUUID(),
			Name: lspName,
		}

		ops, err := nbClient.CreateLogicalSwitchPortOp(lsp, lsName)
		require.NoError(t, err)
		require.Len(t, ops, 2)

		require.Equal(t, ovsdb.OvsMap{
			GoMap: map[interface{}]interface{}{
				logicalSwitchKey: lsName,
				"vendor":         "kube-ovn",
			},
		}, ops[0].Row["external_ids"])

		require.Equal(t, []ovsdb.Mutation{
			{
				Column:  "ports",
				Mutator: ovsdb.MutateOperationInsert,
				Value: ovsdb.OvsSet{
					GoSet: []interface{}{
						ovsdb.UUID{
							GoUUID: lsp.UUID,
						},
					},
				},
			},
		}, ops[1].Mutations)
	})
}

func (suite *OvnClientTestSuite) testDeleteLogicalSwitchPortOp() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lspName := "test-del-op-lsp"
	lsName := "test-del-op-ls"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	err = nbClient.CreateBareLogicalSwitchPort(lsName, lspName, "unknown", "")
	require.NoError(t, err)

	lsp, err := nbClient.GetLogicalSwitchPort(lspName, false)
	require.NoError(t, err)

	ops, err := nbClient.DeleteLogicalSwitchPortOp(lspName)
	require.NoError(t, err)
	require.Len(t, ops, 1)

	require.Equal(t, []ovsdb.Mutation{
		{
			Column:  "ports",
			Mutator: ovsdb.MutateOperationDelete,
			Value: ovsdb.OvsSet{
				GoSet: []interface{}{
					ovsdb.UUID{
						GoUUID: lsp.UUID,
					},
				},
			},
		},
	}, ops[0].Mutations)
}

func (suite *OvnClientTestSuite) testLogicalSwitchPortFilter() {
	t := suite.T()
	t.Parallel()

	lsName := "test-filter-lsp-lr"
	prefix := "test-filter-lsp"
	lsps := make([]*ovnnb.LogicalSwitchPort, 0)
	var patchPort string

	i := 0
	// create three normal lsp
	for ; i < 3; i++ {
		lspName := fmt.Sprintf("%s-%d", prefix, i)
		lsp := &ovnnb.LogicalSwitchPort{
			Name: lspName,
			ExternalIDs: map[string]string{
				logicalSwitchKey: lsName,
				"vendor":         util.CniTypeName,
			},
		}

		lsps = append(lsps, lsp)
	}

	// create one patch lsp
	for ; i < 4; i++ {
		lspName := fmt.Sprintf("%s-%d", prefix, i)
		patchPort = fmt.Sprintf("%s-lrp", lspName)
		lsp := &ovnnb.LogicalSwitchPort{
			Name: lspName,
			ExternalIDs: map[string]string{
				logicalSwitchKey: lsName,
				"vendor":         util.CniTypeName,
			},
			Type: "router",
			Options: map[string]string{
				"router-port": patchPort,
			},
		}

		lsps = append(lsps, lsp)
	}

	// create one remote lsp
	for ; i < 5; i++ {
		lspName := fmt.Sprintf("%s-%d", prefix, i)
		lsp := &ovnnb.LogicalSwitchPort{
			Name: lspName,
			ExternalIDs: map[string]string{
				logicalSwitchKey: lsName,
				"vendor":         util.CniTypeName,
			},
			Type: "remote",
		}

		lsps = append(lsps, lsp)
	}

	// create one virtual lsp
	for ; i < 6; i++ {
		lspName := fmt.Sprintf("%s-%d", prefix, i)
		lsp := &ovnnb.LogicalSwitchPort{
			Name: lspName,
			ExternalIDs: map[string]string{
				logicalSwitchKey: lsName,
				"vendor":         util.CniTypeName,
			},
			Type: "virtual",
		}

		lsps = append(lsps, lsp)
	}

	// create two normal lsp with different logical switch name and vendor
	for ; i < 8; i++ {
		lspName := fmt.Sprintf("%s-%d", prefix, i)
		lsp := &ovnnb.LogicalSwitchPort{
			Name: lspName,
			ExternalIDs: map[string]string{
				logicalSwitchKey: lsName + "-test",
				"vendor":         util.CniTypeName + "-test",
			},
		}

		lsps = append(lsps, lsp)
	}

	// create one normal lsp with different logical switch name and no vendor
	for ; i < 9; i++ {
		lspName := fmt.Sprintf("%s-%d", prefix, i)
		lsp := &ovnnb.LogicalSwitchPort{
			Name: lspName,
			ExternalIDs: map[string]string{
				logicalSwitchKey: lsName + "-test",
			},
		}

		lsps = append(lsps, lsp)
	}

	t.Run("include all lsp", func(t *testing.T) {
		filterFunc := logicalSwitchPortFilter(false, nil, nil)
		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Equal(t, count, 9)
	})

	t.Run("include all lsp which vendor is kube-ovn", func(t *testing.T) {
		filterFunc := logicalSwitchPortFilter(true, nil, nil)
		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Equal(t, count, 6)
	})

	t.Run("include all lsp with external ids", func(t *testing.T) {
		filterFunc := logicalSwitchPortFilter(true, map[string]string{logicalSwitchKey: lsName}, nil)
		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Equal(t, count, 6)
	})

	t.Run("list normal type lsp", func(t *testing.T) {
		filterFunc := logicalSwitchPortFilter(true, map[string]string{logicalSwitchKey: lsName}, func(lsp *ovnnb.LogicalSwitchPort) bool {
			return lsp.Type == ""
		})
		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Equal(t, count, 3)
	})

	t.Run("list remote type lsp", func(t *testing.T) {
		filterFunc := logicalSwitchPortFilter(true, map[string]string{logicalSwitchKey: lsName}, func(lsp *ovnnb.LogicalSwitchPort) bool {
			return lsp.Type == "remote"
		})
		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Equal(t, count, 1)
	})

	t.Run("list virtual type lsp", func(t *testing.T) {
		filterFunc := logicalSwitchPortFilter(true, map[string]string{logicalSwitchKey: lsName}, func(lsp *ovnnb.LogicalSwitchPort) bool {
			return lsp.Type == "virtual"
		})
		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Equal(t, count, 1)
	})

	t.Run("list patch type lsp", func(t *testing.T) {
		filterFunc := logicalSwitchPortFilter(true, map[string]string{logicalSwitchKey: lsName}, func(lsp *ovnnb.LogicalSwitchPort) bool {
			return lsp.Type == "router" && len(lsp.Options) != 0 && lsp.Options["router-port"] == patchPort
		})

		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Equal(t, count, 1)
	})

	t.Run("externalIDs's length is not equal", func(t *testing.T) {
		t.Parallel()

		filterFunc := logicalSwitchPortFilter(true, map[string]string{
			logicalSwitchKey: lsName,
			"key":            "value",
		}, nil)

		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Empty(t, count)
	})

	t.Run("list lsp without vendor", func(t *testing.T) {
		filterFunc := logicalSwitchPortFilter(false, nil, func(lsp *ovnnb.LogicalSwitchPort) bool {
			return len(lsp.ExternalIDs) == 0 || len(lsp.ExternalIDs["vendor"]) == 0
		})

		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Equal(t, count, 1)
	})

	t.Run("list lsp which vendor is not kube-ovn", func(t *testing.T) {
		filterFunc := logicalSwitchPortFilter(false, nil, func(lsp *ovnnb.LogicalSwitchPort) bool {
			return len(lsp.ExternalIDs) == 0 || lsp.ExternalIDs["vendor"] != util.CniTypeName
		})

		count := 0
		for _, lsp := range lsps {
			if filterFunc(lsp) {
				count++
			}
		}
		require.Equal(t, count, 3)
	})
}

func (suite *OvnClientTestSuite) testGetLogicalSwitchPortSgs() {
	t := suite.T()
	t.Parallel()

	t.Run("has associated security group", func(t *testing.T) {
		t.Parallel()
		lsp := &ovnnb.LogicalSwitchPort{
			ExternalIDs: map[string]string{
				"vendor":            util.CniTypeName,
				"associated_sg_sg1": "true",
				"associated_sg_sg2": "true",
			},
		}

		sgs := getLogicalSwitchPortSgs(lsp).List()
		require.ElementsMatch(t, []string{"sg1", "sg2"}, sgs)
	})

	t.Run("has no associated security group", func(t *testing.T) {
		t.Parallel()
		lsp := &ovnnb.LogicalSwitchPort{
			ExternalIDs: map[string]string{
				"vendor": util.CniTypeName,
			},
		}

		sgs := getLogicalSwitchPortSgs(lsp).List()
		require.Empty(t, sgs)
	})

	t.Run("has no external ids", func(t *testing.T) {
		t.Parallel()
		lsp := &ovnnb.LogicalSwitchPort{}

		sgs := getLogicalSwitchPortSgs(lsp).List()
		require.Empty(t, sgs)
	})
}

func (suite *OvnClientTestSuite) testGetLogicalSwitchPort() {
	t := suite.T()
	t.Parallel()

	nbClient := suite.ovnNBClient
	lsName := "test-get-lsp"

	err := nbClient.CreateBareLogicalSwitch(lsName)
	require.NoError(t, err)

	t.Run("get non-existent logical switch port", func(t *testing.T) {
		t.Parallel()

		lspName := "non-existent-lsp"
		_, err := nbClient.GetLogicalSwitchPort(lspName, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})
}
