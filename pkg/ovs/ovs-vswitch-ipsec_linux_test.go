package ovs

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/vswitch"
)

func TestIPsecConfigurationPreservesOtherModules(t *testing.T) {
	c := newTestCNIVswitchClient(t)
	row, err := c.IPsecConfiguration()
	require.NoError(t, err)
	require.NoError(t, c.patchCNIMap(vswitch.OpenvSwitchTable, row.UUID, "other_config", map[string]string{"hw-offload": "true", "certificate": "old-cert", "private_key": "old-key", "ca_cert": "old-ca"}, nil))
	paths := map[string]string{"certificate": "new-cert", "private_key": "new-key", "ca_cert": "new-ca"}
	require.NoError(t, c.SetIPsecConfiguration(row.UUID, paths))
	got, err := c.IPsecConfiguration()
	require.NoError(t, err)
	require.Equal(t, "true", got.OtherConfig["hw-offload"])
	for key, value := range paths {
		require.Equal(t, value, got.OtherConfig[key])
	}
	c.Disconnect()
	require.Eventually(t, c.Connected, 3e9, 1e7)
	require.NoError(t, c.SetIPsecConfiguration(row.UUID, paths))
	require.Error(t, c.SetIPsecConfiguration("00000000-0000-0000-0000-000000000000", paths))
}
