package ovs

import (
	"fmt"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/vswitch"
)

// IPsecConfiguration reads the singleton synchronously, including after a
// database reset, without depending on a stale monitor cache.
func (c *VswitchClient) IPsecConfiguration() (*vswitch.OpenvSwitch, error) {
	rows, err := readVswitch[vswitch.OpenvSwitch](c, vswitch.OpenvSwitchTable, nil)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("expected one Open_vSwitch row, found %d", len(rows))
	}
	return &rows[0], nil
}

// SetIPsecConfiguration replaces only the three IPsec paths in one transaction.
// Other node modules retain ownership of the rest of other_config.
func (c *VswitchClient) SetIPsecConfiguration(uuid string, paths map[string]string) error {
	op := cniMapPatch(vswitch.OpenvSwitchTable, uuid, "other_config", paths, []string{"certificate", "private_key", "ca_cert"})
	results, err := c.transactVswitchOperations([]ovsdb.Operation{op})
	if err != nil {
		return err
	}
	if results[0].Count != 1 {
		return fmt.Errorf("IPsec configuration changed %d Open_vSwitch rows", results[0].Count)
	}
	return nil
}
