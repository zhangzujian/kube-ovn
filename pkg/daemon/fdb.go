package daemon

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	"github.com/kubeovn/kube-ovn/pkg/ovs"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

// default max fdb age is 300s in ovs-vswitchd
const fdbSyncPeriod = 100 * time.Second

// regexp to match fdb entry line
var macMatch = regexp.MustCompile(`(?i)\s+([0-9a-f]{2}:){5}([0-9a-f]{2})\s+`)

// fdbIndex represents the identity of a fdb entry
type fdbIndex struct {
	vlan int
	mac  string
}

// fdbEntries represents fdb entries on an ovs bridge
type fdbEntries map[fdbIndex]string

func newFdbEntries() fdbEntries {
	return make(fdbEntries)
}

// parse output of command `ovs-appctl fdb/show <bridge>` and return static fdb entries
func parseStaticFdbEntries(bridge, output string, ports map[int]string) fdbEntries {
	// example output:
	//  port  VLAN  MAC                Age
	//     1   341  be:42:32:58:3d:73   65
	//     1   341  da:4c:ba:95:93:60  static
	entries := newFdbEntries()
	for s := range strings.SplitAfterSeq(strings.TrimSpace(output), "\n") {
		fields := strings.Fields(s)
		if len(fields) != 4 || !macMatch.MatchString(s) {
			continue
		}
		if fields[0] == "LOCAL" || fields[3] != "static" {
			continue
		}
		klog.V(3).Infof("found static fdb entry on bridge %s: %s", bridge, s)

		ofport, err1 := strconv.Atoi(fields[0])
		vlan, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			klog.Warningf("failed to parse ofport/vlan from fdb entry on bridge %s: %s", bridge, s)
			continue
		}

		mac := fields[2]
		if port := ports[ofport]; port != "" {
			klog.V(3).Infof("parsed static fdb entry on bridge %s: vlan %d mac %s port %s", bridge, vlan, mac, port)
			entries[fdbIndex{vlan, mac}] = port
		}
	}

	return entries
}

func (f fdbEntries) Insert(vlan int, mac, port string) {
	f[fdbIndex{vlan, mac}] = port
}

func (c *Controller) requestFdbSync() {
	select {
	case c.fdbSyncChan <- struct{}{}:
		klog.V(5).Info("fdb sync requested")
	default:
		klog.V(5).Info("fdb sync request has already been queued")
	}
}

func (c *Controller) syncFdb() {
	c.fdbSyncMutex.Lock()
	defer c.fdbSyncMutex.Unlock()

	bridges, err := ovs.Find("Bridge", []string{"external-ids:vendor=" + util.CniTypeName}, "name", "ports")
	if err != nil {
		klog.Errorf("failed to list ovs bridges: %v", err)
		return
	}
	ports, err := ovs.Find("Port", []string{`external-ids:ovn-localnet-port!=""`}, "_uuid", "name")
	if err != nil {
		klog.Errorf("failed to list ovs patch ports: %v", err)
		return
	}
	klog.V(3).Infof("found ovs patch ports: %v", ports)
	interfaces, err := ovs.Find("Interface", []string{"type=patch"}, "name", "ofport")
	if err != nil {
		klog.Errorf("failed to list ovs patch interfaces: %v", err)
		return
	}
	klog.V(3).Infof("found ovs patch interfaces: %v", interfaces)

	patchInterfaces := make(map[string]int, len(interfaces))
	for iface := range slices.Values(interfaces) {
		name, ok1 := iface["name"].(string)
		ofport, ok2 := iface["ofport"].(float64)
		if !ok1 || !ok2 {
			klog.Warningf("failed to parse name or ofport for interface: %v", iface)
			continue
		}
		patchInterfaces[name] = int(ofport)
	}
	patchPorts := make(map[string]map[int]string, len(ports))
	for port := range slices.Values(ports) {
		uuid := port["_uuid"].(ovsdb.UUID).GoUUID
		name := port["name"].(string)
		ofport, ok := patchInterfaces[name]
		if !ok {
			klog.V(3).Infof("port %s is not a patch port", name)
			continue
		}
		patchPorts[uuid] = map[int]string{ofport: name}
	}
	klog.V(3).Infof("found patch ports: %v", patchPorts)

	bridgePatchPorts := make(map[string]map[int]string, len(bridges))
	for bridge := range slices.Values(bridges) {
		name := bridge["name"].(string)
		portUUIDs := bridge["ports"].(ovsdb.OvsSet).GoSet
		for portUUID := range slices.Values(portUUIDs) {
			uuid := portUUID.(ovsdb.UUID).GoUUID
			klog.V(3).Infof("checking port with uuid %s on bridge %s", uuid, name)
			if ofportNameMap := patchPorts[uuid]; len(ofportNameMap) != 0 {
				if bridgePatchPorts[name] == nil {
					bridgePatchPorts[name] = make(map[int]string, 1)
				}
				maps.Insert(bridgePatchPorts[name], maps.All(ofportNameMap))
			}
		}
		klog.V(3).Infof("found patch ports on bridge %s: %v", name, bridgePatchPorts[name])
	}

	current := make(map[string]fdbEntries)
	for bridge := range slices.Values(bridges) {
		name := bridge["name"].(string)
		output, err := ovs.Appctl(ovs.OvsVswitchd, "fdb/show", name)
		if err != nil {
			klog.Errorf("failed to show fdb for bridge %s: %v", name, err)
			return
		}
		current[name] = parseStaticFdbEntries(name, output, bridgePatchPorts[name])
		klog.V(3).Infof("current static fdb entries on bridge %s: %v", name, current[name])
	}

	subnets, err := c.subnetsLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("failed to list subnets: %v", err)
		return
	}

	for subnet := range slices.Values(subnets) {
		if subnet.Spec.Vlan == "" ||
			!subnet.Spec.U2OInterconnection ||
			subnet.Status.U2OInterconnectionMAC == "" {
			continue
		}

		vlan, err := c.vlansLister.Get(subnet.Spec.Vlan)
		if err != nil {
			klog.Errorf("failed to get vlan %q for subnet %s: %v", subnet.Spec.Vlan, subnet.Name, err)
			continue
		}
		pn, err := c.providerNetworksLister.Get(vlan.Spec.Provider)
		if err != nil {
			klog.Errorf("failed to get provider network %q for vlan %s: %v", vlan.Spec.Provider, vlan.Name, err)
			continue
		}

		bridge := util.ExternalBridgeName(pn.Name)
		port := fmt.Sprintf("patch-localnet.%s-to-br-int", subnet.Name)
		if _, ok := patchInterfaces[port]; !ok {
			klog.Warningf("patch port %s not found on bridge %s", port, bridge)
			continue
		}
		index := fdbIndex{vlan.Spec.VlanID, subnet.Status.U2OInterconnectionMAC}
		entries := current[bridge]
		if entries != nil && entries[index] == port {
			// the fdb entry already exists, remove it from current entries to avoid deletion
			delete(current[bridge], index)
			continue
		}
		// install static fdb entry
		klog.Infof("adding fdb entry vlan %d mac %s port %s on bridge %s", index.vlan, index.mac, port, bridge)
		if _, err = ovs.Appctl(ovs.OvsVswitchd, "fdb/add", bridge, port, strconv.Itoa(index.vlan), index.mac); err != nil {
			klog.Errorf("failed to add fdb entry vlan %d mac %s port %s on bridge %s: %v", index.vlan, index.mac, port, bridge, err)
		}
	}

	// delete unused fdb entries
	for bridge, entries := range current {
		for index := range entries {
			klog.Infof("deleting fdb entry vlan %d mac %s on bridge %s", index.vlan, index.mac, bridge)
			if _, err = ovs.Appctl(ovs.OvsVswitchd, "fdb/del", bridge, strconv.Itoa(index.vlan), index.mac); err != nil {
				klog.Errorf("failed to delete fdb entry vlan %d mac %s on bridge %s: %v", index.vlan, index.mac, bridge, err)
			}
		}
	}
}

func (c *Controller) runFdbSync(stopCh <-chan struct{}) {
	klog.Info("Starting fdb sync loop")

	ticker := time.NewTicker(fdbSyncPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.syncFdb()
		case <-c.fdbSyncChan:
			ticker.Reset(fdbSyncPeriod)
			c.syncFdb()
		case <-stopCh:
			klog.Info("Stopping fdb sync loop")
			return
		}
	}
}
