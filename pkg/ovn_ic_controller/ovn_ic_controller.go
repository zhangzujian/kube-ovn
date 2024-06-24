package ovn_ic_controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/scylladb/go-set/strset"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	kubeovnv1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

var (
	icEnabled = "unknown"
	lastIcCm  map[string]string
	lastTSs   []string
	curTSs    []string
)

const (
	icNoAction = iota
	icFirstEstablish
	icConfigChange
)

func getTsCIDR(azName string, af, index int) string {
	hash := sha256.Sum256([]byte(azName))
	if af == 4 {
		cidr := net.IPNet{
			IP:   net.ParseIP("169.0.0.0").To4(),
			Mask: net.CIDRMask(28, 32),
		}
		cidr.IP[1] = hash[0]
		cidr.IP[2] = hash[1]
		cidr.IP[3] = 0xf0 & (byte(index) << 4)
		return cidr.String()
	}

	cidr := net.IPNet{
		IP:   net.ParseIP("fe80:a9fe::").To16(),
		Mask: net.CIDRMask(120, 128),
	}
	for i := 0; i < 6; i++ {
		cidr.IP[i+2] = hash[i]
	}
	cidr.IP[8] = byte(index)
	return cidr.String()
}

func getTsSubnet(azName string, index int) (string, error) {
	switch util.CheckProtocol(os.Getenv("POD_IPS")) {
	case kubeovnv1.ProtocolIPv4:
		return getTsCIDR(azName, 4, index), nil
	case kubeovnv1.ProtocolIPv6:
		return getTsCIDR(azName, 6, index), nil
	case kubeovnv1.ProtocolDual:
		return fmt.Sprintf("%s,%s", getTsCIDR(azName, 4, index), getTsCIDR(azName, 6, index)), nil
	default:
		return "", fmt.Errorf(`invalid environment variable "POD_IPS": %q`, os.Getenv("POD_IPS"))
	}
}

func (c *Controller) disableOVNIC(azName string) error {
	if err := c.removeInterConnection(azName); err != nil {
		klog.Errorf("failed to remove ovn-ic: %v", err)
		return err
	}
	if err := c.delLearnedRoute(); err != nil {
		klog.Errorf("failed to remove learned static routes: %v", err)
		return err
	}

	if err := c.RemoveOldChassisInSbDB(azName); err != nil {
		klog.Errorf("failed to remove remote chassis for az %q: %v", azName, err)
		return err
	}
	return nil
}

func (c *Controller) setAutoRoute(autoRoute bool) {
	var blackList []string
	subnets, err := c.subnetsLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("failed to list subnets, %v", err)
		return
	}
	for _, subnet := range subnets {
		if subnet.Spec.DisableInterConnection || subnet.Name == c.config.NodeSwitch {
			blackList = append(blackList, subnet.Spec.CIDRBlock)
		}
	}
	nodes, err := c.nodesLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("failed to list node, %v", err)
		return
	}
	for _, node := range nodes {
		ipv4, ipv6 := util.GetNodeInternalIP(*node)
		if ipv4 != "" {
			blackList = append(blackList, ipv4)
		}
		if ipv6 != "" {
			blackList = append(blackList, ipv6)
		}
	}
	if err := c.OVNNbClient.SetICAutoRoute(autoRoute, blackList); err != nil {
		klog.Errorf("failed to config auto route, %v", err)
		return
	}
}

func (c *Controller) DeleteICResources(azName string) error {
	icTSs := make([]string, 0)
	if err := c.OVNNbClient.DeleteLogicalSwitchPorts(nil, func(lsp *ovnnb.LogicalSwitchPort) bool {
		// add the code below because azName may have multi "-"
		firstIndex := strings.Index(lsp.Name, "-")
		if firstIndex != -1 {
			firstPart := lsp.Name[:firstIndex]
			secondPart := lsp.Name[firstIndex+1:]
			needDelete := secondPart == azName && strings.HasPrefix(firstPart, util.InterconnectionSwitch)
			if needDelete {
				icTSs = append(icTSs, firstPart)
			}
			return needDelete
		}
		return false
	}); err != nil {
		return err
	}

	if err := c.OVNNbClient.DeleteLogicalRouterPorts(nil, func(lrp *ovnnb.LogicalRouterPort) bool {
		lastIndex := strings.LastIndex(lrp.Name, "-")
		if lastIndex != -1 {
			firstPart := lrp.Name[:lastIndex]
			secondPart := lrp.Name[lastIndex+1:]
			return firstPart == azName && strings.HasPrefix(secondPart, util.InterconnectionSwitch)
		}
		return false
	}); err != nil {
		return err
	}

	for _, icTS := range icTSs {
		if err := c.OVNNbClient.DeleteLogicalSwitch(icTS); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) getICState(cmData, lastcmData map[string]string) int {
	isCMEqual := reflect.DeepEqual(cmData, lastcmData)
	if icEnabled != "true" && len(lastcmData) == 0 && cmData["enable-ic"] == "true" {
		return icFirstEstablish
	}

	if icEnabled == "true" && lastcmData != nil && isCMEqual {
		var err error
		c.ovnLegacyClient.OvnICNbAddress = genHostAddress(cmData["ic-db-host"], cmData["ic-nb-port"])
		curTSs, err = c.ovnLegacyClient.GetTs()
		if err != nil {
			klog.Errorf("failed to get Transit_Switch, %v", err)
			return icNoAction
		}
		isTsEqual := reflect.DeepEqual(lastTSs, curTSs)
		if isTsEqual {
			return icNoAction
		}
	}
	return icConfigChange
}

func (c *Controller) resyncInterConnection() {
	cm, err := c.configMapsLister.ConfigMaps(c.config.PodNamespace).Get(util.InterconnectionConfig)
	if err != nil && !k8serrors.IsNotFound(err) {
		klog.Errorf("failed to get ovn-ic-config, %v", err)
		return
	}

	if k8serrors.IsNotFound(err) || cm.Data["enable-ic"] == "false" {
		if icEnabled == "false" {
			return
		}
		klog.Info("start to remove ovn-ic")
		var azName, icDBHost, icSBPort, icNBPort string
		if cm != nil {
			azName = cm.Data["az-name"]
			icDBHost = cm.Data["ic-db-host"]
			icSBPort = cm.Data["ic-sb-port"]
			icNBPort = cm.Data["ic-nb-port"]
		} else if lastIcCm != nil {
			azName = lastIcCm["az-name"]
			icDBHost = lastIcCm["ic-db-host"]
			icSBPort = lastIcCm["ic-sb-port"]
			icNBPort = lastIcCm["ic-nb-port"]
		}

		if icDBHost != "" {
			c.ovnLegacyClient.OvnICSbAddress = genHostAddress(icDBHost, icSBPort)
			c.ovnLegacyClient.OvnICNbAddress = genHostAddress(icDBHost, icNBPort)
		}

		err := c.disableOVNIC(azName)
		if err != nil {
			klog.Errorf("Disable az %s OVN IC failed: %v", azName, err)
			return
		}
		icEnabled = "false"
		lastIcCm = nil

		klog.Info("finish removing ovn-ic")
		return
	}

	autoRoute := false
	if cm.Data["auto-route"] == "true" {
		autoRoute = true
	}
	c.setAutoRoute(autoRoute)

	switch c.getICState(cm.Data, lastIcCm) {
	case icNoAction:
		return
	case icFirstEstablish:
		c.ovnLegacyClient.OvnICNbAddress = genHostAddress(cm.Data["ic-db-host"], cm.Data["ic-nb-port"])
		klog.Info("start to establish ovn-ic")
		if err := c.establishInterConnection(cm.Data); err != nil {
			klog.Errorf("failed to establish ovn-ic, %v", err)
			return
		}
		curTSs, err := c.ovnLegacyClient.GetTs()
		if err != nil {
			klog.Errorf("failed to get Transit_Switch, %v", err)
			return
		}
		icEnabled = "true"
		lastIcCm = cm.Data
		lastTSs = curTSs
		klog.Info("finish establishing ovn-ic")
		return
	case icConfigChange:
		c.ovnLegacyClient.OvnICSbAddress = genHostAddress(lastIcCm["ic-db-host"], cm.Data["ic-sb-port"])
		c.ovnLegacyClient.OvnICNbAddress = genHostAddress(lastIcCm["ic-db-host"], cm.Data["ic-nb-port"])
		err := c.disableOVNIC(lastIcCm["az-name"])
		if err != nil {
			klog.Errorf("Disable az %s OVN IC failed: %v", lastIcCm["az-name"], err)
			return
		}
		klog.Info("start to reestablish ovn-ic")
		if err := c.establishInterConnection(cm.Data); err != nil {
			klog.Errorf("failed to reestablish ovn-ic, %v", err)
			return
		}

		icEnabled = "true"
		lastIcCm = cm.Data
		lastTSs = curTSs
		klog.Info("finish reestablishing ovn-ic")
		return
	}
}

func (c *Controller) removeInterConnection(azName string) error {
	sel, _ := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: map[string]string{util.ICGatewayLabel: "true"}})
	nodes, err := c.nodesLister.List(sel)
	if err != nil {
		klog.Errorf("failed to list nodes, %v", err)
		return err
	}
	for _, cachedNode := range nodes {
		node := cachedNode.DeepCopy()
		patchPayloadTemplate := `[{"op": "%s", "path": "/metadata/labels", "value": %s}]`
		op := "replace"
		if len(node.Labels) == 0 {
			node.Labels = make(map[string]string, 1)
			op = "add"
		}
		if node.Labels[util.ICGatewayLabel] != "false" {
			node.Labels[util.ICGatewayLabel] = "false"
			raw, _ := json.Marshal(node.Labels)
			patchPayload := fmt.Sprintf(patchPayloadTemplate, op, raw)
			if _, err = c.config.KubeClient.CoreV1().Nodes().Patch(context.Background(), node.Name, types.JSONPatchType, []byte(patchPayload), metav1.PatchOptions{}, ""); err != nil {
				klog.Errorf("failed to patch ic gw node %s: %v", node.Name, err)
				return err
			}
		}
	}

	if err := c.stopOVNIC(); err != nil {
		klog.Errorf("failed to stop ovn-ic, %v", err)
		return err
	}

	if azName != "" {
		if err := c.DeleteICResources(azName); err != nil {
			klog.Errorf("failed to delete ovn-ic resource on az %s: %v", azName, err)
			return err
		}
	}

	return nil
}

func (c *Controller) establishInterConnection(config map[string]string) error {
	azName := config["az-name"]
	if err := c.OVNNbClient.SetAzName(azName); err != nil {
		klog.Errorf("failed to set az name: %v", err)
		return err
	}

	if err := c.startOVNIC(config["ic-db-host"], config["ic-nb-port"], config["ic-sb-port"]); err != nil {
		klog.Errorf("failed to start ovn-ic: %v", err)
		return err
	}

	tsList, err := c.ovnLegacyClient.GetTsByAZ()
	if err != nil {
		klog.Errorf("failed to list ic logical switch: %v", err)
		return err
	}

	current := tsList[azName]
	expected := make([]string, 0, 3)
	for i := 1; i <= 3; i++ {
		expected = append(expected, fmt.Sprintf("%s-egress-%d", azName, i))
	}
	for _, tsName := range current {
		if !slices.Contains(expected, tsName) {
			if err = c.ovnLegacyClient.DelTS(tsName); err != nil {
				klog.Error(err)
				return err
			}
		}
	}
	for i, tsName := range expected {
		subnet, err := getTsSubnet(azName, i)
		if err != nil {
			klog.Errorf("failed to get subnet of ts %s: %v", tsName, err)
			return err
		}
		if err = c.ovnLegacyClient.AddTS(tsName, azName, subnet); err != nil {
			klog.Error(err)
			return err
		}
	}

	for az, tsNames := range tsList {
		if az == "" {
			continue
		}
		if len(tsNames) != 3 {
			klog.Infof("ts count of az %s is %d, skip", az, len(tsNames))
			continue
		}

		setLrpChassis := az != azName
		gwNodes := strings.Split(strings.Trim(config["gw-nodes"], ","), ",")
		sort.Strings(tsNames)

		for i, tsName := range tsNames {
			chassises := make([]string, 0, len(gwNodes))
			gwNodesOrdered := generateNewOrderGwNodes(gwNodes, i)
			for _, gw := range gwNodesOrdered {
				gw = strings.TrimSpace(gw)
				chassis, err := c.OVNSbClient.GetChassisByHost(gw)
				if err != nil {
					klog.Errorf("failed to get gw %q chassis: %v", gw, err)
					return err
				}
				if chassis.Name == "" {
					return fmt.Errorf("no chassis for gw %q", gw)
				}
				if setLrpChassis {
					chassises = append(chassises, chassis.Name)
				}

				cachedNode, err := c.nodesLister.Get(gw)
				if err != nil {
					klog.Errorf("failed to get gw node %q: %v", gw, err)
					return err
				}
				node := cachedNode.DeepCopy()
				patchPayloadTemplate := `[{"op": "%s", "path": "/metadata/labels", "value": %s}]`
				op := "replace"
				if len(node.Labels) == 0 {
					node.Labels = make(map[string]string, 1)
					op = "add"
				}
				if node.Labels[util.ICGatewayLabel] != "true" {
					node.Labels[util.ICGatewayLabel] = "true"
					raw, _ := json.Marshal(node.Labels)
					patchPayload := fmt.Sprintf(patchPayloadTemplate, op, raw)
					if _, err = c.config.KubeClient.CoreV1().Nodes().Patch(context.Background(), gw, types.JSONPatchType, []byte(patchPayload), metav1.PatchOptions{}, ""); err != nil {
						klog.Errorf("failed to patch gw node %q: %v", gw, err)
						return err
					}
				}
			}

			tsPort := fmt.Sprintf("%s-%s", tsName, azName)
			exist, err := c.OVNNbClient.LogicalSwitchPortExists(tsPort)
			if err != nil {
				klog.Errorf("failed to check logical switch port %q: %v", tsPort, err)
				return err
			}
			if exist {
				klog.Infof("ts port %s already exists", tsPort)
				continue
			}

			lrpAddr, err := c.acquireLrpAddress(tsName)
			if err != nil {
				klog.Errorf("failed to acquire lrp address for ts %q: %v", tsName, err)
				return err
			}

			lrpName := fmt.Sprintf("%s-%s", azName, tsName)
			if err := c.OVNNbClient.CreateLogicalPatchPort(tsName, c.config.ClusterRouter, tsPort, lrpName, lrpAddr, util.GenerateMac(), chassises...); err != nil {
				klog.Errorf("failed to create ovn-ic lrp %q: %v", lrpName, err)
				return err
			}
		}
	}

	return nil
}

func (c *Controller) acquireLrpAddress(ts string) (string, error) {
	cidr, err := c.ovnLegacyClient.GetTsSubnet(ts)
	if err != nil {
		klog.Errorf("failed to get ts subnet %s: %v", ts, err)
		return "", err
	}
	existAddress, err := c.listRemoteLogicalSwitchPortAddress()
	if err != nil {
		klog.Errorf("failed to list remote port address: %v", err)
		return "", err
	}

	for {
		var random string
		var ips []string
		v4Cidr, v6Cidr := util.SplitStringIP(cidr)
		if v4Cidr != "" {
			ips = append(ips, util.GenerateRandomV4IP(v4Cidr))
		}
		if v6Cidr != "" {
			ips = append(ips, util.GenerateRandomV6IP(v6Cidr))
		}
		random = strings.Join(ips, ",")
		// find a free address
		if !existAddress.Has(random) {
			return random, nil
		}
		klog.Infof("random ip %s already exists", random)
		time.Sleep(time.Second)
	}
}

func (c *Controller) startOVNIC(icHost, icNbPort, icSbPort string) error {
	// #nosec G204
	cmd := exec.Command("/usr/share/ovn/scripts/ovn-ctl",
		fmt.Sprintf("--ovn-ic-nb-db=%s", genHostAddress(icHost, icNbPort)),
		fmt.Sprintf("--ovn-ic-sb-db=%s", genHostAddress(icHost, icSbPort)),
		fmt.Sprintf("--ovn-northd-nb-db=%s", c.config.OvnNbAddr),
		fmt.Sprintf("--ovn-northd-sb-db=%s", c.config.OvnSbAddr),
		"start_ic")
	if os.Getenv("ENABLE_SSL") == "true" {
		// #nosec G204
		cmd = exec.Command("/usr/share/ovn/scripts/ovn-ctl",
			fmt.Sprintf("--ovn-ic-nb-db=%s", genHostAddress(icHost, icNbPort)),
			fmt.Sprintf("--ovn-ic-sb-db=%s", genHostAddress(icHost, icSbPort)),
			fmt.Sprintf("--ovn-northd-nb-db=%s", c.config.OvnNbAddr),
			fmt.Sprintf("--ovn-northd-sb-db=%s", c.config.OvnSbAddr),
			"--ovn-ic-ssl-key=/var/run/tls/key",
			"--ovn-ic-ssl-cert=/var/run/tls/cert",
			"--ovn-ic-ssl-ca-cert=/var/run/tls/cacert",
			"start_ic")
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("output: %s, err: %v", output, err)
	}
	return nil
}

func (c *Controller) stopOVNIC() error {
	cmd := exec.Command("/usr/share/ovn/scripts/ovn-ctl", "stop_ic")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("output: %s, err: %v", output, err)
	}
	return nil
}

func (c *Controller) delLearnedRoute() error {
	lrList, err := c.OVNNbClient.ListLogicalRouter(false, nil)
	if err != nil {
		klog.Errorf("failed to list logical routers: %v", err)
		return err
	}
	for _, lr := range lrList {
		routeList, err := c.OVNNbClient.ListLogicalRouterStaticRoutes(lr.Name, nil, nil, "", map[string]string{"ic-learned-route": ""})
		if err != nil {
			klog.Errorf("failed to list learned static routes on logical router %s: %v", lr.Name, err)
			return err
		}
		for _, r := range routeList {
			var policy ovnnb.LogicalRouterStaticRoutePolicy
			if r.Policy != nil {
				policy = *r.Policy
			}

			if err = c.deleteStaticRouteFromVpc(
				lr.Name,
				r.RouteTable,
				r.IPPrefix,
				r.Nexthop,
				reversePolicy(policy),
			); err != nil {
				klog.Errorf("failed to delete learned static route %#v on logical router %s: %v", r, lr.Name, err)
				return err
			}

		}
	}

	klog.V(5).Infof("finish removing learned routes")
	return nil
}

func (c *Controller) deleteStaticRouteFromVpc(name, table, cidr, nextHop string, policy kubeovnv1.RoutePolicy) error {
	var (
		vpc, cachedVpc *kubeovnv1.Vpc
		policyStr      string
		err            error
	)

	policyStr = convertPolicy(policy)
	if err = c.OVNNbClient.DeleteLogicalRouterStaticRoute(name, &table, &policyStr, cidr, nextHop); err != nil {
		klog.Errorf("del vpc %s static route failed, %v", name, err)
		return err
	}

	cachedVpc, err = c.vpcsLister.Get(name)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		klog.Error(err)
		return err
	}
	vpc = cachedVpc.DeepCopy()
	// make sure custom policies not be deleted
	_, err = c.config.KubeOvnClient.KubeovnV1().Vpcs().Update(context.Background(), vpc, metav1.UpdateOptions{})
	if err != nil {
		klog.Error(err)
		return err
	}
	return nil
}

func genHostAddress(host, port string) (hostAddress string) {
	hostList := strings.Split(strings.Trim(host, ","), ",")
	if len(hostList) == 1 {
		hostAddress = fmt.Sprintf("tcp:[%s]:%s", hostList[0], port)
	} else {
		var builder strings.Builder
		i := 0
		for i < len(hostList)-1 {
			builder.WriteString(fmt.Sprintf("tcp:[%s]:%s,", hostList[i], port))
			i++
		}
		builder.WriteString(fmt.Sprintf("tcp:[%s]:%s", hostList[i], port))
		hostAddress = builder.String()
	}
	return hostAddress
}

func (c *Controller) SynRouteToPolicy() {
	c.syncOneRouteToPolicy(util.OvnICKey, util.OvnICConnected)
	c.syncOneRouteToPolicy(util.OvnICKey, util.OvnICStatic)
	// To support the version before kube-ovn v1.9, in which version the option tag is origin=""
	c.syncOneRouteToPolicy(util.OvnICKey, util.OvnICNone)
}

func (c *Controller) RemoveOldChassisInSbDB(azName string) error {
	if azName == "" {
		return nil
	}

	azUUID, err := c.ovnLegacyClient.GetAzUUID(azName)
	if err != nil {
		klog.Errorf("failed to get UUID of AZ %s: %v", lastIcCm["az-name"], err)
		return err
	}

	if azUUID == "" {
		klog.Infof("%s have already been deleted", azName)
		return nil
	}

	gateways, err := c.ovnLegacyClient.GetGatewayUUIDsInOneAZ(azUUID)
	if err != nil {
		klog.Errorf("failed to get gateway UUIDs in AZ %s: %v", azUUID, err)
		return err
	}

	routes, err := c.ovnLegacyClient.GetRouteUUIDsInOneAZ(azUUID)
	if err != nil {
		klog.Errorf("failed to get route UUIDs in AZ %s: %v", azUUID, err)
		return err
	}

	portBindings, err := c.ovnLegacyClient.GetPortBindingUUIDsInOneAZ(azUUID)
	if err != nil {
		klog.Errorf("failed to get Port_Binding UUIDs in AZ %s: %v", azUUID, err)
		return err
	}

	if err := c.ovnLegacyClient.DestroyPortBindings(portBindings); err != nil {
		return err
	}

	if err := c.ovnLegacyClient.DestroyGateways(gateways); err != nil {
		return err
	}

	if err := c.ovnLegacyClient.DestroyRoutes(routes); err != nil {
		return err
	}

	return c.ovnLegacyClient.DestroyChassis(azUUID)
}

func stripPrefix(policyMatch string) (string, error) {
	matches := strings.Split(policyMatch, "==")

	switch {
	case strings.Trim(matches[0], " ") == util.MatchV4Dst:
		return strings.Trim(matches[1], " "), nil
	case strings.Trim(matches[0], " ") == util.MatchV6Dst:
		return strings.Trim(matches[1], " "), nil
	default:
		return "", fmt.Errorf("policy %s is mismatched", policyMatch)
	}
}

func (c *Controller) syncOneRouteToPolicy(key, value string) {
	lr, err := c.OVNNbClient.GetLogicalRouter(c.config.ClusterRouter, false)
	if err != nil {
		klog.Infof("logical router %s is not ready at %v", util.DefaultVpc, time.Now())
		return
	}
	lrRouteList, err := c.OVNNbClient.ListLogicalRouterStaticRoutesByOption(lr.Name, util.MainRouteTable, key, value)
	if err != nil {
		klog.Errorf("failed to list lr ovn-ic route %v", err)
		return
	}

	lrPolicyList, err := c.OVNNbClient.GetLogicalRouterPoliciesByExtID(lr.Name, key, value)
	if err != nil {
		klog.Errorf("failed to list ovn-ic lr policy: %v", err)
		return
	}

	if len(lrRouteList) == 0 {
		klog.V(5).Info("lr ovn-ic route does not exist")
		err := c.OVNNbClient.DeleteLogicalRouterPolicies(lr.Name, util.OvnICPolicyPriority, map[string]string{key: value})
		if err != nil {
			klog.Errorf("failed to delete ovn-ic lr policy: %v", err)
			return
		}
		return
	}

	policyMap := map[string]string{}

	for _, lrPolicy := range lrPolicyList {
		match, err := stripPrefix(lrPolicy.Match)
		if err != nil {
			klog.Errorf("policy match abnormal: %v", err)
			continue
		}
		policyMap[match] = lrPolicy.UUID
	}
	networks := strset.NewWithSize(len(lrRouteList))
	for _, lrRoute := range lrRouteList {
		networks.Add(lrRoute.IPPrefix)
	}

	networks.Each(func(prefix string) bool {
		if _, ok := policyMap[prefix]; ok {
			delete(policyMap, prefix)
			return true
		}
		match := util.MatchV4Dst + " == " + prefix
		if util.CheckProtocol(prefix) == kubeovnv1.ProtocolIPv6 {
			match = util.MatchV6Dst + " == " + prefix
		}

		if err = c.OVNNbClient.AddLogicalRouterPolicy(lr.Name, util.OvnICPolicyPriority, match, ovnnb.LogicalRouterPolicyActionAllow, nil, map[string]string{key: value, "vendor": util.CniTypeName}); err != nil {
			klog.Errorf("failed to add router policy: %v", err)
		}

		return true
	})
	for _, uuid := range policyMap {
		if err := c.OVNNbClient.DeleteLogicalRouterPolicyByUUID(lr.Name, uuid); err != nil {
			klog.Errorf("deleting router policy failed %v", err)
		}
	}
}

func (c *Controller) listRemoteLogicalSwitchPortAddress() (*strset.Set, error) {
	lsps, err := c.OVNNbClient.ListLogicalSwitchPorts(true, nil, func(lsp *ovnnb.LogicalSwitchPort) bool {
		return lsp.Type == "remote"
	})
	if err != nil {
		klog.Error(err)
		return nil, fmt.Errorf("list remote logical switch ports: %v", err)
	}

	existAddress := strset.NewWithSize(len(lsps))
	for _, lsp := range lsps {
		if len(lsp.Addresses) == 0 {
			continue
		}

		addresses := lsp.Addresses[0]

		fields := strings.Fields(addresses)
		if len(fields) != 2 {
			continue
		}

		existAddress.Add(fields[1])
	}

	return existAddress, nil
}

func generateNewOrderGwNodes(arr []string, order int) []string {
	if order >= len(arr) {
		order %= len(arr)
	}

	return append(arr[order:], arr[:order]...)
}

func convertPolicy(origin kubeovnv1.RoutePolicy) string {
	if origin == kubeovnv1.PolicyDst {
		return ovnnb.LogicalRouterStaticRoutePolicyDstIP
	}
	return ovnnb.LogicalRouterStaticRoutePolicySrcIP
}

func reversePolicy(origin ovnnb.LogicalRouterStaticRoutePolicy) kubeovnv1.RoutePolicy {
	if origin == ovnnb.LogicalRouterStaticRoutePolicyDstIP {
		return kubeovnv1.PolicyDst
	}
	return kubeovnv1.PolicySrc
}
