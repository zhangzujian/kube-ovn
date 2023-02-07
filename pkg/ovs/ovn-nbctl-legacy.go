package ovs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/klog/v2"

	kubeovnv1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	"github.com/kubeovn/kube-ovn/pkg/util"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var nbctlDaemonSocketRegexp = regexp.MustCompile(`^/var/run/ovn/ovn-nbctl\.[0-9]+\.ctl$`)

func (c LegacyClient) ovnNbCommand(cmdArgs ...string) (string, error) {
	start := time.Now()
	if os.Getenv("ENABLE_SSL") == "true" {
		cmdArgs = append([]string{
			fmt.Sprintf("--timeout=%d", c.OvnTimeout),
			fmt.Sprintf("--db=%s", c.OvnNbAddress),
			"--no-wait",
			"-p", "/var/run/tls/key",
			"-c", "/var/run/tls/cert",
			"-C", "/var/run/tls/cacert"}, cmdArgs...)
	} else {
		cmdArgs = append([]string{
			fmt.Sprintf("--timeout=%d", c.OvnTimeout),
			fmt.Sprintf("--db=%s", c.OvnNbAddress),
			"--no-wait",
		}, cmdArgs...)
	}

	raw, err := exec.Command(OvnNbCtl, cmdArgs...).CombinedOutput()
	elapsed := float64((time.Since(start)) / time.Millisecond)
	klog.V(4).Infof("command %s %s in %vms, output %q", OvnNbCtl, strings.Join(cmdArgs, " "), elapsed, raw)
	method := ""
	for _, arg := range cmdArgs {
		if !strings.HasPrefix(arg, "--") {
			method = arg
			break
		}
	}
	code := "0"
	defer func() {
		ovsClientRequestLatency.WithLabelValues("ovn-nb", method, code).Observe(elapsed)
	}()

	if err != nil {
		code = "1"
		klog.Warningf("ovn-nbctl command error: %s %s in %vms", OvnNbCtl, strings.Join(cmdArgs, " "), elapsed)
		return "", fmt.Errorf("%s, %q", raw, err)
	} else if elapsed > 500 {
		klog.Warningf("ovn-nbctl command took too long: %s %s in %vms", OvnNbCtl, strings.Join(cmdArgs, " "), elapsed)
	}
	return trimCommandOutput(raw), nil
}

func (c LegacyClient) GetVersion() (string, error) {
	if c.Version != "" {
		return c.Version, nil
	}
	output, err := c.ovnNbCommand("--version")
	if err != nil {
		return "", fmt.Errorf("failed to get version,%v", err)
	}
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		c.Version = strings.Split(lines[0], " ")[1]
	}
	return c.Version, nil
}

func (c LegacyClient) SetLsDnatModDlDst(enabled bool) error {
	if _, err := c.ovnNbCommand("set", "NB_Global", ".", fmt.Sprintf("options:ls_dnat_mod_dl_dst=%v", enabled)); err != nil {
		return fmt.Errorf("failed to set NB_Global option ls_dnat_mod_dl_dst to %v: %v", enabled, err)
	}
	return nil
}

func (c LegacyClient) SetLogicalSwitchConfig(ls, lr, protocol, subnet, gateway string, excludeIps []string, needRouter bool) error {
	klog.Infof("set logical switch: ls %s, lr %s, protocol %s, subnet %s, gw %s", ls, lr, protocol, subnet, gateway)
	var err error
	cidrBlocks := strings.Split(subnet, ",")
	temp := strings.Split(cidrBlocks[0], "/")
	if len(temp) != 2 {
		klog.Errorf("cidrBlock %s is invalid", cidrBlocks[0])
		return err
	}
	mask := temp[1]

	var cmd []string
	var networks string
	switch protocol {
	case kubeovnv1.ProtocolIPv4:
		networks = fmt.Sprintf("%s/%s", gateway, mask)
		cmd = []string{MayExist, "ls-add", ls}
	case kubeovnv1.ProtocolIPv6:
		gateway := strings.ReplaceAll(gateway, ":", "\\:")
		networks = fmt.Sprintf("%s/%s", gateway, mask)
		cmd = []string{MayExist, "ls-add", ls}
	case kubeovnv1.ProtocolDual:
		gws := strings.Split(gateway, ",")
		v6Mask := strings.Split(cidrBlocks[1], "/")[1]
		gwStr := gws[0] + "/" + mask + "," + gws[1] + "/" + v6Mask
		networks = strings.ReplaceAll(strings.Join(strings.Split(gwStr, ","), " "), ":", "\\:")

		cmd = []string{MayExist, "ls-add", ls}
	}
	if needRouter {
		lsTolr := fmt.Sprintf("%s-%s", ls, lr)
		lrTols := fmt.Sprintf("%s-%s", lr, ls)

		exist, err := c.LogicalSwitchPortExists(lsTolr)
		if err != nil {
			klog.Errorf("failed to get logical switch port %s to router, %v", lsTolr, err)
			return err
		}
		if !exist {
			cmd = append(cmd, []string{"--", MayExist, "lsp-add", ls, lsTolr, "--",
				"set", "logical_switch_port", lsTolr, "type=router", "--",
				"lsp-set-addresses", lsTolr, "router", "--",
				"set", "logical_switch_port", lsTolr, fmt.Sprintf("options:router-port=%s", lrTols), "--",
				"set", "logical_switch_port", lsTolr, fmt.Sprintf("external_ids:vendor=%s", util.CniTypeName)}...)
		}

		// check router port exist
		results, err := c.ListLogicalEntity("logical_router_port", fmt.Sprintf("name=%s", lrTols))
		if err != nil {
			klog.Errorf("failed to list router port %s, %v", lrTols, err)
			return err
		}
		if len(results) == 0 {
			// v6address no need add \ when use lrp-add
			networks = strings.ReplaceAll(networks, "\\:", ":")
			networkList := strings.Split(networks, " ")
			cmd = append(cmd, []string{"--", MayExist, "lrp-add", lr, lrTols, util.GenerateMac()}...)
			cmd = append(cmd, networkList...)
		} else {
			cmd = append(cmd, []string{"--",
				"set", "logical_router_port", fmt.Sprintf("%s-%s", lr, ls), fmt.Sprintf("networks=%s", networks)}...)
		}
	}
	cmd = append(cmd, []string{"--",
		"set", "logical_switch", ls, fmt.Sprintf("external_ids:vendor=%s", util.CniTypeName)}...)
	_, err = c.ovnNbCommand(cmd...)
	if err != nil {
		klog.Errorf("set switch config for %s failed: %v", ls, err)
		return err
	}
	return nil
}

// CreateLogicalSwitch create logical switch in ovn, connect it to router and apply tcp/udp lb rules
func (c LegacyClient) CreateLogicalSwitch(ls, lr, subnet, gateway string, needRouter bool) error {
	_, err := c.ovnNbCommand(MayExist, "ls-add", ls, "--",
		"set", "logical_switch", ls, fmt.Sprintf("external_ids:vendor=%s", util.CniTypeName))

	if err != nil {
		klog.Errorf("create switch %s failed: %v", ls, err)
		return err
	}

	if needRouter {
		if err := c.createRouterPort(ls, lr); err != nil {
			klog.Errorf("failed to connect switch %s to router, %v", ls, err)
			return err
		}
	}
	return nil
}

func (c LegacyClient) ConnectRouterToExternal(externalNet, vpcRouter, lrpIpCidr, lrpMac string, chassises []string) error {
	// add lrp and lsp between vpc router and external network
	lsTolr := fmt.Sprintf("%s-%s", externalNet, vpcRouter)
	lrTols := fmt.Sprintf("%s-%s", vpcRouter, externalNet)
	klog.Infof("add vpc lrp %s, cidr %s", lrTols, lrpIpCidr)
	klog.Infof("add lsp %s", lsTolr)
	_, err := c.ovnNbCommand(
		MayExist, "lrp-add", vpcRouter, lrTols, lrpMac, lrpIpCidr, "--",
		MayExist, "lsp-add", externalNet, lsTolr, "--",
		"lsp-set-type", lsTolr, "router", "--",
		"lsp-set-addresses", lsTolr, "router", "--",
		"lsp-set-options", lsTolr, fmt.Sprintf("router-port=%s", lrTols),
	)
	if err != nil {
		return fmt.Errorf("failed to connect vpc to external, %v", err)
	}
	for index, chassis := range chassises {
		if _, err := c.ovnNbCommand("lrp-set-gateway-chassis", lrTols, chassis, fmt.Sprintf("%d", 100-index)); err != nil {
			return fmt.Errorf("failed to set gateway chassis, %v", err)
		}
	}
	return nil
}

func (c LegacyClient) DisconnectRouterToExternal(externalNet, vpcRouter string) error {
	lrTols := fmt.Sprintf("%s-%s", vpcRouter, externalNet)
	klog.Infof("delete lrp %s", lrTols)
	if _, err := c.ovnNbCommand(IfExists, "lrp-del", lrTols); err != nil {
		return err
	}
	lsTolr := fmt.Sprintf("%s-%s", externalNet, vpcRouter)
	klog.Infof("delete lsp %s", lsTolr)
	if _, err := c.ovnNbCommand(IfExists, "lsp-del", lsTolr); err != nil {
		return err
	}
	return nil
}

func (c LegacyClient) ListLogicalEntity(entity string, args ...string) ([]string, error) {
	cmd := []string{"--format=csv", "--data=bare", "--no-heading", "--columns=name", "find", entity}
	cmd = append(cmd, args...)
	output, err := c.ovnNbCommand(cmd...)
	if err != nil {
		klog.Errorf("failed to list logical %s: %v", entity, err)
		return nil, err
	}
	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if len(l) > 0 {
			result = append(result, l)
		}
	}
	return result, nil
}

func (c LegacyClient) CustomFindEntity(entity string, attris []string, args ...string) (result []map[string][]string, err error) {
	result = []map[string][]string{}
	var attrStr strings.Builder
	for _, e := range attris {
		attrStr.WriteString(e)
		attrStr.WriteString(",")
	}
	// Assuming that the order of the elements in attris does not change
	cmd := []string{"--format=csv", "--data=bare", "--no-heading", fmt.Sprintf("--columns=%s", attrStr.String()), "find", entity}
	cmd = append(cmd, args...)
	output, err := c.ovnNbCommand(cmd...)
	if err != nil {
		klog.Errorf("failed to customized list logical %s: %v", entity, err)
		return nil, err
	}
	if output == "" {
		return result, nil
	}
	lines := strings.Split(output, "\n")
	for _, l := range lines {
		aResult := make(map[string][]string)
		parts := strings.Split(strings.TrimSpace(l), ",")
		for i, e := range attris {
			if aResult[e] = strings.Fields(parts[i]); aResult[e] == nil {
				aResult[e] = []string{}
			}
		}
		result = append(result, aResult)
	}
	return result, nil
}

func (c LegacyClient) LogicalSwitchPortExists(port string) (bool, error) {
	output, err := c.ovnNbCommand("--format=csv", "--data=bare", "--no-heading", "--columns=name", "find", "logical_switch_port", fmt.Sprintf("name=%s", port))
	if err != nil {
		klog.Errorf("failed to find port %s: %v, %q", port, err, output)
		return false, err
	}

	if output != "" {
		return true, nil
	}
	return false, nil
}

func (c LegacyClient) RemoveRouterPort(ls, lr string) error {
	lsTolr := fmt.Sprintf("%s-%s", ls, lr)
	lrTols := fmt.Sprintf("%s-%s", lr, ls)
	klog.Infof("remove router port %s, switch port %s", lrTols, lsTolr)
	_, err := c.ovnNbCommand(IfExists, "lsp-del", lsTolr, "--",
		IfExists, "lrp-del", lrTols)
	if err != nil {
		klog.Errorf("failed to remove router port, %v", err)
		return err
	}
	return nil
}

func (c LegacyClient) createRouterPort(ls, lr string) error {
	klog.Infof("add %s to %s", ls, lr)
	lsTolr := fmt.Sprintf("%s-%s", ls, lr)
	lrTols := fmt.Sprintf("%s-%s", lr, ls)
	_, err := c.ovnNbCommand(MayExist, "lsp-add", ls, lsTolr, "--",
		"set", "logical_switch_port", lsTolr, "type=router", "--",
		"lsp-set-addresses", lsTolr, "router", "--",
		"set", "logical_switch_port", lsTolr, fmt.Sprintf("options:router-port=%s", lrTols), "--",
		"set", "logical_switch_port", lsTolr, fmt.Sprintf("external_ids:vendor=%s", util.CniTypeName))
	if err != nil {
		klog.Errorf("failed to create switch router port %s: %v", lsTolr, err)
		return err
	}
	return nil
}

func (c LegacyClient) AddSnatRule(router, eip, ipCidr string) error {
	// failed if logicalIP externalIP(eip) is different protocol.
	if util.CheckProtocol(ipCidr) != util.CheckProtocol(eip) {
		return nil
	}
	snat := "snat"
	if eip != "" && ipCidr != "" {
		_, err := c.ovnNbCommand(MayExist, "lr-nat-add", router, snat, eip, ipCidr)
		return err
	} else {
		return fmt.Errorf("logical ip, external ip and logical mac must be provided to add snat rule")
	}
}

func (c LegacyClient) DeleteSnatRule(router, eip, ipCidr string) error {
	snat := "snat"
	output, err := c.ovnNbCommand("--format=csv", "--no-heading", "--data=bare", "--columns=type,external_ip", "find", "NAT", fmt.Sprintf("logical_ip=%s", ipCidr))
	if err != nil {
		klog.Errorf("failed to list nat rules, %v", err)
		return err
	}
	rules := strings.Split(output, "\n")
	for _, rule := range rules {
		if len(strings.Split(rule, ",")) != 2 {
			continue
		}
		policy, externalIP := strings.Split(rule, ",")[0], strings.Split(rule, ",")[1]
		if externalIP == eip && policy == snat {
			if _, err := c.ovnNbCommand(IfExists, "lr-nat-del", router, snat, ipCidr); err != nil {
				klog.Errorf("failed to delete snat rule, %v", err)
				return err
			}
		}
	}
	return err
}

// DeleteStaticRoute delete a static route rule in ovn
func (c LegacyClient) DeleteStaticRoute(cidr, router string) error {
	if cidr == "" {
		return nil
	}
	for _, cidrBlock := range strings.Split(cidr, ",") {
		if _, err := c.ovnNbCommand(IfExists, "lr-route-del", router, cidrBlock); err != nil {
			klog.Errorf("fail to delete static route %s from %s, %v", cidrBlock, router, err)
			return err
		}
	}

	return nil
}

// FindLoadbalancer find ovn loadbalancer uuid by name
func (c LegacyClient) FindLoadbalancer(lb string) (string, error) {
	output, err := c.ovnNbCommand("--data=bare", "--no-heading", "--columns=_uuid",
		"find", "load_balancer", fmt.Sprintf("name=%s", lb))
	count := len(strings.FieldsFunc(output, func(c rune) bool { return c == '\n' }))
	if count > 1 {
		klog.Errorf("%s has %d lb entries", lb, count)
		return "", fmt.Errorf("%s has %d lb entries", lb, count)
	}
	return output, err
}

// CreateLoadBalancer create loadbalancer in ovn
func (c LegacyClient) CreateLoadBalancer(lb, protocol, selectFields string) error {
	var err error
	if selectFields == "" {
		_, err = c.ovnNbCommand("create", "load_balancer",
			fmt.Sprintf("name=%s", lb), fmt.Sprintf("protocol=%s", protocol))
	} else {
		_, err = c.ovnNbCommand("create", "load_balancer",
			fmt.Sprintf("name=%s", lb), fmt.Sprintf("protocol=%s", protocol), fmt.Sprintf("selection_fields=%s", selectFields))
	}

	return err
}

// SetLoadBalancerAffinityTimeout sets the LB's affinity timeout in seconds
func (c LegacyClient) SetLoadBalancerAffinityTimeout(lb string, timeout int) error {
	output, err := c.ovnNbCommand("set", "load_balancer", lb, fmt.Sprintf("options:affinity_timeout=%d", timeout))
	if err != nil {
		klog.Errorf("failed to set affinity timeout of LB %s to %d, error: %v, output: %s", lb, timeout, err, output)
		return err
	}
	return nil
}

// CreateLoadBalancerRule create loadbalancer rul in ovn
func (c LegacyClient) CreateLoadBalancerRule(lb, vip, ips, protocol string) error {
	_, err := c.ovnNbCommand(MayExist, "lb-add", lb, vip, ips, strings.ToLower(protocol))
	return err
}

// DeleteLoadBalancerVip delete a vip rule from loadbalancer
func (c LegacyClient) DeleteLoadBalancerVip(vip, lb string) error {
	lbUuid, err := c.FindLoadbalancer(lb)
	if err != nil {
		klog.Errorf("failed to get lb: %v", err)
		return err
	}

	existVips, err := c.GetLoadBalancerVips(lbUuid)
	if err != nil {
		klog.Errorf("failed to list lb %s vips: %v", lb, err)
		return err
	}
	// vip is empty or delete last rule will destroy the loadbalancer
	if vip == "" || len(existVips) == 1 {
		return nil
	}
	_, err = c.ovnNbCommand(IfExists, "lb-del", lb, vip)
	return err
}

// GetLoadBalancerVips return vips of a loadbalancer
func (c LegacyClient) GetLoadBalancerVips(lb string) (map[string]string, error) {
	output, err := c.ovnNbCommand("--data=bare", "--no-heading",
		"get", "load_balancer", lb, "vips")
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	err = json.Unmarshal([]byte(strings.Replace(output, "=", ":", -1)), &result)
	return result, err
}

// CleanLogicalSwitchAcl clean acl of a switch
func (c LegacyClient) CleanLogicalSwitchAcl(ls string) error {
	_, err := c.ovnNbCommand("acl-del", ls)
	return err
}

// ResetLogicalSwitchAcl reset acl of a switch
func (c LegacyClient) ResetLogicalSwitchAcl(ls string) error {
	_, err := c.ovnNbCommand("acl-del", ls)
	return err
}

// SetPrivateLogicalSwitch will drop all ingress traffic except allow subnets
func (c LegacyClient) SetPrivateLogicalSwitch(ls, cidr string, allow []string) error {
	ovnArgs := []string{"acl-del", ls}
	trimName := ls
	if len(ls) > 63 {
		trimName = ls[:63]
	}
	dropArgs := []string{"--", "--log", fmt.Sprintf("--name=%s", trimName), fmt.Sprintf("--severity=%s", "warning"), "acl-add", ls, "to-lport", util.DefaultDropPriority, "ip", "drop"}
	ovnArgs = append(ovnArgs, dropArgs...)

	for _, cidrBlock := range strings.Split(cidr, ",") {
		allowArgs := []string{}
		protocol := util.CheckProtocol(cidrBlock)
		if protocol == kubeovnv1.ProtocolIPv4 {
			allowArgs = append(allowArgs, "--", MayExist, "acl-add", ls, "to-lport", util.SubnetAllowPriority, fmt.Sprintf(`ip4.src==%s && ip4.dst==%s`, cidrBlock, cidrBlock), "allow-related")
		} else if protocol == kubeovnv1.ProtocolIPv6 {
			allowArgs = append(allowArgs, "--", MayExist, "acl-add", ls, "to-lport", util.SubnetAllowPriority, fmt.Sprintf(`ip6.src==%s && ip6.dst==%s`, cidrBlock, cidrBlock), "allow-related")
		} else {
			klog.Errorf("the cidrBlock: %s format is error in subnet: %s", cidrBlock, ls)
			continue
		}

		for _, nodeCidrBlock := range strings.Split(c.NodeSwitchCIDR, ",") {
			if protocol != util.CheckProtocol(nodeCidrBlock) {
				continue
			}

			if protocol == kubeovnv1.ProtocolIPv4 {
				allowArgs = append(allowArgs, "--", MayExist, "acl-add", ls, "to-lport", util.NodeAllowPriority, fmt.Sprintf("ip4.src==%s", nodeCidrBlock), "allow-related")
			} else if protocol == kubeovnv1.ProtocolIPv6 {
				allowArgs = append(allowArgs, "--", MayExist, "acl-add", ls, "to-lport", util.NodeAllowPriority, fmt.Sprintf("ip6.src==%s", nodeCidrBlock), "allow-related")
			}
		}

		for _, subnet := range allow {
			if strings.TrimSpace(subnet) != "" {
				allowProtocol := util.CheckProtocol(strings.TrimSpace(subnet))
				if allowProtocol != protocol {
					continue
				}

				var match string
				switch protocol {
				case kubeovnv1.ProtocolIPv4:
					match = fmt.Sprintf("(ip4.src==%s && ip4.dst==%s) || (ip4.src==%s && ip4.dst==%s)", strings.TrimSpace(subnet), cidrBlock, cidrBlock, strings.TrimSpace(subnet))
				case kubeovnv1.ProtocolIPv6:
					match = fmt.Sprintf("(ip6.src==%s && ip6.dst==%s) || (ip6.src==%s && ip6.dst==%s)", strings.TrimSpace(subnet), cidrBlock, cidrBlock, strings.TrimSpace(subnet))
				}

				allowArgs = append(allowArgs, "--", MayExist, "acl-add", ls, "to-lport", util.SubnetAllowPriority, match, "allow-related")
			}
		}
		ovnArgs = append(ovnArgs, allowArgs...)
	}
	_, err := c.ovnNbCommand(ovnArgs...)
	return err
}

func (c LegacyClient) GetLogicalSwitchPortAddress(port string) ([]string, error) {
	output, err := c.ovnNbCommand("get", "logical_switch_port", port, "addresses")
	if err != nil {
		klog.Errorf("get port %s addresses failed: %v", port, err)
		return nil, err
	}
	if strings.Contains(output, "dynamic") {
		// [dynamic]
		return nil, nil
	}
	output = strings.Trim(output, `[]"`)
	fields := strings.Fields(output)
	if len(fields) != 2 {
		return nil, nil
	}

	// currently user may only have one fixed address
	// ["0a:00:00:00:00:0c 10.16.0.13"]
	return fields, nil
}

func (c LegacyClient) GetLogicalSwitchPortDynamicAddress(port string) ([]string, error) {
	output, err := c.ovnNbCommand("wait-until", "logical_switch_port", port, "dynamic_addresses!=[]", "--",
		"get", "logical_switch_port", port, "dynamic-addresses")
	if err != nil {
		klog.Errorf("get port %s dynamic_addresses failed: %v", port, err)
		return nil, err
	}
	if output == "[]" {
		return nil, ErrNoAddr
	}
	output = strings.Trim(output, `"`)
	// "0a:00:00:00:00:02"
	fields := strings.Fields(output)
	if len(fields) != 2 {
		klog.Error("Subnet address space has been exhausted")
		return nil, ErrNoAddr
	}
	// "0a:00:00:00:00:02 100.64.0.3"
	return fields, nil
}

// GetPortAddr return port [mac, ip]
func (c LegacyClient) GetPortAddr(port string) ([]string, error) {
	var address []string
	var err error
	address, err = c.GetLogicalSwitchPortAddress(port)
	if err != nil {
		return nil, err
	}
	if address == nil {
		address, err = c.GetLogicalSwitchPortDynamicAddress(port)
		if err != nil {
			return nil, err
		}
	}
	return address, nil
}

func (c LegacyClient) CreateNpPortGroup(pgName, npNs, npName string) error {
	output, err := c.ovnNbCommand(
		"--data=bare", "--no-heading", "--columns=_uuid", "find", "port_group", fmt.Sprintf("name=%s", pgName))
	if err != nil {
		klog.Errorf("failed to find port_group %s: %v, %q", pgName, err, output)
		return err
	}
	if output != "" {
		return nil
	}
	_, err = c.ovnNbCommand(
		"pg-add", pgName,
		"--", "set", "port_group", pgName, fmt.Sprintf("external_ids:np=%s/%s", npNs, npName),
	)
	return err
}

func (c LegacyClient) DeletePortGroup(pgName string) error {
	output, err := c.ovnNbCommand(
		"--data=bare", "--no-heading", "--columns=_uuid", "find", "port_group", fmt.Sprintf("name=%s", pgName))
	if err != nil {
		klog.Errorf("failed to find port_group %s: %v, %q", pgName, err, output)
		return err
	}
	if output == "" {
		return nil
	}

	_, err = c.ovnNbCommand("pg-del", pgName)
	return err
}

type portGroup struct {
	Name        string
	NpName      string
	NpNamespace string
}

func (c LegacyClient) ListNpPortGroup() ([]portGroup, error) {
	output, err := c.ovnNbCommand("--data=bare", "--format=csv", "--no-heading", "--columns=name,external_ids", "find", "port_group", "external_ids:np!=[]")
	if err != nil {
		klog.Errorf("failed to list logical port-group, %v", err)
		return nil, err
	}
	lines := strings.Split(output, "\n")
	result := make([]portGroup, 0, len(lines))
	for _, l := range lines {
		if len(strings.TrimSpace(l)) == 0 {
			continue
		}
		parts := strings.Split(strings.TrimSpace(l), ",")
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		np := strings.Split(strings.TrimPrefix(strings.TrimSpace(parts[1]), "np="), "/")
		if len(np) != 2 {
			continue
		}
		result = append(result, portGroup{Name: name, NpNamespace: np[0], NpName: np[1]})
	}
	return result, nil
}

func (c LegacyClient) CreateAddressSet(name string) error {
	output, err := c.ovnNbCommand("--data=bare", "--no-heading", "--columns=_uuid", "find", "address_set", fmt.Sprintf("name=%s", name))
	if err != nil {
		klog.Errorf("failed to find address_set %s: %v, %q", name, err, output)
		return err
	}
	if output != "" {
		return nil
	}
	_, err = c.ovnNbCommand("create", "address_set", fmt.Sprintf("name=%s", name), fmt.Sprintf("external_ids:vendor=%s", util.CniTypeName))
	return err
}

func (c LegacyClient) CreateAddressSetWithAddresses(name string, addresses ...string) error {
	output, err := c.ovnNbCommand("--data=bare", "--no-heading", "--columns=_uuid", "find", "address_set", fmt.Sprintf("name=%s", name))
	if err != nil {
		klog.Errorf("failed to find address_set %s: %v, %q", name, err, output)
		return err
	}

	var args []string
	argAddrs := strings.ReplaceAll(strings.Join(addresses, ","), ":", `\:`)
	if output == "" {
		args = []string{"create", "address_set", fmt.Sprintf("name=%s", name), fmt.Sprintf("external_ids:vendor=%s", util.CniTypeName)}
		if argAddrs != "" {
			args = append(args, fmt.Sprintf("addresses=%s", argAddrs))
		}
	} else {
		args = []string{"clear", "address_set", name, "addresses"}
		if argAddrs != "" {
			args = append(args, "--", "set", "address_set", name, "addresses", argAddrs)
		}
	}

	_, err = c.ovnNbCommand(args...)
	return err
}

func (c LegacyClient) AddAddressSetAddresses(name string, address string) error {
	output, err := c.ovnNbCommand("add", "address_set", name, "addresses", strings.ReplaceAll(address, ":", `\:`))
	if err != nil {
		klog.Errorf("failed to add address %s to address_set %s: %v, %q", address, name, err, output)
		return err
	}
	return nil
}

func (c LegacyClient) RemoveAddressSetAddresses(name string, address string) error {
	output, err := c.ovnNbCommand("remove", "address_set", name, "addresses", strings.ReplaceAll(address, ":", `\:`))
	if err != nil {
		klog.Errorf("failed to remove address %s from address_set %s: %v, %q", address, name, err, output)
		return err
	}
	return nil
}

func (c LegacyClient) DeleteAddressSet(name string) error {
	_, err := c.ovnNbCommand(IfExists, "destroy", "address_set", name)
	return err
}

func (c LegacyClient) ListNpAddressSet(npNamespace, npName, direction string) ([]string, error) {
	output, err := c.ovnNbCommand("--data=bare", "--no-heading", "--columns=name", "find", "address_set", fmt.Sprintf("external_ids:np=%s/%s/%s", npNamespace, npName, direction))
	if err != nil {
		klog.Errorf("failed to list address_set of %s/%s/%s: %v, %q", npNamespace, npName, direction, err, output)
		return nil, err
	}
	return strings.Split(output, "\n"), nil
}

func (c LegacyClient) ListAddressesByName(addressSetName string) ([]string, error) {
	output, err := c.ovnNbCommand("--data=bare", "--no-heading", "--columns=addresses", "find", "address_set", fmt.Sprintf("name=%s", addressSetName))
	if err != nil {
		klog.Errorf("failed to list address_set of %s, error %v", addressSetName, err)
		return nil, err
	}

	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))
	for _, l := range lines {
		if len(strings.TrimSpace(l)) == 0 {
			continue
		}
		result = append(result, strings.Fields(l)...)
	}
	return result, nil
}

func (c LegacyClient) CreateNpAddressSet(asName, npNamespace, npName, direction string) error {
	output, err := c.ovnNbCommand("--data=bare", "--no-heading", "--columns=_uuid", "find", "address_set", fmt.Sprintf("name=%s", asName))
	if err != nil {
		klog.Errorf("failed to find address_set %s: %v, %q", asName, err, output)
		return err
	}
	if output != "" {
		return nil
	}
	_, err = c.ovnNbCommand("create", "address_set", fmt.Sprintf("name=%s", asName), fmt.Sprintf("external_ids:np=%s/%s/%s", npNamespace, npName, direction))
	return err
}

func (c LegacyClient) CombineIngressACLCmd(pgName, asIngressName, asExceptName, protocol string, npp []netv1.NetworkPolicyPort, logEnable bool, aclCmds []string, index int, namedPortMap map[string]*util.NamedPortInfo) []string {
	var allowArgs, ovnArgs []string

	ipSuffix := "ip4"
	if protocol == kubeovnv1.ProtocolIPv6 {
		ipSuffix = "ip6"
	}
	id := pgName + "_" + ipSuffix

	if logEnable {
		ovnArgs = []string{"--", fmt.Sprintf("--id=@%s.drop.%d", id, index), "create", "acl", "action=drop", "direction=to-lport", "log=true", "severity=warning", fmt.Sprintf("priority=%s", util.IngressDefaultDrop), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("outport==@%s && ip", pgName)), "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.drop.%d", id, index)}
	} else {
		ovnArgs = []string{"--", fmt.Sprintf("--id=@%s.drop.%d", id, index), "create", "acl", "action=drop", "direction=to-lport", "log=false", fmt.Sprintf("priority=%s", util.IngressDefaultDrop), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("outport==@%s && ip", pgName)), "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.drop.%d", id, index)}
	}

	if len(npp) == 0 {
		allowArgs = []string{"--", fmt.Sprintf("--id=@%s.noport.%d", id, index), "create", "acl", "action=allow-related", "direction=to-lport", fmt.Sprintf("priority=%s", util.IngressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.src == $%s && %s.src != $%s && outport==@%s && ip", ipSuffix, asIngressName, ipSuffix, asExceptName, pgName)), "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.noport.%d", id, index)}
		ovnArgs = append(ovnArgs, allowArgs...)
	} else {
		for pidx, port := range npp {
			if port.Port != nil {
				if port.EndPort != nil {
					allowArgs = []string{"--", fmt.Sprintf("--id=@%s.%d.port.%d", id, index, pidx), "create", "acl", "action=allow-related", "direction=to-lport", fmt.Sprintf("priority=%s", util.IngressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.src == $%s && %s.src != $%s && %d <= %s.dst <= %d && outport==@%s && ip", ipSuffix, asIngressName, ipSuffix, asExceptName, port.Port.IntVal, strings.ToLower(string(*port.Protocol)), *port.EndPort, pgName)), "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.%d.port.%d", id, index, pidx)}
				} else {
					if port.Port.Type == intstr.Int {
						allowArgs = []string{"--", fmt.Sprintf("--id=@%s.%d.port.%d", id, index, pidx), "create", "acl", "action=allow-related", "direction=to-lport", fmt.Sprintf("priority=%s", util.IngressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.src == $%s && %s.src != $%s && %s.dst == %d && outport==@%s && ip", ipSuffix, asIngressName, ipSuffix, asExceptName, strings.ToLower(string(*port.Protocol)), port.Port.IntVal, pgName)), "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.%d.port.%d", id, index, pidx)}
					} else {
						var portId int32 = 0
						if namedPortMap != nil {
							_, ok := namedPortMap[port.Port.StrVal]
							if !ok {
								// for cyclonus network policy test case 'should allow ingress access on one named port'
								// this case expect all-deny if no named port defined
								klog.Errorf("no named port with name %s found ", port.Port.StrVal)
							} else {
								portId = namedPortMap[port.Port.StrVal].PortId
							}
						}
						allowArgs = []string{"--", fmt.Sprintf("--id=@%s.%d.port.%d", id, index, pidx), "create", "acl", "action=allow-related", "direction=to-lport", fmt.Sprintf("priority=%s", util.IngressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.src == $%s && %s.src != $%s && %s.dst == %d && outport==@%s && ip", ipSuffix, asIngressName, ipSuffix, asExceptName, strings.ToLower(string(*port.Protocol)), portId, pgName)), "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.%d.port.%d", id, index, pidx)}
					}
				}
			} else {
				allowArgs = []string{"--", fmt.Sprintf("--id=@%s.%d.port.%d", id, index, pidx), "create", "acl", "action=allow-related", "direction=to-lport", fmt.Sprintf("priority=%s", util.IngressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.src == $%s && %s.src != $%s && %s && outport==@%s && ip", ipSuffix, asIngressName, ipSuffix, asExceptName, strings.ToLower(string(*port.Protocol)), pgName)), "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.%d.port.%d", id, index, pidx)}
			}
			ovnArgs = append(ovnArgs, allowArgs...)
		}
	}
	aclCmds = append(aclCmds, ovnArgs...)
	return aclCmds
}

func (c LegacyClient) CreateACL(aclCmds []string) error {
	_, err := c.ovnNbCommand(aclCmds...)
	return err
}

func (c LegacyClient) CombineEgressACLCmd(pgName, asEgressName, asExceptName, protocol string, npp []netv1.NetworkPolicyPort, logEnable bool, aclCmds []string, index int, namedPortMap map[string]*util.NamedPortInfo) []string {
	var allowArgs, ovnArgs []string

	ipSuffix := "ip4"
	if protocol == kubeovnv1.ProtocolIPv6 {
		ipSuffix = "ip6"
	}
	id := pgName + "_" + ipSuffix

	if logEnable {
		ovnArgs = []string{"--", fmt.Sprintf("--id=@%s.drop.%d", id, index), "create", "acl", "action=drop", "direction=from-lport", "log=true", "severity=warning", fmt.Sprintf("priority=%s", util.EgressDefaultDrop), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("inport==@%s && ip", pgName)), "options={apply-after-lb=\"true\"}", "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.drop.%d", id, index)}
	} else {
		ovnArgs = []string{"--", fmt.Sprintf("--id=@%s.drop.%d", id, index), "create", "acl", "action=drop", "direction=from-lport", "log=false", fmt.Sprintf("priority=%s", util.EgressDefaultDrop), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("inport==@%s && ip", pgName)), "options={apply-after-lb=\"true\"}", "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.drop.%d", id, index)}
	}

	if ipSuffix == "ip6" {
		ovnArgs = append(ovnArgs, []string{"--", fmt.Sprintf("--id=@%s.ip6nd.%d", id, index), "create", "acl", "action=allow-related", "direction=from-lport", fmt.Sprintf("priority=%s", util.EgressAllowPriority), "match=\"nd || nd_ra || nd_rs\"", "options={apply-after-lb=\"true\"}", "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.ip6nd.%d", id, index)}...)
	}

	if len(npp) == 0 {
		allowArgs = []string{"--", fmt.Sprintf("--id=@%s.noport.%d", id, index), "create", "acl", "action=allow-related", "direction=from-lport", fmt.Sprintf("priority=%s", util.EgressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.dst == $%s && %s.dst != $%s && inport==@%s && ip", ipSuffix, asEgressName, ipSuffix, asExceptName, pgName)), "options={apply-after-lb=\"true\"}", "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.noport.%d", id, index)}
		ovnArgs = append(ovnArgs, allowArgs...)
	} else {
		for pidx, port := range npp {
			if port.Port != nil {
				if port.EndPort != nil {
					allowArgs = []string{"--", fmt.Sprintf("--id=@%s.%d.port.%d", id, index, pidx), "create", "acl", "action=allow-related", "direction=from-lport", fmt.Sprintf("priority=%s", util.EgressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.dst == $%s && %s.dst != $%s && %d <= %s.dst <= %d && inport==@%s && ip", ipSuffix, asEgressName, ipSuffix, asExceptName, port.Port.IntVal, strings.ToLower(string(*port.Protocol)), *port.EndPort, pgName)), "options={apply-after-lb=\"true\"}", "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.%d.port.%d", id, index, pidx)}
				} else {
					if port.Port.Type == intstr.Int {
						allowArgs = []string{"--", fmt.Sprintf("--id=@%s.%d.port.%d", id, index, pidx), "create", "acl", "action=allow-related", "direction=from-lport", fmt.Sprintf("priority=%s", util.EgressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.dst == $%s && %s.dst != $%s && %s.dst == %d && inport==@%s && ip", ipSuffix, asEgressName, ipSuffix, asExceptName, strings.ToLower(string(*port.Protocol)), port.Port.IntVal, pgName)), "options={apply-after-lb=\"true\"}", "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.%d.port.%d", id, index, pidx)}
					} else {
						var portId int32 = 0
						if namedPortMap != nil {
							_, ok := namedPortMap[port.Port.StrVal]
							if !ok {
								klog.Errorf("no named port with name %s found ", port.Port.StrVal)
							} else {
								portId = namedPortMap[port.Port.StrVal].PortId
							}
						}
						allowArgs = []string{"--", fmt.Sprintf("--id=@%s.%d.port.%d", id, index, pidx), "create", "acl", "action=allow-related", "direction=from-lport", fmt.Sprintf("priority=%s", util.EgressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.dst == $%s && %s.dst != $%s && %s.dst == %d && inport==@%s && ip", ipSuffix, asEgressName, ipSuffix, asExceptName, strings.ToLower(string(*port.Protocol)), portId, pgName)), "options={apply-after-lb=\"true\"}", "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.%d.port.%d", id, index, pidx)}
					}
				}
			} else {
				allowArgs = []string{"--", fmt.Sprintf("--id=@%s.%d.port.%d", id, index, pidx), "create", "acl", "action=allow-related", "direction=from-lport", fmt.Sprintf("priority=%s", util.EgressAllowPriority), fmt.Sprintf("match=\"%s\"", fmt.Sprintf("%s.dst == $%s && %s.dst != $%s && %s && inport==@%s && ip", ipSuffix, asEgressName, ipSuffix, asExceptName, strings.ToLower(string(*port.Protocol)), pgName)), "options={apply-after-lb=\"true\"}", "--", "add", "port-group", pgName, "acls", fmt.Sprintf("@%s.%d.port.%d", id, index, pidx)}
			}
			ovnArgs = append(ovnArgs, allowArgs...)
		}
	}
	aclCmds = append(aclCmds, ovnArgs...)
	return aclCmds
}

func (c LegacyClient) DeleteACL(pgName, direction string) (err error) {
	if _, err := c.ovnNbCommand("get", "port_group", pgName, "_uuid"); err != nil {
		if strings.Contains(err.Error(), "no row") {
			return nil
		}
		klog.Errorf("failed to get pg %s, %v", pgName, err)
		return err
	}

	if direction != "" {
		_, err = c.ovnNbCommand("--type=port-group", "acl-del", pgName, direction)
	} else {
		_, err = c.ovnNbCommand("--type=port-group", "acl-del", pgName)
	}
	return
}

func (c LegacyClient) CreateGatewayACL(pgName, gateway, cidr string) error {
	for _, cidrBlock := range strings.Split(cidr, ",") {
		for _, gw := range strings.Split(gateway, ",") {
			if util.CheckProtocol(cidrBlock) != util.CheckProtocol(gw) {
				continue
			}
			protocol := util.CheckProtocol(cidrBlock)
			ipSuffix := "ip4"
			if protocol == kubeovnv1.ProtocolIPv6 {
				ipSuffix = "ip6"
			}
			ingressArgs := []string{MayExist, "--type=port-group", "acl-add", pgName, "to-lport", util.IngressAllowPriority, fmt.Sprintf("%s.src == %s", ipSuffix, gw), "allow-related"}
			egressArgs := []string{"--", MayExist, "--type=port-group", "--apply-after-lb", "acl-add", pgName, "from-lport", util.EgressAllowPriority, fmt.Sprintf("%s.dst == %s", ipSuffix, gw), "allow-related"}
			ovnArgs := append(ingressArgs, egressArgs...)
			if _, err := c.ovnNbCommand(ovnArgs...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c LegacyClient) CreateACLForNodePg(pgName, nodeIpStr, joinIpStr string) error {
	nodeIPs := strings.Split(nodeIpStr, ",")
	for _, nodeIp := range nodeIPs {
		protocol := util.CheckProtocol(nodeIp)
		ipSuffix := "ip4"
		if protocol == kubeovnv1.ProtocolIPv6 {
			ipSuffix = "ip6"
		}
		pgAs := fmt.Sprintf("%s_%s", pgName, ipSuffix)

		ingressArgs := []string{MayExist, "--type=port-group", "acl-add", pgName, "to-lport", util.NodeAllowPriority, fmt.Sprintf("%s.src == %s && %s.dst == $%s", ipSuffix, nodeIp, ipSuffix, pgAs), "allow-related"}
		egressArgs := []string{"--", MayExist, "--type=port-group", "--apply-after-lb", "acl-add", pgName, "from-lport", util.NodeAllowPriority, fmt.Sprintf("%s.dst == %s && %s.src == $%s", ipSuffix, nodeIp, ipSuffix, pgAs), "allow-related"}
		ovnArgs := append(ingressArgs, egressArgs...)
		if _, err := c.ovnNbCommand(ovnArgs...); err != nil {
			klog.Errorf("failed to add node port-group acl: %v", err)
			return err
		}
	}
	for _, joinIp := range strings.Split(joinIpStr, ",") {
		if util.ContainsString(nodeIPs, joinIp) {
			continue
		}

		protocol := util.CheckProtocol(joinIp)
		ipSuffix := "ip4"
		if protocol == kubeovnv1.ProtocolIPv6 {
			ipSuffix = "ip6"
		}
		pgAs := fmt.Sprintf("%s_%s", pgName, ipSuffix)

		ingressArgs := []string{"acl-del", pgName, "to-lport", util.NodeAllowPriority, fmt.Sprintf("%s.src == %s && %s.dst == $%s", ipSuffix, joinIp, ipSuffix, pgAs)}
		egressArgs := []string{"--", "acl-del", pgName, "from-lport", util.NodeAllowPriority, fmt.Sprintf("%s.dst == %s && %s.src == $%s", ipSuffix, joinIp, ipSuffix, pgAs)}
		ovnArgs := append(ingressArgs, egressArgs...)
		if _, err := c.ovnNbCommand(ovnArgs...); err != nil {
			klog.Errorf("failed to delete node port-group acl: %v", err)
			return err
		}
	}

	return nil
}

func (c LegacyClient) DeleteAclForNodePg(pgName string) error {
	ingressArgs := []string{"acl-del", pgName, "to-lport"}
	if _, err := c.ovnNbCommand(ingressArgs...); err != nil {
		klog.Errorf("failed to delete node port-group ingress acl: %v", err)
		return err
	}

	egressArgs := []string{"acl-del", pgName, "from-lport"}
	if _, err := c.ovnNbCommand(egressArgs...); err != nil {
		klog.Errorf("failed to delete node port-group egress acl: %v", err)
		return err
	}

	return nil
}

func (c LegacyClient) SetAddressesToAddressSet(addresses []string, as string) error {
	ovnArgs := []string{"clear", "address_set", as, "addresses"}
	if len(addresses) > 0 {
		var newAddrs []string
		for _, addr := range addresses {
			if util.CheckProtocol(addr) == kubeovnv1.ProtocolIPv6 {
				newAddr := strings.ReplaceAll(addr, ":", "\\:")
				newAddrs = append(newAddrs, newAddr)
			} else {
				newAddrs = append(newAddrs, addr)
			}
		}
		ovnArgs = append(ovnArgs, "--", "add", "address_set", as, "addresses")
		ovnArgs = append(ovnArgs, newAddrs...)
	}
	_, err := c.ovnNbCommand(ovnArgs...)
	return err
}

// StartOvnNbctlDaemon start a daemon and set OVN_NB_DAEMON env
func StartOvnNbctlDaemon(ovnNbAddr string) error {
	klog.Infof("start ovn-nbctl daemon")
	output, err := exec.Command(
		"pkill",
		"-f",
		"ovn-nbctl",
	).CombinedOutput()
	if err != nil {
		klog.Errorf("failed to kill old ovn-nbctl daemon: %q", output)
		return err
	}
	command := []string{
		fmt.Sprintf("--db=%s", ovnNbAddr),
		"--pidfile",
		"--detach",
		"--overwrite-pidfile",
	}
	if os.Getenv("ENABLE_SSL") == "true" {
		command = []string{
			"-p", "/var/run/tls/key",
			"-c", "/var/run/tls/cert",
			"-C", "/var/run/tls/cacert",
			fmt.Sprintf("--db=%s", ovnNbAddr),
			"--pidfile",
			"--detach",
			"--overwrite-pidfile",
		}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("ovn-nbctl", command...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err = cmd.Run(); err != nil {
		klog.Errorf("failed to start ovn-nbctl daemon: %v, %s, %s", err, stdout.String(), stderr.String())
		return err
	}

	daemonSocket := strings.TrimSpace(stdout.String())
	if !nbctlDaemonSocketRegexp.MatchString(daemonSocket) {
		err = fmt.Errorf("invalid nbctl daemon socket: %q", daemonSocket)
		klog.Error(err)
		return err
	}

	_ = os.Unsetenv("OVN_NB_DAEMON")
	if err := os.Setenv("OVN_NB_DAEMON", daemonSocket); err != nil {
		klog.Errorf("failed to set env OVN_NB_DAEMON, %v", err)
		return err
	}
	return nil
}

// CheckAlive check if kube-ovn-controller can access ovn-nb from nbctl-daemon
func CheckAlive() error {
	var stderr bytes.Buffer
	cmd := exec.Command("ovn-nbctl", "--timeout=60", "show")
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		klog.Errorf("failed to access ovn-nb from daemon: %v, %s", err, stderr.String())
		return err
	}
	return nil
}

// GetLogicalSwitchExcludeIPS get a logical switch exclude ips
// ovn-nbctl get logical_switch ovn-default other_config:exclude_ips => "10.17.0.1 10.17.0.2 10.17.0.3..10.17.0.5"
func (c LegacyClient) GetLogicalSwitchExcludeIPS(logicalSwitch string) ([]string, error) {
	output, err := c.ovnNbCommand(IfExists, "get", "logical_switch", logicalSwitch, "other_config:exclude_ips")
	if err != nil {
		return nil, err
	}
	output = strings.Trim(output, `"`)
	if output == "" {
		return nil, ErrNoAddr
	}
	return strings.Fields(output), nil
}

// SetLogicalSwitchExcludeIPS set a logical switch exclude ips
// ovn-nbctl set logical_switch ovn-default other_config:exclude_ips="10.17.0.2 10.17.0.1"
func (c LegacyClient) SetLogicalSwitchExcludeIPS(logicalSwitch string, excludeIPS []string) error {
	_, err := c.ovnNbCommand("set", "logical_switch", logicalSwitch,
		fmt.Sprintf(`other_config:exclude_ips="%s"`, strings.Join(excludeIPS, " ")))
	return err
}

func (c LegacyClient) GetLogicalSwitchPortByLogicalSwitch(logicalSwitch string) ([]string, error) {
	output, err := c.ovnNbCommand("lsp-list", logicalSwitch)
	if err != nil {
		return nil, err
	}
	var rv []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lsp := strings.Fields(line)[0]
		rv = append(rv, lsp)
	}
	return rv, nil
}

func (c LegacyClient) CreateLocalnetPort(ls, port, provider string, vlanID int) error {
	cmdArg := []string{
		MayExist, "lsp-add", ls, port, "--",
		"lsp-set-addresses", port, "unknown", "--",
		"lsp-set-type", port, "localnet", "--",
		"lsp-set-options", port, fmt.Sprintf("network_name=%s", provider), "--",
		"set", "logical_switch_port", port, fmt.Sprintf("external_ids:vendor=%s", util.CniTypeName),
	}
	if vlanID > 0 && vlanID < 4096 {
		cmdArg = append(cmdArg,
			"--", "set", "logical_switch_port", port, fmt.Sprintf("tag=%d", vlanID))
	}

	if _, err := c.ovnNbCommand(cmdArg...); err != nil {
		klog.Errorf("create localnet port %s failed, %v", port, err)
		return err
	}

	return nil
}

func (c LegacyClient) CreateSgPortGroup(sgName string) error {
	sgPortGroupName := GetSgPortGroupName(sgName)
	output, err := c.ovnNbCommand(
		"--data=bare", "--no-heading", "--columns=_uuid", "find", "port_group", fmt.Sprintf("name=%s", sgPortGroupName))
	if err != nil {
		klog.Errorf("failed to find port_group of sg %s: %v", sgPortGroupName, err)
		return err
	}
	if output != "" {
		return nil
	}
	_, err = c.ovnNbCommand(
		"pg-add", sgPortGroupName,
		"--", "set", "port_group", sgPortGroupName, "external_ids:type=security_group",
		fmt.Sprintf("external_ids:sg=%s", sgName),
		fmt.Sprintf("external_ids:name=%s", sgPortGroupName))
	return err
}

func (c LegacyClient) CreateSgAssociatedAddressSet(sgName string) error {
	v4AsName := GetSgV4AssociatedName(sgName)
	v6AsName := GetSgV6AssociatedName(sgName)
	outputV4, err := c.ovnNbCommand("--data=bare", "--no-heading", "--columns=_uuid", "find", "address_set", fmt.Sprintf("name=%s", v4AsName))
	if err != nil {
		klog.Errorf("failed to find address_set for sg %s: %v", sgName, err)
		return err
	}
	outputV6, err := c.ovnNbCommand("--data=bare", "--no-heading", "--columns=_uuid", "find", "address_set", fmt.Sprintf("name=%s", v6AsName))
	if err != nil {
		klog.Errorf("failed to find address_set for sg %s: %v", sgName, err)
		return err
	}

	if outputV4 == "" {
		_, err = c.ovnNbCommand("create", "address_set", fmt.Sprintf("name=%s", v4AsName), fmt.Sprintf("external_ids:sg=%s", sgName))
		if err != nil {
			klog.Errorf("failed to create v4 address_set for sg %s: %v", sgName, err)
			return err
		}
	}
	if outputV6 == "" {
		_, err = c.ovnNbCommand("create", "address_set", fmt.Sprintf("name=%s", v6AsName), fmt.Sprintf("external_ids:sg=%s", sgName))
		if err != nil {
			klog.Errorf("failed to create v6 address_set for sg %s: %v", sgName, err)
			return err
		}
	}
	return nil
}

func (c *LegacyClient) AclExists(priority, direction string) (bool, error) {
	priorityVal, _ := strconv.Atoi(priority)
	results, err := c.CustomFindEntity("acl", []string{"match"}, fmt.Sprintf("priority=%d", priorityVal), fmt.Sprintf("direction=%s", direction))
	if err != nil {
		klog.Errorf("customFindEntity failed, %v", err)
		return false, err
	}
	if len(results) == 0 {
		return false, nil
	}
	return true, nil
}

func (c *LegacyClient) SetLBCIDR(svccidr string) error {
	if _, err := c.ovnNbCommand("set", "NB_Global", ".", fmt.Sprintf("options:svc_ipv4_cidr=%s", svccidr)); err != nil {
		return fmt.Errorf("failed to set svc cidr for lb, %v", err)
	}
	return nil
}

func (c *LegacyClient) PortGroupExists(pgName string) (bool, error) {
	results, err := c.CustomFindEntity("port_group", []string{"_uuid"}, fmt.Sprintf("name=%s", pgName))
	if err != nil {
		klog.Errorf("customFindEntity failed, %v", err)
		return false, err
	}
	if len(results) == 0 {
		return false, nil
	}
	return true, nil
}

func (c *LegacyClient) VpcHasPolicyRoute(vpc string, nextHops []string, priority int32) (bool, error) {
	// get all policies by vpc
	outPolicies, err := c.ovnNbCommand("--data=bare", "--no-heading",
		"--columns=policies", "find", "Logical_Router", fmt.Sprintf("name=%s", vpc))
	if err != nil {
		klog.Errorf("failed to find Logical_Router_Policy %s: %v, %q", vpc, err, outPolicies)
		return false, err
	}
	if outPolicies == "" {
		klog.V(3).Infof("vpc %s has no policy routes", vpc)
		return false, nil
	}

	strRoutes := strings.Split(outPolicies, "\n")[0]
	strPriority := fmt.Sprint(priority)
	routes := strings.Fields(strRoutes)
	// check if policie already exist
	for _, r := range routes {
		outPriorityNexthops, err := c.ovnNbCommand("--data=bare", "--no-heading", "--format=csv", "--columns=priority,nexthops", "list", "Logical_Router_Policy", r)
		if err != nil {
			klog.Errorf("failed to show Logical_Router_Policy %s: %v, %q", r, err, outPriorityNexthops)
			return false, err
		}
		if outPriorityNexthops == "" {
			return false, nil
		}
		priorityNexthops := strings.Split(outPriorityNexthops, "\n")[0]
		result := strings.Split(priorityNexthops, ",")
		if len(result) == 2 {
			routePriority := result[0]
			strNodeIPs := result[1]
			nodeIPs := strings.Fields(strNodeIPs)
			sort.Strings(nodeIPs)
			if routePriority == strPriority && slices.Equal(nextHops, nodeIPs) {
				// make sure priority, nexthops is just the same
				return true, nil
			}
		}
	}
	return false, nil
}

func (c *LegacyClient) PolicyRouteExists(priority int32, match string) (bool, error) {
	results, err := c.CustomFindEntity("Logical_Router_Policy", []string{"_uuid"}, fmt.Sprintf("priority=%d", priority), fmt.Sprintf("match=\"%s\"", match))
	if err != nil {
		klog.Errorf("customFindEntity failed, %v", err)
		return false, err
	}
	if len(results) == 0 {
		return false, nil
	}
	return true, nil
}

func (c *LegacyClient) DeletePolicyRouteByUUID(router string, uuids []string) error {
	if len(uuids) == 0 {
		return nil
	}
	for _, uuid := range uuids {
		var args []string
		args = append(args, []string{"lr-policy-del", router, uuid}...)
		if _, err := c.ovnNbCommand(args...); err != nil {
			klog.Errorf("failed to delete router %s policy route: %v", router, err)
			return err
		}
	}
	return nil
}

func (c *LegacyClient) GetPolicyRouteParas(priority int32, match string) ([]string, map[string]string, error) {
	result, err := c.CustomFindEntity("Logical_Router_Policy", []string{"nexthops", "external_ids"}, fmt.Sprintf("priority=%d", priority), fmt.Sprintf(`match="%s"`, match))
	if err != nil {
		klog.Errorf("customFindEntity failed, %v", err)
		return nil, nil, err
	}
	if len(result) == 0 {
		return nil, nil, nil
	}

	nameIpMap := make(map[string]string, len(result[0]["external_ids"]))
	for _, l := range result[0]["external_ids"] {
		if len(strings.TrimSpace(l)) == 0 {
			continue
		}
		parts := strings.Split(strings.TrimSpace(l), "=")
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		ip := strings.TrimSpace(parts[1])
		nameIpMap[name] = ip
	}

	return result[0]["nexthops"], nameIpMap, nil
}

func (c LegacyClient) SetPolicyRouteExternalIds(priority int32, match string, nameIpMaps map[string]string) error {
	result, err := c.CustomFindEntity("Logical_Router_Policy", []string{"_uuid"}, fmt.Sprintf("priority=%d", priority), fmt.Sprintf("match=\"%s\"", match))
	if err != nil {
		klog.Errorf("customFindEntity failed, %v", err)
		return err
	}
	if len(result) == 0 {
		return nil
	}

	uuid := result[0]["_uuid"][0]
	ovnCmd := []string{"set", "logical-router-policy", uuid}
	for nodeName, nodeIP := range nameIpMaps {
		ovnCmd = append(ovnCmd, fmt.Sprintf("external_ids:%s=\"%s\"", nodeName, nodeIP))
	}

	if _, err := c.ovnNbCommand(ovnCmd...); err != nil {
		return fmt.Errorf("failed to set logical-router-policy externalIds, %v", err)
	}
	return nil
}

func (c LegacyClient) CheckPolicyRouteNexthopConsistent(router, match, nexthop string, priority int32) (bool, error) {
	exist, err := c.PolicyRouteExists(priority, match)
	if err != nil {
		return false, err
	}
	if !exist {
		return false, nil
	}

	dbNextHops, _, err := c.GetPolicyRouteParas(priority, match)
	if err != nil {
		klog.Errorf("failed to get policy route paras, %v", err)
		return false, err
	}
	cfgNextHops := strings.Split(nexthop, ",")

	sort.Strings(dbNextHops)
	sort.Strings(cfgNextHops)
	if slices.Equal(dbNextHops, cfgNextHops) {
		return true, nil
	}
	return false, nil
}

type dhcpOptions struct {
	UUID        string
	CIDR        string
	ExternalIds map[string]string
	options     map[string]string
}

func (c LegacyClient) ListDHCPOptions(needVendorFilter bool, ls string, protocol string) ([]dhcpOptions, error) {
	cmds := []string{"--format=csv", "--no-heading", "--data=bare", "--columns=_uuid,cidr,external_ids,options", "find", "dhcp_options"}
	if needVendorFilter {
		cmds = append(cmds, fmt.Sprintf("external_ids:vendor=%s", util.CniTypeName))
	}
	if len(ls) != 0 {
		cmds = append(cmds, fmt.Sprintf("external_ids:ls=%s", ls))
	}
	if len(protocol) != 0 && protocol != kubeovnv1.ProtocolDual {
		cmds = append(cmds, fmt.Sprintf("external_ids:protocol=%s", protocol))
	}

	output, err := c.ovnNbCommand(cmds...)
	if err != nil {
		klog.Errorf("failed to find dhcp options, %v", err)
		return nil, err
	}
	entries := strings.Split(output, "\n")
	dhcpOptionsList := make([]dhcpOptions, 0, len(entries))
	for _, entry := range strings.Split(output, "\n") {
		if len(strings.Split(entry, ",")) == 4 {
			t := strings.Split(entry, ",")

			externalIdsMap := map[string]string{}
			for _, ex := range strings.Split(t[2], " ") {
				ids := strings.Split(strings.TrimSpace(ex), "=")
				if len(ids) == 2 {
					externalIdsMap[ids[0]] = ids[1]
				}
			}

			optionsMap := map[string]string{}
			for _, op := range strings.Split(t[3], " ") {
				kv := strings.Split(strings.TrimSpace(op), "=")
				if len(kv) == 2 {
					optionsMap[kv[0]] = kv[1]
				}
			}

			dhcpOptionsList = append(dhcpOptionsList,
				dhcpOptions{UUID: strings.TrimSpace(t[0]), CIDR: strings.TrimSpace(t[1]), ExternalIds: externalIdsMap, options: optionsMap})
		}
	}
	return dhcpOptionsList, nil
}

func (c *LegacyClient) createDHCPOptions(ls, cidr, optionsStr string) (dhcpOptionsUuid string, err error) {
	klog.Infof("create dhcp options ls:%s, cidr:%s, optionStr:[%s]", ls, cidr, optionsStr)

	protocol := util.CheckProtocol(cidr)
	output, err := c.ovnNbCommand("create", "dhcp_options",
		fmt.Sprintf("cidr=%s", strings.ReplaceAll(cidr, ":", "\\:")),
		fmt.Sprintf("options=%s", strings.ReplaceAll(optionsStr, ":", "\\:")),
		fmt.Sprintf("external_ids=ls=%s,protocol=%s,vendor=%s", ls, protocol, util.CniTypeName))
	if err != nil {
		klog.Errorf("create dhcp options %s for switch %s failed: %v", cidr, ls, err)
		return "", err
	}
	dhcpOptionsUuid = strings.Split(output, "\n")[0]

	return dhcpOptionsUuid, nil
}

func (c *LegacyClient) updateDHCPv4Options(ls, v4CIDR, v4Gateway, dhcpV4OptionsStr string) (dhcpV4OptionsUuid string, err error) {
	dhcpV4OptionsStr = strings.ReplaceAll(dhcpV4OptionsStr, " ", "")
	dhcpV4Options, err := c.ListDHCPOptions(true, ls, kubeovnv1.ProtocolIPv4)
	if err != nil {
		klog.Errorf("list dhcp options for switch %s protocol %s failed: %v", ls, kubeovnv1.ProtocolIPv4, err)
		return "", err
	}

	if len(v4CIDR) > 0 {
		if len(dhcpV4Options) == 0 {
			// create
			mac := util.GenerateMac()
			if len(dhcpV4OptionsStr) == 0 {
				// default dhcp v4 options
				dhcpV4OptionsStr = fmt.Sprintf("lease_time=%d,router=%s,server_id=%s,server_mac=%s", 3600, v4Gateway, "169.254.0.254", mac)
			}
			dhcpV4OptionsUuid, err = c.createDHCPOptions(ls, v4CIDR, dhcpV4OptionsStr)
			if err != nil {
				klog.Errorf("create dhcp options for switch %s failed: %v", ls, err)
				return "", err
			}
		} else {
			// update
			v4Options := dhcpV4Options[0]
			if len(dhcpV4OptionsStr) == 0 {
				mac := v4Options.options["server_mac"]
				if len(mac) == 0 {
					mac = util.GenerateMac()
				}
				dhcpV4OptionsStr = fmt.Sprintf("lease_time=%d,router=%s,server_id=%s,server_mac=%s", 3600, v4Gateway, "169.254.0.254", mac)
			}
			_, err = c.ovnNbCommand("set", "dhcp_options", v4Options.UUID, fmt.Sprintf("cidr=%s", v4CIDR),
				fmt.Sprintf("options=%s", strings.ReplaceAll(dhcpV4OptionsStr, ":", "\\:")))
			if err != nil {
				klog.Errorf("set cidr and options for dhcp v4 options %s failed: %v", v4Options.UUID, err)
				return "", err
			}
			dhcpV4OptionsUuid = v4Options.UUID
		}
	} else if len(dhcpV4Options) > 0 {
		// delete
		if err = c.DeleteDHCPOptions(ls, kubeovnv1.ProtocolIPv4); err != nil {
			klog.Errorf("delete dhcp options for switch %s protocol %s failed: %v", ls, kubeovnv1.ProtocolIPv4, err)
			return "", err
		}
	}

	return
}

func (c *LegacyClient) updateDHCPv6Options(ls, v6CIDR, dhcpV6OptionsStr string) (dhcpV6OptionsUuid string, err error) {
	dhcpV6OptionsStr = strings.ReplaceAll(dhcpV6OptionsStr, " ", "")
	dhcpV6Options, err := c.ListDHCPOptions(true, ls, kubeovnv1.ProtocolIPv6)
	if err != nil {
		klog.Errorf("list dhcp options for switch %s protocol %s failed: %v", ls, kubeovnv1.ProtocolIPv6, err)
		return "", err
	}

	if len(v6CIDR) > 0 {
		if len(dhcpV6Options) == 0 {
			// create
			if len(dhcpV6OptionsStr) == 0 {
				mac := util.GenerateMac()
				dhcpV6OptionsStr = fmt.Sprintf("server_id=%s", mac)
			}
			dhcpV6OptionsUuid, err = c.createDHCPOptions(ls, v6CIDR, dhcpV6OptionsStr)
			if err != nil {
				klog.Errorf("create dhcp options for switch %s failed: %v", ls, err)
				return "", err
			}
		} else {
			// update
			v6Options := dhcpV6Options[0]
			if len(dhcpV6OptionsStr) == 0 {
				mac := v6Options.options["server_id"]
				if len(mac) == 0 {
					mac = util.GenerateMac()
				}
				dhcpV6OptionsStr = fmt.Sprintf("server_id=%s", mac)
			}
			_, err = c.ovnNbCommand("set", "dhcp_options", v6Options.UUID, fmt.Sprintf("cidr=%s", strings.ReplaceAll(v6CIDR, ":", "\\:")),
				fmt.Sprintf("options=%s", strings.ReplaceAll(dhcpV6OptionsStr, ":", "\\:")))
			if err != nil {
				klog.Errorf("set cidr and options for dhcp v6 options %s failed: %v", v6Options.UUID, err)
				return "", err
			}
			dhcpV6OptionsUuid = v6Options.UUID
		}
	} else if len(dhcpV6Options) > 0 {
		// delete
		if err = c.DeleteDHCPOptions(ls, kubeovnv1.ProtocolIPv6); err != nil {
			klog.Errorf("delete dhcp options for switch %s protocol %s failed: %v", ls, kubeovnv1.ProtocolIPv6, err)
			return "", err
		}
	}

	return
}

func (c *LegacyClient) UpdateDHCPOptions(ls, cidrBlock, gateway, dhcpV4OptionsStr, dhcpV6OptionsStr string, enableDHCP bool) (dhcpOptionsUUIDs *DHCPOptionsUUIDs, err error) {
	dhcpOptionsUUIDs = &DHCPOptionsUUIDs{}
	if enableDHCP {
		var v4CIDR, v6CIDR string
		var v4Gateway string
		switch util.CheckProtocol(cidrBlock) {
		case kubeovnv1.ProtocolIPv4:
			v4CIDR = cidrBlock
			v4Gateway = gateway
		case kubeovnv1.ProtocolIPv6:
			v6CIDR = cidrBlock
		case kubeovnv1.ProtocolDual:
			cidrBlocks := strings.Split(cidrBlock, ",")
			gateways := strings.Split(gateway, ",")
			v4CIDR, v6CIDR = cidrBlocks[0], cidrBlocks[1]
			v4Gateway = gateways[0]
		}

		dhcpOptionsUUIDs.DHCPv4OptionsUUID, err = c.updateDHCPv4Options(ls, v4CIDR, v4Gateway, dhcpV4OptionsStr)
		if err != nil {
			klog.Errorf("update dhcp options for switch %s failed: %v", ls, err)
			return nil, err
		}
		dhcpOptionsUUIDs.DHCPv6OptionsUUID, err = c.updateDHCPv6Options(ls, v6CIDR, dhcpV6OptionsStr)
		if err != nil {
			klog.Errorf("update dhcp options for switch %s failed: %v", ls, err)
			return nil, err
		}

	} else {
		if err = c.DeleteDHCPOptions(ls, kubeovnv1.ProtocolDual); err != nil {
			klog.Errorf("delete dhcp options for switch %s failed: %v", ls, err)
			return nil, err
		}
	}
	return dhcpOptionsUUIDs, nil
}

func (c *LegacyClient) DeleteDHCPOptionsByUUIDs(uuidList []string) (err error) {
	for _, uuid := range uuidList {
		_, err = c.ovnNbCommand("dhcp-options-del", uuid)
		if err != nil {
			klog.Errorf("delete dhcp options %s failed: %v", uuid, err)
			return err
		}
	}
	return nil
}

func (c *LegacyClient) DeleteDHCPOptions(ls string, protocol string) error {
	klog.Infof("delete dhcp options for switch %s protocol %s", ls, protocol)
	dhcpOptionsList, err := c.ListDHCPOptions(true, ls, protocol)
	if err != nil {
		klog.Errorf("find dhcp options failed, %v", err)
		return err
	}
	uuidToDeleteList := []string{}
	for _, item := range dhcpOptionsList {
		uuidToDeleteList = append(uuidToDeleteList, item.UUID)
	}

	return c.DeleteDHCPOptionsByUUIDs(uuidToDeleteList)
}

func (c *LegacyClient) UpdateRouterPortIPv6RA(ls, lr, cidrBlock, gateway, ipv6RAConfigsStr string, enableIPv6RA bool) error {
	var err error
	lrTols := fmt.Sprintf("%s-%s", lr, ls)
	ip := util.GetIpAddrWithMask(gateway, cidrBlock)
	ipStr := strings.Split(ip, ",")
	if enableIPv6RA {
		var ipv6Prefix string
		switch util.CheckProtocol(ip) {
		case kubeovnv1.ProtocolIPv4:
			klog.Warningf("enable ipv6 router advertisement is not effective to IPv4")
			return nil
		case kubeovnv1.ProtocolIPv6:
			ipv6Prefix = strings.Split(ipStr[0], "/")[1]
		case kubeovnv1.ProtocolDual:
			ipv6Prefix = strings.Split(ipStr[1], "/")[1]
		}

		if len(ipv6RAConfigsStr) == 0 {
			// default ipv6_ra_configs
			ipv6RAConfigsStr = "address_mode=dhcpv6_stateful,max_interval=30,min_interval=5,send_periodic=true"
		}

		ipv6RAConfigsStr = strings.ReplaceAll(ipv6RAConfigsStr, " ", "")
		klog.Infof("set lrp %s, ipv6_prefix %s", lrTols, ipv6Prefix)
		_, err = c.ovnNbCommand("--",
			"set", "logical_router_port", lrTols, fmt.Sprintf("ipv6_prefix=%s", ipv6Prefix), fmt.Sprintf("ipv6_ra_configs=%s", ipv6RAConfigsStr))
		if err != nil {
			klog.Errorf("failed to set ipv6_prefix: %s ans ipv6_ra_configs: %s for router port: %s, err: %s", ipv6Prefix, ipv6RAConfigsStr, lrTols, err)
			return err
		}
	} else {
		klog.Infof("set lrp %s", lrTols)
		_, err = c.ovnNbCommand("--",
			"set", "logical_router_port", lrTols, "ipv6_prefix=[]", "ipv6_ra_configs={}")
		if err != nil {
			klog.Errorf("failed to reset ipv6_prefix and ipv6_ra_config for router port: %s, err: %s", lrTols, err)
			return err
		}
	}
	return nil
}

func (c LegacyClient) DeleteSubnetACL(ls string) error {
	results, err := c.CustomFindEntity("acl", []string{"direction", "priority", "match"}, fmt.Sprintf("external_ids:subnet=\"%s\"", ls))
	if err != nil {
		klog.Errorf("customFindEntity failed, %v", err)
		return err
	}
	if len(results) == 0 {
		return nil
	}

	for _, result := range results {
		aclArgs := []string{"acl-del", ls}
		aclArgs = append(aclArgs, result["direction"][0], result["priority"][0], result["match"][0])

		_, err := c.ovnNbCommand(aclArgs...)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c LegacyClient) UpdateSubnetACL(ls string, acls []kubeovnv1.Acl) error {
	if err := c.DeleteSubnetACL(ls); err != nil {
		klog.Errorf("failed to delete acls for subnet %s, %v", ls, err)
		return err
	}
	if len(acls) == 0 {
		return nil
	}

	for _, acl := range acls {
		aclArgs := []string{}
		aclArgs = append(aclArgs, "--", MayExist, "acl-add", ls, acl.Direction, strconv.Itoa(acl.Priority), acl.Match, acl.Action)
		_, err := c.ovnNbCommand(aclArgs...)
		if err != nil {
			klog.Errorf("failed to create acl for subnet %s, %v", ls, err)
			return err
		}

		results, err := c.CustomFindEntity("acl", []string{"_uuid"}, fmt.Sprintf("priority=%d", acl.Priority), fmt.Sprintf("direction=%s", acl.Direction), fmt.Sprintf("match=\"%s\"", acl.Match))
		if err != nil {
			klog.Errorf("customFindEntity failed, %v", err)
			return err
		}
		if len(results) == 0 {
			return nil
		}

		uuid := results[0]["_uuid"][0]
		ovnCmd := []string{"set", "acl", uuid}
		ovnCmd = append(ovnCmd, fmt.Sprintf("external_ids:subnet=\"%s\"", ls))

		if _, err := c.ovnNbCommand(ovnCmd...); err != nil {
			return fmt.Errorf("failed to set acl externalIds for subnet %s, %v", ls, err)
		}
	}
	return nil
}

func (c *LegacyClient) GetLspExternalIds(lsp string) map[string]string {
	result, err := c.CustomFindEntity("Logical_Switch_Port", []string{"external_ids"}, fmt.Sprintf("name=%s", lsp))
	if err != nil {
		klog.Errorf("customFindEntity failed, %v", err)
		return nil
	}
	if len(result) == 0 {
		return nil
	}

	nameNsMap := make(map[string]string, 1)
	for _, l := range result[0]["external_ids"] {
		if len(strings.TrimSpace(l)) == 0 {
			continue
		}
		parts := strings.Split(strings.TrimSpace(l), "=")
		if len(parts) != 2 {
			continue
		}
		if strings.TrimSpace(parts[0]) != "pod" {
			continue
		}

		podInfo := strings.Split(strings.TrimSpace(parts[1]), "/")
		if len(podInfo) != 2 {
			continue
		}
		podNs := podInfo[0]
		podName := podInfo[1]
		nameNsMap[podName] = podNs
	}

	return nameNsMap
}

func (c LegacyClient) SetAclLog(pgName string, logEnable, isIngress bool) error {
	var direction, match string
	if isIngress {
		direction = "to-lport"
		match = fmt.Sprintf("outport==@%s && ip", pgName)
	} else {
		direction = "from-lport"
		match = fmt.Sprintf("inport==@%s && ip", pgName)
	}

	priority, _ := strconv.Atoi(util.IngressDefaultDrop)
	result, err := c.CustomFindEntity("acl", []string{"_uuid"}, fmt.Sprintf("priority=%d", priority), fmt.Sprintf(`match="%s"`, match), fmt.Sprintf("direction=%s", direction), "action=drop")
	if err != nil {
		klog.Errorf("failed to get acl UUID: %v", err)
		return err
	}

	if len(result) == 0 {
		return nil
	}

	uuid := result[0]["_uuid"][0]
	ovnCmd := []string{"set", "acl", uuid, fmt.Sprintf("log=%v", logEnable)}

	if _, err := c.ovnNbCommand(ovnCmd...); err != nil {
		return fmt.Errorf("failed to set acl log, %v", err)
	}

	return nil
}

func (c *LegacyClient) GetRouterNat(routerName string) ([]string, error) {
	var nat []string
	results, err := c.CustomFindEntity("logical-router", []string{"nat"}, fmt.Sprintf("name=%s", routerName))
	if err != nil {
		klog.Errorf("customFindEntity failed, %v", err)
		return nat, err
	}
	if len(results) == 0 {
		return nat, nil
	}

	return results[0]["nat"], nil
}

func (c *LegacyClient) GetNatIPInfo(uuid string) (string, error) {
	var logical_ip string

	output, err := c.ovnNbCommand("--data=bare", "--format=csv", "--no-heading", "--columns=logical_ip", "list", "nat", uuid)
	if err != nil {
		klog.Errorf("failed to list nat, %v", err)
		return logical_ip, err
	}
	lines := strings.Split(output, "\n")

	if len(lines) > 0 {
		logical_ip = strings.TrimSpace(lines[0])
	}
	return logical_ip, nil
}
