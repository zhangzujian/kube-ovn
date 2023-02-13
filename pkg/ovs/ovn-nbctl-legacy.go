package ovs

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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
