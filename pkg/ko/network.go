package ko

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const annotationPrefix = "ovn.kubernetes.io/"

type networkSource struct {
	node        string
	lsp         string
	annotations map[string]string
	addresses   []string
	pod         *corev1.Pod
}

type podInterface struct {
	name   string
	netns  string
	ofport int
}

func (a *Application) addNetworkCommands() {
	a.root.AddCommand(&cobra.Command{
		Use: "tcpdump POD [tcpdump arguments...]", Short: "Capture packets in a pod network namespace", DisableFlagParsing: true, Args: cobra.MinimumNArgs(1),
		RunE: a.run(a.tcpdump),
	})
	for _, name := range []string{"trace", "ovn-trace"} {
		a.root.AddCommand(&cobra.Command{
			Use: name + " POD|node//NODE IP [MAC] icmp|tcp|udp|arp [PORT|request|reply]", Short: "Trace a packet through OVN and optionally OVS", Args: cobra.MinimumNArgs(3),
			RunE: a.run(func(ctx context.Context, client *Client, args []string) error {
				request, err := parseTrace(args)
				if err != nil {
					return &usageError{err}
				}
				return a.trace(ctx, client, request, name == "ovn-trace")
			}),
		})
	}
}

func (c *Client) networkSource(ctx context.Context, reference string) (*networkSource, error) {
	if node, ok := strings.CutPrefix(reference, "node//"); ok {
		return c.nodeSource(ctx, node)
	}
	pod, err := c.pod(ctx, reference)
	if err != nil {
		return nil, err
	}
	if pod.Spec.HostNetwork {
		return c.nodeSource(ctx, pod.Spec.NodeName)
	}
	name := pod.Name
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "VirtualMachineInstance" {
			name = owner.Name
			break
		}
	}
	return &networkSource{
		node: pod.Spec.NodeName, lsp: name + "." + pod.Namespace,
		annotations: pod.Annotations, pod: pod,
		addresses: strings.Split(pod.Annotations[annotationPrefix+"ip_address"], ","),
	}, nil
}

func (c *Client) nodeSource(ctx context.Context, name string) (*networkSource, error) {
	node, err := c.Kubernetes.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	source := &networkSource{node: name, lsp: node.Annotations[annotationPrefix+"port_name"], annotations: node.Annotations}
	for _, address := range node.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			source.addresses = append(source.addresses, address.Address)
		}
	}
	source.addresses = append(source.addresses, strings.Split(node.Annotations[annotationPrefix+"ip_address"], ",")...)
	return source, nil
}

func (c *Client) checkSource(ctx context.Context, source *networkSource) error {
	if source.pod == nil {
		return nil
	}
	pod, err := c.Kubernetes.CoreV1().Pods(source.pod.Namespace).Get(ctx, source.pod.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if pod.UID != source.pod.UID || pod.Spec.NodeName != source.node || pod.DeletionTimestamp != nil {
		return fmt.Errorf("pod %s/%s changed while resolving its network; retry", pod.Namespace, pod.Name)
	}
	return nil
}

func (c *Client) ovsRows(ctx context.Context, target Target, binary, columns, table string, conditions ...string) ([]map[string]any, error) {
	argv := append([]string{binary, "--format=json", "--columns=" + columns, "find", table}, conditions...)
	output, err := c.capture(ctx, target, argv...)
	if err != nil {
		return nil, err
	}
	var result struct {
		Headings []string `json:"headings"`
		Data     [][]any  `json:"data"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("decode %s output: %w", binary, err)
	}
	rows := make([]map[string]any, 0, len(result.Data))
	for _, values := range result.Data {
		if len(values) != len(result.Headings) {
			return nil, errors.New("OVSDB headings and row length differ")
		}
		row := make(map[string]any, len(values))
		for i, value := range values {
			row[result.Headings[i]] = value
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func ovsStrings(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []any:
		if len(v) == 2 && v[0] == "set" {
			if elements, ok := v[1].([]any); ok {
				var values []string
				for _, element := range elements {
					values = append(values, ovsStrings(element)...)
				}
				return values
			}
		}
	}
	return nil
}

func ovsMap(value any) map[string]string {
	result := map[string]string{}
	pair, ok := value.([]any)
	if !ok || len(pair) != 2 || pair[0] != "map" {
		return result
	}
	elements, ok := pair[1].([]any)
	if !ok {
		return result
	}
	for _, element := range elements {
		kv, ok := element.([]any)
		if !ok || len(kv) != 2 {
			continue
		}
		key, keyOK := kv[0].(string)
		val, valOK := kv[1].(string)
		if keyOK && valOK {
			result[key] = val
		}
	}
	return result
}

func (c *Client) podInterface(ctx context.Context, target Target, lsp string) (podInterface, error) {
	rows, err := c.ovsRows(ctx, target, "ovs-vsctl", "name,external_ids,ofport", "Interface", "external_ids:iface-id="+strconv.Quote(lsp))
	if err != nil {
		return podInterface{}, err
	}
	if len(rows) != 1 {
		return podInterface{}, fmt.Errorf("expected one OVS interface for %q, found %d", lsp, len(rows))
	}
	name, ok := rows[0]["name"].(string)
	if !ok || name == "" {
		return podInterface{}, errors.New("OVS interface has no name")
	}
	ofport, _ := rows[0]["ofport"].(float64)
	return podInterface{name: name, netns: ovsMap(rows[0]["external_ids"])["pod_netns"], ofport: int(ofport)}, nil
}

func namespaceCommand(netns string, argv ...string) []string {
	if netns == "" {
		return argv
	}
	return append([]string{"nsenter", "--net=" + netns, "--"}, argv...)
}

func (a *Application) tcpdump(ctx context.Context, client *Client, args []string) error {
	pod, err := client.pod(ctx, args[0])
	if err != nil {
		return err
	}
	ovs, err := client.nodeTarget(ctx, pod.Spec.NodeName, "ovs")
	if err != nil {
		return err
	}
	argv := append([]string{"tcpdump", "-nn"}, args[1:]...)
	if pod.Spec.HostNetwork {
		return client.Executor.Exec(ctx, ovs, argv, a.outputStreams())
	}
	source, err := client.networkSource(ctx, args[0])
	if err != nil {
		return err
	}
	nic, err := client.podInterface(ctx, ovs, source.lsp)
	if err != nil {
		return err
	}
	if nic.netns == "" {
		return errors.New("OVS interface has no pod_netns external ID")
	}
	cni, err := client.nodeTarget(ctx, source.node, "kube-ovn-cni")
	if err != nil {
		return err
	}
	name := "eth0"
	if pod.Annotations[annotationPrefix+"pod_nic_type"] == "internal-port" {
		name = nic.name
	}
	argv = namespaceCommand(nic.netns, append([]string{"tcpdump", "-nn", "-i", name}, args[1:]...)...)
	if err := client.checkSource(ctx, source); err != nil {
		return err
	}
	return client.Executor.Exec(ctx, cni, argv, a.outputStreams())
}

type traceRequest struct {
	reference   string
	destination netip.Addr
	mac         string
	protocol    string
	port        uint16
	arpReply    bool
}

func parseTrace(args []string) (traceRequest, error) {
	var request traceRequest
	if len(args) < 3 {
		return request, errors.New("trace requires a source, destination IP and protocol")
	}
	request.reference = args[0]
	ip, err := netip.ParseAddr(args[1])
	if err != nil || ip.Zone() != "" {
		return request, fmt.Errorf("invalid destination IP %q", args[1])
	}
	request.destination = ip.Unmap()
	args = args[2:]
	if mac, err := net.ParseMAC(args[0]); err == nil && len(mac) == 6 {
		request.mac = mac.String()
		args = args[1:]
	}
	if len(args) == 0 {
		return request, errors.New("missing trace protocol")
	}
	request.protocol, args = args[0], args[1:]
	switch request.protocol {
	case "icmp":
		if len(args) != 0 {
			return request, errors.New("icmp does not accept a port")
		}
	case "tcp", "udp":
		if len(args) != 1 {
			return request, errors.New("tcp/udp require exactly one destination port")
		}
		port, err := strconv.ParseUint(args[0], 10, 16)
		if err != nil || port == 0 {
			return request, fmt.Errorf("invalid destination port %q", args[0])
		}
		request.port = uint16(port)
	case "arp":
		if !request.destination.Is4() {
			return request, errors.New("ARP requires IPv4")
		}
		if len(args) > 1 || len(args) == 1 && args[0] != "request" && args[0] != "reply" {
			return request, errors.New("ARP operation must be request or reply")
		}
		request.arpReply = len(args) == 1 && args[0] == "reply"
	default:
		return request, fmt.Errorf("unsupported trace protocol %q", request.protocol)
	}
	return request, nil
}

var subnetResource = schema.GroupVersionResource{Group: "kubeovn.io", Version: "v1", Resource: "subnets"}
