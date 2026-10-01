package ko

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (a *Application) addDiagnosticCommands() {
	a.root.AddCommand(&cobra.Command{Use: "reload", Short: "Restart Kube-OVN components in dependency order", Args: cobra.NoArgs, RunE: a.run(a.reload)})
	a.root.AddCommand(&cobra.Command{Use: "env-check", Short: "Run the image environment checker on each node", Args: cobra.NoArgs, RunE: a.run(a.environmentCheck)})
	var readOnly bool
	command := &cobra.Command{Use: "diagnose [all|node NODE|subnet SUBNET|IPPorts TARGETS]", Short: "Check configuration and probe network connectivity", Args: cobra.MaximumNArgs(2)}
	command.Flags().BoolVar(&readOnly, "read-only", false, "Skip resource creation and active connectivity probes")
	command.RunE = a.run(func(ctx context.Context, client *Client, args []string) error {
		return a.diagnose(ctx, client, args, readOnly)
	})
	a.root.AddCommand(command)
	a.addLogCommand()
}

func (a *Application) environmentCheck(ctx context.Context, client *Client, _ []string) error {
	targets, err := client.targets(ctx, "app=kube-ovn-cni", "", "cni-server", false)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("no running CNI containers")
	}
	var failures []error
	for _, target := range targets {
		if _, err := fmt.Fprintf(a.streams.Out, "Environment check on %s\n", target.Node); err != nil {
			return err
		}
		if err := client.Executor.Exec(ctx, target, []string{"bash", "/kube-ovn/env-check.sh"}, a.outputStreams()); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func diagnoseMode(args []string) (string, string, error) {
	if len(args) == 0 {
		return "all", "", nil
	}
	mode := args[0]
	if mode == "all" && len(args) == 1 {
		return mode, "", nil
	}
	if (mode == "node" || mode == "subnet" || mode == "IPPorts") && len(args) == 2 && args[1] != "" {
		return mode, args[1], nil
	}
	return "", "", errors.New("use diagnose all, node NODE, subnet SUBNET, or IPPorts TARGETS")
}

func (a *Application) diagnose(ctx context.Context, client *Client, args []string, readOnly bool) (resultErr error) {
	mode, value, err := diagnoseMode(args)
	if err != nil {
		return &usageError{err}
	}
	if mode == "node" {
		if _, err := client.Kubernetes.CoreV1().Nodes().Get(ctx, value, metav1.GetOptions{}); err != nil {
			return err
		}
	}
	if mode == "subnet" {
		if _, err := client.Dynamic.Resource(subnetResource).Get(ctx, value, metav1.GetOptions{}); err != nil {
			return err
		}
	}
	configurationErr := errors.Join(a.checkConfiguration(ctx, client), a.diagnoseOVN(ctx, client))
	if readOnly {
		return configurationErr
	}
	run := &resourceRun{client: client, id: runID()}
	defer func() { resultErr = errors.Join(resultErr, run.cleanup(ctx)) }()
	targets := value
	if mode != "IPPorts" {
		targets, err = run.nodePortProbe(ctx)
		if err != nil {
			return errors.Join(configurationErr, err)
		}
	}
	if mode == "subnet" {
		if err := run.subnetProbe(ctx, value); err != nil {
			return errors.Join(configurationErr, err)
		}
	}
	node := ""
	if mode == "node" {
		node = value
	}
	selector, container := "app=kube-ovn-pinger", "pinger"
	if mode == "subnet" {
		selector, container = labels.Set(run.labels()).String(), "probe"
	}
	pingers, err := client.targets(ctx, selector, node, container, true)
	if err != nil {
		return errors.Join(configurationErr, err)
	}
	if len(pingers) == 0 {
		return errors.Join(configurationErr, errors.New("no ready pinger containers matched the diagnostic target"))
	}
	return errors.Join(configurationErr, a.runDiagnosticProbes(ctx, client, pingers, mode, targets))
}

func (a *Application) runDiagnosticProbes(ctx context.Context, client *Client, pingers []Target, mode, targets string) error {
	var failures []error
	for _, target := range pingers {
		if _, err := fmt.Fprintf(a.streams.Out, "Diagnosing node %s\n", target.Node); err != nil {
			return err
		}
		if mode == "all" || mode == "node" {
			for _, argv := range [][]string{{"tail", "/var/log/ovn/ovn-controller.log"}, {"tail", "/var/log/openvswitch/ovs-vswitchd.log"}, {"ovs-vsctl", "show"}} {
				if err := client.Executor.Exec(ctx, target, argv, a.outputStreams()); err != nil {
					failures = append(failures, err)
				}
			}
		}
		argv := []string{"/kube-ovn/kube-ovn-pinger", "--mode=job", "--exit-code=1", "--target-ip-ports=" + targets}
		if mode != "IPPorts" {
			argv = append(argv, "--external-address=1.1.1.1,2606:4700:4700::1111")
		}
		if mode == "subnet" {
			argv = append(argv, "--network-mode=diagnostic", "--enable-verbose-conn-check=true", "--tcp-conn-check-port="+cmp.Or(os.Getenv("TCP_CONN_CHECK_PORT"), "8100"), "--udp-conn-check-port="+cmp.Or(os.Getenv("UDP_CONN_CHECK_PORT"), "8101"))
		}
		if err := client.Executor.Exec(ctx, target, argv, a.outputStreams()); err != nil {
			failures = append(failures, fmt.Errorf("probe on %s: %w", target.Node, err))
		}
	}
	return errors.Join(failures...)
}

type diagnosticCheck struct {
	name string
	run  func() error
}

func (a *Application) checkConfiguration(ctx context.Context, client *Client) error {
	checks := []diagnosticCheck{
		{"Kubernetes service", func() error {
			_, err := client.Kubernetes.CoreV1().Services("default").Get(ctx, "kubernetes", metav1.GetOptions{})
			return err
		}},
		{"Kube-OVN subnets", func() error {
			_, err := client.Dynamic.Resource(subnetResource).List(ctx, metav1.ListOptions{})
			return err
		}},
	}
	checks = append(checks, client.configurationChecks(ctx)...)
	for _, name := range []string{"ovn-central", "kube-ovn-controller"} {
		checks = append(checks, diagnosticCheck{name, func() error { return client.waitDeployment(ctx, name, 30*time.Second) }})
	}
	for _, name := range []string{"kube-ovn-cni", "ovs-ovn"} {
		checks = append(checks, diagnosticCheck{name, func() error { return client.waitDaemonSet(ctx, name, 30*time.Second) }})
	}
	for _, role := range []string{"nb", "sb", "northd"} {
		checks = append(checks, diagnosticCheck{role + " leader", func() error { _, err := client.leader(ctx, role); return err }})
	}
	if os.Getenv("WITHOUT_KUBE_PROXY") != "true" {
		checks = append(checks, diagnosticCheck{"kube-proxy", func() error { return client.checkKubeProxy(ctx) }})
	}
	var failures []error
	for _, check := range checks {
		if err := check.run(); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", check.name, err))
			if _, writeErr := fmt.Fprintf(a.streams.Out, "FAIL %s: %v\n", check.name, err); writeErr != nil {
				return writeErr
			}
		} else if _, err := fmt.Fprintf(a.streams.Out, "PASS %s\n", check.name); err != nil {
			return err
		}
	}
	return errors.Join(failures...)
}

func (c *Client) checkKubeProxy(ctx context.Context) error {
	ds, err := c.Kubernetes.AppsV1().DaemonSets("kube-system").Get(ctx, "kube-proxy", metav1.GetOptions{})
	if err == nil {
		if !daemonSetReady(ds) {
			return errors.New("kube-proxy DaemonSet is not ready")
		}
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	targets, err := c.targets(ctx, "app=kube-ovn-cni", "", "cni-server", true)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("no CNI containers available to probe embedded kube-proxy")
	}
	for _, target := range targets {
		pod, err := c.Kubernetes.CoreV1().Pods(c.Namespace).Get(ctx, target.Pod, metav1.GetOptions{})
		if err != nil {
			return err
		}
		address := "http://" + net.JoinHostPort(pod.Status.PodIP, "10256") + "/healthz"
		if _, err := c.capture(ctx, target, "curl", "--globoff", "--fail", "--silent", "--show-error", "--max-time", "3", address); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) configurationChecks(ctx context.Context) []diagnosticCheck {
	checks := []diagnosticCheck{
		{"ovn service account", func() error {
			_, err := c.Kubernetes.CoreV1().ServiceAccounts(c.Namespace).Get(ctx, "ovn", metav1.GetOptions{})
			return err
		}},
		{"ovn cluster role", func() error {
			_, err := c.Kubernetes.RbacV1().ClusterRoles().Get(ctx, "system:ovn", metav1.GetOptions{})
			return err
		}},
		{"ovn cluster role binding", func() error {
			_, err := c.Kubernetes.RbacV1().ClusterRoleBindings().Get(ctx, "ovn", metav1.GetOptions{})
			return err
		}},
		{"cluster DNS", func() error {
			_, err := c.Kubernetes.CoreV1().Services("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{})
			return err
		}},
		{"CoreDNS", func() error {
			dns := *c
			dns.Namespace = "kube-system"
			return dns.waitDeployment(ctx, "coredns", 30*time.Second)
		}},
	}
	resource := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	for _, name := range []string{"vpcs", "vpc-nat-gateways", "vpc-egress-gateways", "subnets", "ips", "vlans", "provider-networks", "security-groups", "vips", "vpc-dnses", "switch-lb-rules", "ippools", "ovn-eips", "ovn-fips", "ovn-dnat-rules", "ovn-snat-rules", "iptables-eips", "iptables-fip-rules", "iptables-snat-rules", "iptables-dnat-rules"} {
		checks = append(checks, diagnosticCheck{name + " CRD", func() error {
			_, err := c.Dynamic.Resource(resource).Get(ctx, name+".kubeovn.io", metav1.GetOptions{})
			return err
		}})
	}
	return checks
}

func (a *Application) diagnoseOVN(ctx context.Context, client *Client) error {
	var failures []error
	nodes, err := client.Kubernetes.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		failures = append(failures, err)
	} else {
		for _, node := range nodes.Items {
			if _, err := fmt.Fprintf(a.streams.Out, "Node %s: %v\n", node.Name, node.Status.Addresses); err != nil {
				return err
			}
		}
	}
	for _, role := range []string{"nb", "sb"} {
		target, err := client.leader(ctx, role)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		commands := [][]string{{"ovn-" + role + "ctl", "show"}, databaseCommand(role, "cluster/status"), databaseCommand(role, "ovsdb-server/get-db-storage-status")}
		if role == "nb" {
			for _, args := range [][]string{{"lr-policy-list", "ovn-cluster"}, {"lr-route-list", "ovn-cluster"}, {"ls-lb-list", "ovn-default"}, {"list", "address_set"}, {"list", "acl"}} {
				commands = append(commands, append([]string{"ovn-nbctl"}, args...))
			}
		}
		for _, argv := range commands {
			if err := client.Executor.Exec(ctx, target, argv, a.outputStreams()); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func (r *resourceRun) nodePortProbe(ctx context.Context) (string, error) {
	service := &corev1.Service{Name: "ko-nodeport-" + r.id, Labels: r.labels(), Spec: corev1.ServiceSpec{
		Type: corev1.ServiceTypeNodePort, Selector: map[string]string{"app": "kube-ovn-pinger"},
		Ports: []corev1.ServicePort{{Name: "probe", Protocol: corev1.ProtocolTCP, Port: 60001, TargetPort: intstr.FromInt32(8080)}},
	}}
	result, err := r.createService(ctx, service)
	if err != nil {
		return "", err
	}
	if len(result.Spec.Ports) != 1 || result.Spec.Ports[0].NodePort == 0 {
		return "", errors.New("probe Service has no allocated NodePort")
	}
	nodes, err := r.client.Kubernetes.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	var targets []string
	for _, node := range nodes.Items {
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeInternalIP {
				targets = append(targets, fmt.Sprintf("tcp-%s-%d", address.Address, result.Spec.Ports[0].NodePort))
			}
		}
	}
	if len(targets) == 0 {
		return "", errors.New("nodes have no internal addresses")
	}
	return strings.Join(targets, ","), nil
}

func (r *resourceRun) subnetProbe(ctx context.Context, subnet string) error {
	pinger, err := r.client.Kubernetes.AppsV1().DaemonSets(r.client.Namespace).Get(ctx, "kube-ovn-pinger", metav1.GetOptions{})
	if err != nil {
		return err
	}
	image := ""
	for _, container := range pinger.Spec.Template.Spec.Containers {
		if container.Name == "pinger" {
			image = container.Image
		}
	}
	if image == "" {
		return errors.New("pinger DaemonSet has no pinger image")
	}
	tcp, err := strconv.ParseInt(cmp.Or(os.Getenv("TCP_CONN_CHECK_PORT"), "8100"), 10, 32)
	if err != nil || tcp < 1 || tcp > 65535 {
		return errors.New("invalid TCP_CONN_CHECK_PORT")
	}
	udp, err := strconv.ParseInt(cmp.Or(os.Getenv("UDP_CONN_CHECK_PORT"), "8101"), 10, 32)
	if err != nil || udp < 1 || udp > 65535 {
		return errors.New("invalid UDP_CONN_CHECK_PORT")
	}
	ds := &appsv1.DaemonSet{Name: "ko-subnet-" + r.id, Labels: r.labels(), Spec: appsv1.DaemonSetSpec{
		Selector: &metav1.LabelSelector{MatchLabels: r.labels()},
		Template: corev1.PodTemplateSpec{Labels: r.labels(), Annotations: map[string]string{annotationPrefix + "logical_switch": subnet}, Spec: corev1.PodSpec{
			ServiceAccountName: "kube-ovn-app", SecurityContext: &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			Containers: []corev1.Container{{
				Name: "probe", Image: image, Command: []string{"/kube-ovn/kube-ovn-pinger"},
				Args:           []string{"--enable-verbose-conn-check=true", fmt.Sprintf("--tcp-conn-check-port=%d", tcp), fmt.Sprintf("--udp-conn-check-port=%d", udp)},
				Env:            []corev1.EnvVar{{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}}, {Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}}},
				ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(int32(tcp))}}, InitialDelaySeconds: 3, PeriodSeconds: 5},
			}},
		}},
	}}
	return r.createDaemonSet(ctx, ds)
}
