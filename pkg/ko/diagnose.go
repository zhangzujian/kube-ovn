package ko

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	configurationErr := a.checkConfiguration(ctx, client)
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
	pingers, err := client.targets(ctx, "app=kube-ovn-pinger", node, "pinger", true)
	if err != nil {
		return errors.Join(configurationErr, err)
	}
	if len(pingers) == 0 {
		return errors.Join(configurationErr, errors.New("no ready pinger containers matched the diagnostic target"))
	}
	failures := []error{configurationErr}
	for _, target := range pingers {
		if _, err := fmt.Fprintf(a.streams.Out, "Diagnosing node %s\n", target.Node); err != nil {
			return err
		}
		argv := []string{"/kube-ovn/kube-ovn-pinger", "--mode=job", "--target-ip-ports=" + targets}
		if mode != "IPPorts" {
			argv = append(argv, "--external-address=1.1.1.1,2606:4700:4700::1111")
		}
		if mode == "subnet" {
			argv = append(argv, "--tcp-conn-check-port="+cmp.Or(os.Getenv("TCP_CONN_CHECK_PORT"), "8100"), "--udp-conn-check-port="+cmp.Or(os.Getenv("UDP_CONN_CHECK_PORT"), "8101"))
		}
		if err := client.Executor.Exec(ctx, target, argv, a.outputStreams()); err != nil {
			failures = append(failures, fmt.Errorf("probe on %s: %w", target.Node, err))
		}
	}
	return errors.Join(failures...)
}

func (a *Application) checkConfiguration(ctx context.Context, client *Client) error {
	checks := []struct {
		name string
		run  func() error
	}{
		{"Kubernetes service", func() error {
			_, err := client.Kubernetes.CoreV1().Services("default").Get(ctx, "kubernetes", metav1.GetOptions{})
			return err
		}},
		{"Kube-OVN subnets", func() error {
			_, err := client.Dynamic.Resource(subnetResource).List(ctx, metav1.ListOptions{})
			return err
		}},
	}
	for _, name := range []string{"ovn-central", "kube-ovn-controller"} {
		checks = append(checks, struct {
			name string
			run  func() error
		}{name, func() error { return client.waitDeployment(ctx, name, 30*time.Second) }})
	}
	for _, name := range []string{"kube-ovn-cni", "ovs-ovn"} {
		checks = append(checks, struct {
			name string
			run  func() error
		}{name, func() error { return client.waitDaemonSet(ctx, name, 30*time.Second) }})
	}
	for _, role := range []string{"nb", "sb", "northd"} {
		checks = append(checks, struct {
			name string
			run  func() error
		}{role + " leader", func() error { _, err := client.leader(ctx, role); return err }})
	}
	if os.Getenv("WITHOUT_KUBE_PROXY") != "true" {
		checks = append(checks, struct {
			name string
			run  func() error
		}{"kube-proxy", func() error { return client.checkKubeProxy(ctx) }})
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
	// Do not hide RBAC or transport errors behind a missing-component diagnosis.
	return fmt.Errorf("get kube-proxy (set WITHOUT_KUBE_PROXY=true for proxy-free installations): %w", err)
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
