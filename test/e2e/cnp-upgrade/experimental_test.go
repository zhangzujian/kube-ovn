package cnp_upgrade

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"

	kubeovnv1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	"github.com/kubeovn/kube-ovn/pkg/cnp"
	"github.com/kubeovn/kube-ovn/test/e2e/framework"
)

const upgradeDomain = "allowed.upgrade.test."

type connectionProbe struct {
	allowed string
	denied  []string
}

func experimentalPolicy(name, namespace, hostname string) *unstructured.Unstructured {
	framework.ExpectEqual(hostname != "", true, "node peer requires a hostname label")
	rules := make([]any, 0, 4)
	for _, test := range []struct {
		name, action string
		port         int64
		peer         map[string]any
	}{
		{"allow-domain", "Accept", 8090, map[string]any{"domainNames": []any{upgradeDomain}}},
		{"deny-other-domain-addresses", "Deny", 8090, map[string]any{"networks": []any{"0.0.0.0/0", "::/0"}}},
		{"allow-node-port", "Accept", 18080, map[string]any{"nodes": map[string]any{"matchLabels": map[string]any{corev1.LabelHostname: hostname}}}},
		{"deny-node-port", "Deny", 18081, map[string]any{"nodes": map[string]any{"matchLabels": map[string]any{corev1.LabelHostname: hostname}}}},
	} {
		rules = append(rules, map[string]any{
			"name": test.name, "action": test.action, "to": []any{test.peer},
			"ports": []any{map[string]any{"portNumber": map[string]any{"protocol": "TCP", "port": test.port}}},
		})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": cnp.Resource.GroupVersion().String(), "kind": "ClusterNetworkPolicy", "metadata": map[string]any{"name": name},
		"spec": map[string]any{"tier": "Admin", "priority": int64(20), "subject": map[string]any{"pods": map[string]any{
			"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": namespace}},
			"podSelector":       map[string]any{"matchLabels": map[string]any{"app": "cnp-upgrade-probe"}},
		}}, "egress": rules},
	}}
}

func createExperimentalProbes(f *framework.Framework, node *corev1.Node, server *corev1.Pod) []connectionProbe {
	ginkgo.By("Starting live listeners for allowed and denied DNS/node destinations")
	const image = "registry.k8s.io/e2e-test-images/agnhost:2.45"
	rejected := f.PodClient().CreateSync(&corev1.Pod{Name: "dns-denied", Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Name: "server", Image: image, Args: []string{"netexec", "--http-port=8090", "--udp-port=-1"}},
	}}})
	f.PodClient().CreateSync(&corev1.Pod{Name: "node-listeners", Spec: corev1.PodSpec{NodeName: node.Name, HostNetwork: true, Containers: []corev1.Container{
		{Name: "allowed", Image: image, Args: []string{"netexec", "--http-port=18080", "--udp-port=-1"}},
		{Name: "denied", Image: image, Args: []string{"netexec", "--http-port=18081", "--udp-port=-1"}},
	}}})
	var probes []connectionProbe
	for _, address := range server.Status.PodIPs {
		for _, denied := range rejected.Status.PodIPs {
			if (net.ParseIP(address.IP).To4() != nil) == (net.ParseIP(denied.IP).To4() != nil) {
				probes = append(probes, connectionProbe{allowed: "http://" + net.JoinHostPort(address.IP, "8090"), denied: []string{"http://" + net.JoinHostPort(denied.IP, "8090")}})
			}
		}
	}
	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeInternalIP {
			continue
		}
		ipv4 := net.ParseIP(address.Address).To4() != nil
		if (ipv4 && f.HasIPv4()) || (!ipv4 && f.HasIPv6()) {
			probes = append(probes, connectionProbe{allowed: "http://" + net.JoinHostPort(address.Address, "18080"), denied: []string{"http://" + net.JoinHostPort(address.Address, "18081")}})
		}
	}
	framework.ExpectEqual(len(probes), 2*len(server.Status.PodIPs), "DNS and node peers must be probed in every cluster IP family")
	return probes
}

func verifyExperimentalListeners(f *framework.Framework, pod *corev1.Pod, probes []connectionProbe) {
	ginkgo.By("Verifying every listener is reachable before installing denial rules")
	var commands []string
	for _, probe := range probes {
		for _, endpoint := range append([]string{probe.allowed}, probe.denied...) {
			commands = append(commands, "curl -gsS --noproxy '*' --connect-timeout 2 --max-time 3 "+endpoint+" >/dev/null")
		}
	}
	framework.ExpectNoError(wait.PollUntilContextTimeout(context.Background(), time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := executeProbe(ctx, f, pod, strings.Join(commands, " && "))
		return err == nil, nil
	}))
}

// Seed deterministic resolved addresses to isolate representation migration from
// external DNS availability. The separate domain suite exercises real queries.
func seedDNSResolver(f *framework.Framework, name string, server *corev1.Pod) {
	ginkgo.By("Seeding a controlled DNSNameResolver address set for legacy takeover")
	client := f.KubeOVNClientSet.KubeovnV1().DNSNameResolvers()
	framework.ExpectNoError(wait.PollUntilContextTimeout(context.Background(), time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		resolvers, err := client.List(ctx, metav1.ListOptions{LabelSelector: "anp=" + name})
		if err != nil {
			return false, err
		}
		for _, resolver := range resolvers.Items {
			if resolver.Spec.Name != upgradeDomain {
				continue
			}
			addresses := make([]kubeovnv1.DNSNameResolverResolvedAddress, 0, len(server.Status.PodIPs))
			for _, address := range server.Status.PodIPs {
				addresses = append(addresses, kubeovnv1.DNSNameResolverResolvedAddress{IP: address.IP, TTLSeconds: 7200, LastLookupTime: new(metav1.Now())})
			}
			resolver.Status.ResolvedNames = []kubeovnv1.DNSNameResolverResolvedName{{DNSName: upgradeDomain, ResolvedAddresses: addresses}}
			_, err = client.UpdateStatus(ctx, &resolver, metav1.UpdateOptions{})
			return err == nil, err
		}
		return false, nil
	}))
}

func enableHAControllers(f *framework.Framework) {
	ctx := context.Background()
	client := f.ClientSet.AppsV1().Deployments("kube-system")
	deployment, err := client.Get(ctx, "kube-ovn-controller", metav1.GetOptions{})
	framework.ExpectNoError(err)
	deployment.Spec.Replicas = new(int32(2))
	deployment.Spec.Template.Spec.NodeSelector = nil
	deployment.Spec.Template.Spec.Affinity = &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
			LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "kube-ovn-controller"}},
			TopologyKey:   corev1.LabelHostname,
		}},
	}}
	_, err = client.Update(ctx, deployment, metav1.UpdateOptions{})
	framework.ExpectNoError(err)
	waitDeployment(f, deployment.Name, 2)
}

func waitCompatibleController(u *cnp.Upgrade) {
	framework.ExpectNoError(wait.PollUntilContextTimeout(context.Background(), time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := u.VerifyController(ctx)
		return err == nil, nil
	}))
}
