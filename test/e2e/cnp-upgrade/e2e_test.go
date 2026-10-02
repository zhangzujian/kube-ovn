package cnp_upgrade

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e"
	k8sframework "k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/config"

	"github.com/kubeovn/kube-ovn/pkg/cnp"
	"github.com/kubeovn/kube-ovn/test/e2e/framework"
)

var _ = framework.SerialDescribe("[group:cnp-upgrade]", func() {
	f := framework.NewDefaultFramework("cnp-upgrade")
	framework.ConformanceIt("preserves positive and negative new connections through legacy upgrade, mixed leaders, migration and rollback", func() {
		f.SkipVersionPriorTo(1, 17, "CNP upgrade requires the v0.2.0-compatible target")
		target := os.Getenv("CNP_UPGRADE_TARGET_IMAGE")
		source := os.Getenv("CNP_UPGRADE_SOURCE_IMAGE")
		if target == "" || source == "" {
			ginkgo.Skip("requires isolated upgrade cluster and explicit source/target images")
		}
		ctx := context.Background()
		client, err := dynamic.NewForConfig(f.ClientConfig())
		framework.ExpectNoError(err)
		u := &cnp.Upgrade{Dynamic: client, Kube: f.ClientSet, Namespace: "kube-system", Deployment: "kube-ovn-controller", Image: target, Timeout: 3 * time.Minute, WritersFrozen: true, RollbackGuarded: true}
		u.Journal = func(plan *cnp.ObjectPlan) error { return json.MarshalWrite(ginkgo.GinkgoWriter, plan) }

		ginkgo.By("Preparing legacy schema while the legacy controller is running")
		framework.ExpectNoError(u.Prepare(ctx))
		nodes, err := f.ClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		framework.ExpectNoError(err)
		framework.ExpectEqual(len(nodes.Items) >= 2, true, "upgrade traffic probes require two nodes")
		server := &corev1.Pod{Name: "server", Labels: map[string]string{"app": "cnp-upgrade-server"}, Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "allowed", Image: "registry.k8s.io/e2e-test-images/agnhost:2.45", Args: []string{"netexec", "--http-port=8080", "--udp-port=-1"}},
			{Name: "denied", Image: "registry.k8s.io/e2e-test-images/agnhost:2.45", Args: []string{"netexec", "--http-port=8081", "--udp-port=-1"}},
			{Name: "baseline-denied", Image: "registry.k8s.io/e2e-test-images/agnhost:2.45", Args: []string{"netexec", "--http-port=8082", "--udp-port=-1"}},
			{Name: "dns-allowed", Image: "registry.k8s.io/e2e-test-images/agnhost:2.45", Args: []string{"netexec", "--http-port=8090", "--udp-port=-1"}},
		}}}
		server.Spec.NodeName = nodes.Items[0].Name
		server = f.PodClient().CreateSync(server)
		probe := &corev1.Pod{Name: "probe", Labels: map[string]string{"app": "cnp-upgrade-probe"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "probe", Image: source, Command: []string{"sleep", "infinity"}}}}}
		probe.Spec.NodeName = nodes.Items[1].Name
		probe = f.PodClient().CreateSync(probe)
		extra := createExperimentalProbes(f, &nodes.Items[0], server)
		verifyExperimentalListeners(f, probe, extra)
		names := []string{"cnp-upgrade-admin-" + framework.RandomSuffix(), "cnp-upgrade-baseline-" + framework.RandomSuffix(), "cnp-upgrade-experimental-" + framework.RandomSuffix()}
		defer func() {
			for _, name := range names {
				framework.ExpectNoError(client.Resource(cnp.Resource).Delete(ctx, name, metav1.DeleteOptions{}))
			}
		}()
		for i, name := range names {
			policy := upgradePolicy(name, f.Namespace.Name, i == 1)
			if i == 2 {
				policy = experimentalPolicy(name, f.Namespace.Name, nodes.Items[0].Labels[corev1.LabelHostname])
			}
			_, err := client.Resource(cnp.Resource).Create(ctx, policy, metav1.CreateOptions{})
			framework.ExpectNoError(err)
		}
		seedDNSResolver(f, names[2], server)
		addresses := make([]string, 0, len(server.Status.PodIPs))
		for _, address := range server.Status.PodIPs {
			addresses = append(addresses, address.IP)
		}
		framework.ExpectNoError(wait.PollUntilContextTimeout(ctx, time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
			return probeConnections(ctx, f, probe, addresses, extra...) == nil, nil
		}))
		probeCtx, cancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		failures := make(chan error, 1)
		wg.Go(func() {
			for probeCtx.Err() == nil {
				if err := probeConnections(probeCtx, f, probe, addresses, extra...); err != nil && probeCtx.Err() == nil {
					select {
					case failures <- err:
					default:
					}
				}
			}
		})
		defer func() {
			cancel()
			wg.Wait()
			select {
			case err := <-failures:
				framework.ExpectNoError(err)
			default:
			}
		}()

		helm := newControllerHelm(f, source)
		ginkgo.By("Failing an atomic Helm upgrade while legacy rollback is still safe")
		helm.failAndRollback(f, source)
		ginkgo.By("Upgrading central, OVS and node components while policies remain legacy")
		upgradeComponents(f, source, target)
		ginkgo.By("Keeping a legacy standby through the compatible controller rollout")
		legacy := legacyStandby(f, source)
		defer func() {
			framework.ExpectNoError(f.ClientSet.AppsV1().Deployments("kube-system").Delete(ctx, legacy.Name, metav1.DeleteOptions{}))
		}()
		setControllerImage(f, "kube-ovn-controller", target)
		_, err = u.VerifyController(ctx)
		framework.ExpectError(err, "legacy standby must block opening native schema")
		ginkgo.By("Forcing the legacy leader with a compatible standby")
		scaleController(f, "kube-ovn-controller", 0)
		waitForLeader(f, legacy.Name+"-")
		scaleController(f, "kube-ovn-controller", 1)
		ginkgo.By("Forcing the compatible leader before retiring legacy replicas")
		scaleController(f, legacy.Name, 0)
		waitForLeader(f, "kube-ovn-controller-")
		scaleController(f, legacy.Name, 1)
		_, err = u.VerifyController(ctx)
		framework.ExpectError(err, "legacy standby must remain blocked")
		scaleController(f, legacy.Name, 0)
		framework.ExpectNoError(wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
			_, err := u.VerifyController(ctx)
			return err == nil, nil
		}))

		ginkgo.By("Recording the compatible controller as the Helm rollback target")
		framework.ExpectNoError(helm.upgrade(target))
		waitCompatibleController(u)
		ginkgo.By("Independently opening native writes and migrating both tiers/directions")
		framework.ExpectNoError(u.OpenNative(ctx))
		ginkgo.By("Interrupting after one migrated object and resuming from live state")
		journal := u.Journal
		attempts := 0
		u.Journal = func(plan *cnp.ObjectPlan) error {
			if len(plan.Patch) != 0 {
				attempts++
				if attempts == 2 {
					return errors.New("injected journal interruption before the second object")
				}
			}
			return journal(plan)
		}
		framework.ExpectError(u.Migrate(ctx, false))
		partial, err := u.Plan(ctx, false)
		framework.ExpectNoError(err)
		remaining := 0
		for _, object := range partial.Objects {
			if len(object.Patch) != 0 {
				remaining++
			}
		}
		framework.ExpectEqual(remaining, len(names)-1, "the first object's migration must survive interruption")
		ginkgo.By("Detecting a concurrent spec update without overwriting it")
		var concurrentName string
		var concurrentPriority int64
		u.Journal = func(plan *cnp.ObjectPlan) error {
			if concurrentName == "" && len(plan.Patch) != 0 {
				current, err := client.Resource(cnp.Resource).Get(ctx, plan.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				priority, _, err := unstructured.NestedInt64(current.Object, "spec", "priority")
				if err != nil {
					return err
				}
				concurrentName, concurrentPriority = plan.Name, priority+1
				if err := unstructured.SetNestedField(current.Object, concurrentPriority, "spec", "priority"); err != nil {
					return err
				}
				if _, err := client.Resource(cnp.Resource).Update(ctx, current, metav1.UpdateOptions{}); err != nil {
					return err
				}
			}
			return journal(plan)
		}
		framework.ExpectError(u.Migrate(ctx, false), "a stale resourceVersion/spec must stop migration")
		framework.ExpectEqual(concurrentName != "", true)
		u.Journal = journal
		framework.ExpectNoError(u.Migrate(ctx, false))
		framework.ExpectNoError(u.Migrate(ctx, false))
		current, err := client.Resource(cnp.Resource).Get(ctx, concurrentName, metav1.GetOptions{})
		framework.ExpectNoError(err)
		priority, _, err := unstructured.NestedInt64(current.Object, "spec", "priority")
		framework.ExpectNoError(err)
		framework.ExpectEqual(priority, concurrentPriority, "resumption must preserve the concurrent desired spec")
		framework.ExpectNoError(u.Verify(ctx))
		ginkgo.By("Refusing migration when an old ReplicaSet is resurrected")
		scaleController(f, legacy.Name, 1)
		framework.ExpectError(u.Migrate(ctx, false), "resurrected legacy controller must block migration")
		scaleController(f, legacy.Name, 0)
		framework.ExpectNoError(wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
			_, err := u.VerifyController(ctx)
			return err == nil, nil
		}))
		ginkgo.By("Finalizing native schema, then restoring compatibility and reversing current objects")
		framework.ExpectNoError(u.Finalize(ctx))
		beforeRollback, err := u.Plan(ctx, false)
		framework.ExpectNoError(err)
		ginkgo.By("Failing an atomic Helm upgrade with a compatible rollback target and native policies")
		helm.failAndRollback(f, target)
		afterRollback, err := u.Plan(ctx, false)
		framework.ExpectNoError(err)
		framework.ExpectEqual(afterRollback.SchemaDigest, beforeRollback.SchemaDigest, "Helm rollback must not replace the independent CNP schema")
		framework.ExpectEqual(len(afterRollback.Objects), len(beforeRollback.Objects))
		for i, object := range afterRollback.Objects {
			framework.ExpectEqual(object.UID, beforeRollback.Objects[i].UID)
			framework.ExpectEqual(object.Generation, beforeRollback.Objects[i].Generation)
			framework.ExpectEqual(object.SemanticDigest, beforeRollback.Objects[i].SemanticDigest, "Helm rollback must preserve current policy semantics")
		}
		waitCompatibleController(u)
		framework.ExpectNoError(u.Verify(ctx))
		framework.ExpectNoError(u.Migrate(ctx, true))
		framework.ExpectNoError(u.Verify(ctx))
		ginkgo.By("Rolling the controller back to the original legacy image")
		framework.ExpectNoError(helm.run("rollback", "cnp-controller", "1", "--wait", "--timeout=180s"))
		waitDeployment(f, "kube-ovn-controller", 1)
		framework.ExpectNoError(probeConnections(ctx, f, probe, addresses, extra...))
		ginkgo.By("Expanding the legacy fleet to two nodes and upgrading it in HA batches")
		enableHAControllers(f)
		setControllerImage(f, "kube-ovn-controller", target)
		waitCompatibleController(u)
		framework.ExpectNoError(u.Verify(ctx))
	})
})

func upgradePolicy(name, namespace string, baseline bool) *unstructured.Unstructured {
	subject := map[string]any{"pods": map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": namespace}}, "podSelector": map[string]any{"matchLabels": map[string]any{"app": "cnp-upgrade-server"}}}}
	tier, direction, peerKey := "Admin", "ingress", "from"
	if baseline {
		tier, direction, peerKey = "Baseline", "egress", "to"
		subject = map[string]any{"namespaces": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": namespace}}}
	}
	peer := []any{map[string]any{"namespaces": map[string]any{}}}
	denyStart := int64(8081)
	if baseline {
		denyStart = 8082
	}
	rules := []any{
		map[string]any{"name": "accept-8080", "action": "Accept", peerKey: peer, "ports": []any{map[string]any{"portNumber": map[string]any{"port": int64(8080)}}}},
	}
	if !baseline {
		rules = append(rules, map[string]any{"name": "pass-8082", "action": "Pass", peerKey: peer, "ports": []any{map[string]any{"portNumber": map[string]any{"port": int64(8082)}}}})
	}
	rules = append(rules, map[string]any{"name": "deny-range", "action": "Deny", peerKey: peer, "ports": []any{map[string]any{"portRange": map[string]any{"protocol": "TCP", "start": denyStart, "end": denyStart + 1}}}})
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": cnp.Resource.GroupVersion().String(), "kind": "ClusterNetworkPolicy", "metadata": map[string]any{"name": name},
		"spec": map[string]any{"tier": tier, "priority": int64(10), "subject": subject, direction: rules},
	}}
}

func probeConnections(ctx context.Context, f *framework.Framework, pod *corev1.Pod, addresses []string, extra ...connectionProbe) error {
	for _, address := range addresses {
		allowed, denied := "http://"+net.JoinHostPort(address, "8080"), "http://"+net.JoinHostPort(address, "8081")
		command := fmt.Sprintf("curl -gsS --noproxy '*' --connect-timeout 2 --max-time 3 %s >/dev/null && ! curl -gsS --noproxy '*' --connect-timeout 1 --max-time 2 %s >/dev/null", allowed, denied)
		command += fmt.Sprintf(" && ! curl -gsS --noproxy '*' --connect-timeout 1 --max-time 2 http://%s >/dev/null", net.JoinHostPort(address, "8082"))
		stderr, err := executeProbe(ctx, f, pod, command)
		if err != nil {
			return fmt.Errorf("positive/negative new-connection probe %s failed at %s (%s): %w", address, time.Now().UTC().Format(time.RFC3339Nano), stderr, err)
		}
	}
	for _, test := range extra {
		commands := []string{fmt.Sprintf("curl -gsS --noproxy '*' --connect-timeout 2 --max-time 3 %s >/dev/null", test.allowed)}
		for _, denied := range test.denied {
			commands = append(commands, fmt.Sprintf("! curl -gsS --noproxy '*' --connect-timeout 1 --max-time 2 %s >/dev/null", denied))
		}
		stderr, err := executeProbe(ctx, f, pod, strings.Join(commands, " && "))
		if err != nil {
			return fmt.Errorf("experimental peer probe %s failed at %s (%s): %w", test.allowed, time.Now().UTC().Format(time.RFC3339Nano), stderr, err)
		}
	}
	return nil
}

// Bound the API-server exec stream as well as curl. A node rollout may interrupt
// SPDY without closing it, and cleanup must be able to stop the continuous probe.
func executeProbe(ctx context.Context, f *framework.Framework, pod *corev1.Pod, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req := f.ClientSet.CoreV1().RESTClient().Post().Resource("pods").Name(pod.Name).
		Namespace(pod.Namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{
		Container: "probe", Command: []string{"/bin/sh", "-c", command}, Stderr: true,
	}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(f.ClientConfig(), "POST", req.URL())
	if err != nil {
		return "", err
	}
	var stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stderr: &stderr})
	return stderr.String(), err
}

func upgradeComponents(f *framework.Framework, source, target string) {
	ctx := context.Background()
	for _, name := range []string{"ovn-central"} {
		deployment, err := f.ClientSet.AppsV1().Deployments("kube-system").Get(ctx, name, metav1.GetOptions{})
		framework.ExpectNoError(err)
		for i := range deployment.Spec.Template.Spec.Containers {
			if deployment.Spec.Template.Spec.Containers[i].Image == source {
				deployment.Spec.Template.Spec.Containers[i].Image = target
			}
		}
		_, err = f.ClientSet.AppsV1().Deployments("kube-system").Update(ctx, deployment, metav1.UpdateOptions{})
		framework.ExpectNoError(err)
		waitDeployment(f, name, *deployment.Spec.Replicas)
	}
	for _, name := range []string{"ovs-ovn", "kube-ovn-cni"} {
		set, err := f.ClientSet.AppsV1().DaemonSets("kube-system").Get(ctx, name, metav1.GetOptions{})
		framework.ExpectNoError(err)
		for i := range set.Spec.Template.Spec.Containers {
			if set.Spec.Template.Spec.Containers[i].Image == source {
				set.Spec.Template.Spec.Containers[i].Image = target
			}
		}
		_, err = f.ClientSet.AppsV1().DaemonSets("kube-system").Update(ctx, set, metav1.UpdateOptions{})
		framework.ExpectNoError(err)
		framework.ExpectNoError(wait.PollUntilContextTimeout(ctx, time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
			current, err := f.ClientSet.AppsV1().DaemonSets("kube-system").Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return current.Status.ObservedGeneration == current.Generation && current.Status.UpdatedNumberScheduled == current.Status.DesiredNumberScheduled && current.Status.NumberReady == current.Status.DesiredNumberScheduled, nil
		}))
	}
}

func legacyStandby(f *framework.Framework, image string) *appsv1.Deployment {
	deployment, err := f.ClientSet.AppsV1().Deployments("kube-system").Get(context.Background(), "kube-ovn-controller", metav1.GetOptions{})
	framework.ExpectNoError(err)
	deployment.ObjectMeta = metav1.ObjectMeta{Name: "cnp-legacy-standby", Namespace: "kube-system"}
	deployment.Status = appsv1.DeploymentStatus{}
	deployment.Spec.Replicas = new(int32(1))
	deployment.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"cnp-upgrade-standby": "true"}}
	deployment.Spec.Template.Labels["cnp-upgrade-standby"] = "true"
	deployment.Spec.Template.Spec.Affinity = nil
	deployment.Spec.Template.Spec.NodeSelector = nil
	pods, err := f.ClientSet.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{LabelSelector: "app=kube-ovn-controller"})
	framework.ExpectNoError(err)
	framework.ExpectEqual(len(pods.Items) > 0, true)
	nodes, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	framework.ExpectNoError(err)
	for _, node := range nodes.Items {
		if node.Name != pods.Items[0].Spec.NodeName {
			// Controller health endpoints use host networking; a standby must
			// run on a different node to avoid a metrics/health port collision.
			deployment.Spec.Template.Spec.NodeName = node.Name
			break
		}
	}
	framework.ExpectEqual(deployment.Spec.Template.Spec.NodeName != "", true)
	for i := range deployment.Spec.Template.Spec.Containers {
		if deployment.Spec.Template.Spec.Containers[i].Name == "kube-ovn-controller" {
			deployment.Spec.Template.Spec.Containers[i].Image = image
		}
	}
	deployment, err = f.ClientSet.AppsV1().Deployments("kube-system").Create(context.Background(), deployment, metav1.CreateOptions{})
	framework.ExpectNoError(err)
	waitDeployment(f, deployment.Name, 1)
	return deployment
}

func setControllerImage(f *framework.Framework, name, image string) {
	ctx := context.Background()
	deployment, err := f.ClientSet.AppsV1().Deployments("kube-system").Get(ctx, name, metav1.GetOptions{})
	framework.ExpectNoError(err)
	deployment.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{MaxSurge: new(intstr.FromInt32(0)), MaxUnavailable: new(intstr.FromInt32(1))}}
	for i := range deployment.Spec.Template.Spec.Containers {
		if deployment.Spec.Template.Spec.Containers[i].Name == "kube-ovn-controller" {
			deployment.Spec.Template.Spec.Containers[i].Image = image
		}
	}
	_, err = f.ClientSet.AppsV1().Deployments("kube-system").Update(ctx, deployment, metav1.UpdateOptions{})
	framework.ExpectNoError(err)
	waitDeployment(f, name, *deployment.Spec.Replicas)
}

func scaleController(f *framework.Framework, name string, replicas int32) {
	patch, err := json.Marshal(map[string]any{"spec": map[string]any{"replicas": replicas}})
	framework.ExpectNoError(err)
	_, err = f.ClientSet.AppsV1().Deployments("kube-system").Patch(context.Background(), name, types.MergePatchType, patch, metav1.PatchOptions{})
	framework.ExpectNoError(err)
	waitDeployment(f, name, replicas)
}

func waitDeployment(f *framework.Framework, name string, replicas int32) {
	framework.ExpectNoError(wait.PollUntilContextTimeout(context.Background(), time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		deployment, err := f.ClientSet.AppsV1().Deployments("kube-system").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return deployment.Status.ObservedGeneration == deployment.Generation && deployment.Status.UpdatedReplicas == replicas && deployment.Status.ReadyReplicas == replicas && deployment.Status.Replicas == replicas, nil
	}))
}

func waitForLeader(f *framework.Framework, prefix string) {
	framework.ExpectNoError(wait.PollUntilContextTimeout(context.Background(), time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		lease, err := f.ClientSet.CoordinationV1().Leases("kube-system").Get(ctx, "kube-ovn-controller", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return lease.Spec.HolderIdentity != nil && strings.HasPrefix(*lease.Spec.HolderIdentity, prefix), nil
	}))
}

func init() {
	klog.SetOutput(ginkgo.GinkgoWriter)
	config.CopyFlags(config.Flags, flag.CommandLine)
	k8sframework.RegisterCommonFlags(flag.CommandLine)
	k8sframework.RegisterClusterFlags(flag.CommandLine)
}

func TestE2E(t *testing.T) {
	k8sframework.AfterReadingAllFlags(&k8sframework.TestContext)
	e2e.RunE2ETests(t)
}
