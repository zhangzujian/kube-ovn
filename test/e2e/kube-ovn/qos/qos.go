package qos

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2epodoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"

	"github.com/onsi/ginkgo/v2"

	"github.com/kubeovn/kube-ovn/pkg/util"
	"github.com/kubeovn/kube-ovn/test/e2e/framework"
)

const (
	interval = 2 * time.Second
	timeout  = 2 * time.Minute
)

func parseConfig(table, config string) map[string]string {
	kvs := make(map[string]string, 3)
	for _, s := range strings.Fields(config) {
		kv := strings.Split(s, "=")
		if len(kv) != 2 {
			framework.Logf("ignore %s config %s", table, s)
			continue
		}
		kvs[kv[0]] = kv[1]
	}

	return kvs
}

func getOvsQosForPod(cs clientset.Interface, table string, pod *corev1.Pod) map[string]string {
	ovsPod := framework.GetOvsPodOnNode(cs, pod.Spec.NodeName)
	cmd := fmt.Sprintf(`ovs-vsctl --no-heading --columns=other_config --bare find %s external_ids:pod="%s/%s"`, table, pod.Namespace, pod.Name)
	output := e2epodoutput.RunHostCmdOrDie(ovsPod.Namespace, ovsPod.Name, cmd)
	return parseConfig(table, output)
}

func getOvsQosForPodRetry(cs clientset.Interface, table string, pod *corev1.Pod, expected map[string]string, interval, timeout time.Duration) map[string]string {
	ovsPod := framework.GetOvsPodOnNode(cs, pod.Spec.NodeName)
	cmd := fmt.Sprintf(`ovs-vsctl --no-heading --columns=other_config --bare find %s external_ids:pod="%s/%s"`, table, pod.Namespace, pod.Name)

	var config map[string]string
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		output, err := e2epodoutput.RunHostCmd(ovsPod.Namespace, ovsPod.Name, cmd)
		if err != nil {
			return false, err
		}
		if output == "" {
			return false, nil
		}
		kvs := parseConfig(table, output)
		for k, v := range expected {
			if kvs[k] != v {
				return false, nil
			}
		}

		config = kvs
		return true, nil
	})
	framework.ExpectNoError(err, "timed out getting ovs %s config for pod %s/%s", table, pod.Namespace, pod.Name)

	return config
}

var _ = framework.Describe("[group:qos]", func() {
	f := framework.NewDefaultFramework("qos")

	var subnetName, namespaceName string
	var cs clientset.Interface
	var podClient *e2epod.PodClient
	var subnetClient *framework.SubnetClient

	ginkgo.BeforeEach(func() {
		cs = f.ClientSet
		podClient = e2epod.NewPodClient(f.Framework)
		subnetClient = f.SubnetClient()
		namespaceName = f.Namespace.Name
	})
	ginkgo.AfterEach(func() {
		if subnetName != "" {
			ginkgo.By("Deleting subnet " + subnetName)
			subnetClient.DeleteSync(subnetName, metav1.DeleteOptions{}, timeout)
		}
	})

	framework.ConformanceIt(`should support netem QoS"`, func() {
		name := "pod-" + framework.RandomSuffix()
		ginkgo.By("Creating pod " + name)
		latency, limit, loss := 600, 2000, 10
		annotations := map[string]string{
			util.NetemQosLatencyAnnotation: strconv.Itoa(latency),
			util.NetemQosLimitAnnotation:   strconv.Itoa(limit),
			util.NetemQosLossAnnotation:    strconv.Itoa(loss),
		}
		pod := framework.MakePod(namespaceName, name, nil, annotations, "", nil, nil)
		pod = podClient.CreateSync(pod)

		ginkgo.By("Validating pod annotations")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.AllocatedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.RoutedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.NetemQosLatencyAnnotation, strconv.Itoa(latency))
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.NetemQosLimitAnnotation, strconv.Itoa(limit))
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.NetemQosLossAnnotation, strconv.Itoa(loss))

		ginkgo.By("Validating OVS QoS")
		qos := getOvsQosForPod(cs, "qos", pod)
		framework.ExpectHaveKeyWithValue(qos, "latency", strconv.Itoa(latency*1000))
		framework.ExpectHaveKeyWithValue(qos, "limit", strconv.Itoa(limit))
		framework.ExpectHaveKeyWithValue(qos, "loss", strconv.Itoa(loss))

		ginkgo.By("Deleting pod " + name)
		podClient.DeleteSync(pod.Name, metav1.DeleteOptions{}, timeout)
	})

	framework.ConformanceIt(`should be able to update netem QoS"`, func() {
		name := "pod-" + framework.RandomSuffix()
		ginkgo.By("Creating pod " + name + " without QoS")
		pod := framework.MakePod(namespaceName, name, nil, nil, "", nil, nil)
		pod = podClient.CreateSync(pod)

		ginkgo.By("Validating pod annotations")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.AllocatedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.RoutedAnnotation, "true")
		framework.ExpectNotHaveKey(pod.Annotations, util.NetemQosLatencyAnnotation)
		framework.ExpectNotHaveKey(pod.Annotations, util.NetemQosLimitAnnotation)
		framework.ExpectNotHaveKey(pod.Annotations, util.NetemQosLossAnnotation)

		ginkgo.By("Adding netem QoS to pod annotations")
		latency, limit, loss := 600, 2000, 10
		modifiedPod := pod.DeepCopy()
		modifiedPod.Annotations[util.NetemQosLatencyAnnotation] = strconv.Itoa(latency)
		modifiedPod.Annotations[util.NetemQosLimitAnnotation] = strconv.Itoa(limit)
		modifiedPod.Annotations[util.NetemQosLossAnnotation] = strconv.Itoa(loss)
		pod = framework.PatchPod(cs, pod, modifiedPod, timeout)

		ginkgo.By("Validating pod annotations")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.AllocatedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.RoutedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.NetemQosLatencyAnnotation, strconv.Itoa(latency))
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.NetemQosLimitAnnotation, strconv.Itoa(limit))
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.NetemQosLossAnnotation, strconv.Itoa(loss))

		ginkgo.By("Validating OVS QoS")
		qos := getOvsQosForPodRetry(cs, "qos", pod, nil, interval, timeout)
		framework.ExpectHaveKeyWithValue(qos, "latency", strconv.Itoa(latency*1000))
		framework.ExpectHaveKeyWithValue(qos, "limit", strconv.Itoa(limit))
		framework.ExpectHaveKeyWithValue(qos, "loss", strconv.Itoa(loss))

		ginkgo.By("Deleting pod " + name)
		podClient.DeleteSync(pod.Name, metav1.DeleteOptions{}, timeout)
	})

	framework.ConformanceIt(`should support htb QoS"`, func() {
		name := "pod-" + framework.RandomSuffix()
		ginkgo.By("Creating pod " + name)
		priority, ingressRate := 50, 300
		annotations := map[string]string{
			util.PriorityAnnotation:    strconv.Itoa(priority),
			util.IngressRateAnnotation: strconv.Itoa(ingressRate),
		}
		pod := framework.MakePod(namespaceName, name, nil, annotations, "", nil, nil)
		pod = podClient.CreateSync(pod)

		ginkgo.By("Validating pod annotations")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.AllocatedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.RoutedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.PriorityAnnotation, strconv.Itoa(priority))
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.IngressRateAnnotation, strconv.Itoa(ingressRate))

		ginkgo.By("Validating OVS Queue")
		queue := getOvsQosForPod(cs, "queue", pod)
		framework.ExpectHaveKeyWithValue(queue, "max-rate", strconv.Itoa(ingressRate*1000*1000))
		framework.ExpectHaveKeyWithValue(queue, "priority", strconv.Itoa(priority))

		ginkgo.By("Deleting pod " + name)
		podClient.DeleteSync(pod.Name, metav1.DeleteOptions{}, timeout)
	})

	framework.ConformanceIt(`should be able to update htb QoS"`, func() {
		subnetName = f.Namespace.Name
		ginkgo.By("Creating subnet " + subnetName + " with htb QoS")
		cidr := framework.RandomCIDR(f.ClusterIpFamily)
		subnet := framework.MakeSubnet(subnetName, "", cidr, "", nil, nil, []string{namespaceName})
		subnet.Spec.HtbQos = util.HtbQosLow
		subnetClient.CreateSync(subnet, timeout)

		ginkgo.By("Validating subnet .spec.htbqos field")
		framework.ExpectEqual(subnet.Spec.HtbQos, util.HtbQosLow)

		name := "pod-" + framework.RandomSuffix()
		ginkgo.By("Creating pod " + name)
		pod := framework.MakePod(namespaceName, name, nil, nil, "", nil, nil)
		pod = podClient.CreateSync(pod)

		ginkgo.By("Validating pod annotations")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.AllocatedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.RoutedAnnotation, "true")
		framework.ExpectNotHaveKey(pod.Annotations, util.PriorityAnnotation)
		framework.ExpectNotHaveKey(pod.Annotations, util.IngressRateAnnotation)

		ginkgo.By("Validating OVS Queue")
		defaultPriority := 5
		queue := getOvsQosForPod(cs, "queue", pod)
		framework.ExpectHaveKeyWithValue(queue, "priority", strconv.Itoa(defaultPriority))

		ginkgo.By("Update htb priority by adding pod annotation")
		priority := 2
		modifiedPod := pod.DeepCopy()
		modifiedPod.Annotations[util.PriorityAnnotation] = strconv.Itoa(priority)
		pod = framework.PatchPod(cs, pod, modifiedPod, timeout)

		ginkgo.By("Validating pod annotations")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.AllocatedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.RoutedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.PriorityAnnotation, strconv.Itoa(priority))
		framework.ExpectNotHaveKey(pod.Annotations, util.IngressRateAnnotation)

		ginkgo.By("Validating OVS Queue")
		expected := map[string]string{"priority": strconv.Itoa(priority)}
		_ = getOvsQosForPodRetry(cs, "queue", pod, expected, interval, timeout)

		ginkgo.By("Update htb priority by deleting pod annotation")
		modifiedPod = pod.DeepCopy()
		delete(modifiedPod.Annotations, util.PriorityAnnotation)
		pod = framework.PatchPod(cs, pod, modifiedPod, timeout)

		ginkgo.By("Validating pod annotations")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.AllocatedAnnotation, "true")
		framework.ExpectHaveKeyWithValue(pod.Annotations, util.RoutedAnnotation, "true")
		framework.ExpectNotHaveKey(pod.Annotations, util.PriorityAnnotation)
		framework.ExpectNotHaveKey(pod.Annotations, util.IngressRateAnnotation)

		ginkgo.By("Validating OVS Queue")
		expected = map[string]string{"priority": strconv.Itoa(defaultPriority)}
		_ = getOvsQosForPodRetry(cs, "queue", pod, expected, interval, timeout)

		ginkgo.By("Deleting pod " + name)
		podClient.DeleteSync(pod.Name, metav1.DeleteOptions{}, timeout)
	})
})
