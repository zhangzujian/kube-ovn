package ko

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
)

func podTarget(pod *corev1.Pod, container string, ready bool) (Target, bool) {
	if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return Target{}, false
	}
	if container == "" && len(pod.Spec.Containers) == 1 {
		container = pod.Spec.Containers[0].Name
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == container && status.State.Running != nil && (!ready || status.Ready) {
			return Target{Namespace: pod.Namespace, Pod: pod.Name, Container: container, Node: pod.Spec.NodeName}, true
		}
	}
	return Target{}, false
}

func (c *Client) targets(ctx context.Context, selector, node, container string, ready bool) ([]Target, error) {
	options := metav1.ListOptions{LabelSelector: selector}
	if node != "" {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", node).String()
	}
	pods, err := c.Kubernetes.CoreV1().Pods(c.Namespace).List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("list %s pods: %w", selector, err)
	}
	result := make([]Target, 0, len(pods.Items))
	for i := range pods.Items {
		if node != "" && pods.Items[i].Spec.NodeName != node {
			continue
		}
		if target, ok := podTarget(&pods.Items[i], container, ready); ok {
			result = append(result, target)
		}
	}
	slices.SortFunc(result, func(a, b Target) int { return strings.Compare(a.Pod, b.Pod) })
	return result, nil
}

func (c *Client) uniqueTarget(ctx context.Context, selector, node, container string) (Target, error) {
	var result Target
	var candidates []Target
	err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, c.DiscoveryTimeout, true,
		func(ctx context.Context) (bool, error) {
			var err error
			candidates, err = c.targets(ctx, selector, node, container, true)
			if err != nil {
				return false, err
			}
			if len(candidates) != 1 {
				return false, nil
			}
			result = candidates[0]
			return true, nil
		})
	if err != nil {
		return Target{}, fmt.Errorf("resolve %s on node %q: expected one ready container %q, found %d: %w", selector, node, container, len(candidates), err)
	}
	return result, nil
}

func (c *Client) leader(ctx context.Context, role string) (Target, error) {
	container := "ovn-central"
	if strings.HasPrefix(role, "ic-") {
		container = "ovn-ic-server"
	}
	return c.uniqueTarget(ctx, "ovn-"+role+"-leader=true", "", container)
}

func (c *Client) nodeTarget(ctx context.Context, node, component string) (Target, error) {
	if _, err := c.Kubernetes.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{}); err != nil {
		return Target{}, fmt.Errorf("get node %s: %w", node, err)
	}
	container := "openvswitch"
	if component == "kube-ovn-cni" {
		container = "cni-server"
	}
	return c.uniqueTarget(ctx, "app="+component, node, container)
}

func (c *Client) pod(ctx context.Context, name string) (*corev1.Pod, error) {
	namespace, pod := c.WorkloadNamespace, name
	if ns, n, ok := strings.Cut(name, "/"); ok {
		namespace, pod = ns, n
	}
	if namespace == "" || pod == "" || strings.Contains(pod, "/") {
		return nil, fmt.Errorf("invalid pod reference %q", name)
	}
	result, err := c.Kubernetes.CoreV1().Pods(namespace).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", namespace, pod, err)
	}
	if result.Spec.NodeName == "" {
		return nil, fmt.Errorf("pod %s/%s is not scheduled", namespace, pod)
	}
	return result, nil
}
