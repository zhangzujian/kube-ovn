package ko

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

func (c *Client) waitDeployment(ctx context.Context, name string, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		deployment, err := c.Kubernetes.AppsV1().Deployments(c.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		replicas := int32(1)
		if deployment.Spec.Replicas != nil {
			replicas = *deployment.Spec.Replicas
		}
		status := deployment.Status
		return status.ObservedGeneration >= deployment.Generation && status.UpdatedReplicas == replicas && status.ReadyReplicas == replicas && status.AvailableReplicas == replicas && status.Replicas == replicas, nil
	})
}

func (c *Client) waitDaemonSet(ctx context.Context, name string, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		ds, err := c.Kubernetes.AppsV1().DaemonSets(c.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return daemonSetReady(ds), nil
	})
}

func daemonSetReady(ds *appsv1.DaemonSet) bool {
	s := ds.Status
	return s.ObservedGeneration >= ds.Generation && s.DesiredNumberScheduled > 0 && s.CurrentNumberScheduled == s.DesiredNumberScheduled && s.UpdatedNumberScheduled == s.DesiredNumberScheduled && s.NumberReady == s.DesiredNumberScheduled && s.NumberAvailable == s.DesiredNumberScheduled && s.NumberMisscheduled == 0
}

func (c *Client) restart(ctx context.Context, kind, name string) error {
	patch, err := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]string{"kubectl.kubernetes.io/restartedAt": time.Now().UTC().Format(time.RFC3339Nano)}}}}})
	if err != nil {
		return err
	}
	if kind == "deployment" {
		if _, err := c.Kubernetes.AppsV1().Deployments(c.Namespace).Patch(ctx, name, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return err
		}
		return c.waitDeployment(ctx, name, 5*time.Minute)
	}
	if _, err := c.Kubernetes.AppsV1().DaemonSets(c.Namespace).Patch(ctx, name, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return err
	}
	return c.waitDaemonSet(ctx, name, 5*time.Minute)
}

func (a *Application) reload(ctx context.Context, client *Client, _ []string) error {
	components := [][2]string{{"deployment", "ovn-central"}, {"daemonset", "ovs-ovn"}, {"deployment", "kube-ovn-controller"}, {"daemonset", "kube-ovn-cni"}, {"daemonset", "kube-ovn-pinger"}, {"deployment", "kube-ovn-monitor"}}
	for _, component := range components {
		if _, err := fmt.Fprintf(a.streams.ErrOut, "Restarting %s/%s\n", component[0], component[1]); err != nil {
			return err
		}
		if err := client.restart(ctx, component[0], component[1]); err != nil {
			return fmt.Errorf("restart stopped at %s/%s: %w", component[0], component[1], err)
		}
	}
	return nil
}

type ownedResource struct {
	kind, name string
	uid        types.UID
}

type resourceRun struct {
	client    *Client
	id        string
	resources []ownedResource
}

func (r *resourceRun) labels() map[string]string {
	return map[string]string{"app": "kubectl-ko-probe", "kubeovn.io/ko-run": r.id}
}

func (r *resourceRun) cleanup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var failures []error
	for i := len(r.resources) - 1; i >= 0; i-- {
		item := r.resources[i]
		options := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: new(item.uid)}}
		var err error
		switch item.kind {
		case "pod":
			err = r.client.Kubernetes.CoreV1().Pods(r.client.Namespace).Delete(ctx, item.name, options)
		case "service":
			err = r.client.Kubernetes.CoreV1().Services(r.client.Namespace).Delete(ctx, item.name, options)
		case "daemonset":
			err = r.client.Kubernetes.AppsV1().DaemonSets(r.client.Namespace).Delete(ctx, item.name, options)
		}
		if err != nil && !apierrors.IsNotFound(err) {
			failures = append(failures, fmt.Errorf("cleanup %s/%s/%s (UID %s): %w", r.client.Namespace, item.kind, item.name, item.uid, err))
		}
	}
	return errors.Join(failures...)
}

func (r *resourceRun) createPod(ctx context.Context, pod *corev1.Pod) (*corev1.Pod, error) {
	result, err := r.client.Kubernetes.CoreV1().Pods(r.client.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	r.resources = append(r.resources, ownedResource{kind: "pod", name: result.Name, uid: result.UID})
	return result, nil
}

func (r *resourceRun) createService(ctx context.Context, service *corev1.Service) (*corev1.Service, error) {
	result, err := r.client.Kubernetes.CoreV1().Services(r.client.Namespace).Create(ctx, service, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	r.resources = append(r.resources, ownedResource{kind: "service", name: result.Name, uid: result.UID})
	return result, nil
}

func (r *resourceRun) createDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	result, err := r.client.Kubernetes.AppsV1().DaemonSets(r.client.Namespace).Create(ctx, ds, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	r.resources = append(r.resources, ownedResource{kind: "daemonset", name: result.Name, uid: result.UID})
	return r.client.waitDaemonSet(ctx, result.Name, 2*time.Minute)
}

func (c *Client) waitPod(ctx context.Context, name string) (*corev1.Pod, error) {
	var result *corev1.Pod
	err := wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		var err error
		result, err = c.Kubernetes.CoreV1().Pods(c.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, condition := range result.Status.Conditions {
			if condition.Type == corev1.PodReady {
				return condition.Status == corev1.ConditionTrue, nil
			}
		}
		return false, nil
	})
	return result, err
}
