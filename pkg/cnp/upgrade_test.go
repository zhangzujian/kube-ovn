package cnp

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func compatibleFleet(t *testing.T) (*Upgrade, *corev1.Pod, *appsv1.ReplicaSet) {
	t.Helper()
	image := "example/controller@sha256:" + strings.Repeat("a", 64)
	template := corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "kube-ovn-controller", Image: image, Args: []string{"--enable-anp=true"}}}}}
	deployment := &appsv1.Deployment{Name: "kube-ovn-controller", Namespace: "kube-system", UID: "deployment", Generation: 2, Spec: appsv1.DeploymentSpec{Replicas: new(int32(1)), Template: template}, Status: appsv1.DeploymentStatus{ObservedGeneration: 2, UpdatedReplicas: 1, AvailableReplicas: 1}}
	set := &appsv1.ReplicaSet{Name: "controller-new", Namespace: "kube-system", UID: "set", OwnerReferences: []metav1.OwnerReference{{UID: deployment.UID, Controller: new(true)}}, Spec: appsv1.ReplicaSetSpec{Replicas: new(int32(1)), Template: template}}
	pod := &corev1.Pod{Name: "leader", Namespace: "kube-system", UID: "pod", OwnerReferences: []metav1.OwnerReference{{UID: set.UID, Controller: new(true)}}, Spec: template.Spec, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "kube-ovn-controller", Ready: true, ImageID: "docker-pullable://" + image}}}}
	lease := &coordv1.Lease{Name: "kube-ovn-controller", Namespace: "kube-system", Spec: coordv1.LeaseSpec{HolderIdentity: new("leader"), LeaseDurationSeconds: new(int32(30)), RenewTime: new(metav1.NewMicroTime(time.Now()))}}
	data, err := json.Marshal(Receipt{Capability: Capability, Leader: pod.Name, PodUID: string(pod.UID), Session: "session", ImageID: image})
	if err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{Name: CapabilityName(pod.UID), Namespace: "kube-system", Data: map[string]string{"receipt": string(data)}}
	client := fake.NewClientset([]runtime.Object{deployment, set, pod, lease, cm}...)
	return &Upgrade{Kube: client, Namespace: "kube-system", Deployment: deployment.Name, Image: image}, pod, set
}

func TestControllerGateRejectsUnsafeFleet(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*testing.T, *Upgrade, *corev1.Pod, *appsv1.ReplicaSet)
	}{
		{"legacy standby", func(t *testing.T, u *Upgrade, pod *corev1.Pod, _ *appsv1.ReplicaSet) {
			old := pod.DeepCopy()
			old.Name, old.UID = "legacy-standby", "old"
			old.Spec.Containers[0].Image = "old:v1.16.10"
			if _, err := u.Kube.CoreV1().Pods(u.Namespace).Create(t.Context(), old, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{"old ReplicaSet resurrected", func(t *testing.T, u *Upgrade, _ *corev1.Pod, set *appsv1.ReplicaSet) {
			old := set.DeepCopy()
			old.Name, old.UID = "controller-old", "oldset"
			old.Spec.Template.Spec.Containers[0].Image = "old:v1.16.10"
			if _, err := u.Kube.AppsV1().ReplicaSets(u.Namespace).Create(t.Context(), old, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{"disabled policy flag", func(t *testing.T, u *Upgrade, pod *corev1.Pod, _ *appsv1.ReplicaSet) {
			pod.Spec.Containers[0].Args = []string{"--enable-anp=false"}
			if _, err := u.Kube.CoreV1().Pods(u.Namespace).Update(t.Context(), pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{"PodReady with wrong digest", func(t *testing.T, u *Upgrade, pod *corev1.Pod, _ *appsv1.ReplicaSet) {
			pod.Status.ContainerStatuses[0].ImageID = "old@sha256:" + strings.Repeat("b", 64)
			if _, err := u.Kube.CoreV1().Pods(u.Namespace).Update(t.Context(), pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{"capability missing", func(t *testing.T, u *Upgrade, pod *corev1.Pod, _ *appsv1.ReplicaSet) {
			if err := u.Kube.CoreV1().ConfigMaps(u.Namespace).Delete(t.Context(), CapabilityName(pod.UID), metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{"terminating old Pod", func(t *testing.T, u *Upgrade, pod *corev1.Pod, _ *appsv1.ReplicaSet) {
			pod.DeletionTimestamp = new(metav1.Now())
			if _, err := u.Kube.CoreV1().Pods(u.Namespace).Update(t.Context(), pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, pod, set := compatibleFleet(t)
			if _, err := u.VerifyController(t.Context()); err != nil {
				t.Fatalf("compatible fleet was rejected: %v", err)
			}
			tt.mutate(t, u, pod, set)
			if _, err := u.VerifyController(t.Context()); err == nil {
				t.Fatal("unsafe fleet was accepted")
			}
		})
	}
}

func TestExternalGateIsMandatory(t *testing.T) {
	u, _, _ := compatibleFleet(t)
	if err := u.requireExternalGate(); err == nil {
		t.Fatal("missing external gate was accepted")
	}
	u.WritersFrozen = true
	if err := u.requireExternalGate(); err == nil {
		t.Fatal("unguarded legacy rollback was accepted")
	}
	u.RollbackGuarded = true
	if err := u.requireExternalGate(); err != nil {
		t.Fatal(err)
	}
}
