package cnp

import (
	"encoding/json/v2"
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
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
	pod.Annotations = map[string]string{CapabilityAnnotation: string(data)}
	client := fake.NewClientset([]runtime.Object{deployment, set, pod, lease}...)
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
			delete(pod.Annotations, CapabilityAnnotation)
			if _, err := u.Kube.CoreV1().Pods(u.Namespace).Update(t.Context(), pod, metav1.UpdateOptions{}); err != nil {
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

func TestInventoryVerificationRejectsLeaderChange(t *testing.T) {
	for _, changeLeader := range []bool{false, true} {
		t.Run(fmt.Sprintf("changeLeader=%v", changeLeader), func(t *testing.T) {
			u, pod, _ := compatibleFleet(t)
			u.Timeout = time.Second
			crd, err := Schema("dual")
			if err != nil {
				t.Fatal(err)
			}
			first := rawPolicy(t, `,"ports":[{"portNumber":{"port":80}}]}`)
			first.SetName("first")
			second := first.DeepCopy()
			second.SetName("second")
			second.SetUID("uid-2")
			client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{Resource: "ClusterNetworkPolicyList"}, crd, first, second)
			u.Dynamic = client
			session := "session"
			publish := func(receipt *Receipt) {
				t.Helper()
				capability, err := json.Marshal(Receipt{Capability: Capability, Leader: pod.Name, PodUID: string(pod.UID), Session: session, ImageID: u.Image})
				if err != nil {
					t.Fatal(err)
				}
				pod.Annotations[CapabilityAnnotation] = string(capability)
				if receipt != nil {
					data, err := json.Marshal(receipt)
					if err != nil {
						t.Fatal(err)
					}
					pod.Annotations[ReceiptAnnotation] = string(data)
				}
				if _, err := u.Kube.CoreV1().Pods(u.Namespace).Update(t.Context(), pod, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			client.PrependReactor("patch", Resource.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				patch := action.(k8stesting.PatchAction)
				obj, err := client.Tracker().Get(Resource, "", patch.GetName())
				if err != nil {
					return true, nil, err
				}
				var operations []PatchOperation
				if err := json.Unmarshal(patch.GetPatch(), &operations); err != nil {
					return true, nil, err
				}
				plan, err := PlanObject(obj.(*unstructured.Unstructured), false)
				if err != nil {
					return true, nil, err
				}
				request := operations[2].Value.(map[string]any)[VerifyAnnotation].(string)
				publish(&Receipt{
					Capability: Capability, Leader: pod.Name, PodUID: string(pod.UID), Session: session, ImageID: u.Image,
					Request: request, PolicyUID: plan.UID, Generation: plan.Generation, SemanticDigest: plan.SemanticDigest, OVNDigest: "verified-nb",
				})
				return true, obj, nil
			})
			gets := 0
			client.PrependReactor("get", Resource.Resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.(k8stesting.GetAction).GetName() == first.GetName() {
					gets++
					if changeLeader && gets == 2 {
						// Replace the leader session after the first receipt was
						// validated, before the next policy requests its receipt.
						session = "replacement-session"
						publish(nil)
					}
				}
				return false, nil, nil
			})
			err = u.Verify(t.Context())
			if changeLeader {
				if err == nil || !strings.Contains(err.Error(), "leader changed during inventory verification") {
					t.Fatalf("receipts from different leader sessions were accepted: %v", err)
				}
			} else if err != nil {
				t.Fatalf("stable leader verification failed: %v", err)
			}
		})
	}
}
