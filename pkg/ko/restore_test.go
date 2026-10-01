package ko

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func recoverySpec(container string) corev1.PodSpec {
	return corev1.PodSpec{Containers: []corev1.Container{{Name: container, VolumeMounts: []corev1.VolumeMount{{Name: "db", MountPath: "/etc/ovn"}}, Env: []corev1.EnvVar{{Name: "NODE_IPS", Value: "10.0.0.1,10.0.0.2"}}}}, Volumes: []corev1.Volume{{Name: "db", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/ovn"}}}}}
}

func recoveryApplication(t *testing.T) (*Application, *Client, *recordingExecutor, *appsv1.Deployment) {
	t.Helper()
	deployment := &appsv1.Deployment{Name: "ovn-central", Namespace: "ovn-system", Spec: appsv1.DeploymentSpec{Replicas: new(int32(2)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "ovn-central"}}, Template: corev1.PodTemplateSpec{Spec: recoverySpec("ovn-central")}}, Status: appsv1.DeploymentStatus{Replicas: 2, UpdatedReplicas: 2, ReadyReplicas: 2, AvailableReplicas: 2}}
	objects := []runtime.Object{deployment, &appsv1.DaemonSet{Name: "ovs-ovn", Namespace: "ovn-system", Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, CurrentNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberReady: 2, NumberAvailable: 2}}}
	for i := 1; i <= 2; i++ {
		name := fmt.Sprintf("node-%d", i)
		node := &corev1.Node{Name: name, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: fmt.Sprintf("10.0.0.%d", i)}}}}
		pod := readyPod("ovs-"+name, name, "openvswitch", map[string]string{"app": "ovs"})
		pod.Spec = recoverySpec("openvswitch")
		pod.Spec.NodeName = name
		objects = append(objects, node, pod)
	}
	app, executor, _, _ := testApplication(t, objects...)
	client, err := app.newClient()
	require.NoError(t, err)
	executor.run = func(_ context.Context, _ Target, argv []string, s Streams) error {
		if len(argv) > 1 && argv[1] == "db-name" {
			_, err := io.WriteString(s.Out, "OVN_Northbound\n")
			return err
		}
		if len(argv) > 3 && argv[3] == "ovsdb-server/get-db-storage-status" {
			_, err := io.WriteString(s.Out, "status: ok\n")
			return err
		}
		return nil
	}
	return app, client, executor, deployment
}

func TestRecoveryPlanRejectsNonBootstrapSource(t *testing.T) {
	_, client, executor, _ := recoveryApplication(t)
	_, _, err := client.planRecovery(t.Context(), "node-2")
	require.ErrorContains(t, err, "first NODE_IPS member")
	require.Empty(t, executor.calls)
	_, record, err := client.planRecovery(t.Context(), "node-1")
	require.NoError(t, err)
	require.Len(t, record.Targets, 2)
}

func TestRecoveryRejectsUnsharedDatabaseVolumes(t *testing.T) {
	_, client, _, deployment := recoveryApplication(t)
	deployment.Spec.Template.Spec.Volumes[0].HostPath = nil
	_, err := client.Kubernetes.AppsV1().Deployments(client.Namespace).Update(t.Context(), deployment, metav1.UpdateOptions{})
	require.NoError(t, err)
	_, _, err = client.planRecovery(t.Context(), "node-1")
	require.ErrorContains(t, err, "writable hostPath")
}

func installRecoveryScaleReactor(t *testing.T, client *Client) *[]int32 {
	t.Helper()
	cs := client.Kubernetes.(*fake.Clientset)
	scales := new([]int32)
	cs.PrependReactor("get", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "scale" {
			return false, nil, nil
		}
		return true, &autoscalingv1.Scale{Spec: autoscalingv1.ScaleSpec{Replicas: 2}}, nil
	})
	cs.PrependReactor("update", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "scale" {
			return false, nil, nil
		}
		scale := action.(ktesting.UpdateAction).GetObject().(*autoscalingv1.Scale)
		*scales = append(*scales, scale.Spec.Replicas)
		if scale.Spec.Replicas == 2 {
			pod := readyPod("central-new", "node-1", "ovn-central", map[string]string{"app": "ovn-central", "ovn-nb-leader": "true", "ovn-sb-leader": "true", "ovn-northd-leader": "true"})
			if err := cs.Tracker().Add(pod); err != nil {
				return true, nil, err
			}
		}
		return true, scale, nil
	})
	return scales
}

func TestRecoveryStagesStopWithoutRestartingOnFailure(t *testing.T) {
	for _, failCommand := range []string{"mkdir", "cp", "cluster-to-standalone", "mv", "none"} {
		t.Run(failCommand, func(t *testing.T) {
			t.Chdir(t.TempDir())
			app, client, executor, deployment := recoveryApplication(t)
			_, record, err := client.planRecovery(t.Context(), "node-1")
			require.NoError(t, err)
			scales := installRecoveryScaleReactor(t, client)
			executor.calls = nil
			original := executor.run
			failed := false
			executor.run = func(ctx context.Context, target Target, argv []string, s Streams) error {
				require.False(t, failed, "execution continued after an injected failure")
				if argv[0] == failCommand || len(argv) > 1 && argv[1] == failCommand {
					failed = true
					return errors.New("injected failure")
				}
				return original(ctx, target, argv, s)
			}
			err = app.restore(t.Context(), client, deployment, record)
			if failCommand == "none" {
				require.NoError(t, err)
				require.Equal(t, []int32{0, 2}, *scales)
				require.Equal(t, "completed", record.Stage)
			} else {
				require.ErrorContains(t, err, "injected failure")
				require.ErrorContains(t, err, "preserve kubectl-ko-recovery-")
				require.Equal(t, []int32{0}, *scales, "a failed restore must not restart partially replaced databases")
			}
			data, readErr := os.ReadFile("kubectl-ko-recovery-" + record.ID + ".json")
			require.NoError(t, readErr)
			require.Contains(t, string(data), record.Stage)
			if failCommand == "none" {
				var backups, moves int
				for _, call := range executor.calls {
					if call.argv[0] == "cp" && strings.Contains(call.argv[len(call.argv)-1], ".original") {
						backups++
					}
					if call.argv[0] == "mv" {
						require.Equal(t, 4, backups, "all originals must be copied before any member is replaced")
						moves++
					}
				}
				require.Equal(t, 8, moves, "both databases and their RAFT headers must be archived on each node")
			}
		})
	}
}
