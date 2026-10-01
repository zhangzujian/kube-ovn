package ko

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestCleanupIsReverseOrderedUIDScopedAndSurvivesCancellation(t *testing.T) {
	cs := fake.NewClientset()
	client := &Client{Kubernetes: cs, Namespace: "ovn-system"}
	run := &resourceRun{client: client, resources: []ownedResource{{kind: "pod", name: "a", uid: "pod-original"}, {kind: "service", name: "b", uid: "service-original"}, {kind: "daemonset", name: "c", uid: "ds-original"}}}
	var deleted []string
	cs.PrependReactor("delete", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		deletion := action.(ktesting.DeleteAction)
		require.NotNil(t, deletion.GetDeleteOptions().Preconditions)
		deleted = append(deleted, deletion.GetName()+":"+string(*deletion.GetDeleteOptions().Preconditions.UID))
		if deletion.GetName() == "b" {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "services"}, "b", errors.New("UID changed"))
		}
		return true, nil, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := run.cleanup(ctx)
	require.ErrorContains(t, err, "UID changed")
	require.Equal(t, []string{"c:ds-original", "b:service-original", "a:pod-original"}, deleted)
	require.ErrorContains(t, err, "service/b (UID service-original)")
}

func TestCleanupNeverDeletesAnUncreatedObject(t *testing.T) {
	cs := fake.NewClientset(&corev1.Pod{Name: "existing", Namespace: "ovn-system", UID: "other"})
	run := &resourceRun{client: &Client{Kubernetes: cs, Namespace: "ovn-system"}}
	_, err := run.createPod(t.Context(), &corev1.Pod{Name: "existing"})
	require.True(t, apierrors.IsAlreadyExists(err))
	require.NoError(t, run.cleanup(t.Context()))
	pod, err := cs.CoreV1().Pods("ovn-system").Get(t.Context(), "existing", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, types.UID("other"), pod.UID)
	for _, action := range cs.Actions() {
		require.NotEqual(t, "delete", action.GetVerb())
	}
}

func TestDaemonSetWaitDoesNotAcceptPreviousGeneration(t *testing.T) {
	ds := &appsv1.DaemonSet{Generation: 2, Status: appsv1.DaemonSetStatus{ObservedGeneration: 1, DesiredNumberScheduled: 1, CurrentNumberScheduled: 1, UpdatedNumberScheduled: 1, NumberReady: 1, NumberAvailable: 1}}
	require.False(t, daemonSetReady(ds))
	ds.Status.ObservedGeneration = 2
	require.True(t, daemonSetReady(ds))
	ds.Status.UpdatedNumberScheduled = 0
	require.False(t, daemonSetReady(ds))
}

func TestCleanupRecoversLostCreateResponseWithoutAdoptingOtherRuns(t *testing.T) {
	for _, owner := range []string{"ours", "other"} {
		t.Run(owner, func(t *testing.T) {
			cs := fake.NewClientset()
			run := &resourceRun{client: &Client{Kubernetes: cs, Namespace: "ovn-system"}, id: "ours"}
			cs.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
				pod := action.(ktesting.CreateAction).GetObject().(*corev1.Pod).DeepCopy()
				pod.Namespace, pod.UID = "ovn-system", "server-uid"
				pod.Labels = map[string]string{"kubeovn.io/ko-run": owner}
				require.NoError(t, cs.Tracker().Add(pod))
				return true, nil, context.DeadlineExceeded
			})
			_, err := run.createPod(t.Context(), &corev1.Pod{Name: "probe"})
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.NoError(t, run.cleanup(t.Context()))
			_, err = cs.CoreV1().Pods("ovn-system").Get(t.Context(), "probe", metav1.GetOptions{})
			if owner == "ours" {
				require.True(t, apierrors.IsNotFound(err))
			} else {
				require.NoError(t, err, "another run's resource must survive")
			}
		})
	}
}
