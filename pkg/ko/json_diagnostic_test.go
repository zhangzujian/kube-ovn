package ko

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"reflect"
	"runtime"
	"sync"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/remotecommand"
)

// reportJSONDiagnostic avoids invoking Error until the error structure is recorded.
func reportJSONDiagnostic(t *testing.T, value any, err error) {
	t.Helper()
	if err == nil {
		return
	}
	t.Errorf("[DEBUG-json-127182547277] value=%T error-type=%T error-fields=%#v", value, err, err)
	v := reflect.ValueOf(err)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		t.Errorf("[DEBUG-json-127182547277] typed nil error")
		return
	}
	if semantic, ok := errors.AsType[*json.SemanticError](err); ok && semantic != nil {
		t.Errorf("[DEBUG-json-127182547277] offset=%d pointer=%q kind=%d go-type=%#v nested-type=%T nested-fields=%#v",
			semantic.ByteOffset, semantic.JSONPointer, semantic.JSONKind, semantic.GoType, semantic.Err, semantic.Err)
	}
}

func TestJSONDiagnosticSerialization(t *testing.T) {
	t.Logf("[DEBUG-json-127182547277] runtime=%s os=%s arch=%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	for _, workers := range []int{1, 16} {
		var wg sync.WaitGroup
		for range workers {
			wg.Go(func() {
				for range 1000 {
					for _, value := range jsonDiagnosticFixtures() {
						if _, err := json.Marshal(value); err != nil {
							reportJSONDiagnostic(t, value, err)
							return
						}
						var out bytes.Buffer
						if err := json.MarshalWrite(&out, value); err != nil {
							reportJSONDiagnostic(t, value, err)
							return
						}
					}
				}
			})
		}
		wg.Wait()
		if t.Failed() {
			return
		}
	}
}

func jsonDiagnosticFixtures() []any {
	status := metav1.Status{Status: metav1.StatusFailure, Reason: remotecommand.NonZeroExitCodeReason,
		Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{{Type: remotecommand.ExitCodeCauseType, Message: "42"}}}}
	ds := &appsv1.DaemonSet{Name: "ko-subnet-owned", Namespace: "ovn-system", UID: "owned-ds", Spec: appsv1.DaemonSetSpec{
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"run": "owned"}},
	}}
	owned := corev1.Pod{Name: "owned-pod", Namespace: ds.Namespace, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: ds.Name, UID: ds.UID, Controller: new(true)}}, Status: corev1.PodStatus{
		ContainerStatuses: []corev1.ContainerStatus{{Name: "probe", RestartCount: 2, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}},
	}}
	other := owned.DeepCopy()
	other.Name, other.OwnerReferences[0].UID = "unrelated-pod", "other-ds"
	return []any{
		metav1.Status{Status: metav1.StatusSuccess}, status,
		&metav1.Status{Kind: "Status", APIVersion: "v1", Status: "Failure", Reason: metav1.StatusReasonForbidden, Code: 403, Message: "cannot observe readiness"},
		ds, &corev1.PodList{Items: []corev1.Pod{*other, owned}},
	}
}
