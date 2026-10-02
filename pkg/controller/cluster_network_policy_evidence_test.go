package controller

import (
	"context"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/kubeovn/kube-ovn/pkg/cnp"
)

func TestCnpEvidenceUsesBoundedLeaderPodAnnotations(t *testing.T) {
	pod := &corev1.Pod{Name: "leader", Namespace: "kube-system", UID: "pod", Annotations: map[string]string{"unrelated": "keep"}}
	client := fake.NewClientset(pod)
	c := &Controller{config: &Configuration{KubeClient: client, PodNamespace: pod.Namespace}, cnpContext: t.Context()}
	record := &cnp.Receipt{Capability: cnp.Capability, Leader: pod.Name, PodUID: string(pod.UID), Session: "session"}
	require.NoError(t, c.writeCnpEvidence(record))
	for _, uid := range []string{"first-policy", "second-policy"} {
		record.PolicyUID, record.Request = uid, uid+"-nonce"
		require.NoError(t, c.writeCnpEvidence(record))
	}
	observed, err := client.CoreV1().Pods(pod.Namespace).Get(t.Context(), pod.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, "keep", observed.Annotations["unrelated"])
	require.Len(t, observed.Annotations, 3, "receipts must not grow with policy count")
	var receipt cnp.Receipt
	require.NoError(t, json.Unmarshal([]byte(observed.Annotations[cnp.ReceiptAnnotation]), &receipt))
	require.Equal(t, "second-policy", receipt.PolicyUID)
	require.Equal(t, "second-policy-nonce", receipt.Request)
	for _, action := range client.Actions() {
		require.Equal(t, "pods", action.GetResource().Resource, "legacy controller must not need ConfigMap writes")
	}
	record.Request = ""
	require.NoError(t, c.writeCnpEvidence(record))
	record.PodUID = "replacement"
	record.Request = "new-nonce"
	require.Error(t, c.writeCnpEvidence(record), "stale leader identity must not overwrite a replacement Pod")
}

func TestCnpEvidenceRecoversAfterPodStatusAppears(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	pod := &corev1.Pod{Name: "leader", Namespace: "kube-system", UID: "pod"}
	client := fake.NewClientset(pod)
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	require.NoError(t, indexer.Add(&unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"name": "policy"}}}))
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	t.Cleanup(queue.ShutDown)
	c := &Controller{
		config: &Configuration{KubeClient: client, PodNamespace: pod.Namespace, PodName: pod.Name}, cnpContext: ctx,
		cnpsLister: &cnp.Lister{Indexer: indexer}, addCnpQueue: queue,
	}
	require.Error(t, c.initCnpEvidence(), "an unresolved imageID must not publish capability")
	require.Nil(t, c.cnpSession.Load())
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: controllerAgentName, ImageID: "registry/controller@sha256:" + strings.Repeat("a", 64)}}
	_, err := client.CoreV1().Pods(pod.Namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	c.retryCnpEvidence(ctx)
	require.NoError(t, ctx.Err())
	require.NotNil(t, c.cnpSession.Load(), "evidence must recover without a controller restart")
	require.Equal(t, 1, queue.Len(), "recovery must revisit policies applied without evidence")
	observed, err := client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	require.NoError(t, err)
	var capability cnp.Receipt
	require.NoError(t, json.Unmarshal([]byte(observed.Annotations[cnp.CapabilityAnnotation]), &capability))
	require.Equal(t, c.cnpSession.Load().Session, capability.Session)
}
