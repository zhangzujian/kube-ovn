package ko

import (
	"bytes"
	"context"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestKubernetesAgentRequestCancellation(t *testing.T) {
	executor, target, pod := newRuntimeProofExecutor(t)
	var stdout, stderr bytes.Buffer
	err := executor.Exec(t.Context(), target, []string{"sh", "-c", `printf '\000\377\015\012'; printf diagnostic >&2; exit 17`}, Streams{Out: &stdout, ErrOut: &stderr})
	require.Equal(t, 17, ExitCode(err))
	require.Equal(t, []byte{0, 255, 13, 10}, stdout.Bytes())
	require.Equal(t, "diagnostic", stderr.String())
	directory, err := runtimeProofCapture(t.Context(), executor, target, "mktemp", "-d", "/tmp/ko-runtime-proof-XXXXXX")
	require.NoError(t, err)
	directory = strings.TrimSpace(directory)
	require.True(t, strings.HasPrefix(directory, "/tmp/ko-runtime-proof-"))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := runtimeProofCapture(cleanup, executor, target, "rm", "-r", directory)
		require.NoError(t, err)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- executor.Exec(ctx, target, []string{"sh", "-c", `printf '%s\n' "$$" > "$1/parent"; sleep 600 & printf '%s\n' "$!" > "$1/child"; wait`, "sh", directory}, Streams{Out: io.Discard, ErrOut: io.Discard})
	}()
	var pids []string
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		output, err := runtimeProofCapture(t.Context(), executor, target, "cat", directory+"/parent", directory+"/child")
		if !assert.NoError(collect, err) {
			return
		}
		pids = strings.Fields(output)
		assert.Len(collect, pids, 2)
	}, 20*time.Second, 100*time.Millisecond)
	parent := runtimeProofProcess(t, executor, target, pids[0])
	child := runtimeProofProcess(t, executor, target, pids[1])
	require.Equal(t, pids[0], parent[2], "the command must lead its isolated process group")
	require.Equal(t, parent[2], child[2], "the descendant must belong to that process group")
	helperPID := parent[1]
	require.NotEqual(t, "1", helperPID, "request helper must be independent of the agent main process")
	command, err := runtimeProofCapture(t.Context(), executor, target, "cat", "/proc/"+helperPID+"/cmdline")
	require.NoError(t, err)
	require.Contains(t, command, "kubectl-ko-node-agent\x00--stdio")
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, 130, ExitCode(err))
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled Kubernetes request did not return")
	}
	pids = append(pids, helperPID)
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		args := append([]string{"sh", "-c", `for pid in "$@"; do if [ -r "/proc/$pid/stat" ]; then cat "/proc/$pid/stat"; fi; done`, "sh"}, pids...)
		output, err := runtimeProofCapture(t.Context(), executor, target, args...)
		assert.NoError(collect, err)
		for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
			if line == "" {
				continue
			}
			_, fields, found := strings.CutLast(line, ") ")
			if assert.True(collect, found) {
				assert.True(collect, slices.Contains([]string{"Z", "X"}, strings.Fields(fields)[0]), "process survived: %s", line)
			}
		}
	}, 10*time.Second, 100*time.Millisecond)
	_, err = runtimeProofCapture(t.Context(), executor, target, "true")
	require.NoError(t, err, "later requests must succeed without restarting the agent")
	after, err := executor.client.CoreV1().Pods(target.Namespace).Get(t.Context(), target.Pod, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, pod.UID, after.UID)
	require.Zero(t, after.Status.ContainerStatuses[0].RestartCount)
	t.Logf("runtime proof: binary streams/exit17, cancellation130, command=%s child=%s helper=%s terminated, unchanged agent UID, restartCount=0", pids[0], pids[1], helperPID)
}

func newRuntimeProofExecutor(t *testing.T) (*helperExecutor, Target, *corev1.Pod) {
	t.Helper()
	kubeconfig := os.Getenv("KO_RUNTIME_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("requires the isolated Kubernetes runtime proof cluster")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	client, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)
	executor := &helperExecutor{client: client, legacy: &remoteExecutor{client: client, config: config}}
	target := Target{Namespace: "default", Pod: "ko-runtime-proof", Container: "agent"}
	pod, err := client.CoreV1().Pods(target.Namespace).Get(t.Context(), target.Pod, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, "kubectl-ko-node-agent", pod.Labels["app"])
	require.False(t, *pod.Spec.AutomountServiceAccountToken)
	return executor, target, pod
}

func runtimeProofCapture(ctx context.Context, executor Executor, target Target, argv ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var output bytes.Buffer
	err := executor.Exec(ctx, target, argv, Streams{Out: &output, ErrOut: io.Discard})
	return output.String(), err
}

func runtimeProofProcess(t *testing.T, executor Executor, target Target, pid string) []string {
	t.Helper()
	_, err := strconv.Atoi(pid)
	require.NoError(t, err)
	output, err := runtimeProofCapture(t.Context(), executor, target, "cat", "/proc/"+pid+"/stat")
	require.NoError(t, err)
	_, fields, found := strings.CutLast(strings.TrimSpace(output), ") ")
	require.True(t, found)
	parsed := strings.Fields(fields)
	require.GreaterOrEqual(t, len(parsed), 3)
	return parsed
}
