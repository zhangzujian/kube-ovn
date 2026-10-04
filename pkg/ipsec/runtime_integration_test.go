package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/kubeovn/kube-ovn/pkg/util"
)

// TestCandidateRuntime exercises the actual image programs and host kernel.
// Kubernetes is simulated here; cluster rollout and encrypted traffic require
// separate E2E coverage. Run only in the isolated containers created by the
// runtime harness, never in an operator's host network namespace.
func TestCandidateRuntime(t *testing.T) {
	if os.Getenv("KUBE_OVN_IPSEC_RUNTIME_TEST") != "true" {
		t.Skip("requires the isolated candidate-image runtime harness")
	}
	require.NoError(t, checkIKEPorts(), "the test network namespace must be isolated")
	cert, key, trust := testIdentity(t, "runtime-test-chassis")
	client := fake.NewClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "runtime-node", UID: "runtime-node-uid"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: util.DefaultOVNIPSecCA, Namespace: "kube-system"}, Data: map[string][]byte{"cacert": trust}},
	)
	a, err := New(Configuration{
		NodeName: "runtime-node", PodUID: "runtime-pod-uid", Namespace: "kube-system", Kube: client,
		KeyDir: t.TempDir(), RuntimeDir: t.TempDir(), OVSSocket: "/run/openvswitch/db.sock", Duration: time.Hour, RequestTimeout: 30 * time.Second, Priority: -5,
	})
	require.NoError(t, err)
	g := &generation{ID: digest(key), NodeUID: "runtime-node-uid", Chassis: "runtime-test-chassis"}
	require.NoError(t, a.store.write(g, "private-key", key))
	require.NoError(t, a.store.write(g, "certificate", cert))
	require.NoError(t, a.store.save("pending", g))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(20 * time.Second):
			t.Error("owned runtime did not stop")
		}
		require.Eventually(t, func() bool { return checkIKEPorts() == nil }, 10*time.Second, 100*time.Millisecond,
			"charon must release the IKE ports after shutdown")
	})
	ready := func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		return Check(ctx, a.config.RuntimeDir, "readyz") == nil
	}
	require.Eventually(t, ready, 60*time.Second, 200*time.Millisecond, "candidate monitor and strongSwan must become ready")
	pidBytes, err := os.ReadFile(filepath.Join(a.config.RuntimeDir, "monitor.pid"))
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	require.NoError(t, err)
	priority, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
	require.NoError(t, err)
	// Linux's raw getpriority syscall returns 20 minus the nice value.
	require.Equal(t, -5, 20-priority, "SYS_NICE must be effective in the minimal-capability IPsec container")
	require.NoError(t, syscall.Kill(pid, syscall.SIGKILL))
	require.Eventually(t, func() bool { return !a.runtime.healthy.Load() }, 10*time.Second, 50*time.Millisecond)
	require.Eventually(t, ready, 60*time.Second, 200*time.Millisecond, "the runtime must recover after a monitor crash")
	newPID, err := os.ReadFile(filepath.Join(a.config.RuntimeDir, "monitor.pid"))
	require.NoError(t, err)
	require.NotEqual(t, string(pidBytes), string(newPID))
}
