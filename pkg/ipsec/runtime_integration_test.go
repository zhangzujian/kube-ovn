package ipsec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
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
	require.NoError(t, command(t.Context(), "ovs-vsctl", "--timeout=5", "--no-wait", "add-br", "br-fixture"))
	require.NoError(t, command(t.Context(), "ovs-vsctl", "--timeout=5", "--no-wait", "add-port", "br-fixture", "unrelated-ipsec", "--", "set", "Interface", "unrelated-ipsec", "type=geneve", "options:remote_ip=198.51.100.77", "options:remote_name=external-peer"))
	cert, key, trust := testIdentity(t, "runtime-test-chassis")
	client := fake.NewClientset(
		&corev1.Node{Name: "runtime-node", UID: "runtime-node-uid"},
		&corev1.Secret{Name: util.DefaultOVNIPSecCA, Namespace: "kube-system", Data: map[string][]byte{"cacert": trust}},
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
	checkTrust := func() {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, "/usr/sbin/ipsec", "listcacerts").Output()
		require.NoError(t, err)
		require.Contains(t, string(output), "CN=test CA", "readiness must follow loading the configured trust")
	}
	checkTrust()
	require.Eventually(t, func() bool {
		config, err := os.ReadFile("/etc/ipsec.conf")
		return err == nil && strings.Contains(string(config), "ca ca_auth") && !strings.Contains(string(config), "unrelated-ipsec")
	}, 10*time.Second, 200*time.Millisecond, "the monitor must recognize the certificate and leave unowned IPsec interfaces out of its configuration")
	pidBytes, err := os.ReadFile(filepath.Join(a.config.RuntimeDir, "monitor.pid"))
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	require.NoError(t, err)
	priority, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
	require.NoError(t, err)
	// Linux's raw getpriority syscall returns 20 minus the nice value.
	require.Equal(t, -5, 20-priority, "SYS_NICE must be effective in the minimal-capability IPsec container")
	charonPIDBytes, err := os.ReadFile("/run/charon.pid")
	require.NoError(t, err)
	charonPID, err := strconv.Atoi(strings.TrimSpace(string(charonPIDBytes)))
	require.NoError(t, err)
	charonPriority, err := unix.Getpriority(unix.PRIO_PROCESS, charonPID)
	require.NoError(t, err)
	require.Equal(t, -5, 20-charonPriority, "charon must inherit the IPsec priority")
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	require.NoError(t, err)
	var effective uint64
	for line := range strings.SplitSeq(string(status), "\n") {
		if value, found := strings.CutPrefix(line, "CapEff:"); found {
			effective, err = strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			require.NoError(t, err)
		}
	}
	for _, capability := range []uint{unix.CAP_NET_ADMIN, unix.CAP_NET_BIND_SERVICE, unix.CAP_SYS_NICE} {
		require.NotZero(t, effective&(uint64(1)<<capability), "the nice launcher must preserve runtime capabilities")
	}
	require.NoError(t, syscall.Kill(pid, syscall.SIGKILL))
	require.Eventually(t, func() bool { return !a.runtime.healthy.Load() }, 10*time.Second, 50*time.Millisecond)
	require.Eventually(t, ready, 60*time.Second, 200*time.Millisecond, "the runtime must recover after a monitor crash")
	newPID, err := os.ReadFile(filepath.Join(a.config.RuntimeDir, "monitor.pid"))
	require.NoError(t, err)
	require.NotEqual(t, string(pidBytes), string(newPID))
	checkTrust()
}
