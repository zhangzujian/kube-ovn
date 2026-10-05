package ipsec

import (
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCandidateCleanup(t *testing.T) {
	if os.Getenv("KUBE_OVN_IPSEC_RUNTIME_TEST") != "true" {
		t.Skip("requires the isolated candidate-image runtime harness")
	}
	// This separate container intentionally has no SYS_NICE. Cleanup must not
	// depend on either a signer, trust bundle, or an IKE/monitor runtime.
	kernel, err := netlink.NewHandle(unix.NETLINK_XFRM)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, kernel.Close()) })
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o750))
	client := fake.NewClientset(&corev1.Node{Name: "cleanup-node", UID: "cleanup-node-uid"})
	config := Configuration{
		NodeName: "cleanup-node", PodUID: "cleanup-pod-uid", Namespace: "kube-system", Kube: client,
		KeyDir: t.TempDir(), RuntimeDir: t.TempDir(), ProtectionDir: dir,
		OVSSocket: "/run/openvswitch/db.sock", Duration: time.Hour, RequestTimeout: time.Second, CleanupOnly: true,
	}
	start := func(config Configuration) (*Agent, func()) {
		t.Helper()
		a, err := New(config)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- a.Run(ctx) }()
		stop := sync.OnceFunc(func() {
			t.Helper()
			cancel()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("cleanup owner did not stop")
			}
		})
		t.Cleanup(stop)
		return a, stop
	}
	a, stop := start(config)
	require.Eventually(t, func() bool { return a.Status().Phase == "CleanupIdle" }, 10*time.Second, 100*time.Millisecond)
	require.NoError(t, Check(t.Context(), config.RuntimeDir, "livez"))
	require.Error(t, Check(t.Context(), config.RuntimeDir, "readyz"), "idle cleanup is not an encryption readiness receipt")
	for _, path := range []string{filepath.Join(config.KeyDir, "protection.json"), filepath.Join(dir, "required"), filepath.Join(dir, "protection.sock")} {
		_, err := os.Lstat(path)
		require.True(t, os.IsNotExist(err), "fresh disabled installation must not acquire protection")
	}
	stop()

	storage := store{dir: config.KeyDir}
	lock, err := storage.lock()
	require.NoError(t, err)
	owner, err := prepareProtection(storage, "cleanup-node-uid", kernel)
	require.NoError(t, err)
	require.NoError(t, owner.arm())
	reservation := owner.reservation
	require.NoError(t, lock.Close())
	state := Coordination{Version: 1, Generation: "cleanup-generation", Epoch: "cleanup-epoch", Phase: CleanupPhase,
		DaemonSetUID: "cleanup-daemonset", TemplateHash: strings.Repeat("a", 64), TrustHash: strings.Repeat("b", 64),
		Targets: map[string]string{"cleanup-node": "cleanup-node-uid"}, NBGlobalUUID: uuid.New().String(), SBGlobalUUID: uuid.New().String()}
	data, err := json.Marshal(state)
	require.NoError(t, err)
	_, err = client.CoreV1().ConfigMaps(config.Namespace).Create(t.Context(), &corev1.ConfigMap{Name: CoordinationConfigMap, Data: map[string]string{"state": string(data)}}, metav1.CreateOptions{})
	require.NoError(t, err)
	config.PodUID = "replacement-cleanup-pod"
	a, stop = start(config)
	require.Eventually(t, func() bool { return a.Status().Phase == "CleanupDrained" }, 10*time.Second, 100*time.Millisecond)
	require.True(t, a.Status().ProtectionArmed)
	require.False(t, a.runtime.enabled.Load())
	require.NoError(t, checkIKEPorts())
	row, err := a.ovs.IPsecDatapathConfiguration()
	require.NoError(t, err)
	require.NoError(t, CheckProtection(t.Context(), dir, row.UUID), "the disabled helper must unblock protected OVS startup")
	actual, err := storage.loadProtection("cleanup-node-uid")
	require.NoError(t, err)
	require.Equal(t, reservation, *actual, "cleanup must reuse its existing durable lease")
	for _, action := range client.Actions() {
		require.NotEqual(t, "secrets", action.GetResource().Resource, "cleanup cannot access a CA")
		require.NotEqual(t, "certificatesigningrequests", action.GetResource().Resource, "preflight cannot issue a certificate")
	}
	// A changed frozen target revokes the preflight without withdrawing guards.
	state.Targets["cleanup-node"] = "replaced-node-uid"
	data, err = json.Marshal(state)
	require.NoError(t, err)
	cm, err := client.CoreV1().ConfigMaps(config.Namespace).Get(t.Context(), CoordinationConfigMap, metav1.GetOptions{})
	require.NoError(t, err)
	cm.Data["state"] = string(data)
	_, err = client.CoreV1().ConfigMaps(config.Namespace).Update(t.Context(), cm, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return a.Status().Phase == "CleanupBlocked" }, 5*time.Second, 100*time.Millisecond)
	require.NoError(t, CheckProtection(t.Context(), dir, row.UUID))
	stop()
	require.NoError(t, owner.verify())
	_, err = os.Stat(filepath.Join(dir, "required"))
	require.NoError(t, err, "cleanup preflight shutdown must retain required intent")
	// Reset only this test's OVS fixture before the separate runtime tests.
	require.NoError(t, command(t.Context(), "ovs-vsctl", "--timeout=5", "--no-wait", "remove", "Open_vSwitch", ".", "external_ids",
		"ovn-ipsec-protection-node-uid", "ovn-ipsec-protection-lease", "ovn-ipsec-protection-mark", "ovn-ipsec-protection-reqid"))
}
