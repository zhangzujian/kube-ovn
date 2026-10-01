package ko

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	utilexec "k8s.io/client-go/util/exec"
)

func TestDiagnosticProbeReportsConnectivityFailures(t *testing.T) {
	app, executor, _, _ := testApplication(t)
	client, err := app.newClient()
	require.NoError(t, err)
	executor.run = func(_ context.Context, _ Target, argv []string, _ Streams) error {
		require.Contains(t, argv, "--exit-code=1")
		require.Contains(t, argv, "--enable-verbose-conn-check=true")
		require.Contains(t, argv, "--network-mode=diagnostic")
		return utilexec.CodeExitError{Err: errors.New("connectivity failure"), Code: 1}
	}
	err = app.runDiagnosticProbes(t.Context(), client, []Target{{Pod: "subnet-a", Node: "a"}, {Pod: "subnet-b", Node: "b"}}, "subnet", "tcp-192.0.2.1-1", diagnosticOptions{tcpPort: "8100", udpPort: "8101"})
	require.ErrorContains(t, err, "probe on a")
	require.ErrorContains(t, err, "probe on b")
	require.Len(t, executor.calls, 2, "one failed node must not hide other nodes")
}

func TestPerformanceCleansUpAnAmbiguousCommittedTransaction(t *testing.T) {
	app, executor, _, _ := testApplication(t, readyPod("nb", "node", "ovn-central", map[string]string{"ovn-nb-leader": "true"}))
	client, err := app.newClient()
	require.NoError(t, err)
	run := &resourceRun{client: client, id: "unique-run"}
	pods := &performancePods{server: &corev1.Pod{Annotations: map[string]string{annotationPrefix + "logical_switch": "subnet"}, Status: corev1.PodStatus{PodIP: "10.0.0.2"}}, service: &corev1.Service{Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.2"}}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	executor.run = func(execCtx context.Context, _ Target, argv []string, _ Streams) error {
		if len(executor.calls) == 1 {
			cancel() // The transaction committed, but its response disappeared.
			return context.DeadlineExceeded
		}
		require.NoError(t, execCtx.Err(), "cleanup must survive the cancelled invocation")
		require.Equal(t, []string{"ovn-nbctl", "--if-exists", "lb-del", "ko-perf-unique-run"}, argv)
		return nil
	}
	require.ErrorIs(t, app.servicePerformance(ctx, run, pods, performanceOptions{}), context.DeadlineExceeded)
	require.Len(t, executor.calls, 2)
}

func TestRecoveryOptionalHeadersAndProbeErrors(t *testing.T) {
	for _, code := range []int{1, 126} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			_, client, executor, _ := recoveryApplication(t)
			record := &recoveryRecord{SourceNode: "node", Directory: "/etc/ovn/recovery", Targets: []Target{{Node: "node"}}}
			executor.run = func(_ context.Context, _ Target, argv []string, _ Streams) error {
				if argv[0] == "test" {
					return utilexec.CodeExitError{Err: errors.New("test failed"), Code: code}
				}
				return nil
			}
			err := client.replaceRecoveryFiles(t.Context(), record)
			if code == 1 {
				require.NoError(t, err, "headers are optional on older images")
			} else {
				require.Error(t, err, "execution errors must not masquerade as missing headers")
				require.Len(t, executor.calls, 2)
			}
		})
	}
}

func TestDatabaseStatusRejectsInconsistentStorage(t *testing.T) {
	app, executor, out, _ := testApplication(t, readyPod("central", "node", "ovn-central", map[string]string{"app": "ovn-central"}))
	executor.run = func(_ context.Context, _ Target, _ []string, s Streams) error {
		_, err := io.WriteString(s.Out, "status: inconsistent data\n")
		return err
	}
	require.ErrorContains(t, app.Execute(t.Context(), []string{"db", "health"}), "storage is unhealthy")
	require.Equal(t, 2, strings.Count(out.String(), "inconsistent data"))
}

func TestMulticastCleansUpLostAddResponseAndPreservesExistingMembership(t *testing.T) {
	app, executor, _, _ := testApplication(t,
		&corev1.Node{Name: "a"}, &corev1.Node{Name: "b"},
		readyPod("ovs-a", "a", "openvswitch", map[string]string{"app": "ovs"}),
		readyPod("ovs-b", "b", "openvswitch", map[string]string{"app": "ovs"}),
	)
	client, err := app.newClient()
	require.NoError(t, err)
	pods := []*corev1.Pod{
		{Spec: corev1.PodSpec{NodeName: "a", HostNetwork: true}, Status: corev1.PodStatus{PodIP: "192.0.2.1"}},
		{Spec: corev1.PodSpec{NodeName: "b", HostNetwork: true}, Status: corev1.PodStatus{PodIP: "192.0.2.2"}},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	membership := map[string]bool{"a": true}
	executor.run = func(execCtx context.Context, target Target, argv []string, streams Streams) error {
		switch strings.Join(argv, " ") {
		case "ip -o addr show":
			address := "192.0.2.1"
			if target.Node == "b" {
				address = "192.0.2.2"
			}
			_, err := io.WriteString(streams.Out, "2: eth0 inet "+address+"/24\n")
			return err
		case "ip maddr show dev eth0":
			if membership[target.Node] {
				_, err := io.WriteString(streams.Out, "link 01:00:5e:00:00:64\n")
				return err
			}
		case "ip maddr add 01:00:5e:00:00:64 dev eth0":
			require.Equal(t, "b", target.Node)
			membership[target.Node] = true
			cancel() // The host changed, but the exec result was lost.
			return context.DeadlineExceeded
		case "ip maddr del 01:00:5e:00:00:64 dev eth0":
			require.NoError(t, execCtx.Err(), "cleanup must survive cancellation")
			require.Equal(t, "b", target.Node, "preexisting membership must not be removed")
			delete(membership, target.Node)
		default:
			t.Fatalf("unexpected command: %v", argv)
		}
		return nil
	}
	require.ErrorIs(t, app.multicastPerformance(ctx, client, pods[0], pods[1], performanceOptions{}), context.DeadlineExceeded)
	require.Equal(t, map[string]bool{"a": true}, membership)
}
