package ko

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilexec "k8s.io/client-go/util/exec"
)

func TestDatabaseKickUsesTheRequestedLeaderAndPreservesFailure(t *testing.T) {
	for _, role := range []string{"nb", "sb"} {
		for _, dryRun := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/dryRun=%t", role, dryRun), func(t *testing.T) {
				app, executor, out, _ := testApplication(t,
					readyPod("nb-leader", "a", "ovn-central", map[string]string{"ovn-nb-leader": "true"}),
					readyPod("sb-leader", "b", "ovn-central", map[string]string{"ovn-sb-leader": "true"}),
				)
				failure := utilexec.CodeExitError{Err: errors.New("member removal failed"), Code: 42}
				executor.run = func(_ context.Context, _ Target, _ []string, _ Streams) error { return failure }
				args := []string{"db", role, "kick", "ffffffff"}
				if dryRun {
					args = append(args, "--dry-run")
				}
				err := app.Execute(t.Context(), args)
				database := "OVN_Northbound"
				if role == "sb" {
					database = "OVN_Southbound"
				}
				argv := []string{"ovn-appctl", "-t", "/var/run/ovn/ovn" + role + "_db.ctl", "cluster/kick", database, "ffffffff"}
				if dryRun {
					require.NoError(t, err)
					require.Empty(t, executor.calls, "dry-run must not execute member removal")
					require.Equal(t, fmt.Sprintf("ovn-system/%s-leader: %q\n", role, argv), out.String())
					return
				}
				require.ErrorIs(t, err, failure)
				require.Equal(t, 42, ExitCode(err))
				require.Len(t, executor.calls, 1, "failed member removal must not be replayed")
				require.Equal(t, role+"-leader", executor.calls[0].target.Pod)
				require.Equal(t, "ovn-central", executor.calls[0].target.Container)
				require.Equal(t, argv, executor.calls[0].argv)
			})
		}
	}
}

func TestEnvironmentChecksAllRunningCNIsAndPreservesFailures(t *testing.T) {
	pending := readyPod("pending", "c", "cni-server", map[string]string{"app": "kube-ovn-cni"})
	pending.Status.Phase = corev1.PodPending
	terminating := readyPod("terminating", "d", "cni-server", map[string]string{"app": "kube-ovn-cni"})
	terminating.DeletionTimestamp = new(metav1.Now())
	app, executor, out, _ := testApplication(t,
		readyPod("cni-a", "a", "cni-server", map[string]string{"app": "kube-ovn-cni"}),
		readyPod("cni-b", "b", "cni-server", map[string]string{"app": "kube-ovn-cni"}),
		readyPod("other", "e", "other", map[string]string{"app": "kube-ovn-cni"}),
		pending, terminating,
	)
	failures := map[string]error{"a": errors.New("checker unavailable"), "b": errors.New("checker failed")}
	executor.run = func(_ context.Context, target Target, argv []string, _ Streams) error {
		require.Equal(t, "cni-server", target.Container)
		require.Equal(t, []string{"bash", "/kube-ovn/env-check.sh"}, argv)
		return failures[target.Node]
	}
	err := app.Execute(t.Context(), []string{"diagnose", "environment"})
	for node, failure := range failures {
		require.ErrorIs(t, err, failure, "one failed checker must not prevent other nodes from being checked")
		require.Contains(t, out.String(), "Environment check on "+node+"\n")
	}
	require.Len(t, executor.calls, 2)
}

func TestDiagnosticProbeReportsConnectivityFailures(t *testing.T) {
	podA := readyPod("subnet-a", "a", "probe", nil)
	podA.Status.PodIPs = []corev1.PodIP{{IP: "192.0.2.2"}, {IP: "2001:db8::2"}}
	podB := readyPod("subnet-b", "b", "probe", nil)
	podB.Status.PodIPs = []corev1.PodIP{{IP: "192.0.2.3"}, {IP: "2001:db8::3"}}
	app, executor, _, _ := testApplication(t, podA, podB)
	client, err := app.newClient()
	require.NoError(t, err)
	executor.run = func(_ context.Context, _ Target, argv []string, _ Streams) error {
		require.Contains(t, argv, "--exit-code=1")
		require.NotContains(t, argv, "--enable-verbose-conn-check=true", "node TCP/UDP listeners are optional")
		require.Contains(t, argv, "--network-mode=diagnostic")
		require.Contains(t, argv, "--target-ip-ports=tcp-192.0.2.1-1,tcp-192.0.2.2-8100,udp-192.0.2.2-8101,tcp-2001:db8::2-8100,udp-2001:db8::2-8101,tcp-192.0.2.3-8100,udp-192.0.2.3-8101,tcp-2001:db8::3-8100,udp-2001:db8::3-8101")
		return utilexec.CodeExitError{Err: errors.New("connectivity failure"), Code: 1}
	}
	err = app.runDiagnosticProbes(t.Context(), client, []Target{{Namespace: podA.Namespace, Pod: podA.Name, Node: "a"}, {Namespace: podB.Namespace, Pod: podB.Name, Node: "b"}}, "subnet", "tcp-192.0.2.1-1", diagnosticOptions{tcpPort: "8100", udpPort: "8101"})
	require.ErrorContains(t, err, "probe on a")
	require.ErrorContains(t, err, "probe on b")
	require.Len(t, executor.calls, 2, "one failed node must not hide other nodes")
}

func TestDiagnosticExternalPingIsExplicitAndPropagatesFailure(t *testing.T) {
	for _, addresses := range [][]string{nil, {"192.0.2.1", "2001:db8::1"}} {
		t.Run(strings.Join(addresses, ","), func(t *testing.T) {
			pod := readyPod("pinger", "worker", "pinger", nil)
			pod.Status.PodIPs = []corev1.PodIP{{IP: "192.0.2.2"}, {IP: "2001:db8::2"}}
			app, executor, _, _ := testApplication(t, pod)
			client, err := app.newClient()
			require.NoError(t, err)
			executor.run = func(_ context.Context, _ Target, argv []string, _ Streams) error {
				if argv[0] != "/kube-ovn/kube-ovn-pinger" {
					return nil
				}
				require.Contains(t, argv, "--external-address="+strings.Join(addresses, ","))
				require.Contains(t, argv, "--exit-code=1")
				if len(addresses) != 0 {
					return utilexec.CodeExitError{Err: errors.New("external ping failure"), Code: 1}
				}
				return nil
			}
			err = app.runDiagnosticProbes(t.Context(), client, []Target{{Namespace: pod.Namespace, Pod: pod.Name, Node: "worker"}}, "all", "tcp-192.0.2.2-30000", diagnosticOptions{externalAddresses: addresses})
			if len(addresses) == 0 {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "probe on worker")
				require.ErrorContains(t, err, "external ping failure")
			}
		})
	}
}

func TestDiagnosticExternalPingRejectsAnUnsupportedFamily(t *testing.T) {
	for _, ips := range [][]corev1.PodIP{nil, {{IP: "192.0.2.2"}}, {{IP: "invalid"}}} {
		t.Run(fmt.Sprint(ips), func(t *testing.T) {
			pod := readyPod("pinger", "worker", "pinger", nil)
			pod.Status.PodIPs = ips
			app, executor, _, _ := testApplication(t, pod)
			client, err := app.newClient()
			require.NoError(t, err)
			err = app.runDiagnosticProbes(t.Context(), client, []Target{{Namespace: pod.Namespace, Pod: pod.Name, Node: "worker"}}, "all", "", diagnosticOptions{externalAddresses: []string{"2001:db8::1"}})
			require.ErrorContains(t, err, "probe on worker")
			require.Empty(t, executor.calls, "pinger must not silently skip an explicit target")
		})
	}
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

func TestServicePerformanceWaitsForChassisBeforeMeasurement(t *testing.T) {
	for _, syncFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("syncFails=%t", syncFails), func(t *testing.T) {
			app, executor, _, _ := testApplication(t, readyPod("nb", "node", "ovn-central", map[string]string{"ovn-nb-leader": "true"}))
			client, err := app.newClient()
			require.NoError(t, err)
			run := &resourceRun{client: client, id: "unique-run"}
			pods := &performancePods{
				client:  &corev1.Pod{Name: "client"},
				server:  &corev1.Pod{Annotations: map[string]string{annotationPrefix + "logical_switch": "subnet"}, Status: corev1.PodStatus{PodIP: "10.0.0.2"}},
				service: &corev1.Service{Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.2"}},
			}
			failure := errors.New("measurement failed")
			if syncFails {
				failure = errors.New("flow synchronization failed")
			}
			executor.run = func(_ context.Context, _ Target, argv []string, _ Streams) error {
				switch len(executor.calls) {
				case 1:
					require.Equal(t, []string{"ovn-nbctl", "--wait=hv", "--timeout=30", "--", "lb-add", "ko-perf-unique-run", "10.96.0.2", "10.0.0.2", "--", "ls-lb-add", "subnet", "ko-perf-unique-run"}, argv)
					if syncFails {
						return failure
					}
					return nil
				case 2:
					if !syncFails {
						require.Equal(t, "qperf", argv[0])
						return failure
					}
				}
				require.Equal(t, []string{"ovn-nbctl", "--if-exists", "lb-del", "ko-perf-unique-run"}, argv)
				return nil
			}
			require.ErrorIs(t, app.servicePerformance(t.Context(), run, pods, performanceOptions{duration: 1}), failure)
			calls := 3
			if syncFails {
				calls = 2
			}
			require.Len(t, executor.calls, calls, "failed synchronization must stop measurements and still remove the owned LB")
		})
	}
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
		readyPod("cni-a", "a", "cni-server", map[string]string{"app": "kube-ovn-cni"}),
		readyPod("cni-b", "b", "cni-server", map[string]string{"app": "kube-ovn-cni"}),
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
		require.Equal(t, "cni-server", target.Container, "host membership inspection and cleanup need CNI network capabilities")
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

func TestMulticastPodNamespaceUsesCNIContainer(t *testing.T) {
	app, executor, _, _ := testApplication(t,
		&corev1.Node{Name: "worker"},
		readyPod("ovs-worker", "worker", "openvswitch", map[string]string{"app": "ovs"}),
		readyPod("cni-worker", "worker", "cni-server", map[string]string{"app": "kube-ovn-cni"}),
	)
	client, err := app.newClient()
	require.NoError(t, err)
	executor.run = func(_ context.Context, target Target, argv []string, streams Streams) error {
		require.Equal(t, "openvswitch", target.Container)
		require.Contains(t, argv, "ovs-vsctl")
		_, err := io.WriteString(streams.Out, `{"headings":["name","external_ids","ofport"],"data":[["pod-port",["map",[["pod_netns","/var/run/netns/pod"]]],1]]}`)
		return err
	}
	for _, nicType := range []string{"veth-pair", "internal-port"} {
		pod := &corev1.Pod{Name: "probe", Namespace: "ovn-system", Annotations: map[string]string{annotationPrefix + "pod_nic_type": nicType}, Spec: corev1.PodSpec{NodeName: "worker"}}
		target, err := client.multicastTarget(t.Context(), pod)
		require.NoError(t, err)
		require.Equal(t, "cni-worker", target.target.Pod, "only CNI mounts the host Pod network namespaces")
		require.Equal(t, "cni-server", target.target.Container)
		require.Equal(t, "/var/run/netns/pod", target.netns)
		expected := "eth0"
		if nicType == "internal-port" {
			expected = "pod-port"
		}
		require.Equal(t, expected, target.nic)
	}
}

func TestMulticastHostNamespaceUsesPrivilegedCNIContainer(t *testing.T) {
	app, executor, _, _ := testApplication(t,
		&corev1.Node{Name: "worker"},
		readyPod("ovs-worker", "worker", "openvswitch", map[string]string{"app": "ovs"}),
		readyPod("cni-worker", "worker", "cni-server", map[string]string{"app": "kube-ovn-cni"}),
	)
	client, err := app.newClient()
	require.NoError(t, err)
	executor.run = func(_ context.Context, target Target, argv []string, streams Streams) error {
		if target.Container != "cni-server" {
			return errors.New("Helm OVS lacks NET_ADMIN: ioctl: Operation not permitted")
		}
		require.Equal(t, []string{"ip", "-o", "addr", "show"}, argv)
		_, err := io.WriteString(streams.Out, "2: eth0@if3 inet 192.0.2.1/24\n")
		return err
	}
	pod := &corev1.Pod{Spec: corev1.PodSpec{NodeName: "worker", HostNetwork: true}, Status: corev1.PodStatus{PodIP: "192.0.2.1"}}
	target, err := client.multicastTarget(t.Context(), pod)
	require.NoError(t, err)
	require.Equal(t, "cni-server", target.target.Container)
	require.Equal(t, "cni-worker", target.target.Pod)
	require.Empty(t, target.netns)
	require.Equal(t, "eth0", target.nic)
}
