package ko

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"
	"k8s.io/streaming/pkg/httpstream"

	"github.com/kubeovn/kube-ovn/pkg/kohelper"
)

type helperExecutor struct {
	client kubernetes.Interface
	config *rest.Config
	legacy *remoteExecutor
}

// Exec attaches to the independent node-agent container and carries the
// structured helper protocol over its stdin/stdout streams. The operation is
// never replayed after an attach or helper failure because argv may mutate DB
// state.
func (r *helperExecutor) Exec(ctx context.Context, target Target, argv []string, streams Streams) error {
	if target.Container != "agent" {
		pod, err := r.client.CoreV1().Pods(target.Namespace).Get(ctx, target.Pod, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if labels := pod.Labels; labels["app"] == "kube-ovn-cni" || labels["app"] == "ovs" || labels["app"] == "ovs-ovn" || labels["app"] == "ovn-central" {
			return fmt.Errorf("component exec is disabled for %s/%s (deploy ko-node-agent and retry)", pod.Namespace, pod.Name)
		}
		return r.legacy.Exec(ctx, target, argv, streams)
	}
	request := r.client.CoreV1().RESTClient().Post().Namespace(target.Namespace).
		Resource("pods").Name(target.Pod).SubResource("attach").
		VersionedParams(&corev1.PodAttachOptions{Container: target.Container, Stdin: true, Stdout: true, Stderr: false}, scheme.ParameterCodec)
	cfg := rest.CopyConfig(r.config)
	cfg.Timeout = 0
	executor, err := remotecommand.NewSPDYExecutor(cfg, http.MethodPost, request.URL())
	if err != nil {
		return fmt.Errorf("create node-agent attach executor: %w", err)
	}
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	streamErr := make(chan error, 1)
	go func() {
		streamErr <- executor.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin: inputReader, Stdout: outputWriter,
		})
		_ = outputWriter.Close()
		_ = inputReader.Close()
	}()
	conn := &kohelper.StreamConn{Reader: outputReader, Writer: inputWriter}
	grpcConn, err := kohelper.Dial(conn)
	if err == nil {
		err = kohelper.Run(ctx, grpcConn, kohelper.Request{Version: kohelper.Version, Argv: argv}, streams.Out, streams.ErrOut)
		_ = grpcConn.Close()
	}
	_ = conn.Close()
	attachErr := <-streamErr
	if err != nil {
		return err
	}
	return attachErr
}

// Target identifies a container, not the default container selected by kubectl.
type Target struct {
	Namespace string
	Pod       string
	Container string
	Node      string
}

// Streams preserves binary output and keeps diagnostics separate from stdout.
type Streams struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
}

// Executor runs a single remote command. Implementations must not replay failures.
type Executor interface {
	Exec(context.Context, Target, []string, Streams) error
}

// Client contains only the Kubernetes and exec capabilities needed by the CLI.
type Client struct {
	Kubernetes        kubernetes.Interface
	Dynamic           dynamic.Interface
	Executor          Executor
	Namespace         string
	WorkloadNamespace string
	DiscoveryTimeout  time.Duration
	// ComponentFree routes node and database operations through the independent
	// ko-node-agent rather than an OVN, OVS, or CNI component container.
	ComponentFree bool
}

type remoteExecutor struct {
	client kubernetes.Interface
	config *rest.Config
}

func (r *remoteExecutor) Exec(ctx context.Context, target Target, argv []string, streams Streams) error {
	req := r.client.CoreV1().RESTClient().Post().Namespace(target.Namespace).
		Resource("pods").Name(target.Pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: target.Container, Command: argv, Stdin: streams.In != nil,
			Stdout: streams.Out != nil, Stderr: streams.ErrOut != nil,
		}, scheme.ParameterCodec)
	cfg := rest.CopyConfig(r.config)
	// A streaming session is bounded by its context, not an HTTP request timeout.
	cfg.Timeout = 0
	spdy, err := remotecommand.NewSPDYExecutor(cfg, http.MethodPost, req.URL())
	if err != nil {
		return fmt.Errorf("create SPDY executor: %w", err)
	}
	websocket, err := remotecommand.NewWebSocketExecutor(cfg, http.MethodGet, req.URL().String())
	if err != nil {
		return fmt.Errorf("create WebSocket executor: %w", err)
	}
	executor, err := remotecommand.NewFallbackExecutor(websocket, spdy, retryUpgrade)
	if err != nil {
		return fmt.Errorf("create exec transport: %w", err)
	}
	return executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin: streams.In, Stdout: streams.Out, Stderr: streams.ErrOut,
	})
}

func retryUpgrade(err error) bool {
	return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
}

const maxQueryOutput = 8 << 20

type boundedBuffer struct{ buffer bytes.Buffer }

func (b *boundedBuffer) String() string { return b.buffer.String() }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > maxQueryOutput-b.buffer.Len() {
		return 0, errors.New("remote query exceeds 8 MiB output limit")
	}
	return b.buffer.Write(p)
}

func (c *Client) capture(ctx context.Context, target Target, argv ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var stdout, stderr boundedBuffer
	if err := c.Executor.Exec(ctx, target, argv, Streams{Out: &stdout, ErrOut: &stderr}); err != nil {
		return "", fmt.Errorf("%s/%s (%s): %w: %s", target.Namespace, target.Pod, argv[0], err, stderr.String())
	}
	return stdout.String(), nil
}

// ExitCode preserves remote exit status, including errors wrapped by command handlers.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if remote, ok := errors.AsType[utilexec.ExitError](err); ok {
		return remote.ExitStatus()
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	if _, ok := errors.AsType[*usageError](err); ok {
		return 2
	}
	return 1
}

type usageError struct{ error }
