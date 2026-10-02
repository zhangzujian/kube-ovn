package kohelper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type testRunner struct {
	result Result
}

func (r testRunner) Run(_ context.Context, request Request, stdout, stderr io.Writer) Result {
	_, _ = stdout.Write([]byte(request.Argv[0]))
	_, _ = stderr.Write([]byte("diagnostic"))
	return r.result
}

func TestRunOverAttachStream(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- Serve(context.Background(), serverConn, testRunner{}) }()
	client, err := Dial(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	err = Run(ctx, client, Request{Version: Version, Argv: []string{"show"}}, &stdout, &stderr)
	_ = client.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "show" {
		t.Fatalf("stdout = %q", got)
	}
	if got := stderr.String(); got != "diagnostic" {
		t.Fatalf("stderr = %q", got)
	}
	if err := <-serverDone; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestRunPreservesRemoteExitCode(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- Serve(context.Background(), serverConn, testRunner{result: Result{Code: 17, Error: "command failed"}})
	}()
	client, err := Dial(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = Run(t.Context(), client, Request{Version: Version, Argv: []string{"show"}}, io.Discard, io.Discard)
	var exit *ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("error = %v, want ExitError", err)
	}
	if exit.ExitStatus() != 17 {
		t.Fatalf("exit status = %d, want 17", exit.ExitStatus())
	}
	_ = client.Close()
	if err := <-serverDone; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestRunRejectsUnsupportedVersion(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- Serve(context.Background(), serverConn, testRunner{}) }()
	client, err := Dial(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = Run(t.Context(), client, Request{Version: Version + 1, Argv: []string{"show"}}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "without success") {
		t.Fatalf("error = %v, want unsupported-version stream failure", err)
	}
	_ = client.Close()
	if err := <-serverDone; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
