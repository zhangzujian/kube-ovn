package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kubeovn/kube-ovn/pkg/kohelper"
)

type childPIDWriter struct{ pid chan string }

func (w childPIDWriter) Write(p []byte) (int, error) {
	w.pid <- string(p)
	return len(p), nil
}

func TestRunnerCancellationStopsDescendants(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pidOutput := make(chan string, 1)
	done := make(chan kohelper.Result, 1)
	go func() {
		done <- (runner{}).Run(ctx, kohelper.Request{Argv: []string{"sh", "-c", "sleep 60 & echo $!; wait"}}, childPIDWriter{pidOutput}, io.Discard)
	}()
	var pid int
	select {
	case output := <-pidOutput:
		var err error
		pid, err = strconv.Atoi(strings.TrimSpace(output))
		if err != nil || pid <= 0 {
			t.Fatalf("invalid child PID: %q", output)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child process did not start")
	}
	defer func() { _ = syscall.Kill(pid, syscall.SIGKILL) }()
	cancel()
	select {
	case result := <-done:
		if result.Code != 130 {
			t.Errorf("cancelled runner status = %d, want 130", result.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled runner is blocked by a surviving child")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		// procfs may return ESRCH when the process is reaped during a read.
		if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		_, state, ok := strings.Cut(string(data), ") ")
		if ok && strings.HasPrefix(state, "Z ") {
			return // A terminated child may await reaping by the container's PID 1.
		}
		if time.Now().After(deadline) {
			t.Fatal("descendant is still running after cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
