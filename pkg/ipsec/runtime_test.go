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
)

func TestRuntimeStopsChildrenAfterLeaderCrash(t *testing.T) {
	r := &runtimeManager{priority: 0}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	c, err := r.startChild("/bin/sh", "-c", `sleep 60 & echo $! > "$1"; wait`, "runtime-test", pidFile)
	require.NoError(t, err)
	t.Cleanup(c.stop)
	var pid int
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
		return err == nil
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, syscall.Kill(c.cmd.Process.Pid, syscall.SIGKILL))
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("runtime leader did not exit")
	}
	c.stop()
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		// A zombie has terminated and cannot retain the IKE ports; the host PID
		// namespace's init is responsible for reaping an orphaned descendant.
		return os.IsNotExist(err) || (err == nil && strings.Contains(string(data), ") Z "))
	}, time.Second, 10*time.Millisecond)
}

func TestProbesUseThePrivateSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a := &Agent{config: Configuration{RuntimeDir: t.TempDir()}, runtime: &runtimeManager{}}
	require.NoError(t, a.serveStatus(ctx))
	require.NoError(t, Check(t.Context(), a.config.RuntimeDir, "livez"))
	require.Error(t, Check(t.Context(), a.config.RuntimeDir, "readyz"))
	a.setStatus(Status{Phase: "Configured", Generation: "synthetic", Expires: time.Now().Add(time.Hour)})
	a.runtime.healthy.Store(true)
	require.NoError(t, Check(t.Context(), a.config.RuntimeDir, "readyz"))
	a.setStatus(Status{Phase: "Configured", Generation: "synthetic", Expires: time.Now().Add(-time.Second)})
	require.Error(t, Check(t.Context(), a.config.RuntimeDir, "readyz"))
}
