package ipsec

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A mark can distinguish protected traffic from an unrelated tunnel using the
// same underlay/UDP selector. This kernel prerequisite does not prove that
// ovn-controller preserves the mark on every actual overlay output path.
func TestCandidateMarkedGuard(t *testing.T) {
	if os.Getenv("KUBE_OVN_IPSEC_RUNTIME_TEST") != "true" {
		t.Skip("requires the isolated candidate-image runtime harness")
	}
	// Linux disables XFRM on loopback by default. The harness enables it only
	// inside this disposable network namespace so the probe reaches the policy.
	disableXFRM, err := os.ReadFile("/proc/sys/net/ipv4/conf/lo/disable_xfrm")
	require.NoError(t, err)
	require.Equal(t, "0", strings.TrimSpace(string(disableXFRM)), "the loopback fixture must perform outbound XFRM lookups")
	output, err := exec.CommandContext(t.Context(), "ip", "xfrm", "policy", "add", "src", "127.0.0.1", "dst", "0.0.0.0/0", "proto", "udp", "dport", "6081", "dir", "out", "priority", "2147483647", "index", "759833", "action", "block", "mark", "759815", "mask", "0xffffffff").CombinedOutput()
	require.NoError(t, err, "install the synthetic marked guard: %s", output)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		require.NoError(t, command(ctx, "ip", "xfrm", "policy", "delete", "index", "759833", "dir", "out", "mark", "759815", "mask", "0xffffffff"))
	})
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6081})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sender.Close()) })
	peer := listener.LocalAddr().(*net.UDPAddr)
	buffer := make([]byte, 64)
	assertUnmarked := func() {
		t.Helper()
		_, err := sender.WriteToUDP([]byte("unrelated-tunnel"), peer)
		require.NoError(t, err)
		require.NoError(t, listener.SetReadDeadline(time.Now().Add(time.Second)))
		n, _, err := listener.ReadFromUDP(buffer)
		require.NoError(t, err, "the same unmarked underlay/UDP selector must remain usable")
		require.Equal(t, "unrelated-tunnel", string(buffer[:n]))
	}
	assertUnmarked()
	raw, err := sender.SyscallConn()
	require.NoError(t, err)
	setMark := func(value int) {
		t.Helper()
		var markErr error
		err := raw.Control(func(fd uintptr) { markErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, value) })
		require.NoError(t, err)
		require.NoError(t, markErr)
	}
	setMark(759815)
	// The kernel can reject sendto synchronously or silently discard the packet.
	// In either case the listener must receive no protected plaintext payload.
	_, _ = sender.WriteToUDP([]byte("protected-tunnel"), peer)
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	_, _, err = listener.ReadFromUDP(buffer)
	networkErr, ok := errors.AsType[net.Error](err)
	require.True(t, ok && networkErr.Timeout(), "marked plaintext must be blocked")
	setMark(0)
	assertUnmarked()
}
