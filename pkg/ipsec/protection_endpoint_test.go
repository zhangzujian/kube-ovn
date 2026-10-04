package ipsec

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProtectionProbeCannotUseReadyFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "protection.sock"), []byte("ready"), 0o600))
	require.Error(t, CheckProtection(t.Context(), dir, "ovs-uuid"))
	require.Error(t, CheckProtection(t.Context(), dir, ""))
}

func TestProtectionRequirementSurvivesEndpointShutdown(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the public endpoint requires the root node owner")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o750))
	a := &Agent{config: Configuration{ProtectionDir: dir}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	require.NoError(t, a.serveProtection(ctx))
	// A persisted requirement cannot act as a cached successful receipt.
	require.Error(t, CheckProtection(t.Context(), dir, "ovs-uuid"))
	cancel()
	required, err := os.ReadFile(filepath.Join(dir, "required"))
	require.NoError(t, err)
	require.Equal(t, "IPsec output protection version 1\n", string(required))
	info, err := os.Stat(filepath.Join(dir, "required"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestProtectionEndpointRejectsSymlinkDirectory(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "endpoint")
	require.NoError(t, os.Symlink(dir, link))
	a := &Agent{config: Configuration{ProtectionDir: link}}
	require.Error(t, a.serveProtection(t.Context()))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries, "the public endpoint must not create files through a directory symlink")
}
