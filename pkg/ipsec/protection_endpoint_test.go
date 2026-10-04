package ipsec

import (
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
