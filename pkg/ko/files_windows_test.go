package ko

import (
	"archive/tar"
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArchiveRejectsWindowsDeviceVolumeAndStreamPaths(t *testing.T) {
	for _, name := range []string{"C:/outside", "C:outside", "//server/share/outside", "file:stream", "NUL", "CON.txt", "nested/AUX"} {
		t.Run(name, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			require.NoError(t, err)
			defer root.Close()
			require.Error(t, extractTar(root, bytes.NewReader(archive(t, name, tar.TypeReg, "secret")), 100))
		})
	}
}
