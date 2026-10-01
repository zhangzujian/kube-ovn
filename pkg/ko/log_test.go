package ko

import (
	"archive/tar"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogsWritesManifestAndRetainsPartialFailures(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(strconv.FormatBool(strict), func(t *testing.T) {
			pod := readyPod("cni", "worker", "cni-server", map[string]string{"app": "kube-ovn-cni"})
			app, executor, _, _ := testApplication(t, pod)
			executor.run = func(_ context.Context, _ Target, argv []string, streams Streams) error {
				if argv[0] == "dmesg" {
					return errors.New("dmesg denied")
				}
				_, err := io.WriteString(streams.Out, "node diagnostics\n")
				return err
			}
			dir := t.TempDir()
			err := app.Execute(t.Context(), []string{"logs", "--component", "linux", "--output-dir", dir, "--concurrency", "1", "--strict=" + strconv.FormatBool(strict)})
			if strict {
				require.ErrorContains(t, err, "dmesg denied")
			} else {
				require.NoError(t, err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			require.NoError(t, err)
			var manifest struct {
				SchemaVersion string           `json:"schemaVersion"`
				Items         []collectionTask `json:"items"`
			}
			require.NoError(t, json.Unmarshal(data, &manifest))
			require.Equal(t, "v1", manifest.SchemaVersion)
			require.NotEmpty(t, manifest.Items)
			failures := 0
			for _, item := range manifest.Items {
				require.Positive(t, item.Duration)
				require.FileExists(t, item.Path)
				if item.Error != "" {
					failures++
					require.Equal(t, "dmesg", item.Name)
					require.Contains(t, item.Error, "dmesg denied")
				}
			}
			require.Equal(t, 1, failures)
			data, err = os.ReadFile(filepath.Join(dir, "worker", "linux", "addr.log"))
			require.NoError(t, err)
			require.Contains(t, string(data), "node diagnostics")
		})
	}
}

func TestCollectDirectoryDrainsTarRecordPadding(t *testing.T) {
	app, executor, _, _ := testApplication(t)
	client, err := app.newClient()
	require.NoError(t, err)
	data := archive(t, "daemon.log", tar.TypeReg, "remote log\n")
	executor.run = func(_ context.Context, _ Target, _ []string, streams Streams) error {
		if _, err := streams.Out.Write(data); err != nil {
			return err
		}
		_, err := streams.Out.Write(make([]byte, 8192))
		return err
	}
	dir := t.TempDir()
	require.NoError(t, client.collectDirectory(t.Context(), Target{}, "/var/log/ovn", dir, 1<<20))
	contents, err := os.ReadFile(filepath.Join(dir, "daemon.log"))
	require.NoError(t, err)
	require.Equal(t, "remote log\n", string(contents))
}
