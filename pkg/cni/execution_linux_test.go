package cni

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubeovn/kube-ovn/pkg/util"
)

func TestReleaseVfSkipsMissingPodNetNS(t *testing.T) {
	handler := executionHandler{}
	for _, podNetns := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		t.Run(podNetns, func(t *testing.T) {
			err := handler.releaseVf("pod", "namespace", podNetns, "net1", util.OffloadType, "0000:65:00.1")
			if err != nil {
				t.Fatalf("releaseVf() error = %v", err)
			}
		})
	}
}

func TestReleaseVfKeepsUnexpectedPodNetNSError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	err := (executionHandler{}).releaseVf("pod", "namespace", path, "net1", util.OffloadType, "0000:65:00.1")
	if err == nil {
		t.Fatal("releaseVf() error = nil, want an error for a non-namespace path")
	}
}
