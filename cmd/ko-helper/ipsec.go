package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/kubeovn/kube-ovn/pkg/kohelper"
)

func collectIPsec(ctx context.Context, procRoot, uid string, stdout, stderr io.Writer) (resultErr error) {
	root, err := kohelper.OpenPodIPsecRoot(ctx, procRoot, uid)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	// A pinned descriptor survives PID reuse and prevents querying another Pod.
	configRoot := fmt.Sprintf("/proc/self/fd/%d", root.Fd())
	config, err := os.OpenInRoot(configRoot, "etc/ipsec.conf")
	if err == nil {
		_, writeErr := fmt.Fprintln(stdout, "=== Active Pod IPsec configuration ===")
		if writeErr == nil {
			_, writeErr = io.Copy(stdout, config)
		}
		resultErr = errors.Join(resultErr, writeErr, config.Close())
	} else {
		resultErr = fmt.Errorf("read active Pod IPsec configuration: %w", err)
	}
	// stroke reads this documented strongSwan setting instead of the agent's
	// default socket. Descriptor 3 is passed to the agent-owned subprocess.
	settings, err := os.CreateTemp("", "ko-ipsec-*.conf")
	if err != nil {
		return errors.Join(resultErr, err)
	}
	defer func() { resultErr = errors.Join(resultErr, os.Remove(settings.Name())) }()
	_, err = io.WriteString(settings, "charon {\n plugins {\n  stroke {\n   socket = unix:///proc/self/fd/3/run/charon.ctl\n  }\n }\n}\n")
	if err = errors.Join(err, settings.Close()); err != nil {
		return errors.Join(resultErr, err)
	}
	for _, operation := range []string{"listcacerts", "listcerts", "statusall"} {
		if _, err := fmt.Fprintf(stdout, "\n=== IPsec %s ===\n", operation); err != nil {
			return errors.Join(resultErr, err)
		}
		command := exec.CommandContext(ctx, "ipsec", "stroke", operation)
		command.Env = append(os.Environ(), "STRONGSWAN_CONF="+filepath.Clean(settings.Name()))
		command.ExtraFiles = []*os.File{root}
		configureProcessGroup(command)
		command.WaitDelay = 5 * time.Second
		command.Stdout, command.Stderr = stdout, stderr
		resultErr = errors.Join(resultErr, command.Run())
		if ctx.Err() != nil {
			return errors.Join(resultErr, ctx.Err())
		}
	}
	return resultErr
}
