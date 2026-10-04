package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/klog/v2"

	"github.com/kubeovn/kube-ovn/pkg/fileutil"
)

const strongSwanConfig = `charon {
  plugins {
    kernel-netlink {
      set_proto_port_transport_sa = yes
      xfrm_ack_expires = 10
    }
    gcm { load = yes }
  }
  load_modular = yes
}
`

type runtimeManager struct {
	dir, ovsSocket string
	priority       int
	mu             sync.Mutex
	enabled        atomic.Bool
	healthy        atomic.Bool
}

func command(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 G702 -- callers select fixed programs; argv is never interpreted by a shell.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func (r *runtimeManager) prepare() error {
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return err
	}
	for path, data := range map[string][]byte{
		"/etc/strongswan.d/ovs.conf": []byte(strongSwanConfig),
		"/etc/ipsec.conf":            []byte("config setup\n    uniqueids=yes\n"),
		"/etc/ipsec.secrets":         {},
	} {
		if err := fileutil.AtomicWriteFile(path, data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func checkIKEPorts() error {
	// Never stop an unrelated host IKE daemon to make room for Kube-OVN.
	for _, port := range []int{500, 4500} {
		for _, network := range []string{"udp4", "udp6"} {
			conn, err := net.ListenPacket(network, fmt.Sprintf(":%d", port))
			if err != nil {
				if errors.Is(err, syscall.EAFNOSUPPORT) {
					continue
				}
				return fmt.Errorf("IKE port %d (%s) is unavailable: %w", port, network, err)
			}
			if err := conn.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

type child struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func (r *runtimeManager) startChild(name string, args ...string) (*child, error) {
	args = append([]string{"-n", strconv.Itoa(r.priority), name}, args...)
	cmd := exec.Command("nice", args...) // #nosec G204 -- fixed runtime programs and validated configuration.
	cmd.Env = append(os.Environ(), "OVS_RUNDIR="+r.dir)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &child{cmd: cmd, done: make(chan struct{})}
	go func() { c.err = cmd.Wait(); close(c.done) }()
	return c, nil
}

func (c *child) stop() {
	// Terminate the owned process group even if its leader was killed: charon
	// must not survive a crashed starter and occupy the IKE ports on retry.
	if err := syscall.Kill(-c.cmd.Process.Pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		klog.ErrorS(err, "Terminate IPsec process group")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(-c.cmd.Process.Pid, 0); errors.Is(err, syscall.ESRCH) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		klog.ErrorS(err, "Kill IPsec process group")
	}
	<-c.done
}

func (c *child) failure() error {
	if c.err == nil {
		return errors.New("runtime process exited unexpectedly with status 0")
	}
	return c.err
}

func (r *runtimeManager) runPair(ctx context.Context) error {
	if err := checkIKEPorts(); err != nil {
		return err
	}
	if err := r.prepare(); err != nil {
		return err
	}
	starter, err := r.startChild("/usr/sbin/ipsec", "start", "--nofork")
	if err != nil {
		return err
	}
	defer starter.stop()
	// The monitor's update/reread commands require a running IKE daemon.
	startupCtx, startupCancel := context.WithTimeout(ctx, 30*time.Second)
	defer startupCancel()
	for {
		checkCtx, checkCancel := context.WithTimeout(startupCtx, time.Second)
		err := command(checkCtx, "/usr/sbin/ipsec", "status")
		checkCancel()
		if err == nil {
			break
		}
		select {
		case <-starter.done:
			return fmt.Errorf("IPsec starter exited during startup: %w", starter.failure())
		case <-startupCtx.Done():
			return startupCtx.Err()
		case <-time.After(time.Second):
		}
	}
	monitor, err := r.startChild("/usr/share/openvswitch/scripts/ovs-monitor-ipsec", "unix:"+r.ovsSocket,
		"--ike-daemon=strongswan", "--no-restart-ike-daemon", "--ovn-owned-only", "--pidfile="+filepath.Join(r.dir, "monitor.pid"))
	if err != nil {
		return err
	}
	defer monitor.stop()
	defer r.healthy.Store(false)
	// Starting the Python process does not prove its OVSDB/event loop is
	// responding. Confirm both private control endpoints and keep checking
	// them so a hung process is recovered without waiting for Pod restart.
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := r.check(probeCtx)
		cancel()
		if err == nil {
			if err := r.confirmTrust(ctx); err != nil {
				return err
			}
		} else if r.healthy.Load() || startupCtx.Err() != nil {
			return fmt.Errorf("IPsec runtime health check failed: %w", err)
		}
		select {
		case <-starter.done:
			return fmt.Errorf("IPsec starter exited: %w", starter.failure())
		case <-monitor.done:
			return fmt.Errorf("IPsec monitor exited: %w", monitor.failure())
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (r *runtimeManager) check(ctx context.Context) error {
	if err := command(ctx, "/usr/sbin/ipsec", "status"); err != nil {
		return err
	}
	// list-commands is a harmless liveness request; tunnels/show and
	// xfrm/state may expose keys and must not be used in health probes.
	pidBytes, err := os.ReadFile(filepath.Join(r.dir, "monitor.pid"))
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid <= 0 {
		return errors.New("invalid private IPsec monitor PID")
	}
	return command(ctx, "ovs-appctl", "-t", filepath.Join(r.dir, fmt.Sprintf("ovs-monitor-ipsec.%d.ctl", pid)), "list-commands")
}

func (r *runtimeManager) run(ctx context.Context) {
	for ctx.Err() == nil {
		if r.enabled.Load() {
			if err := r.runPair(ctx); err != nil && ctx.Err() == nil {
				klog.ErrorS(err, "IPsec runtime stopped; retrying")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (r *runtimeManager) reloadTrust(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.healthy.Load() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return command(ctx, "/usr/sbin/ipsec", "rereadcacerts")
}

func (r *runtimeManager) confirmTrust(ctx context.Context) error {
	// Serialize the transition with reloadTrust. Trust written while charon
	// is starting must be reread either here or by the reconciler after this
	// transition, so a concurrent restart cannot acknowledge stale trust.
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.healthy.Load() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := command(ctx, "/usr/sbin/ipsec", "rereadcacerts"); err != nil {
		return err
	}
	r.healthy.Store(true)
	return nil
}
