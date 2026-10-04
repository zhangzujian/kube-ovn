package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	"github.com/kubeovn/kube-ovn/pkg/fileutil"
)

// The public endpoint exposes no key material and is separate from private
// identity storage. Its directory is root-owned and not writable by OVS/CNI.
func (a *Agent) serveProtection(ctx context.Context) error {
	dir := a.config.ProtectionDir
	if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	var info unix.Stat_t
	if err := unix.Lstat(dir, &info); err != nil {
		return err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != 0 || int64(info.Gid) != int64(os.Getegid()) || info.Mode&0o027 != 0 {
		return errors.New("IPsec protection endpoint requires a root-owned directory without group/other write access")
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	// OVSDB can be recreated independently of the identity/protection stores.
	// Persist the requirement outside that database before exposing the gate;
	// absence of a database lease must never authorize an unprotected restart.
	// This is only a durable intent, never a substitute for live readback. Only
	// coordinated disable cleanup may remove it; normal shutdown retains it.
	if err := fileutil.AtomicWriteFile(filepath.Join(dir, "required"), []byte("IPsec output protection version 1\n"), 0o640); err != nil {
		return err
	}
	path := filepath.Join(dir, "protection.sock")
	if err := unix.Lstat(path, &info); err == nil {
		if info.Mode&unix.S_IFMT != unix.S_IFSOCK || info.Uid != 0 {
			return errors.New("IPsec protection endpoint path is not an owned Unix socket")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return errors.Join(err, listener.Close())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /armed", func(w http.ResponseWriter, req *http.Request) {
		uuid := req.URL.Query().Get("ovs-uuid")
		a.protectionMu.Lock()
		defer a.protectionMu.Unlock()
		p := a.protection
		if uuid == "" || p == nil || p.owner.verify() != nil {
			http.Error(w, "IPsec protection is not armed", http.StatusServiceUnavailable)
			return
		}
		lease := p.publicLease()
		lease.OVSUUID = uuid
		if err := p.ovs.VerifyIPsecProtection(lease); err != nil {
			http.Error(w, "IPsec protection does not cover the current OVS database", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		if err := server.Close(); err != nil {
			klog.ErrorS(err, "Close IPsec protection endpoint")
		}
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.ErrorS(err, "Serve IPsec protection endpoint")
		}
	}()
	return nil
}

// CheckProtection obtains a fresh readback from the root node owner. A stale
// file/socket cannot pass; the check is bound to the caller's current OVS UUID.
func CheckProtection(ctx context.Context, dir, ovsUUID string) error {
	if ovsUUID == "" {
		return errors.New("the protection probe requires the current OVS UUID")
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "protection.sock"))
		if err != nil {
			return nil, err
		}
		raw, err := conn.(*net.UnixConn).SyscallConn()
		if err == nil {
			var credential *unix.Ucred
			var credentialErr error
			err = raw.Control(func(fd uintptr) {
				credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
			})
			if err == nil {
				err = credentialErr
			}
			if err == nil && credential.Uid != 0 {
				err = errors.New("IPsec protection endpoint is not served by the root owner")
			}
		}
		if err != nil {
			return nil, errors.Join(err, conn.Close())
		}
		return conn, nil
	}}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/armed?"+url.Values{"ovs-uuid": {ovsUUID}}.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("IPsec protection probe returned HTTP %d", resp.StatusCode)
	}
	return nil
}
