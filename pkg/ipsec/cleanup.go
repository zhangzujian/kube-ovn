package ipsec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/kubeovn/kube-ovn/pkg/ovs"
)

// runCleanup is the restartable init sidecar used when the feature is off.
// It never starts IKE, imports an identity, allocates a new lease, or issues a
// certificate. It must run alongside OVS: an ordinary blocking init container
// would prevent chassis registration and local tunnel convergence.
func (a *Agent) runCleanup(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer a.closeProtection()
	defer func() {
		if a.ovs != nil {
			a.ovs.Close()
		}
	}()
	a.beat.Store(time.Now().UnixNano())
	if err := a.serveStatus(ctx); err != nil {
		return err
	}
	serving := false
	for ctx.Err() == nil {
		a.beat.Store(time.Now().UnixNano())
		needed, err := a.restoreCleanupProtection(ctx)
		if err == nil && needed && !serving {
			err = a.serveProtection(ctx)
			serving = err == nil
		}
		if err == nil && needed {
			err = a.cleanupPreflight(ctx)
		}
		status := Status{Phase: "CleanupIdle"}
		if needed {
			status.Phase = "CleanupDrained"
			a.protectionMu.Lock()
			if a.protection != nil {
				status.NodeUID, status.Chassis = a.protection.owner.reservation.NodeUID, a.protection.chassis
			}
			a.protectionMu.Unlock()
		}
		if err != nil {
			status.Phase, status.Reason = "CleanupBlocked", err.Error()
			klog.ErrorS(err, "IPsec cleanup retains protection")
		}
		a.setStatus(status)
		a.beat.Store(time.Now().UnixNano())
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}

// A fresh disabled installation must not create durable required intent or a
// lease. Lost private evidence, a replaced Node UID and foreign OVS leases are
// failures, not evidence that encryption was never active.
func (a *Agent) restoreCleanupProtection(ctx context.Context) (bool, error) {
	if a.ovs == nil {
		var err error
		a.ovs, err = ovs.NewCNIVswitchClient("unix:" + a.config.OVSSocket)
		if err != nil {
			return false, err
		}
	}
	row, err := a.ovs.IPsecDatapathConfiguration()
	if err != nil {
		return false, err
	}
	node, err := a.config.Kube.CoreV1().Nodes().Get(ctx, a.config.NodeName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if node.UID == "" || node.DeletionTimestamp != nil {
		return false, errors.New("IPsec cleanup needs a live Node UID")
	}
	reservation, err := a.store.loadProtection(string(node.UID))
	if err != nil {
		return false, err
	}
	if reservation == nil {
		for _, key := range []string{"certificate", "private_key", "ca_cert"} {
			if row.OtherConfig[key] != "" {
				return false, errors.New("IPsec identity paths exist without their private ownership reservation")
			}
		}
		if err := a.noCleanupEvidence(row.ExternalIDs); err != nil {
			return false, err
		}
		return false, nil
	}
	// Do not kill/adopt another daemon, even while the feature is disabled.
	if err := checkLegacyMonitor(a.config.OVSSocket); err != nil {
		return true, err
	}
	if err := checkIKEPorts(); err != nil {
		return true, err
	}
	if err := checkOVNProtection(ctx); err != nil {
		return true, err
	}
	return true, a.ensureProtection(string(node.UID), row.ExternalIDs["system-id"])
}

func (a *Agent) noCleanupEvidence(externalIDs map[string]string) error {
	for _, key := range []string{"ovn-ipsec-protection-node-uid", "ovn-ipsec-protection-lease", "ovn-ipsec-protection-mark", "ovn-ipsec-protection-reqid"} {
		if externalIDs[key] != "" {
			return errors.New("OVS protection exists without its private ownership reservation")
		}
	}
	for _, path := range []string{filepath.Join(a.config.ProtectionDir, "required"), filepath.Join(a.store.dir, "current.json"), filepath.Join(a.store.dir, "pending.json"), filepath.Join(a.store.dir, "connections")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return err
			}
			return errors.New("IPsec cleanup evidence exists without its private ownership reservation")
		}
	}
	return nil
}

// This is a live preflight only, never a Disabled receipt or authorization to
// remove output protection. No CA or cert-manager access is needed on this path.
func (a *Agent) cleanupPreflight(ctx context.Context) error {
	cm, err := a.config.Kube.CoreV1().ConfigMaps(a.config.Namespace).Get(ctx, CoordinationConfigMap, metav1.GetOptions{})
	if err != nil {
		return err
	}
	state, err := DecodeCoordination([]byte(cm.Data["state"]))
	if err != nil {
		return err
	}
	if state.Phase != CleanupPhase {
		return errors.New("IPsec cleanup is waiting for the controller's live NB/SB barrier")
	}
	claim, err := a.observeCleanup(state)
	if err != nil {
		return err
	}
	return a.publishCleanupReceipt(ctx, cm, state, claim)
}

func (a *Agent) observeCleanup(state *Coordination) (CleanupReceipt, error) {
	if err := checkLegacyMonitor(a.config.OVSSocket); err != nil {
		return CleanupReceipt{}, err
	}
	if err := checkIKEPorts(); err != nil {
		return CleanupReceipt{}, err
	}
	a.protectionMu.Lock()
	defer a.protectionMu.Unlock()
	p := a.protection
	if p == nil || state.Targets[a.config.NodeName] != p.owner.reservation.NodeUID {
		return CleanupReceipt{}, errors.New("IPsec cleanup target does not bind the local protection owner")
	}
	if err := p.verify(); err != nil {
		return CleanupReceipt{}, err
	}
	row, err := p.ovs.IPsecDatapathConfiguration()
	if err != nil {
		return CleanupReceipt{}, err
	}
	lease := p.publicLease()
	lease.OVSUUID = row.UUID
	if err := p.ovs.VerifyIPsecTunnelQuiescence(lease); err != nil {
		return CleanupReceipt{}, err
	}
	bootID, err := a.store.liveDrainInventory(p.owner.reservation, p.owner.kernel)
	if err != nil {
		return CleanupReceipt{}, err
	}
	return CleanupReceipt{
		Generation: state.Generation, Epoch: state.Epoch, Phase: state.Phase, DaemonSetUID: state.DaemonSetUID, TemplateHash: state.TemplateHash,
		NBGlobalUUID: state.NBGlobalUUID, SBGlobalUUID: state.SBGlobalUUID,
		NodeName: a.config.NodeName, NodeUID: lease.NodeUID, PodUID: a.config.PodUID, Chassis: lease.Chassis,
		Lease: lease.Lease, Mark: lease.Mark, Reqid: lease.Reqid, OVSUUID: lease.OVSUUID, BootID: bootID,
	}, nil
}
