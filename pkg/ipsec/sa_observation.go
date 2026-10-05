package ipsec

import (
	"context"
	"errors"
	"maps"
	"os/exec"
	"slices"
	"time"

	"github.com/vishvananda/netlink"
)

func privateIKEStatus(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// statusall contains public identities, selectors and SPIs, never SA keys.
	// Do not return command output on failure or pass it through diagnostics.
	return exec.CommandContext(ctx, "/usr/sbin/ipsec", "statusall").Output()
}

func (r *runtimeManager) observeSAs(ctx context.Context, session connectionSession, kernel *netlink.Handle) error {
	intent, err := session.loadIntent(r.store)
	if err != nil {
		return err
	}
	before, err := privateIKEStatus(ctx)
	if err != nil {
		return err
	}
	children, err := intent.installedChildren(before)
	if err != nil {
		return err
	}
	if len(children) == 0 {
		return nil // This empty observation never authorizes removal of old SAs.
	}
	// Netlink returns key material. Keep it transient: only kernelInstance's
	// explicit public fields cross the persistence seam; never log states.
	states, err := kernel.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	bindings, err := intent.bindChildren(children, states)
	if err != nil {
		return err
	}
	after, err := privateIKEStatus(ctx)
	if err != nil {
		return err
	}
	confirmed, err := intent.installedChildren(after)
	if err != nil {
		return err
	}
	latest, err := session.loadIntent(r.store)
	if err != nil {
		return err
	}
	if !maps.Equal(children, confirmed) || !maps.Equal(intent.Connections, latest.Connections) {
		return errors.New("IPsec connections changed during ownership observation")
	}
	ledger, err := session.loadLedger(r.store)
	if err != nil {
		return err
	}
	previous := len(ledger.Bindings)
	ledger.record(bindings)
	if previous == len(ledger.Bindings) {
		return nil
	}
	// Retain retired/rekeyed instances. Asynchronous IKE deletion is not proof
	// that an earlier SPI has disappeared from the kernel after a crash.
	return ledger.save(r.store)
}

func (ledger *saLedger) record(bindings []saBinding) {
	for _, binding := range bindings {
		if !slices.Contains(ledger.Bindings, binding) {
			ledger.Bindings = append(ledger.Bindings, binding)
		}
	}
}

func (intent *connectionIntent) bindChildren(children map[string]childAssociation, states []netlink.XfrmState) ([]saBinding, error) {
	bindings := make([]saBinding, 0, 2*len(children))
	instances := make(map[saInstance]string)
	for _, child := range children {
		for _, direction := range []string{"in", "out"} {
			binding, err := intent.bindChild(child, direction, states)
			if err != nil {
				return nil, err
			}
			if _, exists := instances[binding.Instance]; exists {
				return nil, errors.New("multiple CHILD_SAs claim the same kernel instance")
			}
			instances[binding.Instance] = child.Connection
			bindings = append(bindings, binding)
		}
	}
	return bindings, nil
}
