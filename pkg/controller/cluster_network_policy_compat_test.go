package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/keymutex"
	"sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"github.com/kubeovn/kube-ovn/pkg/cnp"
)

func TestDeleteCnpRawTombstonePreservesOtherPriorities(t *testing.T) {
	fake := newFakeController(t)
	c := fake.fakeController
	c.cnpKeyMutex = keymutex.NewHashed(1)
	c.cnpsLister = &cnp.Lister{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})}
	c.deleteCnpQueue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[*v1alpha2.ClusterNetworkPolicy]())
	t.Cleanup(c.deleteCnpQueue.ShutDown)
	c.anpPrioNameMap = map[int32]string{0: "keep", 55: "gone"}
	c.anpNamePrioMap = map[string]int32{"keep": 0, "gone": 55}
	c.bnpPrioNameMap = map[int32]string{}
	c.bnpNamePrioMap = map[string]int32{}

	// A malformed rule must not prevent cleanup. The raw deletion adapter
	// intentionally extracts only name/UID/tier, not an untrusted spec.
	raw := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "gone", "uid": "old"},
		"spec": map[string]any{
			"tier": "Admin", "priority": int64(55),
			"ingress": []any{map[string]any{"ports": "invalid"}},
		},
	}}
	c.enqueueDeleteCnp(cache.DeletedFinalStateUnknown{Key: "gone", Obj: raw})
	policy, shutdown := c.deleteCnpQueue.Get()
	require.False(t, shutdown)
	defer c.deleteCnpQueue.Done(policy)
	fake.mockOvnClient.EXPECT().DeletePortGroup("gone").Return(nil)
	fake.mockOvnClient.EXPECT().DeleteAddressSets(map[string]string{clusterNetworkPolicyKey: "gone/ingress"}).Return(nil)
	fake.mockOvnClient.EXPECT().DeleteAddressSets(map[string]string{clusterNetworkPolicyKey: "gone/egress"}).Return(nil)
	require.NoError(t, c.handleDeleteCnp(policy))
	require.Equal(t, map[int32]string{0: "keep"}, c.anpPrioNameMap)
	require.Equal(t, map[string]int32{"keep": 0}, c.anpNamePrioMap)
}

func TestCnpDisabledDNSRejectsBeforeOVNChanges(t *testing.T) {
	fake := newFakeController(t)
	c := fake.fakeController
	c.cnpKeyMutex = keymutex.NewHashed(1)
	c.config.EnableDNSNameResolver = false
	c.cnpsLister = &cnp.Lister{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})}
	c.anpPrioNameMap = map[int32]string{55: "existing"}
	c.anpNamePrioMap = map[string]int32{"existing": 55}
	// This valid update has both directions, so rejecting only while compiling
	// egress would let the new ingress policy replace the last successful ACLs.
	raw := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "existing", "uid": "existing-uid"},
		"spec": map[string]any{
			"tier": "Admin", "priority": int64(56), "subject": map[string]any{"namespaces": map[string]any{}},
			"ingress": []any{map[string]any{"action": "Deny", "from": []any{map[string]any{"namespaces": map[string]any{}}}}},
			"egress":  []any{map[string]any{"action": "Accept", "to": []any{map[string]any{"domainNames": []any{"example.test."}}}}},
		},
	}}
	require.NoError(t, c.cnpsLister.Indexer.Add(raw))
	// No OVN mock expectations: any read/write before rejection fails this test.
	require.ErrorContains(t, c.handleAddCnp(raw.GetName()), "DNSNameResolver is disabled")
	require.Equal(t, map[int32]string{55: "existing"}, c.anpPrioNameMap)
	require.Equal(t, map[string]int32{"existing": 55}, c.anpNamePrioMap)
	policy, err := cnp.Normalize(raw)
	require.NoError(t, err)
	c.config.EnableDNSNameResolver = true
	require.NoError(t, c.validateCnpConfig(policy), "enabled DNS policies must remain supported")
}
