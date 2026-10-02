package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
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

func TestCnpAPIReadFailureRetainsOVNPolicy(t *testing.T) {
	fake := newFakeController(t)
	c := fake.fakeController
	c.cnpContext = t.Context()
	c.cnpKeyMutex = keymutex.NewHashed(1)
	c.anpPrioNameMap = map[int32]string{55: "existing"}
	c.anpNamePrioMap = map[string]int32{"existing": 55}
	// The cached watch object has already lost its port fields. An API error
	// must not fall back to it and replace the last successful OVN rules.
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	require.NoError(t, indexer.Add(&unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "existing"},
		"spec": map[string]any{
			"tier": "Admin", "priority": int64(55), "subject": map[string]any{"namespaces": map[string]any{}},
			"ingress": []any{map[string]any{"action": "Accept", "from": []any{map[string]any{"namespaces": map[string]any{}}}}},
		},
	}}))
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	client.PrependReactor("get", cnp.Resource.Resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("injected API read failure")
	})
	c.cnpsLister = &cnp.Lister{Indexer: indexer, Resource: client.Resource(cnp.Resource)}
	// No OVN mock expectations: any read/write after API failure fails.
	require.ErrorContains(t, c.handleAddCnp("existing"), "injected API read failure")
	require.Equal(t, map[int32]string{55: "existing"}, c.anpPrioNameMap)
	require.Equal(t, map[string]int32{"existing": 55}, c.anpNamePrioMap)
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
	raw.SetAPIVersion(cnp.Resource.GroupVersion().String())
	raw.SetKind("ClusterNetworkPolicy")
	c.cnpContext = t.Context()
	c.cnpsLister.Resource = dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), raw).Resource(cnp.Resource)
	// No OVN mock expectations: any read/write before rejection fails this test.
	require.ErrorContains(t, c.handleAddCnp(raw.GetName()), "DNSNameResolver is disabled")
	require.Equal(t, map[int32]string{55: "existing"}, c.anpPrioNameMap)
	require.Equal(t, map[string]int32{"existing": 55}, c.anpNamePrioMap)
	policy, err := cnp.Normalize(raw)
	require.NoError(t, err)
	c.config.EnableDNSNameResolver = true
	require.NoError(t, c.validateCnpConfig(policy), "enabled DNS policies must remain supported")
}
