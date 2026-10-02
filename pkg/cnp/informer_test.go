package cnp

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/tools/cache"
)

func TestRawInformerListWatchRetainsPortRestrictions(t *testing.T) {
	legacy := rawPolicy(t, `,"ports":[{"portNumber":{"port":80}}]}`)
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{Resource: "ClusterNetworkPolicyList"}, legacy)
	factory := dynamicinformer.NewDynamicSharedInformerFactory(client, 0)
	informer := factory.ForResource(Resource).Informer()
	factory.Start(t.Context().Done())
	if !cache.WaitForCacheSync(t.Context().Done(), informer.HasSynced) {
		t.Fatal("raw informer did not synchronize")
	}
	lister := &Lister{Indexer: informer.GetIndexer()}
	policy, err := lister.Get(legacy.GetName())
	if err != nil || policy.Spec.Ingress[0].Protocols[0].TCP.DestinationPort.Number != 80 {
		t.Fatalf("initial list lost ports: %v", err)
	}
	updated := rawPolicy(t, `,"protocols":[{"tcp":{"destinationPort":{"number":81}}}]}`)
	updated.SetGeneration(2)
	updated.SetResourceVersion("11")
	if _, err := client.Resource(Resource).Update(t.Context(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := wait.PollUntilContextTimeout(t.Context(), time.Millisecond, time.Second, true, func(_ context.Context) (bool, error) {
		policy, err := lister.Get(updated.GetName())
		return err == nil && policy.Generation == 2 && policy.Spec.Ingress[0].Protocols[0].TCP.DestinationPort.Number == 81, nil
	}); err != nil {
		t.Fatal(err)
	}
}
