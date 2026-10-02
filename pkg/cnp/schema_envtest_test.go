package cnp

import (
	"context"
	"os"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// This test runs against an isolated real API server in CI. It never uses the
// current kubeconfig, and is skipped unless envtest assets were explicitly set.
func TestAPIServerCNPTransition(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS to run real API-server migration validation")
	}
	environment := &envtest.Environment{}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})
	install := func(mode string) {
		t.Helper()
		obj, err := Schema(mode)
		if err != nil {
			t.Fatal(err)
		}
		var external apiextensionsv1.CustomResourceDefinition
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &external); err != nil {
			t.Fatal(err)
		}
		if _, err := envtest.InstallCRDs(config, envtest.CRDInstallOptions{CRDs: []*apiextensionsv1.CustomResourceDefinition{&external}}); err != nil {
			t.Fatal(err)
		}
	}
	install("legacy-only")
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	obj := rawPolicy(t, `,"ports":[{"portNumber":{"port":80}}]}`)
	obj.SetUID("")
	obj.SetResourceVersion("")
	obj.SetGeneration(0)
	legacy, err := client.Resource(Resource).Create(t.Context(), obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanObject(legacy, false)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := plan.PatchBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Resource(Resource).Patch(t.Context(), legacy.GetName(), types.JSONPatchType, patch, metav1.PatchOptions{}); err == nil {
		t.Fatal("native migration bypassed the legacy-only CEL gate")
	}
	install("dual")
	// A CRD update reaches etcd before every admission handler has rebuilt its
	// schema. Wait for a dry-run to observe the dual schema before migrating.
	probe := &Upgrade{Dynamic: client}
	if err := wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		return probe.probeSchema(ctx, "dual")
	}); err != nil {
		t.Fatal(err)
	}
	// Confirm the legacy field survives a real API-server round-trip.
	current, err := client.Resource(Resource).Get(t.Context(), legacy.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err = PlanObject(current, false)
	if err != nil {
		t.Fatal(err)
	}
	patch, err = plan.PatchBytes()
	if err != nil {
		t.Fatal(err)
	}
	native, err := client.Resource(Resource).Patch(t.Context(), current.GetName(), types.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if native.GetUID() != legacy.GetUID() || native.GetGeneration() <= legacy.GetGeneration() {
		t.Fatal("migration did not preserve UID and advance generation")
	}
	if _, err := client.Resource(Resource).Patch(t.Context(), current.GetName(), types.JSONPatchType, patch, metav1.PatchOptions{}); err == nil {
		t.Fatal("stale resourceVersion patch succeeded")
	}
	u := &Upgrade{Dynamic: client, Kube: kube, Namespace: "default"}
	observed, err := u.Plan(t.Context(), false)
	if err != nil || len(observed.Objects) != 1 || len(observed.Objects[0].Patch) != 0 {
		t.Fatalf("native read-back failed: %v", err)
	}
	backward, err := PlanObject(native, true)
	if err != nil {
		t.Fatal(err)
	}
	patch, err = backward.PatchBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Resource(Resource).Patch(t.Context(), native.GetName(), types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		t.Fatal(err)
	}
	// Deletion followed by a same-name creation is a new policy. An old plan
	// must not overwrite the replacement even when its spec is identical.
	current, err = client.Resource(Resource).Get(t.Context(), legacy.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := PlanObject(current, false)
	if err != nil {
		t.Fatal(err)
	}
	stalePatch, err := stale.PatchBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Resource(Resource).Delete(t.Context(), current.GetName(), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	obj.SetName(current.GetName())
	replacement, err := client.Resource(Resource).Create(t.Context(), obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if replacement.GetUID() == current.GetUID() {
		t.Fatal("same-name replacement retained the old UID")
	}
	if _, err := client.Resource(Resource).Patch(t.Context(), replacement.GetName(), types.JSONPatchType, stalePatch, metav1.PatchOptions{}); err == nil {
		t.Fatal("old plan overwrote a same-name replacement")
	}
	fresh, err := client.Resource(Resource).Get(t.Context(), replacement.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := PlanObject(fresh, false)
	if err != nil || fresh.GetUID() != replacement.GetUID() || len(remaining.Patch) == 0 {
		t.Fatalf("replacement identity or legacy restrictions changed: %v", err)
	}
	install("legacy-only")
}

// A controller's watch can outlive a CRD schema change. Exercise reverse
// migration on the same watch that first observed the native representation.
func TestAPIServerCNPReverseMigrationWatch(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS to run real API-server migration validation")
	}
	environment := &envtest.Environment{}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})
	install := func(mode string) {
		t.Helper()
		obj, err := Schema(mode)
		if err != nil {
			t.Fatal(err)
		}
		var external apiextensionsv1.CustomResourceDefinition
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &external); err != nil {
			t.Fatal(err)
		}
		if _, err := envtest.InstallCRDs(config, envtest.CRDInstallOptions{CRDs: []*apiextensionsv1.CustomResourceDefinition{&external}}); err != nil {
			t.Fatal(err)
		}
	}
	install("native")
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	obj := rawPolicy(t, `,"protocols":[{"tcp":{"destinationPort":{"number":80}}}]}`)
	obj.SetUID("")
	obj.SetResourceVersion("")
	obj.SetGeneration(0)
	native, err := client.Resource(Resource).Create(t.Context(), obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	factory := dynamicinformer.NewDynamicSharedInformerFactory(client, 0)
	informer := factory.ForResource(Resource).Informer()
	factory.Start(t.Context().Done())
	if !cache.WaitForCacheSync(t.Context().Done(), informer.HasSynced) {
		t.Fatal("native informer did not synchronize")
	}
	lister := &Lister{Indexer: informer.GetIndexer(), Resource: client.Resource(Resource)}
	install("dual")
	probe := &Upgrade{Dynamic: client}
	if err := wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		return probe.probeSchema(ctx, "dual")
	}); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanObject(native, true)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := plan.PatchBytes()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := client.Resource(Resource).Patch(t.Context(), native.GetName(), types.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, 10*time.Second, true, func(context.Context) (bool, error) {
		obj, exists, err := informer.GetIndexer().GetByKey(legacy.GetName())
		return exists && obj.(metav1.Object).GetResourceVersion() == legacy.GetResourceVersion(), err
	}); err != nil {
		t.Fatal(err)
	}
	policy, err := lister.Get(t.Context(), legacy.GetName())
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Spec.Ingress[0].Protocols) != 1 || policy.Spec.Ingress[0].Protocols[0].TCP.DestinationPort.Number != 80 {
		t.Fatal("reverse migration lost the port restriction on the existing native watch")
	}
	policies, err := lister.List(t.Context(), labels.Everything())
	if err != nil || len(policies) != 1 || len(policies[0].Spec.Ingress[0].Protocols) != 1 || policies[0].Spec.Ingress[0].Protocols[0].TCP.DestinationPort.Number != 80 {
		t.Fatalf("selector reconciliation list lost reverse-migrated restrictions: %v", err)
	}
}
