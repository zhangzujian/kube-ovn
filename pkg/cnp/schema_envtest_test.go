package cnp

import (
	"os"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
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
	install("legacy-only")
}
