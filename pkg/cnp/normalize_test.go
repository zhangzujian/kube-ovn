package cnp

import (
	"encoding/json/v2"
	"reflect"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/tools/cache"
)

func rawPolicy(t *testing.T, rule string) *unstructured.Unstructured {
	t.Helper()
	data := `{"apiVersion":"policy.networking.k8s.io/v1alpha2","kind":"ClusterNetworkPolicy","metadata":{"name":"test","uid":"uid-1","resourceVersion":"10","generation":1},"spec":{"tier":"Admin","priority":10,"subject":{"pods":{"podSelector":{}}},"ingress":[{"action":"Deny","from":[{"namespaces":{}}]` + rule + `]}}`
	// The suffix is an entire optional field fragment including the rule's }.
	obj := new(unstructured.Unstructured)
	if err := obj.UnmarshalJSON([]byte(data)); err != nil {
		t.Fatal(err)
	}
	return obj
}

func TestNormalizeEquivalentRepresentations(t *testing.T) {
	for _, tt := range []struct {
		name   string
		legacy string
		native string
	}{
		{"default TCP", `,"ports":[{"portNumber":{"port":80}}]}`, `,"protocols":[{"tcp":{"destinationPort":{"number":80}}}]}`},
		{"UDP range", `,"ports":[{"portRange":{"protocol":"UDP","start":53,"end":54}}]}`, `,"protocols":[{"udp":{"destinationPort":{"range":{"start":53,"end":54}}}}]}`},
		{"SCTP", `,"ports":[{"portNumber":{"protocol":"SCTP","port":9999}}]}`, `,"protocols":[{"sctp":{"destinationPort":{"number":9999}}}]}`},
		{"unrestricted", `}`, `}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := rawPolicy(t, tt.legacy)
			before := old.DeepCopy()
			legacy, err := Normalize(old)
			if err != nil {
				t.Fatal(err)
			}
			native, err := Normalize(rawPolicy(t, tt.native))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(legacy.Spec, native.Spec) || !reflect.DeepEqual(old, before) {
				t.Fatal("normalization changed semantics or mutated the raw cache")
			}
		})
	}
}

func TestNormalizeRejectsUnsafeConditions(t *testing.T) {
	for _, suffix := range []string{
		`,"ports":[]}`, `,"ports":null}`, `,"protocols":[]}`, `,"protocols":null}`,
		`,"ports":[{"portNumber":{"port":80}}],"protocols":[{"tcp":{"destinationPort":{"number":80}}}]}`,
		`,"ports":[{}]}`, `,"ports":[{"portNumber":{"port":80,"protocol":"ICMP"}}]}`,
		`,"ports":[{"namedPort":"http"}]}`, `,"ports":[{"portNumber":{"port":80,"typo":1}}]}`,
		`,"protocols":[{"destinationNamedPort":"http"}]}`, `,"protocols":[{"tcp":{}}]}`,
		`,"protocols":[{"tcp":{"destinationPort":{"number":0}}}]}`,
		`,"protocols":[{"tcp":{"destinationPort":{"range":{"start":100,"end":90}}}}]}`,
		`,"protocols":[{"tcp":{"destinationPort":{"number":80}},"udp":{"destinationPort":{"number":80}}}]}`,
		`,"protocols":[{"icmp":{}}]}`, `,"protocols":[{"tcp":{"destinationPort":{"number":80,"typo":1}}}]}`,
		`,"unknownCondition":true}`,
	} {
		t.Run(suffix, func(t *testing.T) {
			if _, err := Normalize(rawPolicy(t, suffix)); err == nil {
				t.Fatal("unsafe condition was accepted")
			}
		})
	}
}

func applyPlan(t *testing.T, obj *unstructured.Unstructured, plan *ObjectPlan) *unstructured.Unstructured {
	t.Helper()
	patch, err := plan.PatchBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := jsonpatch.DecodePatch(patch)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(obj.Object)
	if err != nil {
		t.Fatal(err)
	}
	data, err = decoded.Apply(data)
	if err != nil {
		t.Fatal(err)
	}
	result := new(unstructured.Unstructured)
	if err := result.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestMigrationRoundTripAndConflicts(t *testing.T) {
	old := rawPolicy(t, `,"ports":[{"portNumber":{"port":80}},{"portRange":{"protocol":"UDP","start":53,"end":54}}]}`)
	forward, err := PlanObject(old, false)
	if err != nil {
		t.Fatal(err)
	}
	native := applyPlan(t, old, forward)
	normalized, err := Normalize(native)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(normalized)
	if err != nil || digest != forward.SemanticDigest || native.GetUID() != old.GetUID() {
		t.Fatal("migration changed semantics or UID")
	}
	again, err := PlanObject(native, false)
	if err != nil || len(again.Patch) != 0 {
		t.Fatal("migration is not idempotent")
	}
	backward, err := PlanObject(native, true)
	if err != nil {
		t.Fatal(err)
	}
	restored := applyPlan(t, native, backward)
	if _, found, _ := unstructured.NestedMap(restored.Object, "spec", "subject", "pods", "namespaceSelector"); !found {
		t.Fatal("rollback did not restore required legacy namespaceSelector")
	}
	if backward.SemanticDigest != forward.SemanticDigest {
		t.Fatal("rollback changed semantics")
	}
	patch, err := forward.PatchBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := jsonpatch.DecodePatch(patch)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*unstructured.Unstructured){
		func(obj *unstructured.Unstructured) { obj.SetUID("replacement") },
		func(obj *unstructured.Unstructured) { obj.SetResourceVersion("11") },
		func(obj *unstructured.Unstructured) { obj.Object["spec"].(map[string]any)["priority"] = float64(11) },
	} {
		changed := old.DeepCopy()
		mutate(changed)
		data, err := json.Marshal(changed.Object)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoded.Apply(data); err == nil {
			t.Fatal("stale patch overwrote a concurrent update/replacement")
		}
	}
}

func TestRawListerPreservesLegacyAndIsolatesInvalidObjects(t *testing.T) {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	legacy := rawPolicy(t, `,"ports":[{"portNumber":{"port":80}}]}`)
	invalid := rawPolicy(t, `,"ports":[]}`)
	invalid.SetName("invalid")
	for _, obj := range []*unstructured.Unstructured{legacy, invalid} {
		if err := indexer.Add(obj); err != nil {
			t.Fatal(err)
		}
	}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{Resource: "ClusterNetworkPolicyList"}, legacy, invalid)
	lister := &Lister{Indexer: indexer, Resource: client.Resource(Resource)}
	policy, err := lister.Get(t.Context(), "test")
	if err != nil || policy.Spec.Ingress[0].Protocols[0].TCP.DestinationPort.Number != 80 {
		t.Fatalf("lost legacy ports: %v", err)
	}
	items, err := lister.List(t.Context(), labels.Everything())
	if len(items) != 1 || err == nil {
		t.Fatal("invalid object must be reported without hiding valid policies")
	}
}
