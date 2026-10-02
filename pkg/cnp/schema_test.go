package cnp

import (
	"os"
	"path/filepath"
	"testing"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

func TestTransitionCRDValidation(t *testing.T) {
	legacy := rawPolicy(t, `,"ports":[{"portNumber":{"port":80}}]}`)
	native := rawPolicy(t, `,"protocols":[{"tcp":{"destinationPort":{"number":80}}}]}`)
	dual := rawPolicy(t, `,"ports":[{"portNumber":{"port":80}}],"protocols":[{"tcp":{"destinationPort":{"number":80}}}]}`)
	for _, mode := range []string{"legacy-only", "dual", "native"} {
		t.Run(mode, func(t *testing.T) {
			obj, err := Schema(mode)
			if err != nil {
				t.Fatal(err)
			}
			var external apiextensionsv1.CustomResourceDefinition
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &external); err != nil {
				t.Fatal(err)
			}
			apiextensionsv1.SetDefaults_CustomResourceDefinition(&external)
			external.Status.StoredVersions = []string{"v1alpha2"}
			var internal apiextensions.CustomResourceDefinition
			if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&external, &internal, nil); err != nil {
				t.Fatal(err)
			}
			if errs := crdvalidation.ValidateCustomResourceDefinition(t.Context(), &internal); len(errs) != 0 {
				t.Fatalf("invalid CRD: %v", errs)
			}
			for _, tt := range []struct {
				name string
				obj  *unstructured.Unstructured
				want bool
			}{
				{"legacy", legacy, mode != "native"},
				{"native", native, mode != "legacy-only"},
				{"dual-field", dual, false},
			} {
				err := ValidateSchemaObjects(t.Context(), obj, []unstructured.Unstructured{*tt.obj})
				if (err == nil) != tt.want {
					t.Fatalf("%s: expected valid=%v, got %v", tt.name, tt.want, err)
				}
			}
		})
	}
}

func TestLegacyDefaultTCP(t *testing.T) {
	// Kubernetes defaulting and the controller adapter must agree on TCP.
	obj, err := Schema("legacy-only")
	if err != nil {
		t.Fatal(err)
	}
	policy := rawPolicy(t, `,"ports":[{"portNumber":{"port":80}}]}`)
	if err := ValidateSchemaObjects(t.Context(), obj, []unstructured.Unstructured{*policy}); err != nil {
		t.Fatal(err)
	}
	if _, err := Normalize(policy); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedCRDsArePinned(t *testing.T) {
	for _, mode := range []string{"legacy-only", "dual", "native"} {
		expected, err := Schema(mode)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join("../../yamls/cnp", mode+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]any
		if err := yaml.Unmarshal(data, &actual); err != nil {
			t.Fatal(err)
		}
		found, _, err := IdentifySchema(&unstructured.Unstructured{Object: actual})
		if err != nil || found != mode {
			t.Fatalf("artifact drift: %s: %v", mode, err)
		}
		// Server metadata/defaults must not change schema identification.
		expected.SetCreationTimestamp(metav1.Now())
		if _, _, err := IdentifySchema(expected); err != nil {
			t.Fatal(err)
		}
	}
}
