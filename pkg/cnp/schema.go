package cnp

import (
	_ "embed"
	"encoding/json/v2"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// Upstream snapshots are pinned, unmodified experimental CRDs.
//
//go:embed crds/legacy.yaml
var legacyCRD []byte

//go:embed crds/native.yaml
var nativeCRD []byte

const CRDName = "clusternetworkpolicies.policy.networking.k8s.io"

var SchemaModes = []string{"legacy", "legacy-only", "dual", "native"}

func Schema(mode string) (*unstructured.Unstructured, error) {
	source := nativeCRD
	if mode == "legacy" {
		source = legacyCRD
	}
	obj, err := decodeCRD(source)
	if err != nil {
		return nil, err
	}
	if mode == "legacy" || mode == "native" {
		return obj, nil
	}
	if mode != "legacy-only" && mode != "dual" {
		return nil, fmt.Errorf("unknown CNP schema mode %q", mode)
	}
	old, err := decodeCRD(legacyCRD)
	if err != nil {
		return nil, err
	}
	properties := schemaProperties(obj)
	oldProperties := schemaProperties(old)
	for _, direction := range []string{"ingress", "egress"} {
		rule := properties[direction].(map[string]any)["items"].(map[string]any)
		oldRule := oldProperties[direction].(map[string]any)["items"].(map[string]any)
		rule["properties"].(map[string]any)["ports"] = oldRule["properties"].(map[string]any)["ports"]
		validations, _ := rule["x-kubernetes-validations"].([]any)
		oldValidations, _ := oldRule["x-kubernetes-validations"].([]any)
		validations = append(validations, oldValidations...)
		validations = append(validations,
			map[string]any{"rule": "!(has(self.ports) && has(self.protocols))", "message": "ports and protocols are mutually exclusive"},
			map[string]any{"rule": "!has(self.ports) || self.ports.all(p, !has(p.namedPort))", "message": "Kube-OVN CNP does not support named ports"},
			map[string]any{"rule": "!has(self.protocols) || self.protocols.all(p, !has(p.destinationNamedPort))", "message": "Kube-OVN CNP does not support named ports"},
		)
		if mode == "legacy-only" {
			validations = append(validations, map[string]any{"rule": "!has(self.protocols)", "message": "protocols cannot be used while legacy controllers may run"})
		}
		rule["x-kubernetes-validations"] = validations
	}
	annotations := obj.GetAnnotations()
	annotations["kube-ovn.io/cnp-schema-mode"] = mode
	annotations["kube-ovn.io/cnp-native-source"] = "a17adecd0316b8ff1c3f83939ec0441d68cd6cce"
	annotations["kube-ovn.io/cnp-legacy-source"] = "3910463a5686"
	obj.SetAnnotations(annotations)
	return obj, nil
}

func decodeCRD(data []byte) (*unstructured.Unstructured, error) {
	converted, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(converted, &value); err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: value}, nil
}

func schemaProperties(obj *unstructured.Unstructured) map[string]any {
	versions := obj.Object["spec"].(map[string]any)["versions"].([]any)
	version := versions[0].(map[string]any)
	root := version["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)
	return root["properties"].(map[string]any)["spec"].(map[string]any)["properties"].(map[string]any)
}

// SchemaDigest ignores status, metadata, and API-server-defaulted CRD settings.
// Every served/storage version's full validation schema is still checked.
func SchemaDigest(obj *unstructured.Unstructured) (string, error) {
	versions, _, err := unstructured.NestedSlice(obj.Object, "spec", "versions")
	if err != nil {
		return "", err
	}
	var schemas []any
	for _, item := range versions {
		version := item.(map[string]any)
		schemas = append(schemas, map[string]any{"name": version["name"], "served": version["served"], "storage": version["storage"], "schema": version["schema"]})
	}
	return MarshalDigest(schemas)
}

func IdentifySchema(obj *unstructured.Unstructured) (string, string, error) {
	digest, err := SchemaDigest(obj)
	if err != nil {
		return "", "", err
	}
	for _, mode := range SchemaModes {
		expected, err := Schema(mode)
		if err != nil {
			return "", "", err
		}
		want, err := SchemaDigest(expected)
		if err != nil {
			return "", "", err
		}
		if want == digest {
			return mode, digest, nil
		}
	}
	return "", digest, fmt.Errorf("unknown CNP schema %s; refusing a potentially lossy update", digest)
}
