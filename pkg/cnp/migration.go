package cnp

import (
	"encoding/json/v2"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type PatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitzero"`
}

type ObjectPlan struct {
	Name            string           `json:"name"`
	UID             string           `json:"uid"`
	ResourceVersion string           `json:"resourceVersion"`
	Generation      int64            `json:"generation"`
	SemanticDigest  string           `json:"semanticDigest"`
	Patch           []PatchOperation `json:"patch"`
	Receipt         *Receipt         `json:"receipt,omitzero"`
}

// PlanObject uses the current raw object; it never restores a historical spec.
// UID, resourceVersion and spec tests are part of the same request as all edits.
func PlanObject(raw *unstructured.Unstructured, legacy bool) (*ObjectPlan, error) {
	policy, err := Normalize(raw)
	if err != nil {
		return nil, err
	}
	if err := ValidateStructure(policy); err != nil {
		return nil, err
	}
	digest, err := Digest(policy)
	if err != nil {
		return nil, err
	}
	if raw.GetUID() == "" || raw.GetResourceVersion() == "" || raw.GetDeletionTimestamp() != nil {
		return nil, fmt.Errorf("%s is not a live persisted CNP", raw.GetName())
	}
	plan := &ObjectPlan{Name: raw.GetName(), UID: string(raw.GetUID()), ResourceVersion: raw.GetResourceVersion(), Generation: raw.GetGeneration(), SemanticDigest: digest}
	converted := raw.DeepCopy()
	for _, direction := range []string{"ingress", "egress"} {
		rules, found, err := unstructured.NestedSlice(converted.Object, "spec", direction)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		for i, item := range rules {
			rule := item.(map[string]any)
			base := fmt.Sprintf("/spec/%s/%d", direction, i)
			ops, err := planRule(rule, base, legacy)
			if err != nil {
				return nil, err
			}
			plan.Patch = append(plan.Patch, ops...)
		}
		if err := unstructured.SetNestedSlice(converted.Object, rules, "spec", direction); err != nil {
			return nil, err
		}
	}
	if legacy {
		// v0.2.0 permits omitted namespaceSelector; old CRDs require it.
		plan.Patch = append(plan.Patch, addNamespaceSelectors(converted.Object["spec"], "/spec")...)
	}
	if len(plan.Patch) == 0 {
		return plan, nil
	}
	after, err := Normalize(converted)
	if err != nil {
		return nil, err
	}
	afterDigest, err := Digest(after)
	if err != nil {
		return nil, err
	}
	if afterDigest != digest {
		return nil, fmt.Errorf("conversion changes semantics for %s", raw.GetName())
	}
	preconditions := []PatchOperation{
		{Op: "test", Path: "/metadata/uid", Value: plan.UID},
		{Op: "test", Path: "/metadata/resourceVersion", Value: plan.ResourceVersion},
		{Op: "test", Path: "/spec", Value: raw.Object["spec"]},
	}
	plan.Patch = append(preconditions, plan.Patch...)
	return plan, nil
}

func planRule(rule map[string]any, base string, legacy bool) ([]PatchOperation, error) {
	source, target := "ports", "protocols"
	if legacy {
		source, target = target, source
	}
	value, present := rule[source]
	if !present {
		return nil, nil
	}
	if !legacy {
		if err := normalizeRule(rule); err != nil {
			return nil, err
		}
		value = rule[target]
	} else {
		ports := make([]any, 0)
		for _, item := range value.([]any) {
			protocol := item.(map[string]any)
			for transport, attributes := range protocol {
				if transport != "tcp" && transport != "udp" && transport != "sctp" {
					return nil, fmt.Errorf("cannot downgrade protocol %q", transport)
				}
				destination := attributes.(map[string]any)["destinationPort"].(map[string]any)
				port := map[string]any{"protocol": strings.ToUpper(transport)}
				kind := "portNumber"
				if number, exists := destination["number"]; exists {
					port["port"] = number
				} else {
					kind = "portRange"
					rangeValue := destination["range"].(map[string]any)
					port["start"], port["end"] = rangeValue["start"], rangeValue["end"]
				}
				ports = append(ports, map[string]any{kind: port})
			}
		}
		value = ports
		rule[target] = value
		delete(rule, source)
	}
	return []PatchOperation{{Op: "add", Path: base + "/" + target, Value: value}, {Op: "remove", Path: base + "/" + source}}, nil
}

func addNamespaceSelectors(value any, path string) []PatchOperation {
	var ops []PatchOperation
	switch v := value.(type) {
	case map[string]any:
		if pods, ok := v["pods"].(map[string]any); ok {
			if _, exists := pods["namespaceSelector"]; !exists {
				pods["namespaceSelector"] = map[string]any{}
				ops = append(ops, PatchOperation{Op: "add", Path: path + "/pods/namespaceSelector", Value: map[string]any{}})
			}
		}
		for key, item := range v {
			ops = append(ops, addNamespaceSelectors(item, path+"/"+key)...)
		}
	case []any:
		for i, item := range v {
			ops = append(ops, addNamespaceSelectors(item, fmt.Sprintf("%s/%d", path, i))...)
		}
	}
	return ops
}

func (p *ObjectPlan) PatchBytes() ([]byte, error) {
	return json.Marshal(p.Patch)
}
