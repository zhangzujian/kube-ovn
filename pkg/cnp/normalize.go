// Package cnp preserves and validates both CNP representations during upgrades.
package cnp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/network-policy-api/apis/v1alpha2"
)

var Resource = schema.GroupVersionResource{Group: "policy.networking.k8s.io", Version: "v1alpha2", Resource: "clusternetworkpolicies"}

// Normalize never mutates the informer cache or writes a typed object back.
// The raw representation must be inspected before decoding the v0.2.0 API.
func Normalize(raw *unstructured.Unstructured) (*v1alpha2.ClusterNetworkPolicy, error) {
	obj := raw.DeepCopy()
	if err := validateRawSelectors(obj); err != nil {
		return nil, err
	}
	for _, direction := range []string{"ingress", "egress"} {
		rules, found, err := unstructured.NestedSlice(obj.Object, "spec", direction)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		for i, item := range rules {
			rule, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s[%d]: expected an object", direction, i)
			}
			if err := normalizeRule(rule); err != nil {
				return nil, fmt.Errorf("%s[%d]: %w", direction, i, err)
			}
		}
		if err := unstructured.SetNestedSlice(obj.Object, rules, "spec", direction); err != nil {
			return nil, err
		}
	}
	data, err := json.Marshal(obj.Object["spec"])
	if err != nil {
		return nil, err
	}
	var spec v1alpha2.ClusterNetworkPolicySpec
	if err := json.Unmarshal(data, &spec, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("unsupported CNP spec: %w", err)
	}
	policy := new(v1alpha2.ClusterNetworkPolicy)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, policy); err != nil {
		return nil, err
	}
	policy.Spec = spec
	if err := ValidateProtocols(policy); err != nil {
		return nil, err
	}
	if err := ValidateStructure(policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func normalizeRule(rule map[string]any) error {
	ports, legacy := rule["ports"]
	protocols, native := rule["protocols"]
	if legacy && native {
		return errors.New("ports and protocols are mutually exclusive")
	}
	if native {
		items, ok := protocols.([]any)
		if !ok || len(items) == 0 || len(items) > 25 {
			return errors.New("protocols must contain 1 to 25 entries")
		}
		for _, item := range items {
			protocol, ok := item.(map[string]any)
			if !ok || len(protocol) != 1 {
				return errors.New("each protocol must set exactly one field")
			}
			for transport, value := range protocol {
				if transport == "destinationNamedPort" {
					continue
				}
				attributes, ok := value.(map[string]any)
				if !ok {
					return errors.New("protocol attributes must be an object")
				}
				port, ok := attributes["destinationPort"].(map[string]any)
				if !ok || len(port) != 1 {
					return errors.New("destinationPort must set exactly one field")
				}
			}
		}
	}
	if !legacy {
		return nil
	}
	items, ok := ports.([]any)
	if !ok || len(items) == 0 || len(items) > 25 {
		return errors.New("ports must contain 1 to 25 entries")
	}
	converted := make([]any, 0, len(items))
	for _, item := range items {
		protocol, err := convertLegacyPort(item)
		if err != nil {
			return err
		}
		converted = append(converted, protocol)
	}
	rule["protocols"] = converted
	delete(rule, "ports")
	return nil
}

func validateRawSelectors(obj *unstructured.Unstructured) error {
	subject, found, err := unstructured.NestedMap(obj.Object, "spec", "subject")
	if err != nil {
		return err
	}
	if !found || len(subject) != 1 {
		return errors.New("subject must set exactly one selector")
	}
	for _, direction := range []string{"ingress", "egress"} {
		rules, found, err := unstructured.NestedSlice(obj.Object, "spec", direction)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		for _, item := range rules {
			rule, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("%s rule must be an object", direction)
			}
			field := "from"
			if direction == "egress" {
				field = "to"
			}
			peers, ok := rule[field].([]any)
			if !ok || len(peers) == 0 || len(peers) > 25 {
				return fmt.Errorf("%s must contain 1 to 25 peers", field)
			}
			for _, item := range peers {
				peer, ok := item.(map[string]any)
				if !ok || len(peer) != 1 {
					return fmt.Errorf("%s peer must set exactly one selector", field)
				}
			}
		}
	}
	return nil
}

func convertLegacyPort(item any) (map[string]any, error) {
	port, ok := item.(map[string]any)
	if !ok || len(port) != 1 {
		return nil, errors.New("each legacy port must set exactly one field")
	}
	for kind, value := range port {
		if kind == "namedPort" {
			return nil, errors.New("named ports are not supported by Kube-OVN CNP")
		}
		number, ok := value.(map[string]any)
		if !ok || (kind != "portNumber" && kind != "portRange") {
			return nil, fmt.Errorf("unsupported legacy port %q", kind)
		}
		protocol := "TCP"
		if p, exists := number["protocol"]; exists {
			protocol, ok = p.(string)
			if !ok {
				return nil, errors.New("protocol must be a string")
			}
		}
		if protocol != "TCP" && protocol != "UDP" && protocol != "SCTP" {
			return nil, fmt.Errorf("unsupported protocol %q", protocol)
		}
		destination := map[string]any{}
		for field, v := range number {
			switch field {
			case "protocol":
			case "port":
				if kind != "portNumber" {
					return nil, errors.New("port is only valid in portNumber")
				}
				destination["number"] = v
			case "start", "end":
				if kind != "portRange" {
					return nil, errors.New("range is only valid in portRange")
				}
			default:
				return nil, fmt.Errorf("unknown legacy port field %q", field)
			}
		}
		if kind == "portRange" {
			destination = map[string]any{"range": map[string]any{"start": number["start"], "end": number["end"]}}
		}
		return map[string]any{strings.ToLower(protocol): map[string]any{"destinationPort": destination}}, nil
	}
	return nil, errors.New("empty legacy port")
}

// ProtocolPort returns the transport and numeric destination match.
// Named ports must be rejected before changing any existing OVN resources.
func ProtocolPort(p v1alpha2.ClusterNetworkPolicyProtocol) (string, *v1alpha2.Port, error) {
	count, transport := 0, ""
	var port *v1alpha2.Port
	if p.TCP != nil {
		count++
		transport, port = "tcp", p.TCP.DestinationPort
	}
	if p.UDP != nil {
		count++
		transport, port = "udp", p.UDP.DestinationPort
	}
	if p.SCTP != nil {
		count++
		transport, port = "sctp", p.SCTP.DestinationPort
	}
	if p.DestinationNamedPort != "" {
		return "", nil, errors.New("destinationNamedPort is not supported by Kube-OVN CNP")
	}
	if count != 1 || port == nil {
		return "", nil, errors.New("exactly one transport with destinationPort is required")
	}
	if port.Range == nil {
		if port.Number < 1 || port.Number > 65535 {
			return "", nil, errors.New("destination port must be between 1 and 65535")
		}
	} else if port.Number != 0 || port.Range.Start < 1 || port.Range.End > 65535 || port.Range.Start >= port.Range.End {
		return "", nil, errors.New("invalid destination port range")
	}
	return transport, port, nil
}

func ValidateProtocols(policy *v1alpha2.ClusterNetworkPolicy) error {
	for i, rule := range policy.Spec.Ingress {
		for _, p := range rule.Protocols {
			if _, _, err := ProtocolPort(p); err != nil {
				return fmt.Errorf("ingress[%d]: %w", i, err)
			}
		}
	}
	for i, rule := range policy.Spec.Egress {
		for _, p := range rule.Protocols {
			if _, _, err := ProtocolPort(p); err != nil {
				return fmt.Errorf("egress[%d]: %w", i, err)
			}
		}
	}
	return nil
}

func Digest(policy *v1alpha2.ClusterNetworkPolicy) (string, error) {
	data, err := json.Marshal(policy.Spec, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
