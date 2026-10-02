package cnp

import (
	"fmt"
	"net/netip"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/network-policy-api/apis/v1alpha2"
)

// ValidateStructure rejects incomplete peers instead of compiling a wider ACL.
// CRD validation remains responsible for the full upstream API contract.
func ValidateStructure(policy *v1alpha2.ClusterNetworkPolicy) error {
	if policy.Spec.Tier != v1alpha2.AdminTier && policy.Spec.Tier != v1alpha2.BaselineTier {
		return fmt.Errorf("unsupported CNP tier %q", policy.Spec.Tier)
	}
	if err := validatePodSelector(policy.Spec.Subject.Namespaces, policy.Spec.Subject.Pods); err != nil {
		return fmt.Errorf("subject: %w", err)
	}
	if len(policy.Spec.Ingress) > 25 || len(policy.Spec.Egress) > 25 {
		return fmt.Errorf("at most 25 rules per direction are supported")
	}
	for i, rule := range policy.Spec.Ingress {
		if err := validateRule(rule.Action, len(rule.From), len(rule.Protocols)); err != nil {
			return fmt.Errorf("ingress[%d]: %w", i, err)
		}
		for _, peer := range rule.From {
			if err := validatePodSelector(peer.Namespaces, peer.Pods); err != nil {
				return fmt.Errorf("ingress[%d]: %w", i, err)
			}
		}
	}
	for i, rule := range policy.Spec.Egress {
		if err := validateRule(rule.Action, len(rule.To), len(rule.Protocols)); err != nil {
			return fmt.Errorf("egress[%d]: %w", i, err)
		}
		for _, peer := range rule.To {
			count := 0
			if peer.Namespaces != nil || peer.Pods != nil {
				count++
				if err := validatePodSelector(peer.Namespaces, peer.Pods); err != nil {
					return fmt.Errorf("egress[%d]: %w", i, err)
				}
			}
			if peer.Nodes != nil {
				count++
				if _, err := metav1.LabelSelectorAsSelector(peer.Nodes); err != nil {
					return err
				}
			}
			if len(peer.Networks) != 0 {
				count++
				for _, cidr := range peer.Networks {
					if _, err := netip.ParsePrefix(string(cidr)); err != nil {
						return err
					}
				}
			}
			if len(peer.DomainNames) != 0 {
				count++
				if rule.Action != v1alpha2.ClusterNetworkPolicyRuleActionAccept {
					return fmt.Errorf("domainNames requires Accept")
				}
			}
			if count != 1 {
				return fmt.Errorf("egress[%d]: each peer must set exactly one selector", i)
			}
		}
	}
	return nil
}

func validatePodSelector(namespaces *metav1.LabelSelector, pods *v1alpha2.NamespacedPod) error {
	if (namespaces == nil) == (pods == nil) {
		return fmt.Errorf("exactly one of namespaces or pods must be set")
	}
	selectors := []*metav1.LabelSelector{namespaces}
	if pods != nil {
		selectors = []*metav1.LabelSelector{&pods.NamespaceSelector, &pods.PodSelector}
	}
	for _, selector := range selectors {
		if _, err := metav1.LabelSelectorAsSelector(selector); err != nil {
			return err
		}
	}
	return nil
}

func validateRule(action v1alpha2.ClusterNetworkPolicyRuleAction, peers, protocols int) error {
	if action != v1alpha2.ClusterNetworkPolicyRuleActionAccept && action != v1alpha2.ClusterNetworkPolicyRuleActionDeny && action != v1alpha2.ClusterNetworkPolicyRuleActionPass {
		return fmt.Errorf("unsupported action %q", action)
	}
	if peers < 1 || peers > 25 || protocols > 25 {
		return fmt.Errorf("expected 1 to 25 peers and at most 25 protocols")
	}
	return nil
}
