package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	metricNetworkPolicySelectorMatches = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "network_policy_selector_matches_total",
			Help: "Number of NetworkPolicy-family selector Matches evaluations.",
		},
		[]string{"kind", "selector"},
	)
	metricNetworkPolicyCandidateEvaluations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "network_policy_candidate_evaluations_total",
			Help: "Number of NetworkPolicy-family candidates evaluated for label events.",
		},
		[]string{"kind", "event"},
	)
	metricNetworkPolicyAddressSetUpdates = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "network_policy_address_set_updates_total",
			Help: "Number of NetworkPolicy-family address-set create and update attempts.",
		},
		[]string{"kind", "operation"},
	)
)

func registerPerformanceMetrics() {
	metrics.Registry.MustRegister(metricNetworkPolicySelectorMatches)
	metrics.Registry.MustRegister(metricNetworkPolicyCandidateEvaluations)
	metrics.Registry.MustRegister(metricNetworkPolicyAddressSetUpdates)
}

func policySelectorMatches(kind, selector string, sel labels.Selector, set labels.Set) bool {
	metricNetworkPolicySelectorMatches.WithLabelValues(kind, selector).Inc()
	return sel.Matches(set)
}

func policyObjectMatchesSelector(kind, selector string, object metav1.Object, labelSelector *metav1.LabelSelector) bool {
	sel, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return false
	}
	return policySelectorMatches(kind, selector, sel, labels.Set(object.GetLabels()))
}

func observePolicyCandidates(kind, event string, count int) {
	metricNetworkPolicyCandidateEvaluations.WithLabelValues(kind, event).Add(float64(count))
}

func observePolicyAddressSetUpdate(kind, operation string) {
	metricNetworkPolicyAddressSetUpdates.WithLabelValues(kind, operation).Inc()
}
