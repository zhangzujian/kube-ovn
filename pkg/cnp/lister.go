package cnp

import (
	"context"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/network-policy-api/apis/v1alpha2"
)

type Lister struct {
	Indexer  cache.Indexer
	Resource dynamic.ResourceInterface
}

// A long-lived watch can retain the schema that was active when it opened and
// prune fields restored by reverse migration. Use current API reads for every
// enforcement decision; the indexer supplies event identities only. Never fall
// back to cached specs when API access fails.
func (l *Lister) Get(ctx context.Context, name string) (*v1alpha2.ClusterNetworkPolicy, error) {
	obj, err := l.Resource.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	policy, err := Normalize(obj)
	if err != nil {
		return nil, fmt.Errorf("CNP %s: %w", name, err)
	}
	return policy, nil
}

// List returns valid policies even when one current object cannot be normalized.
func (l *Lister) List(ctx context.Context, selector labels.Selector) ([]*v1alpha2.ClusterNetworkPolicy, error) {
	objects, err := l.Resource.List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, err
	}
	var result []*v1alpha2.ClusterNetworkPolicy
	var failures []error
	for i := range objects.Items {
		raw := &objects.Items[i]
		policy, err := Normalize(raw)
		if err != nil {
			failures = append(failures, fmt.Errorf("CNP %s: %w", raw.GetName(), err))
			continue
		}
		result = append(result, policy)
	}
	return result, errors.Join(failures...)
}
