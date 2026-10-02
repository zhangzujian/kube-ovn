package cnp

import (
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/network-policy-api/apis/v1alpha2"
)

type Lister struct {
	Indexer cache.Indexer
}

func (l *Lister) Get(name string) (*v1alpha2.ClusterNetworkPolicy, error) {
	obj, exists, err := l.Indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, apierrors.NewNotFound(Resource.GroupResource(), name)
	}
	policy, err := Normalize(obj.(*unstructured.Unstructured))
	if err != nil {
		return nil, fmt.Errorf("CNP %s: %w", name, err)
	}
	return policy, nil
}

// List returns valid policies even when one cached object cannot be normalized.
func (l *Lister) List(selector labels.Selector) ([]*v1alpha2.ClusterNetworkPolicy, error) {
	var result []*v1alpha2.ClusterNetworkPolicy
	var failures []error
	err := cache.ListAll(l.Indexer, selector, func(obj any) {
		raw := obj.(*unstructured.Unstructured)
		policy, err := Normalize(raw)
		if err != nil {
			failures = append(failures, fmt.Errorf("CNP %s: %w", raw.GetName(), err))
			return
		}
		result = append(result, policy)
	})
	return result, errors.Join(append(failures, err)...)
}
