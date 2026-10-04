package ipsec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	certv1 "k8s.io/api/certificates/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"

	"github.com/kubeovn/kube-ovn/pkg/util"
)

const (
	NodeNameAnnotation = "kube-ovn.io/ipsec-node"
	NodeUIDAnnotation  = "kube-ovn.io/ipsec-node-uid"
)

type issuer struct {
	kube                                         kubernetes.Interface
	cm                                           cmclient.Interface
	node, nodeUID, podUID, namespace, issuerName string
	duration                                     time.Duration
}

func requestName(nodeUID string, csr []byte) string {
	return "ovn-ipsec-" + digest(append([]byte(nodeUID+":"), csr...))[:48]
}

func (i issuer) name(csr []byte) string {
	// A rebuilt Pod has a different authenticated identity even when its
	// pending key survives. Never reuse a CSR bound to the deleted Pod.
	identity := fmt.Sprintf("%s:%s:%s:%s", i.nodeUID, i.podUID, i.issuerName, i.duration)
	return requestName(identity, csr)
}

func (i issuer) sign(ctx context.Context, csr []byte) ([]byte, error) {
	if i.cm != nil {
		return i.signCertManager(ctx, csr)
	}
	client := i.kube.CertificatesV1().CertificateSigningRequests()
	seconds := int64(i.duration / time.Second)
	if seconds < 600 || seconds > math.MaxInt32 {
		return nil, errors.New("invalid IPsec certificate duration")
	}
	req := &certv1.CertificateSigningRequest{
		Name: i.name(csr), Annotations: map[string]string{NodeNameAnnotation: i.node, NodeUIDAnnotation: i.nodeUID},
		Spec: certv1.CertificateSigningRequestSpec{Request: csr, SignerName: util.SignerName, Usages: []certv1.KeyUsage{certv1.UsageIPsecTunnel}, ExpirationSeconds: new(int32(seconds))},
	}
	created, err := client.Create(ctx, req, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		created, err = client.Get(ctx, req.Name, metav1.GetOptions{})
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(created.Spec.Request, csr) || created.Spec.SignerName != req.Spec.SignerName || !slices.Equal(created.Spec.Usages, req.Spec.Usages) || created.Spec.ExpirationSeconds == nil || *created.Spec.ExpirationSeconds != *req.Spec.ExpirationSeconds || created.Annotations[NodeNameAnnotation] != i.node || created.Annotations[NodeUIDAnnotation] != i.nodeUID {
		return nil, errors.New("IPsec CSR name conflicts with a different request")
	}
	check := func(event watch.Event) (bool, error) {
		if event.Type == watch.Deleted {
			return false, errors.New("IPsec CSR deleted while waiting for signing")
		}
		obj, ok := event.Object.(*certv1.CertificateSigningRequest)
		if !ok {
			return false, nil
		}
		if obj.UID != created.UID {
			return false, errors.New("IPsec CSR UID changed")
		}
		for _, condition := range obj.Status.Conditions {
			if condition.Status == "True" && (condition.Type == certv1.CertificateDenied || condition.Type == certv1.CertificateFailed) {
				return false, fmt.Errorf("IPsec CSR %s: %s", condition.Type, condition.Reason)
			}
		}
		return len(obj.Status.Certificate) != 0, nil
	}
	if done, err := check(watch.Event{Type: watch.Added, Object: created}); done || err != nil {
		return created.Status.Certificate, err
	}
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			opts.FieldSelector = "metadata.name=" + req.Name
			return client.List(ctx, opts)
		},
		WatchFuncWithContext: func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
			opts.FieldSelector = "metadata.name=" + req.Name
			return client.Watch(ctx, opts)
		},
	}
	event, err := watchtools.UntilWithSync(ctx, lw, &certv1.CertificateSigningRequest{}, nil, check)
	if err != nil {
		return nil, fmt.Errorf("wait for IPsec CSR: %w", err)
	}
	return event.Object.(*certv1.CertificateSigningRequest).Status.Certificate, nil
}

func (i issuer) signCertManager(ctx context.Context, csr []byte) ([]byte, error) {
	client := i.cm.CertmanagerV1().CertificateRequests(i.namespace)
	req := &certmanagerv1.CertificateRequest{
		Name: i.name(csr), Namespace: i.namespace, Annotations: map[string]string{NodeNameAnnotation: i.node, NodeUIDAnnotation: i.nodeUID},
		Spec: certmanagerv1.CertificateRequestSpec{
			Request: csr, Duration: &metav1.Duration{Duration: i.duration},
			IssuerRef: cmmeta.IssuerReference{Name: i.issuerName, Kind: "ClusterIssuer", Group: certmanager.GroupName},
			Usages:    []certmanagerv1.KeyUsage{certmanagerv1.UsageIPsecTunnel},
		},
	}
	created, err := client.Create(ctx, req, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		created, err = client.Get(ctx, req.Name, metav1.GetOptions{})
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(created.Spec.Request, csr) || created.Spec.IssuerRef != req.Spec.IssuerRef || !slices.Equal(created.Spec.Usages, req.Spec.Usages) || created.Spec.Duration == nil || *created.Spec.Duration != *req.Spec.Duration || created.Spec.IsCA || created.Annotations[NodeNameAnnotation] != i.node || created.Annotations[NodeUIDAnnotation] != i.nodeUID {
		return nil, errors.New("IPsec CertificateRequest name conflicts with a different request")
	}
	check := func(event watch.Event) (bool, error) {
		if event.Type == watch.Deleted {
			return false, errors.New("IPsec CertificateRequest deleted while waiting for signing")
		}
		obj, ok := event.Object.(*certmanagerv1.CertificateRequest)
		if !ok {
			return false, nil
		}
		if obj.UID != created.UID {
			return false, errors.New("IPsec CertificateRequest UID changed")
		}
		if obj.Status.FailureTime != nil {
			return false, errors.New("IPsec CertificateRequest failed")
		}
		for _, condition := range obj.Status.Conditions {
			if (condition.Type == certmanagerv1.CertificateRequestConditionDenied && condition.Status == cmmeta.ConditionTrue) || (condition.Type == certmanagerv1.CertificateRequestConditionReady && condition.Reason == "Failed") {
				return false, fmt.Errorf("IPsec CertificateRequest %s: %s", condition.Type, condition.Reason)
			}
		}
		return len(obj.Status.Certificate) != 0, nil
	}
	if done, err := check(watch.Event{Type: watch.Added, Object: created}); done || err != nil {
		return created.Status.Certificate, err
	}
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			opts.FieldSelector = "metadata.name=" + req.Name
			return client.List(ctx, opts)
		},
		WatchFuncWithContext: func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
			opts.FieldSelector = "metadata.name=" + req.Name
			return client.Watch(ctx, opts)
		},
	}
	event, err := watchtools.UntilWithSync(ctx, lw, &certmanagerv1.CertificateRequest{}, nil, check)
	if err != nil {
		return nil, fmt.Errorf("wait for IPsec CertificateRequest: %w", err)
	}
	return event.Object.(*certmanagerv1.CertificateRequest).Status.Certificate, nil
}
