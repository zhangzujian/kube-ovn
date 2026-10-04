package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	certlisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/kubeovn/kube-ovn/pkg/ipsec"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

func TestIPsecSignerBindsRequesterToLiveNode(t *testing.T) {
	t.Setenv(util.EnvPodNamespace, "kube-system")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "chassis-a"}, DNSNames: []string{"chassis-a"}, PublicKey: &key.PublicKey}
	client := fake.NewClientset(
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "kube-ovn-cni", Namespace: "kube-system", UID: "ds-uid"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "cni-a", Namespace: "kube-system", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "kube-ovn-cni", UID: "ds-uid", Controller: new(true)}}}, Spec: corev1.PodSpec{NodeName: "node-a", ServiceAccountName: "kube-ovn-cni"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: "node-uid", Annotations: map[string]string{util.ChassisAnnotation: "chassis-a"}}},
	)
	c := &Controller{config: &Configuration{KubeClient: client}}
	base := &certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{ipsec.NodeNameAnnotation: "node-a", ipsec.NodeUIDAnnotation: "node-uid"}}, Spec: certv1.CertificateSigningRequestSpec{Username: "system:serviceaccount:kube-system:kube-ovn-cni", Extra: map[string]certv1.ExtraValue{"authentication.kubernetes.io/pod-name": {"cni-a"}, "authentication.kubernetes.io/pod-uid": {"pod-uid"}}}}
	require.NoError(t, c.validateIPsecRequester(base, request))
	for _, tc := range []struct {
		name   string
		mutate func(*certv1.CertificateSigningRequest)
	}{
		{"wrong-SA", func(req *certv1.CertificateSigningRequest) {
			req.Spec.Username = "system:serviceaccount:kube-system:other"
		}},
		{"unbound-token", func(req *certv1.CertificateSigningRequest) { req.Spec.Extra = nil }},
		{"replaced-pod", func(req *certv1.CertificateSigningRequest) {
			req.Spec.Extra["authentication.kubernetes.io/pod-uid"] = certv1.ExtraValue{"old-pod-uid"}
		}},
		{"forged-node", func(req *certv1.CertificateSigningRequest) { req.Annotations[ipsec.NodeNameAnnotation] = "node-b" }},
		{"replaced-node", func(req *certv1.CertificateSigningRequest) { req.Annotations[ipsec.NodeUIDAnnotation] = "old-node-uid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := base.DeepCopy()
			tc.mutate(req)
			require.Error(t, c.validateIPsecRequester(req, request))
		})
	}
	other := *request
	other.DNSNames = []string{"chassis-a", "chassis-b"}
	require.Error(t, c.validateIPsecRequester(base, &other))
}

func TestIPsecSignerDoesNotApproveDeniedOrFailedRequest(t *testing.T) {
	for _, condition := range []certv1.RequestConditionType{certv1.CertificateDenied, certv1.CertificateFailed} {
		t.Run(string(condition), func(t *testing.T) {
			req := &certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: "ovn-ipsec-node"}, Status: certv1.CertificateSigningRequestStatus{Conditions: []certv1.CertificateSigningRequestCondition{{Type: condition, Status: "True"}}}}
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, indexer.Add(req))
			client := fake.NewClientset(req)
			c := &Controller{config: &Configuration{KubeClient: client}, csrLister: certlisters.NewCertificateSigningRequestLister(indexer)}
			require.NoError(t, c.handleAddOrUpdateCsr(req.Name))
			require.Empty(t, client.Actions())
			require.Len(t, req.Status.Conditions, 1)
		})
	}
}

func TestIPsecSignerChecksCSRSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "chassis"}, DNSNames: []string{"chassis"}}, key)
	require.NoError(t, err)
	_, err = decodeCertificateRequest(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	require.NoError(t, err)
	der[len(der)-1] ^= 1
	_, err = decodeCertificateRequest(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	require.Error(t, err)
}
