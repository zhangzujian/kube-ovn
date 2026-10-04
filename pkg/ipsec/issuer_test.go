package ipsec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/kubeovn/kube-ovn/pkg/util"
)

func TestIssuerRejectsCollisionAndTerminalFailure(t *testing.T) {
	csr := []byte("synthetic-request")
	for _, tc := range []struct {
		name    string
		change  func(*certv1.CertificateSigningRequest)
		message string
	}{
		{"different-key", func(req *certv1.CertificateSigningRequest) {
			req.Spec.Request = []byte("stale-request")
			req.Status.Certificate = []byte("stale-certificate")
		}, "conflicts"},
		{"denied", func(req *certv1.CertificateSigningRequest) {
			req.Status.Conditions = []certv1.CertificateSigningRequestCondition{{Type: certv1.CertificateDenied, Status: "True", Reason: "Forbidden"}}
		}, "Denied"},
		{"failed", func(req *certv1.CertificateSigningRequest) {
			req.Status.Conditions = []certv1.CertificateSigningRequestCondition{{Type: certv1.CertificateFailed, Status: "True", Reason: "Invalid"}}
		}, "Failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: requestName("uid-a", csr), UID: "request-uid", Annotations: map[string]string{NodeNameAnnotation: "node-a", NodeUIDAnnotation: "uid-a"}}, Spec: certv1.CertificateSigningRequestSpec{Request: csr, SignerName: util.SignerName, Usages: []certv1.KeyUsage{certv1.UsageIPsecTunnel}, ExpirationSeconds: new(int32(3600))}}
			tc.change(req)
			client := fake.NewClientset(req)
			i := issuer{kube: client, node: "node-a", nodeUID: "uid-a", duration: time.Hour}
			_, err := i.sign(t.Context(), csr)
			require.ErrorContains(t, err, tc.message)
			retained, err := client.CertificatesV1().CertificateSigningRequests().Get(t.Context(), req.Name, metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, req.UID, retained.UID)
		})
	}
}
