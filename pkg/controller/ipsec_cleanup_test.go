package controller

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"encoding/pem"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/kubeovn/kube-ovn/pkg/ipsec"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

func cleanupTestSignature(t *testing.T, claim ipsec.CleanupReceipt, key *rsa.PrivateKey) string {
	t.Helper()
	payload, err := json.Marshal(claim)
	require.NoError(t, err)
	hash := sha256.Sum256(append([]byte("kube-ovn IPsec guarded cleanup receipt v1\x00"), payload...))
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	require.NoError(t, err)
	data, err := json.Marshal(ipsec.SignedReceipt{Payload: payload, Signature: signature})
	require.NoError(t, err)
	return string(data)
}

func TestIPsecCleanupReceiptRequiresCurrentNativePod(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "chassis"}, DNSNames: []string{"chassis"}}, key)
	require.NoError(t, err)
	container := corev1.Container{Name: "ipsec-cleanup", Image: "candidate", RestartPolicy: new(corev1.ContainerRestartPolicyAlways), Command: []string{"/kube-ovn/kube-ovn-ipsec"}, Args: []string{"--cleanup-only"}}
	ds := &appsv1.DaemonSet{
		Name: "kube-ovn-cni", Namespace: "kube-system", UID: "ds-uid",
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{HostNetwork: true, HostPID: true, InitContainers: []corev1.Container{container}}}},
	}
	pod := &corev1.Pod{
		Name: "cni", Namespace: ds.Namespace, UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: ds.Name, UID: ds.UID, Controller: new(true)}},
		Spec: corev1.PodSpec{NodeName: "node", ServiceAccountName: "kube-ovn-cni", HostNetwork: true, HostPID: true, InitContainers: []corev1.Container{container}},
	}
	pod.Spec.InitContainers[0].VolumeMounts = []corev1.VolumeMount{{Name: "kube-api-access-token", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true}}
	pod.Spec.Volumes = []corev1.Volume{ipsecTestAPITokenVolume("kube-api-access-token")}
	node := &corev1.Node{Name: "node", UID: "node-uid", Annotations: map[string]string{util.ChassisAnnotation: "chassis"}}
	csr := &certv1.CertificateSigningRequest{
		Name: "cleanup-binding", UID: "csr-uid", Annotations: map[string]string{ipsec.NodeNameAnnotation: node.Name, ipsec.NodeUIDAnnotation: string(node.UID)},
		Spec: certv1.CertificateSigningRequestSpec{Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), SignerName: ipsec.CleanupSignerName, Usages: []certv1.KeyUsage{certv1.UsageIPsecTunnel}, Username: "system:serviceaccount:kube-system:kube-ovn-cni", Extra: map[string]certv1.ExtraValue{"authentication.kubernetes.io/pod-name": {pod.Name}, "authentication.kubernetes.io/pod-uid": {string(pod.UID)}}},
	}
	template, err := json.Marshal(ds.Spec.Template, json.Deterministic(true))
	require.NoError(t, err)
	state := &ipsec.Coordination{Version: 1, Generation: "gen", Epoch: "epoch", Phase: ipsec.CleanupPhase, DaemonSetUID: string(ds.UID), TemplateHash: ipsecPublicHash(template), TrustHash: ipsecPublicHash([]byte("unused trust")), Targets: map[string]string{node.Name: string(node.UID)}, NBGlobalUUID: uuid.New().String(), SBGlobalUUID: uuid.New().String()}
	claim := ipsec.CleanupReceipt{
		Generation: state.Generation, Epoch: state.Epoch, Phase: state.Phase, DaemonSetUID: state.DaemonSetUID, TemplateHash: state.TemplateHash, NBGlobalUUID: state.NBGlobalUUID, SBGlobalUUID: state.SBGlobalUUID,
		NodeName: node.Name, NodeUID: string(node.UID), PodUID: string(pod.UID), CSRName: csr.Name, CSRUID: string(csr.UID), Chassis: "chassis", Lease: "lease", Mark: 42, Reqid: 99, OVSUUID: uuid.New().String(), BootID: uuid.New().String(), IdentityCleared: true, Observed: time.Now(),
	}
	node.Annotations[ipsec.CleanupReceiptAnnotation] = cleanupTestSignature(t, claim, key)
	verify := func(node *corev1.Node, pod *corev1.Pod, csr *certv1.CertificateSigningRequest) error {
		return verifyIPsecCleanupReceipt(node, ds, state, map[string]*corev1.Pod{pod.Name: pod}, map[string]*certv1.CertificateSigningRequest{csr.Name: csr})
	}
	require.NoError(t, verify(node, pod, csr), "an unapproved binding CSR must suffice without a CA")
	kube := fake.NewClientset(ds, pod, node, csr)
	c := &Controller{config: &Configuration{KubeClient: kube, PodNamespace: ds.Namespace}}
	require.NoError(t, c.verifyIPsecCleanupBarrier(t.Context(), ds, state))
	for _, action := range kube.Actions() {
		require.NotEqual(t, "secrets", action.GetResource().Resource)
	}
	for _, tc := range []struct {
		name   string
		change func(*corev1.Node, *corev1.Pod, *certv1.CertificateSigningRequest)
	}{
		{"another-node", func(n *corev1.Node, _ *corev1.Pod, _ *certv1.CertificateSigningRequest) { n.UID = "replacement" }},
		{"old-pod", func(_ *corev1.Node, p *corev1.Pod, _ *certv1.CertificateSigningRequest) { p.UID = "replacement" }},
		{"wrong-init-image", func(_ *corev1.Node, p *corev1.Pod, _ *certv1.CertificateSigningRequest) {
			p.Spec.InitContainers[0].Image = "foreign"
		}},
		{"wrong-init-mode", func(_ *corev1.Node, p *corev1.Pod, _ *certv1.CertificateSigningRequest) {
			p.Spec.InitContainers[0].Args = nil
		}},
		{"missing-native-restart", func(_ *corev1.Node, p *corev1.Pod, _ *certv1.CertificateSigningRequest) {
			p.Spec.InitContainers[0].RestartPolicy = nil
		}},
		{"writable-token-injection", func(_ *corev1.Node, p *corev1.Pod, _ *certv1.CertificateSigningRequest) {
			p.Spec.InitContainers[0].VolumeMounts[0].ReadOnly = false
		}},
		{"wrong-csr-purpose", func(_ *corev1.Node, _ *corev1.Pod, r *certv1.CertificateSigningRequest) {
			r.Spec.SignerName = util.SignerName
		}},
		{"self-claimed-pod", func(_ *corev1.Node, _ *corev1.Pod, r *certv1.CertificateSigningRequest) { r.Spec.Extra = nil }},
		{"wrong-bound-pod", func(_ *corev1.Node, _ *corev1.Pod, r *certv1.CertificateSigningRequest) {
			r.Spec.Extra["authentication.kubernetes.io/pod-uid"] = certv1.ExtraValue{"foreign-pod"}
		}},
		{"signed-encryption-csr", func(_ *corev1.Node, _ *corev1.Pod, r *certv1.CertificateSigningRequest) {
			r.Status.Certificate = []byte("issued")
		}},
		{"denied-csr", func(_ *corev1.Node, _ *corev1.Pod, r *certv1.CertificateSigningRequest) {
			r.Status.Conditions = []certv1.CertificateSigningRequestCondition{{Type: certv1.CertificateDenied, Status: corev1.ConditionTrue}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, p, r := node.DeepCopy(), pod.DeepCopy(), csr.DeepCopy()
			tc.change(n, p, r)
			require.Error(t, verify(n, p, r))
		})
	}
}
