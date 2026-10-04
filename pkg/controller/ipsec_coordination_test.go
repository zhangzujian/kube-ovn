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

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	appsv1 "k8s.io/api/apps/v1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	mockovs "github.com/kubeovn/kube-ovn/mocks/pkg/ovs"
	"github.com/kubeovn/kube-ovn/pkg/ipsec"
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

func TestIPsecFrozenTargetsIncludeOfflineNodesAndRequiredAffinity(t *testing.T) {
	ds := &appsv1.DaemonSet{UID: "ds-uid", Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "ipsec"}}, NodeSelector: map[string]string{"os": "linux"}, Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "pool", Operator: corev1.NodeSelectorOpIn, Values: []string{"network"}}}}}}}}}}}}
	nodes := []corev1.Node{
		{Name: "online", UID: "online-uid", Labels: map[string]string{"os": "linux", "pool": "network"}},
		{Name: "offline", UID: "offline-uid", Labels: map[string]string{"os": "linux", "pool": "network"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}}},
		{Name: "wrong-pool", UID: "other-uid", Labels: map[string]string{"os": "linux", "pool": "compute"}},
		{Name: "windows", UID: "windows-uid", Labels: map[string]string{"os": "windows", "pool": "network"}},
	}
	state, err := freezeIPsecTargets(ds, nodes, []byte("trust"), false)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"online": "online-uid", "offline": "offline-uid"}, state.Targets)
	require.Equal(t, ipsec.PreparePhase, state.Phase)
	for range 8 {
		repeated, err := freezeIPsecTargets(ds, nodes, []byte("trust"), false)
		require.NoError(t, err)
		require.Equal(t, state.TemplateHash, repeated.TemplateHash, "template maps must have a deterministic digest")
	}
	state, err = freezeIPsecTargets(ds, nodes, []byte("trust"), true)
	require.NoError(t, err)
	require.Equal(t, ipsec.EnabledPhase, state.Phase, "a legacy enabled cluster is recorded without toggling NB")
	_, err = freezeIPsecTargets(ds, nil, []byte("trust"), false)
	require.Error(t, err)
}

func TestIPsecCoordinationRequiresFreshBoundReceiptsBeforeEnable(t *testing.T) {
	t.Setenv(util.EnvPodNamespace, "kube-system")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "chassis-a"}, DNSNames: []string{"chassis-a"}}, key)
	require.NoError(t, err)
	request, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	trust, caKeyPEM, err := newIPsecCA()
	require.NoError(t, err)
	ca, err := decodeCertificate(trust)
	require.NoError(t, err)
	caKey, err := decodePrivateKey(caKeyPEM)
	require.NoError(t, err)
	template, err := newCertificateTemplate(request)
	require.NoError(t, err)
	cert, err := signCSR(template, &key.PublicKey, ca, caKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	ds := &appsv1.DaemonSet{Name: "kube-ovn-cni", Namespace: "kube-system", UID: "ds-uid", Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{HostNetwork: true, HostPID: true, Containers: []corev1.Container{{Name: "ipsec", Image: "candidate"}}}}}}
	pod := &corev1.Pod{Name: "cni-a", Namespace: "kube-system", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: ds.Name, UID: ds.UID, Controller: new(true)}}, Spec: corev1.PodSpec{NodeName: "node-a", ServiceAccountName: "kube-ovn-cni", HostNetwork: true, HostPID: true, Containers: []corev1.Container{{Name: "ipsec", Image: "candidate", VolumeMounts: []corev1.VolumeMount{{Name: "kube-api-access-test", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true}}}}}}
	node := &corev1.Node{Name: "node-a", UID: "node-uid", Annotations: map[string]string{util.ChassisAnnotation: "chassis-a"}}
	csr := &certv1.CertificateSigningRequest{Name: "ovn-ipsec-receipt", UID: "csr-uid", Annotations: map[string]string{ipsec.NodeNameAnnotation: node.Name, ipsec.NodeUIDAnnotation: string(node.UID)}, Spec: certv1.CertificateSigningRequestSpec{SignerName: util.SignerName, Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), Username: "system:serviceaccount:kube-system:kube-ovn-cni", Extra: map[string]certv1.ExtraValue{"authentication.kubernetes.io/pod-name": {pod.Name}, "authentication.kubernetes.io/pod-uid": {string(pod.UID)}}}, Status: certv1.CertificateSigningRequestStatus{Certificate: certPEM}}
	kube := fake.NewClientset(ds, pod, node, csr, &corev1.Secret{Name: util.DefaultOVNIPSecCA, Namespace: "kube-system", Data: map[string][]byte{"cacert": trust}})
	nb := &ovnnb.NBGlobal{}
	ovs := mockovs.NewMockNbClient(gomock.NewController(t))
	ovs.EXPECT().GetNbGlobal().Return(nb, nil).AnyTimes()
	// No transition before fresh Arm receipts may call the enabling operation.
	ovs.EXPECT().SetOVNIPSec(true).DoAndReturn(func(bool) error { nb.Ipsec = true; return nil }).Times(1)
	c := &Controller{config: &Configuration{KubeClient: kube, PodNamespace: "kube-system", EnableOVNIPSec: true}, OVNNbClient: ovs}
	readState := func() *ipsec.Coordination {
		cm, err := kube.CoreV1().ConfigMaps("kube-system").Get(t.Context(), ipsec.CoordinationConfigMap, metav1.GetOptions{})
		require.NoError(t, err)
		state, err := ipsec.DecodeCoordination([]byte(cm.Data["state"]))
		require.NoError(t, err)
		return state
	}
	publish := func(state *ipsec.Coordination) {
		now := time.Now()
		claim := ipsec.Receipt{Generation: state.Generation, Epoch: state.Epoch, Phase: state.Phase, NodeName: node.Name, PodUID: string(pod.UID), CSRName: csr.Name, CSRUID: string(csr.UID), Observed: now, Status: ipsec.Status{NodeUID: string(node.UID), Chassis: "chassis-a", Generation: "identity", CertificateHash: ipsecPublicHash(certPEM), TrustHash: state.TrustHash, RuntimeHealthy: true, ConfigurationApplied: true, ProtectionArmed: true, Expires: cert.NotAfter}}
		payload, err := json.Marshal(claim)
		require.NoError(t, err)
		hash := sha256.Sum256(append([]byte("kube-ovn IPsec coordination receipt v1\x00"), payload...))
		signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		require.NoError(t, err)
		data, err := json.Marshal(ipsec.SignedReceipt{Payload: payload, Signature: signature})
		require.NoError(t, err)
		node.Annotations[ipsec.ReceiptAnnotation] = string(data)
		_, err = kube.CoreV1().Nodes().Update(t.Context(), node, metav1.UpdateOptions{})
		require.NoError(t, err)
	}
	require.NoError(t, c.reconcileIPsecCoordination(t.Context()))
	prepared := readState()
	require.Equal(t, ipsec.PreparePhase, prepared.Phase)
	require.ErrorContains(t, c.reconcileIPsecCoordination(t.Context()), "missing or oversized")
	require.False(t, nb.Ipsec)
	replaced := node.DeepCopy()
	replaced.UID = "replacement-node-uid"
	_, err = kube.CoreV1().Nodes().Update(t.Context(), replaced, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.ErrorContains(t, c.reconcileIPsecCoordination(t.Context()), "removed or replaced")
	require.Equal(t, prepared.Targets, readState().Targets, "reconciliation cannot silently rewrite a frozen Node UID")
	_, err = kube.CoreV1().Nodes().Update(t.Context(), node, metav1.UpdateOptions{})
	require.NoError(t, err)
	publish(prepared)
	replacedPod := pod.DeepCopy()
	replacedPod.UID = "replacement-pod-uid"
	_, err = kube.CoreV1().Pods("kube-system").Update(t.Context(), replacedPod, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.ErrorContains(t, c.reconcileIPsecCoordination(t.Context()), "no longer valid")
	_, err = kube.CoreV1().Pods("kube-system").Update(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.NoError(t, c.reconcileIPsecCoordination(t.Context()))
	armed := readState()
	require.Equal(t, ipsec.ArmPhase, armed.Phase)
	require.Equal(t, prepared.Targets, armed.Targets)
	require.Equal(t, prepared.Generation, armed.Generation)
	require.NotEqual(t, prepared.Epoch, armed.Epoch)
	require.ErrorContains(t, c.reconcileIPsecCoordination(t.Context()), "current barrier")
	require.False(t, nb.Ipsec, "a valid Prepare signature cannot be replayed at Arm")
	publish(armed)
	require.NoError(t, c.reconcileIPsecCoordination(t.Context()))
	require.True(t, nb.Ipsec)
	require.Equal(t, ipsec.EnabledPhase, readState().Phase)
	require.NoError(t, c.reconcileIPsecCoordination(t.Context()), "enabled reconciliation must not toggle IPsec during rolling migration")
	ds.Spec.Template.Spec.Containers[0].Image = "next-candidate"
	_, err = kube.AppsV1().DaemonSets("kube-system").Update(t.Context(), ds, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.NoError(t, c.reconcileIPsecCoordination(t.Context()))
	rolled := readState()
	require.Equal(t, prepared.Targets, rolled.Targets)
	require.NotEqual(t, prepared.Generation, rolled.Generation)
	require.Equal(t, ipsec.EnabledPhase, rolled.Phase)
	require.True(t, nb.Ipsec)
}
