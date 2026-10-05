package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	mockovs "github.com/kubeovn/kube-ovn/mocks/pkg/ovs"
	"github.com/kubeovn/kube-ovn/pkg/ipsec"
	"github.com/kubeovn/kube-ovn/pkg/ovs"
)

func TestIPsecDisableWaitsForLiveNorthboundAndSouthbound(t *testing.T) {
	state := &ipsec.Coordination{Version: 1, Generation: "generation", Epoch: "enable-epoch", Phase: ipsec.EnabledPhase, DaemonSetUID: "ds-uid", TemplateHash: ipsecPublicHash([]byte("template")), TrustHash: ipsecPublicHash([]byte("trust")), Targets: map[string]string{"offline": "offline-uid", "online": "online-uid"}}
	cm := &corev1.ConfigMap{Name: ipsec.CoordinationConfigMap, Namespace: "kube-system"}
	require.NoError(t, encodeIPsecCoordination(cm, state))
	ds := &appsv1.DaemonSet{Name: "kube-ovn-cni", Namespace: "kube-system", UID: "ds-uid", Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: "ipsec-cleanup", RestartPolicy: new(corev1.ContainerRestartPolicyAlways), Command: []string{"/kube-ovn/kube-ovn-ipsec"}, Args: []string{"--cleanup-only"}}}}}}}
	kube := fake.NewClientset(cm, ds)
	ctrl := gomock.NewController(t)
	nb, sb := mockovs.NewMockNbClient(ctrl), mockovs.NewMockSbClient(ctrl)
	c := &Controller{config: &Configuration{KubeClient: kube, PodNamespace: "kube-system"}, OVNNbClient: nb, OVNSbClient: sb}
	nbState := &ovs.IPsecGlobalState{UUID: "75980000-0000-0000-0000-000000000001", Enabled: false}
	sbState := &ovs.IPsecGlobalState{UUID: "75980000-0000-0000-0000-000000000002", Enabled: true}
	var readErr error
	nb.EXPECT().SetOVNIPSec(false).Return(nil).AnyTimes()
	nb.EXPECT().GetIPsecGlobal(gomock.Any()).DoAndReturn(func(context.Context) (*ovs.IPsecGlobalState, error) { return nbState, readErr }).AnyTimes()
	sb.EXPECT().GetIPsecGlobal(gomock.Any()).DoAndReturn(func(context.Context) (*ovs.IPsecGlobalState, error) { return sbState, readErr }).AnyTimes()
	read := func() (*corev1.ConfigMap, *ipsec.Coordination) {
		cm, err := kube.CoreV1().ConfigMaps("kube-system").Get(t.Context(), ipsec.CoordinationConfigMap, metav1.GetOptions{})
		require.NoError(t, err)
		state, err := ipsec.DecodeCoordination([]byte(cm.Data["state"]))
		require.NoError(t, err)
		return cm, state
	}
	require.NoError(t, c.reconcileIPsecCoordination(t.Context()))
	cm, disabling := read()
	require.Equal(t, ipsec.DisablingPhase, disabling.Phase)
	require.NotEqual(t, state.Epoch, disabling.Epoch)
	require.Equal(t, state.Targets, disabling.Targets, "disable cannot discard offline or replaced identities")
	require.ErrorContains(t, c.reconcileIPsecDisable(t.Context(), cm), "NB/SB switch convergence")
	cm, retained := read()
	require.Equal(t, disabling.Epoch, retained.Epoch)
	sbState.Enabled = false
	readErr = errors.New("SB disconnected")
	require.ErrorContains(t, c.reconcileIPsecDisable(t.Context(), cm), "disconnected")
	cm, retained = read()
	require.Equal(t, ipsec.DisablingPhase, retained.Phase)
	readErr = nil
	nbState.Enabled = true
	require.ErrorContains(t, c.reconcileIPsecDisable(t.Context(), cm), "NB/SB switch convergence")
	nbState.Enabled = false
	require.NoError(t, c.reconcileIPsecDisable(t.Context(), cm))
	cm, cleanup := read()
	require.Equal(t, ipsec.CleanupPhase, cleanup.Phase)
	require.NotEqual(t, disabling.Epoch, cleanup.Epoch)
	require.Equal(t, state.Generation, cleanup.Generation)
	require.Equal(t, state.Targets, cleanup.Targets)
	require.Equal(t, nbState.UUID, cleanup.NBGlobalUUID)
	require.Equal(t, sbState.UUID, cleanup.SBGlobalUUID)
	require.ErrorContains(t, c.reconcileIPsecDisable(t.Context(), cm), "missing or replaced")
	cm, retained = read()
	require.Equal(t, cleanup.Epoch, retained.Epoch, "stable convergence preserves the cleanup challenge")
	sbState.UUID = "75980000-0000-0000-0000-000000000003"
	require.NoError(t, c.reconcileIPsecDisable(t.Context(), cm))
	cm, rebuilt := read()
	require.Equal(t, ipsec.CleanupPhase, rebuilt.Phase)
	require.NotEqual(t, cleanup.Epoch, rebuilt.Epoch, "database replacement requires fresh cleanup evidence")
	require.Equal(t, sbState.UUID, rebuilt.SBGlobalUUID)
	sbState.Enabled = true
	require.ErrorContains(t, c.reconcileIPsecDisable(t.Context(), cm), "NB/SB switch convergence")
	_, retained = read()
	require.Equal(t, ipsec.DisablingPhase, retained.Phase)
	require.NotEqual(t, rebuilt.Epoch, retained.Epoch, "a lost convergence revokes the previous cleanup challenge")
	require.Empty(t, retained.NBGlobalUUID)
	require.Empty(t, retained.SBGlobalUUID)
}
