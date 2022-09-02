package controller

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	mockovs "github.com/kubeovn/kube-ovn/mocks/pkg/ovs"
	"github.com/kubeovn/kube-ovn/pkg/client/clientset/versioned/fake"
	informerfactory "github.com/kubeovn/kube-ovn/pkg/client/informers/externalversions"
	kubeovninformer "github.com/kubeovn/kube-ovn/pkg/client/informers/externalversions/kubeovn/v1"
)

type fakeControllerInformers struct {
	vpcInformer kubeovninformer.VpcInformer
}

type fakeController struct {
	fakeController *Controller
	fakeinformers  *fakeControllerInformers
	mockOvnClient  *mockovs.MockOvnClient
}

func newFakeController(t *testing.T) *fakeController {
	/* kube ovn fake client */
	kubeovnClient := fake.NewSimpleClientset()
	kubeovnInformerFactory := informerfactory.NewSharedInformerFactory(kubeovnClient, 0)
	vpcInformer := kubeovnInformerFactory.Kubeovn().V1().Vpcs()

	fakeInformers := &fakeControllerInformers{
		vpcInformer: vpcInformer,
	}

	/* ovn fake client */
	mockOvnClient := mockovs.NewMockOvnClient(gomock.NewController(t))

	ctrl := &Controller{
		vpcsLister: vpcInformer.Lister(),
		vpcSynced:  alwaysReady,
		ovnClient:  mockOvnClient,
	}

	return &fakeController{
		fakeController: ctrl,
		fakeinformers:  fakeInformers,
		mockOvnClient:  mockOvnClient,
	}
}

func Test_allSubnetReady(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient

	subnets := []string{"ovn-default", "join"}

	t.Run("all subnet ready", func(t *testing.T) {
		mockOvnClient.EXPECT().LogicalSwitchExists(gomock.Any()).Return(true, nil).Times(2)

		ready, err := ctrl.allSubnetReady(subnets...)
		require.NoError(t, err)
		require.True(t, ready)
	})

	t.Run("some subnet are not ready", func(t *testing.T) {
		mockOvnClient.EXPECT().LogicalSwitchExists(gomock.Eq(subnets[0])).Return(true, nil)
		mockOvnClient.EXPECT().LogicalSwitchExists(gomock.Eq(subnets[1])).Return(false, nil)

		ready, err := ctrl.allSubnetReady(subnets...)
		require.NoError(t, err)
		require.False(t, ready)
	})
}
