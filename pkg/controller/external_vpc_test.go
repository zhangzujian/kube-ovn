package controller

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
)

func Test_getLogicalRouterPorts(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient

	lrpNamePrefix := "get-lr-ports-lrp"
	lrName := "get-lr-ports-lr"

	lr := &ovnnb.LogicalRouter{
		Name:  lrName,
		Ports: []string{"22155bc5-28c7-45fa-ab40-366e24f12f11", "9f26c67d-cfc9-4f7b-ab94-bce0f4d0c16b"},
	}

	mockOvnClient.EXPECT().GetEntityInfo(gomock.Any()).DoAndReturn(func(in *ovnnb.LogicalRouterPort) error {
		if in.UUID == "22155bc5-28c7-45fa-ab40-366e24f12f11" {
			in.Name = fmt.Sprintf("%s-%d", lrpNamePrefix, 0)
		}
		return nil
	})

	mockOvnClient.EXPECT().GetEntityInfo(gomock.Any()).DoAndReturn(func(in *ovnnb.LogicalRouterPort) error {
		if in.UUID == "9f26c67d-cfc9-4f7b-ab94-bce0f4d0c16b" {
			in.Name = fmt.Sprintf("%s-%d", lrpNamePrefix, 1)
		}
		return nil
	})

	ports, err := ctrl.getLogicalRouterPorts(lr)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{lrpNamePrefix + "-0", lrpNamePrefix + "-1"}, ports)
}

func Test_getLogicalRoutersPorts(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient

	lrpNamePrefix := "get-lrs-ports-lrp"
	lrName := "get-lrs-ports-lr"

	lr := &ovnnb.LogicalRouter{
		Name:  lrName,
		Ports: []string{"22155bc5-28c7-45fa-ab40-366e24f12f11", "9f26c67d-cfc9-4f7b-ab94-bce0f4d0c16b"},
	}

	mockOvnClient.EXPECT().ListLogicalRouter(false, gomock.Any()).Return([]ovnnb.LogicalRouter{*lr}, nil)

	mockOvnClient.EXPECT().GetEntityInfo(gomock.Any()).DoAndReturn(func(in *ovnnb.LogicalRouterPort) error {
		if in.UUID == "22155bc5-28c7-45fa-ab40-366e24f12f11" {
			in.Name = fmt.Sprintf("%s-%d", lrpNamePrefix, 0)
		}
		return nil
	})

	mockOvnClient.EXPECT().GetEntityInfo(gomock.Any()).DoAndReturn(func(in *ovnnb.LogicalRouterPort) error {
		if in.UUID == "9f26c67d-cfc9-4f7b-ab94-bce0f4d0c16b" {
			in.Name = fmt.Sprintf("%s-%d", lrpNamePrefix, 1)
		}
		return nil
	})

	ports, err := ctrl.getLogicalRoutersPorts()
	require.NoError(t, err)
	require.Equal(t, map[string][]string{
		lrName: {lrpNamePrefix + "-0", lrpNamePrefix + "-1"},
	}, ports)
}

func Test_getLogicalSwitchPatchPorts(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient

	lspNamePrefix := "get-ls-ports-lsp"
	lsName := "get-ls-ports-ls"

	ls := &ovnnb.LogicalSwitch{
		Name:  lsName,
		Ports: []string{"22155bc5-28c7-45fa-ab40-366e24f12f11", "9f26c67d-cfc9-4f7b-ab94-bce0f4d0c16b"},
	}

	mockOvnClient.EXPECT().GetEntityInfo(gomock.Any()).DoAndReturn(func(in *ovnnb.LogicalSwitchPort) error {
		if in.UUID == "22155bc5-28c7-45fa-ab40-366e24f12f11" {
			in.Name = fmt.Sprintf("%s-%d", lspNamePrefix, 0)
		}
		return nil
	})

	mockOvnClient.EXPECT().GetEntityInfo(gomock.Any()).DoAndReturn(func(in *ovnnb.LogicalSwitchPort) error {
		if in.UUID == "9f26c67d-cfc9-4f7b-ab94-bce0f4d0c16b" {
			in.Name = fmt.Sprintf("%s-%d", lspNamePrefix, 1)
			in.Type = "router"
			in.Options = map[string]string{
				"router-port": fmt.Sprintf("%s-%d", lspNamePrefix, 1) + "-lrp",
			}
		}
		return nil
	})

	patchPort, err := ctrl.getLogicalSwitchPatchPorts(ls)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s-%d", lspNamePrefix, 1)+"-lrp", patchPort)
}

func Test_getLogicalSwitchsPatchPorts(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient

	lspNamePrefix := "get-lss-ports-lsp"
	lsName := "get-lss-ports-ls"

	ls := &ovnnb.LogicalSwitch{
		Name:  lsName,
		Ports: []string{"22155bc5-28c7-45fa-ab40-366e24f12f11", "9f26c67d-cfc9-4f7b-ab94-bce0f4d0c16b"},
	}

	mockOvnClient.EXPECT().ListLogicalSwitch(false, gomock.Any()).Return([]ovnnb.LogicalSwitch{*ls}, nil)

	mockOvnClient.EXPECT().GetEntityInfo(gomock.Any()).DoAndReturn(func(in *ovnnb.LogicalSwitchPort) error {
		if in.UUID == "22155bc5-28c7-45fa-ab40-366e24f12f11" {
			in.Name = fmt.Sprintf("%s-%d", lspNamePrefix, 0)
		}
		return nil
	})

	mockOvnClient.EXPECT().GetEntityInfo(gomock.Any()).DoAndReturn(func(in *ovnnb.LogicalSwitchPort) error {
		if in.UUID == "9f26c67d-cfc9-4f7b-ab94-bce0f4d0c16b" {
			in.Name = fmt.Sprintf("%s-%d", lspNamePrefix, 1)
			in.Type = "router"
			in.Options = map[string]string{
				"router-port": fmt.Sprintf("%s-%d", lspNamePrefix, 1) + "-lrp",
			}
		}
		return nil
	})

	out, err := ctrl.getLogicalSwitchsPatchPorts()
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		fmt.Sprintf("%s-%d", lspNamePrefix, 1) + "-lrp": lsName,
	}, out)
}

func Test_getlogicalRouterLogicalSwitchs(t *testing.T) {
	t.Parallel()

	lrpNamePrefix := "get-lr-lss-lrp"
	lsNamePrefix := "get-lr-lss-ls"

	lrps := make([]string, 0, 3)
	lrpToLs := make(map[string]string)
	lss := make([]string, 0, 3)

	for i := 0; i < 3; i++ {
		lrpName := fmt.Sprintf("%s-%d", lrpNamePrefix, i)
		lsName := fmt.Sprintf("%s-%d", lsNamePrefix, i)
		lrps = append(lrps, lrpName)
		lss = append(lss, lsName)
		lrpToLs[lrpName] = lsName
	}

	lrpToLs[lrpNamePrefix+"-test"] = lsNamePrefix + "-test"

	result := getlogicalRouterLogicalSwitchs(lrps, lrpToLs)
	require.ElementsMatch(t, lss, result)
}
