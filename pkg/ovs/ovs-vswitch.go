package ovs

import (
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/client"
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/vswitch"
)

// VswitchClient is a client for interacting with the vswitch database
type VswitchClient struct {
	ovsDbClient
}

// NewVswitchClient creates a new vswitch client
func NewVswitchClient(addr string, connTimeout, transactTimeout int) (*VswitchClient, error) {
	dbModel, err := vswitch.FullDatabaseModel()
	if err != nil {
		klog.Error(err)
		return nil, err
	}

	c, err := client.NewOvsDbClient(
		vswitch.DatabaseName,
		addr,
		dbModel,
		nil,
		1,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create vswitch client: %w", err)
	}

	return &VswitchClient{
		ovsDbClient: ovsDbClient{
			Client:  c,
			Timeout: time.Duration(transactTimeout) * time.Second,
		},
	}, nil
}
