package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type VpcGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []VpcGateway `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resourceName=vpc-gateways
// vpc egress gateway is used to forward the egress traffic from the VPC to the external network
type VpcGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VpcGatewaySpec   `json:"spec"`
	Status VpcGatewayStatus `json:"status,omitempty"`
}

// Ready returns true if the VpcGateway has been processed successfully and is ready to serve traffic
func (g *VpcGateway) Ready() bool {
	return g.Status.Ready && g.Status.Conditions.IsReady(g.Generation)
}

type VpcGatewaySpec struct {
	// optional VPC name
	// if not specified, the default VPC will be used
	VPC string `json:"vpc,omitempty"`
	// workload replicas
	// Replicas int32 `json:"replicas,omitempty"`
	// optional name prefix used to generate the workload
	// the workload name will be generated as <prefix><vpc-egress-gateway-name>
	Prefix string `json:"prefix,omitempty"`
	// optional image used by the workload
	// if not specified, the default image passed in by kube-ovn-controller will be used
	Image string `json:"image,omitempty"`
	// optional internal subnet used to create the workload
	// if not specified, the workload will be created in the default subnet of the VPC
	InternalSubnet string `json:"internalSubnet,omitempty"`
	// external subnet used to create the workload
	ExternalSubnet string `json:"externalSubnet"`
	// optional internal/external IPs used to create the workload
	// these IPs must be in the internal/external subnet
	// the IPs count must NOT be less than the replicas count
	InternalIPs []string `json:"internalIPs,omitempty"`
	ExternalIPs []string `json:"externalIPs,omitempty"`

	// BFD configuration
	// BFD VpcEgressGatewayBFDConfig `json:"bfd,omitempty"`
	// egress policies
	// at least one policy must be specified
	// Policies []VpcEgressGatewayPolicy `json:"policies,omitempty"`
	// optional node selector used to select the nodes where the workload will be running
	NodeSelector []VpcEgressGatewayNodeSelector `json:"nodeSelector,omitempty"`
}

type VpcGatewayPolicy struct {
	// whether to enable SNAT/MASQUERADE for the egress traffic
	SNAT bool `json:"snat"`
	// CIDRs/subnets targeted by the egress traffic policy
	// packets whose source address is in the CIDRs/subnets will be forwarded to the egress gateway
	IPBlocks []string `json:"ipBlocks,omitempty"`
	Subnets  []string `json:"subnets,omitempty"`
}

type VpcGatewayNodeSelector VpcEgressGatewayNodeSelector

type VpcGatewayStatus struct {
	// used by the scale subresource
	// Replicas      int32  `json:"replicas,omitempty"`
	// LabelSelector string `json:"labelSelector,omitempty"`

	// whether the egress gateway is ready
	Ready bool  `json:"ready"`
	Phase Phase `json:"phase"`
	// internal/external IPs used by the workload
	InternalIPs []string   `json:"internalIPs,omitempty"`
	ExternalIPs []string   `json:"externalIPs,omitempty"`
	Conditions  Conditions `json:"conditions,omitempty"`

	// workload information
	Workload VpcEgressWorkload `json:"workload,omitempty"`
}

type VpcWorkload VpcEgressWorkload
