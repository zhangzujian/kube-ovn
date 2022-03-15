package e2e_vpc_nat_gateway_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	kubeovnv1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	"github.com/kubeovn/kube-ovn/pkg/util"
	"github.com/kubeovn/kube-ovn/test/e2e/framework"
	"github.com/kubeovn/kube-ovn/versions"
)

const (
	namespace     = "ns-e2e"
	vpc           = "vpc-e2e"
	subnet        = "subnet-e2e"
	vpcNatGateway = "gateway-e2e"

	subnetCIDR            = "10.20.0.0/24"
	lanIP                 = "10.20.0.100"
	externalIP1           = "172.20.0.101"
	externalIP2           = "172.20.0.102"
	externalGateway       = "172.20.0.1"
	externalNetworkPrefix = 24
	routeTable            = 100
)

func TestE2e(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kube-OVN VPC NAT Gateway E2E Suite")
}

var _ = SynchronizedAfterSuite(func() {}, func() {
	f := framework.NewFramework("init", fmt.Sprintf("%s/.kube/config", os.Getenv("HOME")))
	err := f.OvnClientSet.KubeovnV1().VpcNatGateways().Delete(context.Background(), vpcNatGateway, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		Fail(err.Error())
	}
	err = f.OvnClientSet.KubeovnV1().Subnets().Delete(context.Background(), subnet, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		Fail(err.Error())
	}
	err = f.OvnClientSet.KubeovnV1().Vpcs().Delete(context.Background(), vpc, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		Fail(err.Error())
	}
	err = f.KubeClientSet.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		Fail(err.Error())
	}
	err = f.KubeClientSet.CoreV1().ConfigMaps("kube-system").Delete(context.Background(), util.VpcNatGatewayConfig, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		Fail(err.Error())
	}
})

var _ = SynchronizedBeforeSuite(func() []byte {
	f := framework.NewFramework("init", fmt.Sprintf("%s/.kube/config", os.Getenv("HOME")))
	_, err := f.KubeClientSet.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   namespace,
			Labels: map[string]string{"e2e": "true"}}}, metav1.CreateOptions{})
	if err != nil {
		Fail(err.Error())
	}

	_, err = f.OvnClientSet.KubeovnV1().Vpcs().Create(context.Background(), &kubeovnv1.Vpc{
		ObjectMeta: metav1.ObjectMeta{
			Name:   vpc,
			Labels: map[string]string{"e2e": "true"},
		},
		Spec: kubeovnv1.VpcSpec{
			StaticRoutes: []*kubeovnv1.StaticRoute{
				{
					Policy:    kubeovnv1.PolicyDst,
					CIDR:      "0.0.0.0/0",
					NextHopIP: lanIP,
				},
			},
			Namespaces: []string{namespace},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		Fail(err.Error())
	}

	_, err = f.OvnClientSet.KubeovnV1().Subnets().Create(context.Background(), &kubeovnv1.Subnet{
		ObjectMeta: metav1.ObjectMeta{
			Name:   subnet,
			Labels: map[string]string{"e2e": "true"},
		},
		Spec: kubeovnv1.SubnetSpec{
			Vpc:        vpc,
			CIDRBlock:  subnetCIDR,
			Namespaces: []string{namespace},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		Fail(err.Error())
	}
	err = f.WaitSubnetReady(subnet)
	if err != nil {
		Fail(err.Error())
	}

	cm := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:   util.VpcNatGatewayConfig,
			Labels: map[string]string{"e2e": "true"},
		},
		Data: map[string]string{
			"image":             fmt.Sprintf("kubeovn/vpc-nat-gateway:%s", versions.VERSION),
			"enable-vpc-nat-gw": "true",
			"nic":               "eth1",
		},
	}
	_, err = f.KubeClientSet.CoreV1().ConfigMaps("kube-system").Create(context.Background(), &cm, metav1.CreateOptions{})
	if err != nil {
		Fail(err.Error())
	}

	gw := kubeovnv1.VpcNatGateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:   vpcNatGateway,
			Labels: map[string]string{"e2e": "true"},
		},
		Spec: kubeovnv1.VpcNatSpec{
			Vpc:    vpc,
			Subnet: subnet,
			LanIp:  lanIP,
			Eips: []*kubeovnv1.Eip{
				{
					EipCIDR: fmt.Sprintf("%s/%d", externalIP1, externalNetworkPrefix),
					Gateway: externalGateway,
				},
				{
					EipCIDR: fmt.Sprintf("%s/%d", externalIP2, externalNetworkPrefix),
					Gateway: externalGateway,
				},
			},
		},
	}
	_, err = f.OvnClientSet.KubeovnV1().VpcNatGateways().Create(context.Background(), &gw, metav1.CreateOptions{})
	if err != nil {
		Fail(err.Error())
	}

	count, timeout := 0, 90
	deploy := fmt.Sprintf("vpc-nat-gw-%s", vpcNatGateway)
	for {
		time.Sleep(time.Second)
		_, err := f.KubeClientSet.AppsV1().Deployments("kube-system").Get(context.Background(), deploy, metav1.GetOptions{})
		if err == nil {
			break
		}
		if !k8serrors.IsNotFound(err) {
			Fail(err.Error())
		}
		if count++; count == timeout {
			Fail(fmt.Sprintf("vpc-nat-gateway is not created after %d seconds", timeout))
		}
	}
	if err = f.WaitDeploymentReady(deploy, "kube-system"); err != nil {
		Fail(err.Error())
	}

	return nil
}, func(data []byte) {})

var _ = Describe("[normal]", func() {
	f := framework.NewFramework("normal", fmt.Sprintf("%s/.kube/config", os.Getenv("HOME")))

	It("normal", func() {
		deploy := fmt.Sprintf("vpc-nat-gw-%s", vpcNatGateway)
		pods, err := f.KubeClientSet.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{LabelSelector: fmt.Sprintf("app=%s", deploy)})
		Expect(err).NotTo(HaveOccurred())
		Expect(pods.Items).To(HaveLen(1))

		gwPod := &pods.Items[0]
		klog.Infof("Pod: %s/%s, %s", gwPod.Namespace, gwPod.Name, gwPod.Status.Phase)
		{
			stdout, _, err := f.ExecToPodThroughAPI("ip rule show", gwPod.Spec.Containers[0].Name, gwPod.Name, gwPod.Namespace, nil)
			Expect(err).NotTo(HaveOccurred())
			klog.Info(stdout)
		}
		stdout, _, err := f.ExecToPodThroughAPI(fmt.Sprintf("ip route show table %d", routeTable), gwPod.Spec.Containers[0].Name, gwPod.Name, gwPod.Namespace, nil)
		Expect(err).NotTo(HaveOccurred())
		var eth0Route, net1Route, defaultRoute bool
		net1CIDR := (&net.IPNet{IP: net.ParseIP(externalIP1), Mask: net.CIDRMask(externalNetworkPrefix, 32)}).String()
		for _, s := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(s, subnetCIDR) {
				Expect(s).To(ContainSubstring("dev eth0"))
				eth0Route = true
			} else if strings.HasPrefix(s, net1CIDR) {
				Expect(s).To(ContainSubstring("dev net1"))
				net1Route = true
			} else if strings.HasPrefix(s, "default") {
				Expect(s).To(ContainSubstring(fmt.Sprintf("via %s", externalGateway)))
				defaultRoute = true
			}
		}
		Expect(eth0Route).To(BeTrue())
		Expect(net1Route).To(BeTrue())
		Expect(defaultRoute).To(BeTrue())
	})
})
