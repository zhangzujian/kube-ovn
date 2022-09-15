package controller

import (
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
)

func Test_handleServicePorts(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	mockOvnClient := fakeController.mockOvnClient
	lbName := "svc-update-port"

	lb := &ovnnb.LoadBalancer{
		Name: lbName,
		Vips: map[string]string{
			"10.100.185.113:10660":    "192.168.20.4:10660",
			"10.96.0.10:53":           "10.244.0.7:53,10.244.0.8:53",
			"10.96.0.100:53":          "10.244.0.99:53,10.244.0.100:53",
			"[fd00:10:96::8f0b]:8080": "[fc00::af4:11]:8080",
		},
	}

	t.Run("lb vips has the same ip but different port", func(t *testing.T) {
		servicVips := map[string]struct{}{
			"10.96.0.100:153":          {},
			"[fd00:10:96::8f0b]:18080": {},
		}

		mockOvnClient.EXPECT().GetLoadBalancer(lbName, false).Return(lb, nil)

		mockOvnClient.EXPECT().LoadBalancerDeleteVips(lb.Name, map[string]struct{}{
			"10.96.0.100:53":          {},
			"[fd00:10:96::8f0b]:8080": {},
		}).Return(nil)

		err := ctrl.handleServicePorts(lbName, servicVips)
		require.NoError(t, err)
	})

	t.Run("lb vips has the same ip and port", func(t *testing.T) {
		servicVips := map[string]struct{}{
			"10.96.0.100:53":          {},
			"[fd00:10:96::8f0b]:8080": {},
		}

		mockOvnClient.EXPECT().GetLoadBalancer(lbName, false).Return(lb, nil)

		err := ctrl.handleServicePorts(lbName, servicVips)
		require.NoError(t, err)
	})
}

func Test_getServicesVips(t *testing.T) {
	t.Parallel()

	fakeController := newFakeController(t)
	ctrl := fakeController.fakeController
	fakeinformers := fakeController.fakeinformers

	v4TcpSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "get-svcs-vips-v4-tcp",
			Namespace: "default",
		},

		Spec: corev1.ServiceSpec{
			ClusterIP: "10.100.185.113",
			Ports: []corev1.ServicePort{
				{
					Protocol: corev1.ProtocolTCP,
					Port:     9090,
				},
			},
		},
	}

	v4UdpSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "get-svcs-vips-v4-udp",
			Namespace: "default",
		},

		Spec: corev1.ServiceSpec{
			ClusterIP: "10.100.200.113",
			Ports: []corev1.ServicePort{
				{
					Protocol: corev1.ProtocolUDP,
					Port:     9090,
				},
			},
		},
	}

	dualSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "get-svcs-vips-dual",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.110.148.150",
			ClusterIPs: []string{
				"10.110.148.150",
				"fd00:10:96::5ff8",
			},
			Ports: []corev1.ServicePort{
				{
					Protocol: corev1.ProtocolUDP,
					Port:     8080,
				},
				{
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
				},
			},
		},
	}

	err := fakeinformers.serviceInformer.Informer().GetStore().Add(v4TcpSvc)
	require.NoError(t, err)
	err = fakeinformers.serviceInformer.Informer().GetStore().Add(v4UdpSvc)
	require.NoError(t, err)
	err = fakeinformers.serviceInformer.Informer().GetStore().Add(dualSvc)
	require.NoError(t, err)

	vips, err := ctrl.getServicesVips()
	require.NoError(t, err)

	serviceTcpVips, serviceUdpVips, serviceTcpSessionVips, serviceUdpSessionVips := vips[tcpVipsKey], vips[udpVipsKey], vips[tcpSessionVipsKey], vips[udpSessionVipsKey]
	require.Equal(t, map[string]struct{}{
		"10.100.185.113:9090":     {},
		"10.110.148.150:8080":     {},
		"[fd00:10:96::5ff8]:8080": {},
	}, serviceTcpVips)
	require.Equal(t, map[string]struct{}{
		"10.100.200.113:9090":     {},
		"10.110.148.150:8080":     {},
		"[fd00:10:96::5ff8]:8080": {},
	}, serviceUdpVips)
	require.Empty(t, serviceTcpSessionVips)
	require.Empty(t, serviceUdpSessionVips)
}

func Test_getServiceVips(t *testing.T) {
	t.Parallel()

	tests := []struct {
		desc     string
		service  *corev1.Service
		wantVips map[string]map[string]struct{}
	}{
		{
			"ipv4",
			&corev1.Service{
				Spec: corev1.ServiceSpec{
					ClusterIP: "10.110.148.150",
					Ports: []corev1.ServicePort{
						{
							Protocol: corev1.ProtocolTCP,
							Port:     8080,
						},
					},
				},
			},
			map[string]map[string]struct{}{
				tcpVipsKey: {
					"10.110.148.150:8080": {},
				},
				udpVipsKey: {},
			},
		},
		{
			"dual stack",
			&corev1.Service{
				Spec: corev1.ServiceSpec{
					ClusterIP: "10.110.148.150",
					ClusterIPs: []string{
						"10.110.148.150",
						"fd00:10:96::5ff8",
					},
					Ports: []corev1.ServicePort{
						{
							Protocol: corev1.ProtocolTCP,
							Port:     8080,
						},
					},
				},
			},
			map[string]map[string]struct{}{
				tcpVipsKey: {
					"10.110.148.150:8080":     {},
					"[fd00:10:96::5ff8]:8080": {},
				},
				udpVipsKey: {},
			},
		},
		{
			"tcp and udp",
			&corev1.Service{
				Spec: corev1.ServiceSpec{
					ClusterIP: "10.110.148.150",
					ClusterIPs: []string{
						"10.110.148.150",
						"fd00:10:96::5ff8",
					},
					Ports: []corev1.ServicePort{
						{
							Protocol: corev1.ProtocolTCP,
							Port:     8080,
						},
						{
							Protocol: corev1.ProtocolUDP,
							Port:     9090,
						},
					},
				},
			},
			map[string]map[string]struct{}{
				tcpVipsKey: {
					"10.110.148.150:8080":     {},
					"[fd00:10:96::5ff8]:8080": {},
				},
				udpVipsKey: {
					"10.110.148.150:9090":     {},
					"[fd00:10:96::5ff8]:9090": {},
				},
			},
		},
		{
			"no cluster ip",
			&corev1.Service{
				Spec: corev1.ServiceSpec{
					ClusterIP: "None",
					ClusterIPs: []string{
						"None",
					},
					Ports: []corev1.ServicePort{
						{
							Protocol: corev1.ProtocolTCP,
							Port:     8080,
						},
					},
				},
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			gotVips := getServiceVips(tt.service)
			require.Equal(t, tt.wantVips, gotVips)
		})
	}
}
