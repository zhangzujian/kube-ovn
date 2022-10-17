package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/kubeovn/kube-ovn/pkg/util"
)

func (c *Controller) enqueueAddService(obj interface{}) {

	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.updateEndpointQueue.Add(key)
	svc := obj.(*v1.Service)

	if c.config.EnableNP {
		var netpols []string
		if netpols, err = c.svcMatchNetworkPolicies(svc); err != nil {
			utilruntime.HandleError(err)
			return
		}

		for _, np := range netpols {
			c.updateNpQueue.Add(np)
		}
	}

	if c.config.EnableLbSvc {
		klog.V(3).Infof("enqueue add service %s", key)
		c.addServiceQueue.Add(key)
	}
}

func (c *Controller) enqueueDeleteService(obj interface{}) {
	svc := obj.(*v1.Service)

	klog.Infof("enqueue delete service %s/%s", svc.Namespace, svc.Name)

	_, ok := svc.Annotations[util.SwitchLBRuleVipsAnnotation]
	if ok || svc.Spec.ClusterIP != v1.ClusterIPNone && svc.Spec.ClusterIP != "" {
		if c.config.EnableNP {
			var netpols []string
			var err error
			if netpols, err = c.svcMatchNetworkPolicies(svc); err != nil {
				utilruntime.HandleError(err)
				return
			}

			for _, np := range netpols {
				c.updateNpQueue.Add(np)
			}
		}

		c.deleteServiceQueue.Add(obj)
	}
}

func (c *Controller) enqueueUpdateService(old, new interface{}) {
	oldSvc := old.(*v1.Service)
	newSvc := new.(*v1.Service)
	if oldSvc.ResourceVersion == newSvc.ResourceVersion {
		return
	}

	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(new); err != nil {
		utilruntime.HandleError(err)
		return
	}
	klog.V(3).Infof("enqueue update service %s", key)
	c.updateServiceQueue.Add(key)
}

func (c *Controller) runAddServiceWorker() {
	for c.processNextAddServiceWorkItem() {
	}
}

func (c *Controller) runDeleteServiceWorker() {
	for c.processNextDeleteServiceWorkItem() {
	}
}

func (c *Controller) runUpdateServiceWorker() {
	for c.processNextUpdateServiceWorkItem() {
	}
}

func (c *Controller) processNextAddServiceWorkItem() bool {
	obj, shutdown := c.addServiceQueue.Get()
	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.addServiceQueue.Done(obj)
		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			c.addServiceQueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		if err := c.handleAddService(key); err != nil {
			c.addServiceQueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		c.addServiceQueue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}
	return true
}

func (c *Controller) processNextDeleteServiceWorkItem() bool {
	obj, shutdown := c.deleteServiceQueue.Get()
	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.deleteServiceQueue.Done(obj)

		var service *corev1.Service
		var ok bool
		if service, ok = obj.(*corev1.Service); !ok {
			c.deletePodQueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected service in workqueue but got %#v", obj))
			return nil
		}

		if err := c.handleDeleteService(service); err != nil {
			c.deleteServiceQueue.AddRateLimited(obj)
			return fmt.Errorf("error syncing '%s/%s': %s, requeuing", service.Namespace, service.Name, err.Error())
		}

		c.deleteServiceQueue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}
	return true
}

func (c *Controller) processNextUpdateServiceWorkItem() bool {
	obj, shutdown := c.updateServiceQueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.updateServiceQueue.Done(obj)
		var key string
		var ok bool

		if key, ok = obj.(string); !ok {
			c.updateServiceQueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		if err := c.handleUpdateService(key); err != nil {
			c.updateServiceQueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}

		c.updateServiceQueue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}
	return true
}

func (c *Controller) handleDeleteService(service *corev1.Service) error {
	klog.Infof("delete svc %s/%s", service.Namespace, service.Name)

	serviceVips := getServiceVips(service)
	serviceTcpVips, serviceUdpVips := serviceVips[tcpVipsKey], serviceVips[udpVipsKey]

	vpcLbs := c.GenVpcLoadBalancer(service.Annotations[util.VpcAnnotation])
	tcpLbName, udpLbName := vpcLbs.TcpLoadBalancer, vpcLbs.UdpLoadBalancer
	if service.Spec.SessionAffinity == v1.ServiceAffinityClientIP {
		tcpLbName, udpLbName = vpcLbs.TcpSessLoadBalancer, vpcLbs.UdpSessLoadBalancer
	}

	// delete vips from tcp lb
	klog.Infof("remove vip %v from tcp lb %s", serviceTcpVips, tcpLbName)
	if err := c.ovnClient.LoadBalancerDeleteVips(tcpLbName, serviceTcpVips); err != nil {
		klog.Errorf("delete vips from tcp lb %s: %v", tcpLbName, err)
		return err
	}

	// delete vips from udp lb
	klog.Infof("remove vip %v from udp lb %s", serviceUdpVips, udpLbName)
	if err := c.ovnClient.LoadBalancerDeleteVips(udpLbName, serviceUdpVips); err != nil {
		klog.Errorf("delete vips from udp lb %s: %v", udpLbName, err)
		return err
	}

	if service.Spec.Type == v1.ServiceTypeLoadBalancer && c.config.EnableLbSvc {
		if err := c.deleteLbSvc(service); err != nil {
			klog.Errorf("delete service %s, %v", service.Name, err)
			return err
		}
	}

	return nil
}

func (c *Controller) handleUpdateService(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	klog.Infof("update svc %s/%s", namespace, name)

	svc, err := c.servicesLister.Services(namespace).Get(name)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	serviceVips := getServiceVips(svc)
	serviceTcpVips, serviceUdpVips := serviceVips[tcpVipsKey], serviceVips[udpVipsKey]

	// get lbs name
	vpcLbs := c.GenVpcLoadBalancer(svc.Annotations[util.VpcAnnotation])
	tcpLbName, udpLbName := vpcLbs.TcpLoadBalancer, vpcLbs.UdpLoadBalancer
	oldTcpLbName, oldUdpLbName := vpcLbs.TcpSessLoadBalancer, vpcLbs.UdpSessLoadBalancer
	if svc.Spec.SessionAffinity == v1.ServiceAffinityClientIP {
		tcpLbName, udpLbName = vpcLbs.TcpSessLoadBalancer, vpcLbs.UdpSessLoadBalancer
		oldTcpLbName, oldUdpLbName = vpcLbs.TcpLoadBalancer, vpcLbs.UdpLoadBalancer
	}

	/* handle event which servie.spec.sessionAffinity change */
	// delete vips from old tcp lb
	klog.V(6).Infof("remove vip %v from old tcp lb %s", serviceTcpVips, oldTcpLbName)
	if err := c.ovnClient.LoadBalancerDeleteVips(oldTcpLbName, serviceTcpVips); err != nil {
		klog.Errorf("delete vips from old tcp lb %s: %v", oldTcpLbName, err)
		return err
	}

	// delete vips from old udp lb
	klog.V(6).Infof("remove vip %v from old udp lb %s", serviceUdpVips, oldUdpLbName)
	if err := c.ovnClient.LoadBalancerDeleteVips(oldUdpLbName, serviceUdpVips); err != nil {
		klog.Errorf("delete vips from old udp lb %s: %v", oldUdpLbName, err)
		return err
	}

	/* handle event which servie.spec.ports[x].port change */
	if err := c.handleServicePorts(tcpLbName, serviceTcpVips); err != nil {
		klog.Errorf("handle service port change: %v", oldTcpLbName, err)
		return err
	}

	if err := c.handleServicePorts(udpLbName, serviceUdpVips); err != nil {
		klog.Errorf("handle service port change: %v", oldTcpLbName, err)
		return err
	}

	c.updateEndpointQueue.Add(key)

	return nil
}

// The type of vips is map, which format is like [fd00:10:96::11c9]:10665:[fc00:f853:ccd:e793::2]:10665,[fc00:f853:ccd:e793::3]:10665
// Parse key of map, [fd00:10:96::11c9]:10665 for example
func parseVipAddr(vipStr string) string {
	vip := strings.Split(vipStr, ":")[0]
	if strings.ContainsAny(vipStr, "[]") {
		vip = strings.Trim(strings.Split(vipStr, "]")[0], "[]")
	}
	return vip
}

// handleServicePorts handle event which servie.spec.ports[x].port change
func (c *Controller) handleServicePorts(lbName string, serviceVips map[string]struct{}) error {
	/*
		the format of vip in lb is: ip:port, delete vip with same ip but different port from present tcp lb,
		e.g. update servie.spec.ports[x].port
	*/
	lb, err := c.ovnClient.GetLoadBalancer(lbName, false)
	if err != nil {
		klog.Errorf("get lb %s: %v", lbName, err)
		return err
	}

	klog.V(3).Infof("exist tcp lb vips are %v", lb.Vips)

	deleteVips := make(map[string]struct{}, 0)

	for lbVip := range lb.Vips {
		for serviceVip := range serviceVips {
			if lbVip == serviceVip {
				continue // no need to delete when lbVip and serviceVip is selfsame
			}

			if parseVipAddr(lbVip) != parseVipAddr(serviceVip) {
				continue // skip lbVip and serviceVip has different ip
			}

			// lbVip and serviceVip has the same ip but different port
			deleteVips[lbVip] = struct{}{}
		}
	}

	if len(deleteVips) == 0 {
		return nil
	}

	klog.Infof("remove stall vip %v from lb %s", deleteVips, lbName)

	if err := c.ovnClient.LoadBalancerDeleteVips(lbName, deleteVips); err != nil {
		klog.Errorf("remove stall vip %v from lb %s: %v", deleteVips, lbName, err)
		return err
	}

	return nil
}

// getServicesVips get services vips,
// return a map with key is tcpVipsKey,udpVipsKey,tcpSessionVipsKey,udpSessionVipsKey and
// value is map which key is vip
func (c *Controller) getServicesVips() (map[string]map[string]struct{}, error) {
	svcs, err := c.servicesLister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("list services: %v", err)
	}

	vips := make(map[string]map[string]struct{})
	vips[tcpVipsKey] = make(map[string]struct{})
	vips[udpVipsKey] = make(map[string]struct{})
	vips[tcpSessionVipsKey] = make(map[string]struct{})
	vips[udpSessionVipsKey] = make(map[string]struct{})

	getServiceVips := func(svc *corev1.Service) {
		clusterIPs := svc.Spec.ClusterIPs

		if len(clusterIPs) == 0 && len(svc.Spec.ClusterIP) != 0 && svc.Spec.ClusterIP != v1.ClusterIPNone {
			clusterIPs = []string{svc.Spec.ClusterIP}
		}

		if len(clusterIPs) == 0 || clusterIPs[0] == v1.ClusterIPNone {
			return
		}

		for _, clusterIP := range clusterIPs {
			for _, port := range svc.Spec.Ports {
				vip := util.JoinHostPort(clusterIP, port.Port)

				if port.Protocol == corev1.ProtocolTCP {
					if svc.Spec.SessionAffinity == corev1.ServiceAffinityClientIP {
						vips[tcpSessionVipsKey][vip] = struct{}{}
					} else {
						vips[tcpVipsKey][vip] = struct{}{}
					}
				} else {
					if svc.Spec.SessionAffinity == corev1.ServiceAffinityClientIP {
						vips[udpSessionVipsKey][vip] = struct{}{}
					} else {
						vips[udpVipsKey][vip] = struct{}{}
					}
				}
			}
		}
	}

	for _, svc := range svcs {
		getServiceVips(svc)
	}

	return vips, nil
}

// getServiceVips get service vips,
// return a map with key is tcpVipsKey,udpVipsKey and
// value is map which key is vip
func getServiceVips(svc *corev1.Service) map[string]map[string]struct{} {
	vips := make(map[string]map[string]struct{})
	vips[tcpVipsKey] = make(map[string]struct{})
	vips[udpVipsKey] = make(map[string]struct{})

	var clusterIPs []string
	if vip, ok := svc.Annotations[util.SwitchLBRuleVipsAnnotation]; ok {
		clusterIPs = append(clusterIPs, vip)
	} else {
		clusterIPs = svc.Spec.ClusterIPs
	}

	if len(clusterIPs) == 0 && len(svc.Spec.ClusterIP) != 0 && svc.Spec.ClusterIP != v1.ClusterIPNone {
		clusterIPs = []string{svc.Spec.ClusterIP}
	}

	if len(clusterIPs) == 0 || clusterIPs[0] == v1.ClusterIPNone {
		return nil
	}

	for _, clusterIP := range clusterIPs {
		for _, port := range svc.Spec.Ports {
			vip := util.JoinHostPort(clusterIP, port.Port)

			if port.Protocol == corev1.ProtocolTCP {
				vips[tcpVipsKey][vip] = struct{}{}
			} else {
				vips[udpVipsKey][vip] = struct{}{}
			}
		}
	}

	return vips
}

func (c *Controller) handleAddService(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	svc, err := c.servicesLister.Services(namespace).Get(name)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if svc.Spec.Type != v1.ServiceTypeLoadBalancer || !c.config.EnableLbSvc {
		return nil
	}
	klog.Infof("add svc %s/%s", namespace, name)

	if err = c.validateSvc(svc); err != nil {
		klog.Errorf("failed to validate lb svc, %v", err)
		return err
	}

	if err = c.checkAttachNetwork(svc); err != nil {
		klog.Errorf("failed to check attachment network, %v", err)
		return err
	}

	if err = c.createLbSvcPod(svc); err != nil {
		klog.Errorf("failed to create lb svc pod, %v", err)
		return err
	}

	var pod *v1.Pod
	for {
		pod, err = c.getLbSvcPod(name, namespace)
		if err != nil {
			klog.Errorf("wait lb svc pod to running, %v", err)
			time.Sleep(1 * time.Second)
		}
		if pod != nil {
			break
		}

		// It's important here to check existing of svc, used to break the loop.
		_, err = c.servicesLister.Services(namespace).Get(name)
		if err != nil {
			if k8serrors.IsNotFound(err) {
				return nil
			}
			return err
		}
	}

	loadBalancerIP, err := c.getPodAttachIP(pod, svc)
	if err != nil {
		klog.Errorf("failed to get loadBalancerIP: %v", err)
		return err
	}

	newSvc, err := c.servicesLister.Services(namespace).Get(name)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	var ingress v1.LoadBalancerIngress
	ingress.IP = loadBalancerIP
	newSvc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{ingress}

	var updateSvc *v1.Service
	if updateSvc, err = c.config.KubeClient.CoreV1().Services(namespace).UpdateStatus(context.Background(), newSvc, metav1.UpdateOptions{}); err != nil {
		klog.Errorf("update service %s/%s status failed: %v", namespace, name, err)
		return err
	}

	if err := c.updatePodAttachNets(pod, updateSvc); err != nil {
		klog.Errorf("update service %s/%s attachment network failed: %v", namespace, name, err)
		return err
	}

	return nil
}
