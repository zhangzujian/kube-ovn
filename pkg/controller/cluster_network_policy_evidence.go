package controller

import (
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
	"sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"github.com/kubeovn/kube-ovn/pkg/cnp"
	"github.com/kubeovn/kube-ovn/pkg/ovsdb/ovnnb"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

func (c *Controller) initCnpEvidence() error {
	pod, err := c.config.KubeClient.CoreV1().Pods(c.config.PodNamespace).Get(c.cnpContext, c.config.PodName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	record := &cnp.Receipt{Capability: cnp.Capability, Leader: pod.Name, PodUID: string(pod.UID), Session: rand.Text()}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == controllerAgentName {
			record.ImageID = status.ImageID
		}
	}
	if !strings.Contains(record.ImageID, "@sha256:") {
		return errors.New("controller imageID is not resolved to a digest")
	}
	if err := c.writeCnpEvidence(cnp.CapabilityName(pod.UID), record, metav1.OwnerReference{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID}); err != nil {
		return err
	}
	c.cnpSession = record
	return nil
}

func (c *Controller) writeCnpEvidence(name string, record *cnp.Receipt, owner metav1.OwnerReference) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	client := c.config.KubeClient.CoreV1().ConfigMaps(c.config.PodNamespace)
	cm, err := client.Get(c.cnpContext, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = client.Create(c.cnpContext, &corev1.ConfigMap{
			Name: name, Labels: map[string]string{"kube-ovn.io/cnp-evidence": "true"}, OwnerReferences: []metav1.OwnerReference{owner},
			Data: map[string]string{"receipt": string(data)},
		}, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if cm.Labels["kube-ovn.io/cnp-evidence"] != "true" || len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].UID != owner.UID {
		return fmt.Errorf("refusing to overwrite unrelated ConfigMap %s", name)
	}
	cm.Data = map[string]string{"receipt": string(data)}
	_, err = client.Update(c.cnpContext, cm, metav1.UpdateOptions{})
	return err
}

func (c *Controller) cnpOVNDigest(policy *v1alpha2.ClusterNetworkPolicy) (string, error) {
	pg, err := c.OVNNbClient.GetPortGroup(getCnpPortGroupName(policy), false)
	if err != nil {
		return "", err
	}
	slices.Sort(pg.Ports)
	slices.Sort(pg.ACLs)
	acls := make([]ovnnb.ACL, 0, len(pg.ACLs))
	for _, id := range pg.ACLs {
		acl := ovnnb.ACL{UUID: id}
		if err := c.OVNNbClient.GetEntityInfo(&acl); err != nil {
			return "", err
		}
		acls = append(acls, acl)
	}
	var addressSets []ovnnb.AddressSet
	for _, direction := range []string{"ingress", "egress"} {
		sets, err := c.OVNNbClient.ListAddressSets(map[string]string{clusterNetworkPolicyKey: getCnpName(policy.Name) + "/" + direction})
		if err != nil {
			return "", err
		}
		for i := range sets {
			slices.Sort(sets[i].Addresses)
		}
		addressSets = append(addressSets, sets...)
	}
	slices.SortFunc(addressSets, func(a, b ovnnb.AddressSet) int { return strings.Compare(a.Name, b.Name) })
	return cnp.MarshalDigest(struct {
		PortGroup   *ovnnb.PortGroup
		ACLs        []ovnnb.ACL
		AddressSets []ovnnb.AddressSet
	}{pg, acls, addressSets})
}

func cnpApplyDigest(policy *v1alpha2.ClusterNetworkPolicy) (string, error) {
	return cnp.MarshalDigest(struct {
		Spec v1alpha2.ClusterNetworkPolicySpec
		Log  string
	}{policy.Spec, policy.Annotations[util.ACLActionsLogAnnotation]})
}

func (c *Controller) reuseCnpEvidence(policy *v1alpha2.ClusterNetworkPolicy) (bool, error) {
	previous, ok := c.cnpReceipts.Load(policy.Name)
	if !ok || previous.PolicyUID != string(policy.UID) {
		return false, nil
	}
	digest, err := cnpApplyDigest(policy)
	if err != nil || digest != previous.ApplyDigest {
		return false, err
	}
	actual, err := c.cnpOVNDigest(policy)
	if err != nil {
		return false, err
	}
	if actual != previous.OVNDigest {
		return false, nil
	}
	return true, c.completeCnpEvidence(policy)
}

func (c *Controller) completeCnpEvidence(policy *v1alpha2.ClusterNetworkPolicy) error {
	if c.cnpSession == nil {
		return nil
	}
	record := *c.cnpSession
	record.PolicyUID, record.Generation = string(policy.UID), policy.Generation
	record.Request = policy.Annotations[cnp.VerifyAnnotation]
	var err error
	if record.SemanticDigest, err = cnp.Digest(policy); err != nil {
		return err
	}
	if record.ApplyDigest, err = cnpApplyDigest(policy); err != nil {
		return err
	}
	if record.OVNDigest, err = c.cnpOVNDigest(policy); err != nil {
		return err
	}
	current, err := c.config.DynamicClient.Resource(cnp.Resource).Get(c.cnpContext, policy.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if current.GetUID() != policy.UID || current.GetGeneration() != policy.Generation || current.GetAnnotations()[cnp.VerifyAnnotation] != record.Request || current.GetAnnotations()[util.ACLActionsLogAnnotation] != policy.Annotations[util.ACLActionsLogAnnotation] {
		return fmt.Errorf("CNP %s changed during application", policy.Name)
	}
	if err := c.writeCnpEvidence(cnp.ReceiptName(policy.UID), &record, metav1.OwnerReference{APIVersion: cnp.Resource.GroupVersion().String(), Kind: "ClusterNetworkPolicy", Name: policy.Name, UID: policy.UID}); err != nil {
		return err
	}
	c.cnpReceipts.Store(policy.Name, &record)
	return nil
}

func (c *Controller) failCnpEvidence(key string, cause error) {
	if c.cnpSession == nil {
		return
	}
	c.cnpReceipts.Delete(key)
	obj, found, err := c.cnpsLister.Indexer.GetByKey(key)
	if err != nil || !found {
		return
	}
	raw := obj.(*unstructured.Unstructured)
	record := *c.cnpSession
	record.PolicyUID, record.Generation, record.Error = string(raw.GetUID()), raw.GetGeneration(), cause.Error()
	if err := c.writeCnpEvidence(cnp.ReceiptName(raw.GetUID()), &record, metav1.OwnerReference{APIVersion: cnp.Resource.GroupVersion().String(), Kind: "ClusterNetworkPolicy", Name: key, UID: raw.GetUID()}); err != nil {
		klog.Errorf("failed to record CNP %s application error: %v", key, err)
	}
}
