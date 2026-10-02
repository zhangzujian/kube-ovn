package controller

import (
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
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
	if err := c.writeCnpEvidence(record); err != nil {
		return err
	}
	c.cnpSession.Store(record)
	return nil
}

// Pod status and API access can be transiently unavailable during startup.
// Recovery must not require another controller restart or stop enforcement.
func (c *Controller) retryCnpEvidence(ctx context.Context) {
	_ = wait.PollUntilContextCancel(ctx, 5*time.Second, false, func(context.Context) (bool, error) {
		if err := c.initCnpEvidence(); err != nil {
			klog.Errorf("CNP upgrade verification is unavailable: %v", err)
			return false, nil
		}
		for _, item := range c.cnpsLister.Indexer.List() {
			c.addCnpQueue.Add(item.(*unstructured.Unstructured).GetName())
		}
		return true, nil
	})
}

// Evidence uses the leader Pod's existing patch permission, including on legacy
// releases with read-only ConfigMap access. One requested receipt slot bounds
// annotation size independently of the number of policies. The upgrade tool
// verifies one nonce at a time and persists object history in its journal.
func (c *Controller) writeCnpEvidence(record *cnp.Receipt) error {
	annotation := cnp.CapabilityAnnotation
	if record.PolicyUID != "" {
		if record.Request == "" {
			return nil
		}
		annotation = cnp.ReceiptAnnotation
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	client := c.config.KubeClient.CoreV1().Pods(c.config.PodNamespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		pod, err := client.Get(c.cnpContext, record.Leader, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if string(pod.UID) != record.PodUID || pod.DeletionTimestamp != nil {
			return errors.New("refusing to publish evidence on a replaced/terminating leader Pod")
		}
		patch, err := json.Marshal(map[string]any{"metadata": map[string]any{
			"uid": string(pod.UID), "resourceVersion": pod.ResourceVersion,
			"annotations": map[string]string{annotation: string(data)},
		}})
		if err != nil {
			return err
		}
		_, err = client.Patch(c.cnpContext, pod.Name, types.MergePatchType, patch, metav1.PatchOptions{})
		return err
	})
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
	session := c.cnpSession.Load()
	if session == nil {
		return nil
	}
	record := *session
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
	previous, found := c.cnpReceipts.Load(policy.Name)
	if record.Request != "" && (!found || previous.Request != record.Request || previous.PolicyUID != record.PolicyUID) {
		if err := c.writeCnpEvidence(&record); err != nil {
			return err
		}
	}
	c.cnpReceipts.Store(policy.Name, &record)
	return nil
}

func (c *Controller) failCnpEvidence(key string, cause error) {
	session := c.cnpSession.Load()
	if session == nil {
		return
	}
	c.cnpReceipts.Delete(key)
	obj, found, err := c.cnpsLister.Indexer.GetByKey(key)
	if err != nil || !found {
		return
	}
	raw := obj.(*unstructured.Unstructured)
	record := *session
	record.PolicyUID, record.Generation, record.Error = string(raw.GetUID()), raw.GetGeneration(), cause.Error()
	record.Request = raw.GetAnnotations()[cnp.VerifyAnnotation]
	if err := c.writeCnpEvidence(&record); err != nil {
		klog.Errorf("failed to record CNP %s application error: %v", key, err)
	}
}
