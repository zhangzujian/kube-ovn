package controller

import (
	"context"
	"crypto/x509"
	"os"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubeovn/kube-ovn/pkg/ipsec"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

type ipsecIdentityError struct{ message string }

func (e *ipsecIdentityError) Error() string { return e.message }

func rejectIPsecIdentity(message string) error { return &ipsecIdentityError{message: message} }

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Validate server-populated authentication fields, not the request's mutable
// labels or its name. A shared service account alone does not identify a node.
func (c *Controller) validateIPsecRequester(csr *certv1.CertificateSigningRequest, req *x509.CertificateRequest) error {
	namespace := os.Getenv(util.EnvPodNamespace)
	if csr.Spec.Username != "system:serviceaccount:"+namespace+":kube-ovn-cni" {
		return rejectIPsecIdentity("unexpected IPsec requester service account")
	}
	name, uid := csr.Spec.Extra["authentication.kubernetes.io/pod-name"], csr.Spec.Extra["authentication.kubernetes.io/pod-uid"]
	if len(name) != 1 || len(uid) != 1 {
		return rejectIPsecIdentity("IPsec requester needs a bound Pod identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pod, err := c.config.KubeClient.CoreV1().Pods(namespace).Get(ctx, name[0], metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(pod.UID) != uid[0] || pod.Spec.ServiceAccountName != "kube-ovn-cni" || pod.DeletionTimestamp != nil {
		return rejectIPsecIdentity("IPsec requester Pod identity is no longer valid")
	}
	owned := false
	for _, owner := range pod.OwnerReferences {
		if owner.APIVersion == "apps/v1" && owner.Kind == "DaemonSet" && owner.Name == "kube-ovn-cni" && owner.Controller != nil && *owner.Controller {
			ds, err := c.config.KubeClient.AppsV1().DaemonSets(namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			owned = ds.UID == owner.UID
		}
	}
	if !owned || pod.Spec.NodeName == "" {
		return rejectIPsecIdentity("IPsec requester is not a live CNI DaemonSet Pod")
	}
	node, err := c.config.KubeClient.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if csr.Annotations[ipsec.NodeNameAnnotation] != "" && (csr.Annotations[ipsec.NodeNameAnnotation] != node.Name || csr.Annotations[ipsec.NodeUIDAnnotation] != string(node.UID)) {
		return rejectIPsecIdentity("IPsec request Node UID does not match bound Pod")
	}
	if err := ipsec.ValidateRequestProfile(req, node.Annotations[util.ChassisAnnotation]); err != nil {
		return rejectIPsecIdentity(err.Error())
	}
	return nil
}
