package controller

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubeovn/kube-ovn/pkg/ipsec"
	"github.com/kubeovn/kube-ovn/pkg/util"
)

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
		return errors.New("unexpected IPsec requester service account")
	}
	name, uid := csr.Spec.Extra["authentication.kubernetes.io/pod-name"], csr.Spec.Extra["authentication.kubernetes.io/pod-uid"]
	if len(name) != 1 || len(uid) != 1 {
		return errors.New("IPsec requester needs a bound Pod identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pod, err := c.config.KubeClient.CoreV1().Pods(namespace).Get(ctx, name[0], metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(pod.UID) != uid[0] || pod.Spec.ServiceAccountName != "kube-ovn-cni" || pod.DeletionTimestamp != nil {
		return errors.New("IPsec requester Pod identity is no longer valid")
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
		return errors.New("IPsec requester is not a live CNI DaemonSet Pod")
	}
	node, err := c.config.KubeClient.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if csr.Annotations[ipsec.NodeNameAnnotation] != "" && (csr.Annotations[ipsec.NodeNameAnnotation] != node.Name || csr.Annotations[ipsec.NodeUIDAnnotation] != string(node.UID)) {
		return errors.New("IPsec request Node UID does not match bound Pod")
	}
	chassis := node.Annotations[util.ChassisAnnotation]
	if chassis == "" || req.Subject.CommonName != chassis || !slices.Equal(req.DNSNames, []string{chassis}) || len(req.IPAddresses)+len(req.URIs)+len(req.EmailAddresses) != 0 {
		return errors.New("IPsec CSR must request only its bound node chassis")
	}
	key, ok := req.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 {
		return fmt.Errorf("IPsec CSR requires an RSA key of at least 2048 bits")
	}
	for _, ext := range req.Extensions {
		// Accept only subjectAltName. Do not copy arbitrary CA or usage extensions.
		if ext.Id.String() != "2.5.29.17" {
			return errors.New("unexpected IPsec CSR extension")
		}
	}
	return nil
}
