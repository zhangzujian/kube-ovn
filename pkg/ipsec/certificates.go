package ipsec

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Certificates parses the entire bundle. Invalid blocks must not silently
// replace an already working trust configuration with a partial bundle.
func Certificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(data)) != 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("unexpected data in certificate PEM bundle")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate PEM bundle")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
		data = rest
	}
	if len(certs) == 0 {
		return nil, errors.New("empty certificate bundle")
	}
	return certs, nil
}

func privateKey(data []byte) (*rsa.PrivateKey, error) {
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN RSA PRIVATE KEY-----")) && !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, errors.New("unexpected data in private key PEM")
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private key PEM")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		var err error
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		if key, ok = parsed.(*rsa.PrivateKey); !ok {
			return nil, errors.New("IPsec requires an RSA private key")
		}
	default:
		return nil, errors.New("unsupported private key format")
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("IPsec RSA key must be at least 2048 bits")
	}
	return key, key.Validate()
}

func newPrivateKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func newCSR(keyPEM []byte, chassis string) ([]byte, error) {
	key, err := privateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: chassis, Country: []string{"CN"}, Organization: []string{"kubeovn"}, OrganizationalUnit: []string{"kube-ovn"}},
		DNSNames: []string{chassis},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func validateIdentity(certPEM, keyPEM, trustPEM []byte, chassis string, now time.Time) (*x509.Certificate, error) {
	certs, err := Certificates(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := privateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	leaf := certs[0]
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("certificate does not match the private key")
	}
	if leaf.IsCA || leaf.Subject.CommonName != chassis || !slices.Equal(leaf.DNSNames, []string{chassis}) || len(leaf.IPAddresses)+len(leaf.URIs)+len(leaf.EmailAddresses) != 0 {
		return nil, errors.New("certificate does not match the IPsec chassis identity")
	}
	trust, err := Certificates(trustPEM)
	if err != nil {
		return nil, err
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, ca := range trust {
		if !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("trust bundle contains a non-CA certificate")
		}
		roots.AddCert(ca)
	}
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("verify IPsec identity: %w", err)
	}
	return leaf, nil
}
