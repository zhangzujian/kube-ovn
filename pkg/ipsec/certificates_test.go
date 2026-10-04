package ipsec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testIdentity(t *testing.T, chassis string) (cert, key, trust []byte) {
	t.Helper()
	key, err := newPrivateKey()
	require.NoError(t, err)
	parsed, err := privateKey(key)
	require.NoError(t, err)
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	trust = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	ca, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: chassis}, DNSNames: []string{chassis}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &parsed.PublicKey, caKey)
	require.NoError(t, err)
	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, trust
}

func TestValidateIdentityBeforeActivation(t *testing.T) {
	cert, key, trust := testIdentity(t, "chassis-a")
	_, err := validateIdentity(cert, key, trust, "chassis-a", time.Now())
	require.NoError(t, err)
	_, err = validateIdentity(cert, key, trust, "chassis-b", time.Now())
	require.ErrorContains(t, err, "chassis identity")
	otherKey, err := newPrivateKey()
	require.NoError(t, err)
	_, err = validateIdentity(cert, otherKey, trust, "chassis-a", time.Now())
	require.ErrorContains(t, err, "does not match the private key")
	_, err = validateIdentity(cert, key, trust, "chassis-a", time.Now().Add(2*time.Hour))
	require.Error(t, err)
	_, _, otherTrust := testIdentity(t, "chassis-a")
	_, err = validateIdentity(cert, key, otherTrust, "chassis-a", time.Now())
	require.Error(t, err)
}

func TestTrustRejectsPartialAndEmptyBundles(t *testing.T) {
	_, _, trust := testIdentity(t, "chassis")
	for _, invalid := range [][]byte{nil, []byte("invalid"), append(append([]byte{}, trust...), []byte("invalid tail")...), append(append([]byte{}, trust...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})...)} {
		_, err := Certificates(invalid)
		require.Error(t, err)
	}
	_, err := Certificates(append([]byte("discarded prefix\n"), trust...))
	require.Error(t, err)
}

func TestLegacyIdentityIsImportedWithoutReissuing(t *testing.T) {
	cert, key, trust := testIdentity(t, "chassis")
	s := store{dir: t.TempDir()}
	keyPath := filepath.Join(s.dir, "ipsec-privkey-123.pem")
	certPath := filepath.Join(s.dir, "ipsec-cert-123.pem")
	require.NoError(t, os.WriteFile(keyPath, key, 0o600))
	require.NoError(t, os.WriteFile(certPath, cert, 0o600))
	paths := map[string]string{"private_key": keyPath, "certificate": certPath}
	require.NoError(t, s.importLegacy("node-uid", "chassis", trust, paths))
	g, err := s.load("pending")
	require.NoError(t, err)
	require.NotNil(t, g)
	imported, err := s.read(g, "private-key")
	require.NoError(t, err)
	require.Equal(t, key, imported)
	imported, err = s.read(g, "certificate")
	require.NoError(t, err)
	require.Equal(t, cert, imported)
	require.FileExists(t, keyPath)
	require.FileExists(t, certPath)
	require.NoError(t, s.importLegacy("node-uid", "chassis", trust, paths))

	outside := store{dir: t.TempDir()}
	require.ErrorContains(t, outside.importLegacy("node-uid", "chassis", trust, paths), "outside the legacy key layout")
}

func TestStoreRejectsSymlinks(t *testing.T) {
	for _, entry := range []string{"owner.lock", "current.json", "generations"} {
		t.Run(entry, func(t *testing.T) {
			s := store{dir: t.TempDir()}
			target := filepath.Join(t.TempDir(), "target")
			require.NoError(t, os.WriteFile(target, []byte("unrelated data"), 0o600))
			require.NoError(t, os.Symlink(target, filepath.Join(s.dir, entry)))
			switch entry {
			case "owner.lock":
				_, err := s.lock()
				require.Error(t, err)
			case "current.json":
				_, err := s.load("current")
				require.Error(t, err)
			case "generations":
				_, _, err := s.pending("uid", "chassis")
				require.Error(t, err)
			}
			data, err := os.ReadFile(target)
			require.NoError(t, err)
			require.Equal(t, "unrelated data", string(data))
		})
	}
}

func TestPendingSurvivesRestartAndNodeRecreation(t *testing.T) {
	dir := t.TempDir()
	s := store{dir: dir}
	lock, err := s.lock()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lock.Close()) })
	_, err = s.lock()
	require.ErrorContains(t, err, "another IPsec owner")
	g, key, err := s.pending("node-uid-a", "chassis")
	require.NoError(t, err)
	restarted := store{dir: dir}
	g2, key2, err := restarted.pending("node-uid-a", "chassis")
	require.NoError(t, err)
	require.Equal(t, g, g2)
	require.Equal(t, key, key2)
	g3, key3, err := restarted.pending("node-uid-b", "chassis")
	require.NoError(t, err)
	require.NotEqual(t, g.ID, g3.ID)
	require.NotEqual(t, key, key3)
	info, err := os.Stat(s.path(g, "private-key"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.NoError(t, os.WriteFile(filepath.Join(dir, "current.json"), []byte(`{"id":"../../outside"}`), 0o600))
	_, err = s.load("current")
	require.Error(t, err)
}

func TestCSRUsesThePersistedPrivateKeyAndSingleIdentity(t *testing.T) {
	key, err := newPrivateKey()
	require.NoError(t, err)
	csr, err := newCSR(key, "chassis-a")
	require.NoError(t, err)
	block, _ := pem.Decode(csr)
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, parsed.CheckSignature())
	require.Equal(t, "chassis-a", parsed.Subject.CommonName)
	require.Equal(t, []string{"chassis-a"}, parsed.DNSNames)
	parsedKey, err := privateKey(key)
	require.NoError(t, err)
	require.True(t, parsed.PublicKey.(*rsa.PublicKey).Equal(&parsedKey.PublicKey))
	csr2, err := newCSR(key, "chassis-a")
	require.NoError(t, err)
	require.Equal(t, requestName("uid-a", csr), requestName("uid-a", csr2))
	require.NotEqual(t, requestName("uid-a", csr), requestName("uid-b", csr))
}
