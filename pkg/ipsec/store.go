package ipsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/kubeovn/kube-ovn/pkg/fileutil"
)

type generation struct {
	ID      string `json:"id"`
	NodeUID string `json:"nodeUID"`
	Chassis string `json:"chassis"`
}

type store struct {
	dir string
}

func digest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (s store) lock() (*os.File, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(s.dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, "owner.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(fmt.Errorf("another IPsec owner holds the node lock: %w", err), f.Close())
	}
	return f, nil
}

func (s store) load(name string) (*generation, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, name+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var g generation
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, err
	}
	if len(g.ID) != 64 {
		return nil, errors.New("invalid IPsec generation")
	}
	if _, err := hex.DecodeString(g.ID); err != nil {
		return nil, err
	}
	return &g, nil
}

func (s store) save(name string, g *generation) error {
	data, err := json.Marshal(g)
	if err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(filepath.Join(s.dir, name+".json"), data, 0o600)
}

func (s store) path(g *generation, name string) string {
	return filepath.Join(s.dir, "generations", g.ID, name+".pem")
}

func (s store) write(g *generation, name string, data []byte) error {
	path := s.path(g, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(path, data, 0o600)
}

func (s store) read(g *generation, name string) ([]byte, error) {
	return os.ReadFile(s.path(g, name))
}

func (s store) sameIdentity(a, b *generation) bool {
	if a.NodeUID != b.NodeUID || a.Chassis != b.Chassis {
		return false
	}
	for _, name := range []string{"private-key", "certificate"} {
		left, leftErr := s.read(a, name)
		right, rightErr := s.read(b, name)
		if leftErr != nil || rightErr != nil || !bytes.Equal(left, right) {
			return false
		}
	}
	return true
}

// prepareGeneration gives trust updates their own immutable paths. OVSDB can
// switch all three paths together without changing files used by the old IKE
// configuration during a failed or interrupted activation.
func (s store) prepareGeneration(source *generation, trust []byte) (*generation, error) {
	key, err := s.read(source, "private-key")
	if err != nil {
		return nil, err
	}
	cert, err := s.read(source, "certificate")
	if err != nil {
		return nil, err
	}
	data := append(append(append([]byte{}, key...), cert...), trust...)
	g := &generation{ID: digest(data), NodeUID: source.NodeUID, Chassis: source.Chassis}
	for name, value := range map[string][]byte{"private-key": key, "certificate": cert, "ca-bundle": trust} {
		path := s.path(g, name)
		if existing, err := os.ReadFile(path); err == nil {
			if !bytes.Equal(existing, value) {
				return nil, errors.New("IPsec generation content changed")
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := s.write(g, name, value); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// pending persists the private key before submitting a request. Retries and
// container restarts therefore cannot consume a certificate for a different key.
func (s store) pending(nodeUID, chassis string) (*generation, []byte, error) {
	g, err := s.load("pending")
	if err != nil {
		return nil, nil, err
	}
	if g != nil && g.NodeUID == nodeUID && g.Chassis == chassis {
		key, err := s.read(g, "private-key")
		return g, key, err
	}
	key, err := newPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	g = &generation{ID: digest(key), NodeUID: nodeUID, Chassis: chassis}
	if err := s.write(g, "private-key", key); err != nil {
		return nil, nil, err
	}
	if err := s.save("pending", g); err != nil {
		return nil, nil, err
	}
	return g, key, nil
}
