package cnp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
)

const Capability = "cnp-dual-read-v1"

// Receipt binds successful NB transactions and their read-back to a leader
// session. It is not proof of southbound convergence or end-to-end connectivity.
type Receipt struct {
	Capability     string `json:"capability"`
	PolicyUID      string `json:"policyUID"`
	Generation     int64  `json:"generation"`
	SemanticDigest string `json:"semanticDigest"`
	ApplyDigest    string `json:"applyDigest"`
	OVNDigest      string `json:"ovnDigest"`
	Leader         string `json:"leader"`
	PodUID         string `json:"podUID"`
	ImageID        string `json:"imageID"`
	Session        string `json:"session"`
	Request        string `json:"request"`
	Error          string `json:"error"`
}

const VerifyAnnotation = "kube-ovn.io/cnp-verify-request"

const (
	CapabilityAnnotation = "kube-ovn.io/cnp-capability"
	ReceiptAnnotation    = "kube-ovn.io/cnp-verification-receipt"
)

func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func MarshalDigest(value any) (string, error) {
	data, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return Hash(data), nil
}
