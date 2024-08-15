package util

import "k8s.io/utils/set"

type NamedPortInfo struct {
	PortID int32
	Pods   set.Set[string]
}
