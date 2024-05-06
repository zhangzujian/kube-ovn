package main

import (
	"os"
	"strings"

	"github.com/kubeovn/kube-ovn/pkg/ipam"
)

func main() {
	v := ipam.NewIPAM()
	if err := v.AddOrUpdateSubnet("ovn-default", "10.195.0.0/16", "10.195.0.1", []string{"10.195.0.1"}); err != nil {
		panic(err)
	}

	content, err := os.ReadFile("ipam.log")
	if err != nil {
		panic(err)
	}

	var updated bool
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		switch {
		case strings.Contains(line, "ipam.go:60"):
			pod := strings.Trim(fields[12], ",")
			_, _, _, err := v.GetRandomAddress(pod, pod, nil, "ovn-default", "", nil, true)
			if err != nil {
				panic(err)
			}
		// case strings.Contains(line, "ipam.go:72"):
		// 	pod := strings.Trim(fields[12], ",")
		// 	if _, _, _, err := v.GetRandomAddress(pod, pod, nil, "ovn-default", "", nil, true); err != nil {
		// 		panic(err)
		// 	}
		case strings.Contains(line, "ipam.go:102"):
			// allocate v4 10.195.0.42, mac 00:00:00:3A:20:4B for sy-k/k1-virtualmachine from subnet ovn-default
			ip, pod := strings.Trim(fields[6], ","), strings.Trim(fields[10], ",")
			if _, _, _, err := v.GetStaticAddress(pod, pod, ip, nil, "ovn-default", true); err != nil {
				// if
				panic(err)
			}
		case !updated && strings.Contains(line, "ipam.go:245"):
			if err := v.AddOrUpdateSubnet("ovn-default", "10.195.0.0/16", "10.195.0.1", []string{"10.195.0.1", "10.195.0.2"}); err != nil {
				panic(err)
			}
			updated = true
		case strings.Contains(line, "subnet.go:492"):
			pod := strings.Trim(fields[13], ",")
			v.ReleaseAddressByPod(pod, "")
		}
	}
}
