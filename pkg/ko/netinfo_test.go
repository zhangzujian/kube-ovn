package ko

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIPLinksExposeAddressesAndHostVethPeer(t *testing.T) {
	var podLinks []ipJSONLink
	err := json.Unmarshal([]byte(`[
        {"ifindex":2,"ifname":"eth0","link_index":42,"mtu":1500,"operstate":"UP","address":"0a:58:0a:f4:00:02","flags":["BROADCAST","UP"],"link_type":"ether","linkinfo":{"info_kind":"veth"},"addr_info":[{"family":"inet","local":"10.244.0.2","prefixlen":24}]}
    ]`), &podLinks)
	if err != nil {
		t.Fatal(err)
	}
	var hostLinks []ipJSONLink
	err = json.Unmarshal([]byte(`[
        {"ifindex":42,"ifname":"pod123_h","link_index":2,"mtu":1500,"operstate":"UP","address":"aa:bb:cc:dd:ee:ff","flags":["BROADCAST","UP"],"link_type":"ether","linkinfo":{"info_kind":"veth"}}
    ]`), &hostLinks)
	if err != nil {
		t.Fatal(err)
	}
	hostByIndex := map[int]networkLink{hostLinks[0].Index: hostLinks[0].networkLink()}
	item := podLinks[0].podNetworkInterface()
	peer, ok := hostByIndex[item.PeerIndex]
	if !ok {
		t.Fatal("pod veth peer was not found")
	}
	item.HostPeer = new(peer)

	if item.Name != "eth0" || item.Kind != "veth" || item.Addresses[0] != "10.244.0.2/24" {
		t.Fatalf("unexpected pod interface: %#v", item)
	}
	if item.HostPeer.Name != "pod123_h" || item.HostPeer.Index != 42 {
		t.Fatalf("unexpected host peer: %#v", item.HostPeer)
	}
}

func TestIPLinksExposeMacvlanParent(t *testing.T) {
	var podLinks []ipJSONLink
	err := json.Unmarshal([]byte(`[
        {"ifindex":5,"ifname":"net1","link_index":10,"link":"eth0","mtu":1500,"operstate":"UP","address":"02:00:00:00:00:05","flags":["BROADCAST","UP"],"link_type":"ether","linkinfo":{"info_kind":"macvlan"},"addr_info":[{"family":"inet","local":"192.0.2.5","prefixlen":24}]}
    ]`), &podLinks)
	if err != nil {
		t.Fatal(err)
	}
	var hostLinks []ipJSONLink
	err = json.Unmarshal([]byte(`[
        {"ifindex":10,"ifname":"eth0","mtu":1500,"operstate":"UP","address":"aa:bb:cc:dd:ee:01","flags":["BROADCAST","UP"],"link_type":"ether"}
    ]`), &hostLinks)
	if err != nil {
		t.Fatal(err)
	}
	hostByName := map[string]networkLink{hostLinks[0].Name: hostLinks[0].networkLink()}
	hostByIndex := map[int]networkLink{hostLinks[0].Index: hostLinks[0].networkLink()}
	item := podLinks[0].podNetworkInterface()
	parent, ok := podLinks[0].parentLink(hostByName, hostByIndex, nil)
	if !ok {
		t.Fatal("macvlan parent was not found")
	}
	item.Parent = new(parent)

	if item.Kind != "macvlan" || item.Parent.Name != "eth0" || item.Parent.Index != 10 {
		t.Fatalf("unexpected macvlan parent: %#v", item)
	}
}

func TestWritePodNetworkIncludesNetnsAndPeer(t *testing.T) {
	info := &podNetworkInfo{
		Namespace: "app", Name: "web", Node: "worker-a", NetNS: "/var/run/netns/pod", Interfaces: []podNetworkInterface{{
			Name: "eth0", Index: 2, Kind: "veth", MAC: "0a:58:0a:f4:00:02", MTU: 1500, OperState: "UP", Addresses: []string{"10.244.0.2/24"},
			HostPeer: &networkLink{Name: "pod123_h", Index: 42, MAC: "aa:bb:cc:dd:ee:ff", OperState: "UP"},
		}},
	}
	var out bytes.Buffer
	if err := writePodNetwork(&out, info); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/var/run/netns/pod", "eth0", "10.244.0.2/24", "host peer: pod123_h"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q: %s", want, out.String())
		}
	}
}

func TestNetworkInspectReadsPodAndHostLinks(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "app"}, Spec: corev1.PodSpec{NodeName: "worker-a"}}
	ovs := readyPod("ovs-a", "worker-a", "openvswitch", map[string]string{"app": "ovs"})
	app, executor, out, _ := testApplication(t, pod, ovs, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-a"}})
	executor.run = func(_ context.Context, _ Target, argv []string, streams Streams) error {
		switch argv[0] {
		case "ovs-vsctl":
			_, err := io.WriteString(streams.Out, `{"headings":["name","external_ids","ofport"],"data":[["pod123_h",["map",[["pod_name","web"],["pod_namespace","app"],["pod_netns","/var/run/netns/pod"]]],4]]}`)
			return err
		case "nsenter":
			if !slices.Contains(argv, "-s") {
				t.Errorf("pod netns ip command lacks -s: %v", argv)
			}
			_, err := io.WriteString(streams.Out, `[{"ifindex":2,"ifname":"eth0","link_index":42,"mtu":1500,"operstate":"UP","address":"0a:58:0a:f4:00:02","flags":["BROADCAST","UP"],"link_type":"ether","linkinfo":{"info_kind":"veth"},"addr_info":[{"family":"inet","local":"10.244.0.2","prefixlen":24}]}]`)
			return err
		case "ip":
			if !slices.Contains(argv, "-s") {
				t.Errorf("host netns ip command lacks -s: %v", argv)
			}
			_, err := io.WriteString(streams.Out, `[{"ifindex":42,"ifname":"pod123_h","link_index":2,"mtu":1500,"operstate":"UP","address":"aa:bb:cc:dd:ee:ff","flags":["BROADCAST","UP"],"link_type":"ether","linkinfo":{"info_kind":"veth"}}]`)
			return err
		default:
			return nil
		}
	}
	if err := app.Execute(t.Context(), []string{"network", "inspect", "--pod", "app/web"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Network namespace: /var/run/netns/pod", "eth0", "10.244.0.2/24", "host peer: pod123_h"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q: %s", want, out.String())
		}
	}
}
