package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/kubeovn/kube-ovn/pkg/util"
	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/packet"
)

const rarpProtocol = 0x8035
const rarpRequestOp = 3

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <interface>\n", os.Args[0])
		os.Exit(1)
	}

	iface, err := net.InterfaceByName(os.Args[1])
	if err != nil {
		util.LogFatalAndExit(err, "failed to get interface %q", os.Args[1])
	}

	p, err := packet.Listen(iface, packet.Raw, rarpProtocol, nil)
	if err != nil {
		util.LogFatalAndExit(err, "failed to list on interface %q", os.Args[1])
	}
	defer p.Close()

	addr := netip.IPv4Unspecified()
	arp, err := arp.NewPacket(rarpRequestOp, iface.HardwareAddr, addr, ethernet.Broadcast, addr)
	if err != nil {
		util.LogFatalAndExit(err, "failed to create rarp request packet")
	}

	pb, err := arp.MarshalBinary()
	if err != nil {
		util.LogFatalAndExit(err, "failed to convert rarp request packet to binary")
	}

	f := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      arp.SenderHardwareAddr,
		EtherType:   rarpProtocol,
		Payload:     pb,
	}

	fb, err := f.MarshalBinary()
	if err != nil {
		util.LogFatalAndExit(err, "failed to convert ethernet frame to binary")
	}

	_, err = p.WriteTo(fb, &packet.Addr{HardwareAddr: arp.SenderHardwareAddr})
	if err != nil {
		util.LogFatalAndExit(err, "failed to send rarp request packet")
	}
}
