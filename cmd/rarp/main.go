package main

import (
	"net"
	"net/netip"
	"os"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/packet"
)

func main() {
	addr, err := netip.ParseAddr(os.Args[2])
	if err != nil {
		panic(err)
	}

	iface, err := net.InterfaceByName(os.Args[1])
	if err != nil {
		panic(err)
	}

	// client, err := arp.Dial(iface)
	// if err != nil {
	// 	panic(err)
	// }
	// defer client.Close()

	p, err := packet.Listen(iface, packet.Raw, 0x8035, nil)
	if err != nil {
		panic(err)
	}
	defer p.Close()
	//   New(ifi, p)

	arp, err := arp.NewPacket(3, iface.HardwareAddr, addr, ethernet.Broadcast, addr)
	if err != nil {
		panic(err)
	}

	// // arp.ProtocolType = ethernet.EtherTypeIPv4
	// arp.Operation = 3
	// if err = client.WriteTo(arp, ethernet.Broadcast); err != nil {
	// 	panic(err)
	// }
	pb, err := arp.MarshalBinary()
	if err != nil {
		panic(err)
	}

	f := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      arp.SenderHardwareAddr,
		EtherType:   0x8035,
		Payload:     pb,
	}

	fb, err := f.MarshalBinary()
	if err != nil {
		panic(err)
	}

	_, err = p.WriteTo(fb, &packet.Addr{HardwareAddr: arp.SenderHardwareAddr})
	if err != nil {
		panic(err)
	}

}
