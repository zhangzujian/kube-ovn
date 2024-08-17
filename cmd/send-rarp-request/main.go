package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/packet"
)

const rarpProtocol = 0x8035
const rarpRequestOp = 3

func exit(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, args...)
	os.Exit(1)
}

func exitOnError(err error, msg string, args ...interface{}) {
	if err != nil {
		exit(msg, append(args, err)...)
	}
}

func main() {
	if len(os.Args) != 2 && len(os.Args) != 3 {
		exit("Usage: %s <interface> [ip address]\n", os.Args[0])
	}

	addr := netip.IPv4Unspecified()
	if len(os.Args) == 3 {
		var err error
		addr, err = netip.ParseAddr(os.Args[2])
		exitOnError(err, "failed to parse ip address %q: %v", os.Args[2])
		if !addr.Is4() {
			exit("Invalid IPv4 addresses %q\n", os.Args[2])
		}
	}

	iface, err := net.InterfaceByName(os.Args[1])
	exitOnError(err, "failed to get interface %q: %v", os.Args[1])

	p, err := packet.Listen(iface, packet.Raw, rarpProtocol, nil)
	exitOnError(err, "failed to listen on interface %s: %v", os.Args[1])
	defer p.Close()

	arp, err := arp.NewPacket(rarpRequestOp, iface.HardwareAddr, addr, ethernet.Broadcast, addr)
	exitOnError(err, "failed to create rarp request packet: %v")

	pb, err := arp.MarshalBinary()
	exitOnError(err, "failed to convert rarp request packet to binary: %v")

	f := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      arp.SenderHardwareAddr,
		EtherType:   rarpProtocol,
		Payload:     pb,
	}

	fb, err := f.MarshalBinary()
	exitOnError(err, "failed to convert ethernet frame to binary: %v")

	_, err = p.WriteTo(fb, &packet.Addr{HardwareAddr: arp.SenderHardwareAddr})
	exitOnError(err, "failed to send rarp request packet: %v")
}
