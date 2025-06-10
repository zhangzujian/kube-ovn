package main

import (
	"errors"
	"flag"
	"math/rand/v2"
	"net"
	"time"

	"github.com/coredns/coredns/plugin/pkg/parse"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/packet"
	"github.com/miekg/dns"
	"github.com/spf13/pflag"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	"github.com/kubeovn/kube-ovn/pkg/util"
)

type PacketMeta struct {
	srcMAC, dstMAC   net.HardwareAddr
	srcIP, dstIP     net.IP
	srcPort, dstPort layers.UDPPort
}

func (r PacketMeta) Network() string {
	return "raw"
}

func (r PacketMeta) String() string {
	return (&net.UDPAddr{IP: r.srcIP, Port: int(r.srcPort)}).String()
}

type RawConn struct {
	*packet.Conn
	dns.Reader
}

func (c RawConn) ReadPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}

	buf := make([]byte, 0x1000)
	n, _, err := c.Conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}

	klog.V(5).Infof("received raw packet with length %d", n)

	pkt := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
	ether := pkt.Layer(layers.LayerTypeEthernet)
	if ether == nil {
		return nil, nil, errors.New("no ethernet layer")
	}
	etherLayer, _ := ether.(*layers.Ethernet)
	meta := &PacketMeta{srcMAC: etherLayer.SrcMAC, dstMAC: etherLayer.DstMAC}

	ip := pkt.NetworkLayer()
	if ip == nil {
		return nil, nil, errors.New("no network layer")
	}
	switch ip.LayerType() {
	case layers.LayerTypeIPv4:
		ip := ip.(*layers.IPv4)
		meta.srcIP, meta.dstIP = ip.SrcIP, ip.DstIP
	case layers.LayerTypeIPv6:
		ip := ip.(*layers.IPv6)
		meta.srcIP, meta.dstIP = ip.SrcIP, ip.DstIP
	default:
		return nil, nil, errors.New("unknown network layer")
	}

	trans := pkt.TransportLayer()
	if trans == nil {
		return nil, nil, errors.New("no transport layer")
	}
	if trans.LayerType() != layers.LayerTypeUDP {
		return nil, nil, errors.New("no udp layer")
	}

	udp := trans.(*layers.UDP)
	meta.srcPort, meta.dstPort = udp.SrcPort, udp.DstPort

	klog.V(5).Infof("received packet from %s", meta.String())
	return udp.LayerPayload(), meta, nil
}

func (c RawConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	meta := addr.(*PacketMeta)
	var ip gopacket.NetworkLayer
	var ipLayer gopacket.SerializableLayer
	var etherType layers.EthernetType
	if len(meta.dstIP) == net.IPv4len {
		etherType = layers.EthernetTypeIPv4
		layer := &layers.IPv4{
			Version:  4,
			SrcIP:    meta.dstIP,
			DstIP:    meta.srcIP,
			TTL:      0xff,
			Protocol: layers.IPProtocolUDP,
		}
		ip = layer
		ipLayer = layer
	} else {
		etherType = layers.EthernetTypeIPv6
		layer := &layers.IPv6{
			Version:    6,
			SrcIP:      meta.dstIP,
			DstIP:      meta.srcIP,
			HopLimit:   0xff,
			NextHeader: layers.IPProtocolUDP,
		}
		ip = layer
		ipLayer = layer
	}
	udp := &layers.UDP{SrcPort: meta.dstPort, DstPort: meta.srcPort}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       meta.dstMAC,
			DstMAC:       meta.srcMAC,
			EthernetType: etherType,
		},
		ipLayer,
		udp,
		gopacket.Payload(p),
	)
	if err != nil {
		klog.Errorf("failed to serialize packet: %v\n", err)
		return 0, err
	}

	return c.Conn.WriteTo(buf.Bytes(), &packet.Addr{HardwareAddr: meta.srcMAC})
}

func main() {
	klogFlags := flag.NewFlagSet("klog", flag.ExitOnError)
	klog.InitFlags(klogFlags)

	// sync the glog and klog flags.
	pflag.CommandLine.VisitAll(func(f1 *pflag.Flag) {
		f2 := klogFlags.Lookup(f1.Name)
		if f2 != nil {
			value := f1.Value.String()
			if err := f2.Value.Set(value); err != nil {
				util.LogFatalAndExit(err, "failed to set pflag")
			}
		}
	})

	pflag.CommandLine.AddGoFlagSet(klogFlags)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	iface := "br0"
	// upstream := "/etc/resolv.conf"
	upstream := "10.96.0.10:53"
	nameservers, err := parse.HostPortOrFile(upstream)
	if err != nil {
		panic(err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		panic(err)
	}

	filter := []bpf.Instruction{
		// ethernet destination address must match ff:ff:ff:ff:xx:xx
		bpf.LoadAbsolute{Off: 0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xffffffff, SkipFalse: 11},
		// L3 protocol
		bpf.LoadExtension{Num: bpf.ExtProto},
		// IPv6 L4 protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.ETH_P_IP, SkipTrue: 3},
		bpf.LoadConstant{Dst: bpf.RegX, Val: 20},
		bpf.LoadAbsolute{Off: 14 + 6, Size: 1},
		// IPv4 L4 protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.ETH_P_IP, SkipFalse: 1},
		bpf.LoadAbsolute{Off: 14 + 9, Size: 1},
		// L4 protocol must be UDP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_UDP, SkipFalse: 4},
		// UDP destination port must be 53
		bpf.LoadIndirect{Off: 14 + 20 + 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipFalse: 2},
		// return this packet
		bpf.LoadExtension{Num: bpf.ExtLen},
		bpf.RetA{},
		// skip this packet
		bpf.RetConstant{},
	}
	var rawInstructions []bpf.RawInstruction
	for _, instruction := range filter {
		ri, err := instruction.Assemble()
		if err != nil {
			panic(err)
		}

		rawInstructions = append(rawInstructions, ri)
	}

	conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, &packet.Config{Filter: rawInstructions})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler(nameservers))

	svr := &dns.Server{
		PacketConn:     &RawConn{Conn: conn},
		Handler:        mux,
		DecorateReader: func(r dns.Reader) dns.Reader { return &RawConn{Conn: conn, Reader: r} },
		UDPSize:        1024,
		MsgInvalidFunc: func(m []byte, err error) {
			if len(m) != 0 {
				klog.V(3).Infof("invalid message with length %d: %v", len(m), err)
			}
		},
	}
	if err = svr.ActivateAndServe(); err != nil {
		panic(err)
	}
}

func handler(upstreams []string) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		handleDNSRequest(upstreams, w, r)
	}
}

func handleDNSRequest(upstreams []string, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	addr := upstreams[rand.IntN(len(upstreams))]
	klog.V(5).Infof("forwarding request %s to upstream %s", r.Question[0].String(), addr)

	forwardedResponse, err := dns.Exchange(r, addr)
	if err != nil {
		klog.Errorf("failed to forward request to upstream %s: %v", addr, err)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	m.Answer = append(m.Answer, forwardedResponse.Answer...)

	if err := w.WriteMsg(m); err != nil {
		klog.Errorf("failed to write response: %v", err)
	}
}
