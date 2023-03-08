package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	handle, err := pcapgo.NewEthernetHandle("mirror0")
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	var n uint
	for packet := range gopacket.NewPacketSource(handle, layers.LayerTypeEthernet).Packets() {
		for _, l := range packet.Layers() {
			fmt.Println(l.LayerType().String())
		}
		src, dst := packet.LinkLayer().LinkFlow().Endpoints()
		fmt.Println(src.String(), dst.String())
		src, dst = packet.NetworkLayer().NetworkFlow().Endpoints()
		fmt.Println(src.String(), dst.String())
		if n == 5 {
			break
		}
		n++
	}
}
