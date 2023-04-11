package collect

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func Collect(eth string) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	var device pcap.Interface
	for _, d := range devices {
		if d.Name == eth {
			device = d
			fmt.Println(device)
		}
	}
	incative, err := pcap.NewInactiveHandle(eth)
	if err != nil {
		log.Fatal(err)
	}
	defer incative.CleanUp()
	incative.SetImmediateMode(true)
	handle, err := incative.Activate()
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		consumer(packet)
	}
}

func consumer(pk gopacket.Packet) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var udp layers.UDP
	var dns layers.DNS
	var QQ bool
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &eth, &ip4, &udp, &dns)
	decodedLayers := []gopacket.LayerType{}
	// fmt.Printf("协程ID：%d \n", goid.Get())
	parser.DecodeLayers(pk.Data(), &decodedLayers)
	if dns.ID == 0 {
		return
	}
	if !dns.QR {
		QQ = !dns.QR
	}
	fmt.Printf("dnsID:%d,  是否是请求包：%t, Queries: %s\n", dns.ID, QQ, string(dns.Questions[0].Name))
	fmt.Printf("dnsID:%d, answers count: %d,  是否是回应包：%t, Queries: %s\n", dns.ID, dns.ANCount, dns.QR, string(dns.Questions[0].Name))

}
