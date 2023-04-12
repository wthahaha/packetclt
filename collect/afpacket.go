// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// afpacket provides a simple example of using afpacket with zero-copy to read
// packet data.
package collect

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"

	_ "github.com/google/gopacket/layers"
)

// var (
// 	iface      = flag.String("i", "any", "Interface to read from")
// 	cpuprofile = flag.String("cpuprofile", "", "If non-empty, write CPU profile here")
// 	snaplen    = flag.Int("s", 0, "Snaplen, if <= 0, use 65535")
// 	bufferSize = flag.Int("b", 8, "Interface buffersize (MB)")
// 	filter     = flag.String("f", "port not 22", "BPF filter")
// 	count      = flag.Int64("c", -1, "If >= 0, # of packets to capture before returning")
// 	verbose    = flag.Int64("log_every", 1, "Write a log every X packets")
// 	addVLAN    = flag.Bool("add_vlan", false, "If true, add VLAN header")
// )

var (
	snaplen    = 0
	bufferSize = 8
	filter     = ""
	addVLAN    = false
)

type afpacketHandle struct {
	TPacket *afpacket.TPacket
}

func newAfpacketHandle(device string, snaplen int, block_size int, num_blocks int,
	useVLAN bool, timeout time.Duration) (*afpacketHandle, error) {

	h := &afpacketHandle{}
	var err error

	if device == "any" {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(block_size),
			afpacket.OptNumBlocks(num_blocks),
			afpacket.OptAddVLANHeader(useVLAN),
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	} else {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptInterface(device),
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(block_size),
			afpacket.OptNumBlocks(num_blocks),
			afpacket.OptAddVLANHeader(useVLAN),
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	}
	return h, err
}

// ZeroCopyReadPacketData satisfies ZeroCopyPacketDataSource interface
func (h *afpacketHandle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return h.TPacket.ZeroCopyReadPacketData()
}

// SetBPFFilter translates a BPF filter string into BPF RawInstruction and applies them.
func (h *afpacketHandle) SetBPFFilter(filter string, snaplen int) (err error) {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	if err != nil {
		return err
	}
	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}
	if h.TPacket.SetBPF(bpfIns); err != nil {
		return err
	}
	return h.TPacket.SetBPF(bpfIns)
}

// LinkType returns ethernet link type.
func (h *afpacketHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// Close will close afpacket source.
func (h *afpacketHandle) Close() {
	h.TPacket.Close()
}

// SocketStats prints received, dropped, queue-freeze packet stats.
func (h *afpacketHandle) SocketStats() (as afpacket.SocketStats, asv afpacket.SocketStatsV3, err error) {
	return h.TPacket.SocketStats()
}

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {
	fmt.Println(targetSizeMb, snaplen, pageSize)
	if snaplen < pageSize {
		fmt.Println("ddddddddd")
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("Interface buffersize is too small")
	}

	fmt.Println(frameSize, blockSize, numBlocks)
	return frameSize, blockSize, numBlocks, nil
}

func RunAF(iface string) {

	log.Printf("Starting on interface %q", iface)
	if snaplen <= 0 {
		snaplen = 65535
	}
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(bufferSize, snaplen, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}
	afpacketHandle, err := newAfpacketHandle(iface, szFrame, szBlock, numBlocks, addVLAN, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	err = afpacketHandle.SetBPFFilter(filter, snaplen)
	if err != nil {
		log.Fatal(err)
	}
	source := gopacket.ZeroCopyPacketDataSource(afpacketHandle)

	defer afpacketHandle.Close()

	//////////////
	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		udp     layers.UDP
		dns     layers.DNS
		dnsID   = 0
		srcPort = 0
		srcIP   = ""
	)

	// parser := gopacket.NewDecodingLayerParser(
	// 	layers.LayerTypeEthernet, &eth, &ip4, &udp, &dns)
	// decodedLayers := []gopacket.LayerType{}

	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerMap(nil))

	////////////////////
	for {
		data, _, err := source.ZeroCopyReadPacketData()
		if err != nil {
			log.Fatal(err)
		}
		// parser.DecodeLayers(data, &decodedLayers)

		d := make([]byte, len(data))
		copy(d, data)
		dlc = dlc.Put(&eth)
		dlc = dlc.Put(&ip4)
		dlc = dlc.Put(&udp)
		dlc = dlc.Put(&dns)
		decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
		decodedLayers := make([]gopacket.LayerType, 0, 10)
		_, err = decoder(d, &decodedLayers)
		if err != nil {
			fmt.Println(err)
		}
		// fmt.Println(udp.NextLayerType())
		// fmt.Println(udp.SrcPort)
		if dnsID == int(dns.ID) && srcPort == int(udp.SrcPort) && srcIP == string(ip4.SrcIP.String()) {
			continue
		}
		if dns.LayerType().String() == "DNS" {
			dnsID = int(dns.ID)
			srcPort = int(udp.SrcPort)
			srcIP = string(ip4.SrcIP.String())
			fmt.Println(dnsID, srcPort, srcIP)
			fmt.Printf("dnsID:%d,  是否是请求包：%t, Queries: %s\n", dns.ID, !dns.QR, string(dns.Questions[0].Name))
			fmt.Printf("dnsID:%d, answers count: %d,  是否是回应包：%t, Queries: %s\n", dns.ID, dns.ANCount, dns.QR, string(dns.Questions[0].Name))

			continue
		}

	}
}
