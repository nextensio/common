package ethernet

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gitlab.com/nextensio/common"
)

// NOTE: The af-packet stuff needs sudo permissions to run. It can be run as below
// sudo /usr/local/go/bin/go test

func defaultIntf() (string, net.IP) {

	file, err := os.Open("/proc/net/route")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// get field containing gateway address
		tokens := strings.Split(scanner.Text(), "\t")

		flags := "0x" + tokens[3]
		f, _ := strconv.ParseInt(flags, 0, 64)
		if f&0x3 == 0 { // RTF_GATEWAY|RTF_UP
			continue
		}

		gatewayHex := "0x" + tokens[2]
		// cast hex address to uint32
		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)

		// make net.IP address from uint32
		ipd32 := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipd32, d32)
		return tokens[0], ipd32
	}

	return "", nil
}

var testSrcip = "192.0.2.1"
var testDstip = "198.51.100.1"

func createIPv4ChecksumTestLayer() *layers.IPv4 {
	ip4 := &layers.IPv4{}
	ip4.Version = 4
	ip4.TTL = 64
	ip4.SrcIP = net.ParseIP(testSrcip)
	ip4.DstIP = net.ParseIP(testDstip)

	return ip4
}

func createICMPTestLayer(id uint16, seq uint16) *layers.ICMPv4 {
	icmp := &layers.ICMPv4{}
	icmp.TypeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
	icmp.Id = id
	icmp.Seq = seq

	return icmp
}

func createICMPPacket(id uint16, seq uint16) *gopacket.Packet {
	var serialize = make([]gopacket.SerializableLayer, 0, 2)
	var err error

	ip4 := createIPv4ChecksumTestLayer()
	ip4.Protocol = layers.IPProtocolICMPv4
	serialize = append(serialize, ip4)

	icmp := createICMPTestLayer(id, seq)
	serialize = append(serialize, icmp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		return nil
	}

	p := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeRaw, common.LazyNoCopy)
	if p.ErrorLayer() != nil {
		return nil
	}

	return &p
}

// This assumes that the interface with the default route in the system will
// get some packets once in a while, it reads a few packets just to ensure
// reads are working fine
func TestReadWrite(t *testing.T) {
	mainCtx := context.Background()
	intf, nhop := defaultIntf()
	if nhop == nil {
		panic("Cannot find default interface")
	}
	e := NewClient(mainCtx, intf, nhop)
	c := make(chan common.NxtStream)
	e.Dial(c)
	for len(e.dstmac) == 0 {
		fmt.Println("Waiting for arp resolution")
		e.Read()
		time.Sleep(50 * time.Millisecond)
	}

	p := createICMPPacket(100, 200)
	for i := 0; i < 10; i++ {
		err := e.Write(nil, net.Buffers{(*p).Data()})
		if err != nil {
			panic(err)
		}
	}
	for p := 0; p < 3; p++ {
		_, buf, err := e.Read()
		if err != nil {
			panic(err)
		}
		fmt.Println("Packet contents:")
		for i := 0; i < len(buf[0]); i++ {
			if i > 0 && i%16 == 0 {
				fmt.Println()
			}
			fmt.Printf("%02x ", buf[0][i])
		}
		fmt.Println()
	}
}
