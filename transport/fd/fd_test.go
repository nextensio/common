package fd

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gitlab.com/nextensio/common"
	"golang.org/x/sys/unix"
)

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

func createTun() int {
	nfd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	old, err := unix.FcntlInt(uintptr(nfd), unix.F_GETFL, 0)
	if err != nil {
		panic(err)
	}
	_, err = unix.FcntlInt(uintptr(nfd), unix.F_SETFL, old & ^unix.O_NONBLOCK)
	if err != nil {
		panic(err)
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	var flags uint16 = unix.IFF_TUN | unix.IFF_NO_PI
	name := []byte("tun0")
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags
	fmt.Println(string(ifr[:unix.IFNAMSIZ]))
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(nfd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		panic(fmt.Errorf("ioctl errno: %d", errno))
	}

	return nfd
}

// This reads a few packets just to ensure reads are working fine, and writes a few
// packets which we can checkout in tcpdump. Once we run go test, the read here will
// hang till the tun0 interface is up. So we can do the below on a shell
// sudo ifconfig tun0 up; sudo tcpdump -nni tun0
func TestReadWrite(t *testing.T) {
	mainCtx := context.Background()

	nfd := createTun()
	f := NewClient(mainCtx, uintptr(nfd))
	c := make(chan common.NxtStream)
	f.Dial(c)

	// First read three packets from the tun interface, from the shell
	// do a ping or something to generate the pkts
	for p := 0; p < 3; p++ {
		_, buf, err := f.Read()
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

	// Now write some icmp packets, do a tcpdump on the tun interface and
	// check if you see these packets
	p := createICMPPacket(100, 200)
	for i := 0; i < 10; i++ {
		err := f.Write(nil, net.Buffers{(*p).Data()})
		if err != nil {
			panic(err)
		}
	}
}
