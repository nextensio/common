package ethernet

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
)

const (
	ETH_HDR_LEN = 14
)

// Ethernet implements a transport where an IPV4 (no v6 as of today) packet is
// provided to the transport and it dresses up with ethernet headers and sends
// it out of an ethernet interface. Similarly an ethernet packet comes in, we
// strip the ethernet headers and give the IPv4 packet to the upper layer doing
// the Read(). Note that there is no nextensio headers in the Read or Write
// direction, we are just dealing with rx/tx of ethernet packets here
type Ethernet struct {
	lg         *log.Logger
	device     string
	ip         net.IP
	nexthop    net.IP
	snaplen    int
	bufferSize int
	TPacket    *afpacket.TPacket
	source     gopacket.PacketDataSource
	closed     bool
	closeLock  sync.Mutex
	srcmac     net.HardwareAddr
	dstmac     net.HardwareAddr
	ethhdr     []byte
}

func NewClient(ctx context.Context, lg *log.Logger, device string, nexthop net.IP) *Ethernet {
	intf, err := net.InterfaceByName(device)
	if err != nil {
		return nil
	}

	var ip net.IP
	addrs, _ := intf.Addrs()
Loop:
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			// TODO: Handle IPv6
			if v.IP.To4() != nil {
				ip = v.IP.To4()
				break Loop
			}
		case *net.IPAddr:
			// TODO: Handle IPv6
			if v.IP.To4() != nil {
				ip = v.IP.To4()
				break Loop
			}
		}
	}
	// Cant find ip address of interface
	if len(ip) == 0 {
		return nil
	}
	return &Ethernet{
		lg: lg, device: device, ip: ip, nexthop: nexthop.To4(),
		snaplen: common.MAXBUF, bufferSize: 1 /*MB*/, srcmac: intf.HardwareAddr,
	}
}

func (e *Ethernet) sendArp() {
	eth := layers.Ethernet{
		SrcMAC:       e.srcmac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(e.srcmac),
		SourceProtAddress: []byte(e.ip),
		DstProtAddress:    []byte(e.nexthop),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}

	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	e.TPacket.WritePacketData(buf.Bytes())
}

func (e *Ethernet) arpNhop() {
	for {
		if e.closed {
			return
		}
		// We got an arp response
		if len(e.dstmac) != 0 {
			return
		}
		e.sendArp()
		time.Sleep(10 * time.Millisecond)
	}
}

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
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

	return frameSize, blockSize, numBlocks, nil
}

func newAfpacketHandle(device string, snaplen int, block_size int, num_blocks int) (*afpacket.TPacket, error) {
	t, err := afpacket.NewTPacket(
		afpacket.OptInterface(device),
		afpacket.OptFrameSize(snaplen),
		afpacket.OptBlockSize(block_size),
		afpacket.OptNumBlocks(num_blocks),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3)
	return t, err
}

func (e *Ethernet) Listen(c chan common.NxtStream) {
	// ethernet has no server and listen etc.., just Dial which is equivalent of Open()
	panic("Call dial on ethernet")
}

func (e *Ethernet) Dial(sChan chan common.NxtStream) *common.NxtError {
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(e.bufferSize, e.snaplen, os.Getpagesize())
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	t, err := newAfpacketHandle(e.device, szFrame, szBlock, numBlocks)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	e.TPacket = t
	e.source = gopacket.PacketDataSource(t)

	eth := layers.Ethernet{
		SrcMAC:       e.srcmac,
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, &eth)
	// This will get replaced with proper ethhdr once arp is resolved
	e.ethhdr = buf.Bytes()[0:ETH_HDR_LEN]
	go e.arpNhop()

	return nil
}

func (e *Ethernet) Close() *common.NxtError {
	e.closeLock.Lock()
	e.TPacket.Close()
	e.closed = true
	e.closeLock.Unlock()
	return nil
}

func (e *Ethernet) IsClosed() bool {
	return e.closed
}

// To support close cascading, we need an asynchronous way of knowing that
// this stream is closed - asychronous meaning that without anyone doing a
// Read() or Write(), we should know that this stream is closed. Examples
// are the websocket and http2 transports, those streaming protocols have
// state machines that figure out a stream is closed, at which point that
// information is cascaded. So if we need to support this, we need some way
// of asynchronously knowing that this stream is closed
func (e *Ethernet) CloseCascade(cascade common.Transport) {
	panic("This stream does not support close cascading!")
}

func (e *Ethernet) NewStream(hdr http.Header) common.Transport {
	panic("Ethernet has no streams!")
}

func (e *Ethernet) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {
	if e.closed {
		return common.Err(common.CONNECTION_ERR, nil)
	}
	for _, b := range buf {
		err := e.TPacket.WritePacketData(append(e.ethhdr, b...))
		if err != nil {
			return common.Err(common.CONNECTION_ERR, err)
		}
	}
	return nil
}

// Read the packet, strip ethernet headers and send it to the reader. Send
// only the ipv4 packets to the reader. And for non-ipv4 packets like ARP
// responses, see if thats an arp response for our nexthop IP address and
// record it if so
func (e *Ethernet) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	for {
		if e.closed {
			return nil, nil, common.Err(common.CONNECTION_ERR, nil)
		}
		data, _, err := e.source.ReadPacketData()
		if err != nil {
			log.Println("Ethernet read error", err)
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
		}
		p := gopacket.NewPacket(data, layers.LinkTypeEthernet, common.LazyNoCopy)
		if p.ErrorLayer() != nil {
			log.Println("Bad eth pkt:", data)
			continue
		}

		ethLayer := p.Layer(layers.LayerTypeEthernet)
		eth := ethLayer.(*layers.Ethernet)
		// Not packet for us
		if !bytes.Equal([]byte(e.srcmac), eth.DstMAC) {
			continue
		}

		// Handover ipv4 packet to the reader.
		// TODO: Handle ipv6 too
		if p.Layer(layers.LayerTypeIPv4) != nil {
			return nil, net.Buffers{data[ETH_HDR_LEN:]}, nil
		}

		// Packet is not ipv4, check if its ARP
		arpLayer := p.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(e.srcmac), arp.SourceHwAddress) {
				// This is a packet we sent.
				continue
			}
			if bytes.Equal(arp.SourceProtAddress, []byte(e.nexthop)) {
				e.dstmac = net.HardwareAddr(arp.SourceHwAddress)
				eth := layers.Ethernet{
					SrcMAC:       e.srcmac,
					DstMAC:       e.dstmac,
					EthernetType: layers.EthernetTypeIPv4,
				}
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{}
				gopacket.SerializeLayers(buf, opts, &eth)
				e.ethhdr = buf.Bytes()[0:ETH_HDR_LEN]
			}
		}
	}
}

func (e *Ethernet) SetReadDeadline(t time.Time) *common.NxtError {
	return nil
}

func (e *Ethernet) ClockDrift() int64 {
	return 0
}
