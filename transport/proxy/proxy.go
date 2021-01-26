package proxy

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Proxy provides transport where it terminates tcp/udp streams coming
// on an interface (device) and provides the terminated data to the
// reader. And similarly the writer can write data which will get dressed
// up with tcp/udp headers etc.. and get sent over the device
type Proxy struct {
	deviceIP net.IP
	device   common.Transport
	linkEP   *channel.Endpoint
	tcp      *gonet.TCPConn
	tr       *tcp.ForwarderRequest
	udp      *gonet.UDPConn
	closed   bool
}

func (p *Proxy) proxyToDevice() {
	for {
		packetInfo, ok := p.linkEP.ReadContext(context.Background())
		if !ok {
			log.Println("linkEP ReadContext ok=false")
			continue
		}

		pkt := packetInfo.Pkt
		hdrNetwork := pkt.NetworkHeader()
		hdrTransport := pkt.TransportHeader()

		full := make([]byte, 0, pkt.Size())
		full = append(full, hdrNetwork.View()...)
		full = append(full, hdrTransport.View()...)
		full = append(full, pkt.Data.ToView()...)

		if err := p.device.Write(nil, net.Buffers{full}); err != nil {
			log.Println("device write error", err)
			p.Close()
			return
		}
	}
}

func (p *Proxy) deviceToProxy() {
	// TODO: ipv6 support some day
	pn := header.IPv4ProtocolNumber
	for {
		_, buf, err := p.device.Read()
		if err != nil {
			log.Println("Device read error")
			p.Close()
			return
		}
		for _, b := range buf {
			vv := buffer.NewViewFromBytes(b).ToVectorisedView()
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: vv,
			})
			p.linkEP.InjectInbound(pn, packetBuf)
		}
	}
}

func NewListener(device common.Transport, deviceIP net.IP) *Proxy {
	return &Proxy{device: device, deviceIP: deviceIP}
}

func (p *Proxy) Listen(c chan common.NxtStream) {
	uuid := uuid.New()
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        false,
	})
	ipstack.SetForwarding(ipv4.ProtocolNumber, true)
	ipstack.SetForwarding(ipv6.ProtocolNumber, true)

	const mtu = 1500
	p.linkEP = channel.New(512, mtu, "")
	p.linkEP.LinkEPCapabilities = stack.CapabilityRXChecksumOffload

	const nicID = 1
	if err := ipstack.CreateNIC(nicID, p.linkEP); err != nil {
		return
	}
	err := ipstack.AddAddress(nicID, ipv4.ProtocolNumber, tcpip.Address(p.deviceIP.To4()))
	if err != nil {
		return
	}
	ipstack.SetSpoofing(nicID, true)
	ipstack.SetPromiscuousMode(nicID, true)

	// Add 0.0.0.0/0 default route.
	subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         nicID,
		},
	})

	// use Forwarder to accept any connection from stack. The 1024 is the number of "inflight"
	// connections, ie connections attempted to be open but not open yet. Any further connections
	// will be rejected after that
	fwdTcp := tcp.NewForwarder(ipstack, 0, 1024, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		tcp := gonet.NewTCPConn(&wq, ep)
		proxy := &Proxy{tcp: tcp, tr: r}
		c <- common.NxtStream{Parent: uuid, Stream: proxy}
	})
	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwdTcp.HandlePacket)

	fwdUdp := udp.NewForwarder(ipstack, func(r *udp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		udp := gonet.NewUDPConn(ipstack, &wq, ep)
		proxy := &Proxy{udp: udp}
		c <- common.NxtStream{Parent: uuid, Stream: proxy}
	})
	ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, fwdUdp.HandlePacket)

	go p.proxyToDevice()
	p.deviceToProxy()
}

func (p *Proxy) Dial(sChan chan common.NxtStream) *common.NxtError {
	panic("proxy is accept-only, no dial support")
}

func (p *Proxy) Close() *common.NxtError {
	if p.tcp != nil {
		p.tr.Complete(false)
		p.tcp.Close()
	} else if p.udp != nil {
		p.udp.Close()
	}
	p.closed = true
	return nil
}

func (p *Proxy) IsClosed() bool {
	return p.closed
}

// The proxy is an "accept only" stream, cant create anything new
func (p *Proxy) NewStream(hdr http.Header) common.Transport {
	panic("proxy is accept-only, no new streams can be created")
}

func (p *Proxy) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {
	for _, b := range buf {
		if p.tcp != nil {
			l, err := p.tcp.Write(b)
			if err != nil || l < len(b) {
				return common.Err(common.CONNECTION_ERR, err)
			}
		} else if p.udp != nil {
			l, err := p.udp.Write(b)
			if err != nil || l < len(b) {
				return common.Err(common.CONNECTION_ERR, err)
			}
		} else {
			return common.Err(common.GENERAL_ERR, nil)
		}
	}
	return nil
}

func (p *Proxy) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	buf := make([]byte, common.MAXBUF)
	if p.tcp != nil {
		len, err := p.tcp.Read(buf)
		if err != nil {
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
		}
		return nil, net.Buffers{buf[:len]}, nil
	} else if p.udp != nil {
		len, err := p.udp.Read(buf)
		if err != nil {
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
		}
		return nil, net.Buffers{buf[:len]}, nil
	} else {
		return nil, nil, common.Err(common.GENERAL_ERR, nil)
	}
}

func (p *Proxy) SetReadDeadline(t time.Time) *common.NxtError {
	return nil
}
