package proxy

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gopakumarce/tlsx"
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

const (
	TLS_HDRLEN        = 5
	TCP_PARSE_SZ      = 2 * common.MAXBUF
	TCP_PARSE_TIMEOUT = 20 * time.Millisecond // 20 msecs to get all the http request header / tls client hello
)

var methods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodOptions,
	http.MethodTrace,
}

type tls struct {
	notTls bool
}

type text struct {
	notHttp bool
}

// Proxy provides transport where it terminates tcp/udp streams coming
// on an interface (device) and provides the terminated data to the
// reader. And similarly the writer can write data which will get dressed
// up with tcp/udp headers etc.. and get sent over the device
type Proxy struct {
	deviceIP  net.IP
	device    common.Transport
	linkEP    *channel.Endpoint
	tcp       *gonet.TCPConn
	tcpParse  []byte
	tcpParsed chan struct{}
	tcpLen    int
	tls       tls
	http      text
	udp       *gonet.UDPConn
	sip       net.IP
	sport     uint16
	dip       net.IP
	dport     uint16
	service   string
	closed    bool
	hdr       *nxthdr.NxtHdr
}

// These are tcp/udp packets coming in on a device/transport (like ethernet)
// which we want the gvisor stack to terminate using its tcp/ip stack. So we
// send them over to gvisor
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

// These are tcp/udp packets from the govisor tcp/ip stack that we need to send
// out on some other device/transport (like an ethernet interface. These packets
// can be gvisor generated packets like the tcp acks and stuff or app generated
// data like the tcp payload
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

func NewListener(device common.Transport, deviceIP net.IP) *Proxy {
	return &Proxy{device: device, deviceIP: deviceIP}
}

func makeHdr(p *Proxy) *nxthdr.NxtHdr {
	flow := nxthdr.NxtFlow{}
	flow.Source = p.sip.String()
	flow.Sport = uint32(p.sport)
	flow.Dest = p.dip.String()
	flow.Dport = uint32(p.dport)
	flow.DestAgent = p.service
	flow.Type = nxthdr.NxtFlow_L4
	if p.tcp != nil {
		flow.Proto = common.TCP
	} else if p.udp != nil {
		flow.Proto = common.UDP
	}

	hdr := nxthdr.NxtHdr{}
	hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: &flow}
	return &hdr
}

// Listen on a device for incoming tcp/udp streams, terminate them and create
// an individual transport for each of those streams. A read() on that transport
// will get the tcp/udp payload (and not internal tcp stuff like acks) and write
// on that transport will be the tcp/udp payload that gets written
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
		id := r.ID()
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		tcp := gonet.NewTCPConn(&wq, ep)
		parse := make([]byte, TCP_PARSE_SZ)
		parsed := make(chan struct{})
		proxy := &Proxy{
			tcp: tcp, tcpParse: parse, tcpParsed: parsed, tcpLen: 0,
			sip: net.IP(id.RemoteAddress).To4(), sport: id.RemotePort,
			dip: net.IP(id.LocalAddress).To4(), dport: id.LocalPort,
		}
		proxy.hdr = makeHdr(proxy)
		go tcpParse(proxy)
		c <- common.NxtStream{Parent: uuid, Stream: proxy}
	})
	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwdTcp.HandlePacket)

	fwdUdp := udp.NewForwarder(ipstack, func(r *udp.ForwarderRequest) {
		var wq waiter.Queue
		id := r.ID()
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		udp := gonet.NewUDPConn(ipstack, &wq, ep)
		proxy := &Proxy{
			udp: udp,
			sip: net.IP(id.RemoteAddress).To4(), sport: id.RemotePort,
			dip: net.IP(id.LocalAddress).To4(), dport: id.LocalPort,
		}
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
			_, err := p.tcp.Write(b)
			if err != nil {
				return common.Err(common.CONNECTION_ERR, err)
			}
		} else if p.udp != nil {
			_, err := p.udp.Write(b)
			if err != nil {
				return common.Err(common.CONNECTION_ERR, err)
			}
		} else {
			return common.Err(common.GENERAL_ERR, nil)
		}
	}
	return nil
}

func nlcrnl(v []byte) bool {
	if v[0] == '\n' && v[1] == '\r' && v[2] == '\n' {
		return true
	}
	return false
}

func parseHTTP(p *Proxy, prev int) bool {
	if p.http.notHttp {
		return false
	}
	// Look for the sequence '\n\r\n' - ie a CRLF on a line by itself
	// A brute force check here without maintaining any state, for every
	// set of three bytes, check if they are \n\r\n
	found := false
	end := 0
	for i := prev; i < p.tcpLen; i++ {
		if i-2 >= 0 {
			if nlcrnl(p.tcpParse[i-2 : i+1]) {
				found = true
				end = i + 1
				break
			}
		}
		if i-1 >= 0 && i+1 < p.tcpLen {
			if nlcrnl(p.tcpParse[i-1 : i+2]) {
				found = true
				end = i + 2
				break
			}
		}
		if i+2 < p.tcpLen {
			if nlcrnl(p.tcpParse[i : i+3]) {
				found = true
				end = i + 3
				break
			}
		}
	}
	if found {
		reader := bufio.NewReader(bytes.NewReader(p.tcpParse[0:end]))
		req, err := http.ReadRequest(reader)
		if err != nil {
			p.http.notHttp = true
			return false
		}
		if strings.ToUpper(req.Proto) != "HTTP/1.1" {
			p.http.notHttp = true
			return false
		}
		valid := false
		for _, m := range methods {
			if strings.ToUpper(req.Method) == m {
				valid = true
				break
			}
		}
		if !valid {
			p.http.notHttp = true
			return false
		}
		if req.Host == "" {
			p.http.notHttp = true
			return false
		}
		p.service = req.Host
		flow := p.hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
		flow.DestAgent = p.service
		return true
	}

	return false
}

func parseTLS(p *Proxy) bool {
	if p.tls.notTls {
		return false
	}
	// The first 5 bytes is what identifies TLS
	if p.tcpLen < TLS_HDRLEN {
		return false
	}
	t := int(p.tcpParse[0])
	maj := int(p.tcpParse[1])
	min := int(p.tcpParse[2])
	l := (int(p.tcpParse[3]) << 8) | int(p.tcpParse[4])
	// Check if type is client hello (0x16)
	// Check if version is 0300 or 0301 or 0302
	// Check if hello fits in one buffer. Again, like we discussed in tcpParse(), if
	// we come across esoteric hellos that are huge, we need to come back and modify this check
	if t != 0x16 || maj != 3 || ((min != 0) && (min != 1) && (min != 2)) || (l > TCP_PARSE_SZ-TLS_HDRLEN) {
		p.tls.notTls = true
		return false
	}
	// Ok so we know its tls client hello, now we are just waiting to read all the hello bytes
	if p.tcpLen != TLS_HDRLEN+l {
		return false
	}

	var hello = tlsx.ClientHello{}
	err := hello.Unmarshall(p.tcpParse[0:p.tcpLen])
	if err != nil {
		p.tls.notTls = true
		return false
	}
	// The TLS SNI is our service name
	p.service = hello.SNI
	flow := p.hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
	flow.DestAgent = p.service

	return true
}

func tcpParse(p *Proxy) {
	for {
		// Cant wait for ever to decide if its plain text http or if its tls SNI
		p.tcp.SetReadDeadline(time.Now().Add(TCP_PARSE_TIMEOUT))
		n, err := p.tcp.Read(p.tcpParse[p.tcpLen:])
		prev := p.tcpLen
		p.tcpLen += n
		if parseTLS(p) || parseHTTP(p, prev) {
			break
		}
		if err != nil {
			// timed out (or even channel closed), we fall back to just using the
			// ip address as the service name
			break
		}
		if p.tcpLen == len(p.tcpParse) {
			// well, I am not sure if we can expect the client hello/http headers to
			// fit in one TCP_PARSE_SZ buffer. If there are esoteric hellos/headers that need
			// more space, we will need to come back here and increase the size of
			// the tcpParse buf allocated to the Proxy
			break
		}
	}

	// If we cant find a service name, the destination IP is the service name
	if p.service == "" {
		p.service = p.dip.String()
	}
	// Cancel the timeouts
	p.tcp.SetReadDeadline(time.Time{})
	// Parsing activity completed (succesfully or unsuccesfully)
	close(p.tcpParsed)
}

func (p *Proxy) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {

	// Wait till we have identified what the tcp stream is, basically we
	// try to figure out if its TLS and if so get the SNI field, or if its
	// plain http we get the host field
	select {
	case <-p.tcpParsed:
	}
	// We have some data buffered as part of the tcp parsing, return that first
	// and read the next set of data in the next call to Read()
	if p.tcpLen != 0 {
		n := p.tcpLen
		p.tcpLen = 0
		return p.hdr, net.Buffers{p.tcpParse[0:n]}, nil
	}

	var err error
	var n int
	buf := make([]byte, common.MAXBUF)
	if p.tcp != nil {
		n, err = p.tcp.Read(buf)
		if err == nil {
			return p.hdr, net.Buffers{buf[:n]}, nil
		}
	} else if p.udp != nil {
		n, err = p.udp.Read(buf)
		if err == nil {
			return p.hdr, net.Buffers{buf[:n]}, nil
		}
	}
	return nil, nil, common.Err(common.CONNECTION_ERR, err)
}

func (p *Proxy) SetReadDeadline(t time.Time) *common.NxtError {
	return nil
}
