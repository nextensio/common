package netconn

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nextensio/tlsx"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
)

type tls struct {
	notTls bool
}

type text struct {
	notHttp bool
}

// NetConn dresses up a golang net.Conn as a common.Transport.
type NetConn struct {
	server   bool
	lg       *log.Logger
	ctx      context.Context
	parse    []byte
	parsed   chan struct{}
	parseLen int
	tls      tls
	http     text
	service  string
	proto    string
	dest     string
	port     uint32
	conn     net.Conn
	closed   bool
	hdr      *nxthdr.NxtHdr
}

const (
	TLS_HDRLEN   = 5
	TCP_PARSE_SZ = 2048
	// 100 msecs to get all the http request header / tls client hello.
	// TODO: This will undergo more tweaking in future, for now setting it to a considerably high value
	TCP_PARSE_TIMEOUT = 100 * time.Millisecond
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

func makeHdr(p *NetConn, sourceIP string, localPort uint32) *nxthdr.NxtHdr {
	flow := nxthdr.NxtFlow{}
	flow.Source = p.dest
	flow.Sport = p.port
	flow.Dest = sourceIP
	flow.Dport = localPort
	flow.DestSvc = flow.Dest // This will get overridden if http/sni parsing is succesful
	flow.Type = nxthdr.NxtFlow_L4
	if p.proto == "tcp" {
		flow.Proto = common.TCP
	} else if p.proto == "udp" {
		flow.Proto = common.UDP
	}

	hdr := nxthdr.NxtHdr{}
	hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: &flow}
	return &hdr
}

func nlcrnl(v []byte) bool {
	if v[0] == '\n' && v[1] == '\r' && v[2] == '\n' {
		return true
	}
	return false
}

func parseHTTP(p *NetConn, prev int) bool {
	if p.http.notHttp {
		return false
	}
	// Look for the sequence '\n\r\n' - ie a CRLF on a line by itself
	// A brute force check here without maintaining any state, for every
	// set of three bytes, check if they are \n\r\n
	found := false
	end := 0
	for i := prev; i < p.parseLen; i++ {
		if i-2 >= 0 {
			if nlcrnl(p.parse[i-2 : i+1]) {
				found = true
				end = i + 1
				break
			}
		}
		if i-1 >= 0 && i+1 < p.parseLen {
			if nlcrnl(p.parse[i-1 : i+2]) {
				found = true
				end = i + 2
				break
			}
		}
		if i+2 < p.parseLen {
			if nlcrnl(p.parse[i : i+3]) {
				found = true
				end = i + 3
				break
			}
		}
	}
	if found {
		reader := bufio.NewReader(bytes.NewReader(p.parse[0:end]))
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
		return true
	}

	return false
}

func parseTLS(p *NetConn) bool {
	if p.tls.notTls {
		return false
	}
	// The first 5 bytes is what identifies TLS
	if p.parseLen < TLS_HDRLEN {
		return false
	}
	t := int(p.parse[0])
	maj := int(p.parse[1])
	min := int(p.parse[2])
	l := (int(p.parse[3]) << 8) | int(p.parse[4])
	// Check if type is client hello (0x16)
	// Check if version is 0300 or 0301 or 0302
	// Check if hello fits in one buffer. Again, like we discussed in tcpParse(), if
	// we come across esoteric hellos that are huge, we need to come back and modify this check
	if t != 0x16 || maj != 3 || ((min != 0) && (min != 1) && (min != 2)) || (l > TCP_PARSE_SZ-TLS_HDRLEN) {
		p.tls.notTls = true
		return false
	}
	// Ok so we know its tls client hello, now we are just waiting to read all the hello bytes
	if p.parseLen != TLS_HDRLEN+l {
		return false
	}

	var hello = tlsx.ClientHello{}
	err := hello.Unmarshall(p.parse[0:p.parseLen])
	if err != nil {
		p.tls.notTls = true
		return false
	}
	// The TLS SNI is our service name
	p.service = hello.SNI

	return true
}

func tcpParse(p *NetConn) {
	for {
		// Cant wait for ever to decide if its plain text http or if its tls SNI
		p.conn.SetReadDeadline(time.Now().Add(TCP_PARSE_TIMEOUT))
		n, err := p.conn.Read(p.parse[p.parseLen:])
		prev := p.parseLen
		p.parseLen += n
		if parseTLS(p) || parseHTTP(p, prev) {
			break
		}
		if err != nil {
			// timed out (or even channel closed), we fall back to just using the
			// ip address as the service name
			break
		}
		if p.parseLen == len(p.parse) {
			// well, I am not sure if we can expect the client hello/http headers to
			// fit in one TCP_PARSE_SZ buffer. If there are esoteric hellos/headers that need
			// more space, we will need to come back here and increase the size of
			// the parse buf allocated to the Proxy
			break
		}
	}

	// If we cant find a service name, the destination IP is the service name
	if p.service == "" {
		p.service = p.dest
	}
	flow := p.hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
	flow.DestSvc = p.service
	// Cancel the timeouts
	p.conn.SetReadDeadline(time.Time{})
	// Parsing activity completed (succesfully or unsuccesfully)
	close(p.parsed)
}

func NewClient(ctx context.Context, lg *log.Logger, proto string, dest string, port uint32) *NetConn {
	return &NetConn{lg: lg, ctx: ctx, proto: proto, dest: dest, port: port}
}

func (n *NetConn) Listen(c chan common.NxtStream) {
	addr := fmt.Sprintf("%s:%d", n.dest, n.port)
	ln, err := net.Listen(n.proto, addr)
	if err != nil {
		return
	}
	Suuid := uuid.New()
	for {
		conn, err := ln.Accept()
		if err == nil {
			remote := strings.Split(conn.RemoteAddr().String(), ":")
			port, e := strconv.Atoi(remote[1])
			if e == nil {
				parse := make([]byte, TCP_PARSE_SZ)
				parsed := make(chan struct{})
				// We change the dest and port in the accepted stream to the "remote" values
				// The local values are available in the parent NetConn n
				stream := NetConn{
					lg: n.lg, ctx: n.ctx, proto: n.proto, dest: remote[0], port: uint32(port),
					conn: conn, closed: false, server: true, parse: parse, parsed: parsed,
				}
				stream.hdr = makeHdr(&stream, n.dest, n.port)
				if n.proto == "tcp" {
					go tcpParse(&stream)
				} else {
					// TODO: No idea how to parse UDP !
					close(stream.parsed)
				}
				c <- common.NxtStream{Parent: Suuid, Stream: &stream}
			} else {
				n.lg.Println("Bad remote address", remote)
			}
		}
	}
}

func (n *NetConn) Dial(sChan chan common.NxtStream) *common.NxtError {
	addr := fmt.Sprintf("%s:%d", n.dest, n.port)
	var e error
	n.conn, e = net.Dial(n.proto, addr)
	if e != nil {
		return common.Err(common.CONNECTION_ERR, e)
	}
	return nil
}

func (n *NetConn) Close() *common.NxtError {
	if !n.IsClosed() {
		if n.conn != nil {
			n.conn.Close()
		}
		n.closed = true
	}
	return nil
}

func (n *NetConn) IsClosed() bool {
	return n.closed
}

// To support close cascading, we need an asynchronous way of knowing that
// this stream is closed - asychronous meaning that without anyone doing a
// Read() or Write(), we should know that this stream is closed. Examples
// are the websocket and http2 transports, those streaming protocols have
// state machines that figure out a stream is closed, at which point that
// information is cascaded. So if we need to support this, we need some way
// of asynchronously knowing that this stream is closed
func (n *NetConn) CloseCascade(cascade common.Transport) {
	panic("This stream does not support close cascading!")
}

func (n *NetConn) NewStream(hdr http.Header) common.Transport {
	panic("NetConn has no streams!")
}

func (n *NetConn) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {
	if n.closed {
		return common.Err(common.CONNECTION_ERR, nil)
	}
	for _, b := range buf {
		// net.conn is assumed to be blocking, so it has to write all thats asked to be written
		_, err := n.conn.Write(b)
		if err != nil {
			return common.Err(common.CONNECTION_ERR, err)
		}
	}
	return nil
}

func (n *NetConn) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	if n.closed {
		return nil, nil, common.Err(common.CONNECTION_ERR, nil)
	}

	// Wait till we have identified what the tcp stream is, basically we
	// try to figure out if its TLS and if so get the SNI field, or if its
	// plain http we get the host field
	if n.server {
		select {
		case <-n.parsed:
		}
	}

	// Return a copy of the hdr
	var hdr nxthdr.NxtHdr
	var hdrP *nxthdr.NxtHdr = nil
	if n.hdr != nil {
		hdr = *n.hdr
		hdrP = &hdr
	}

	// We have some data buffered as part of the tcp parsing, return that first
	// and read the next set of data in the next call to Read()
	if n.parseLen != 0 {
		l := n.parseLen
		n.parseLen = 0
		buf := net.Buffers{n.parse[0:l]}
		n.parse = nil
		return hdrP, buf, nil
	}

	buf := make([]byte, common.MAXBUF)
	r, err := n.conn.Read(buf[0:common.MAXBUF])
	if err != nil {
		if err != io.EOF || r == 0 {
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
		}
	}
	return hdrP, net.Buffers{buf[0:r]}, nil
}

func (n *NetConn) SetReadDeadline(t time.Time) *common.NxtError {
	e := n.conn.SetReadDeadline(t)
	if e != nil {
		return common.Err(common.GENERAL_ERR, e)
	}
	return nil
}

func (n *NetConn) Timing() common.TimeInfo {
	return common.TimeInfo{}
}
