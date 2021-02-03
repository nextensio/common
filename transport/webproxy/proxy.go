package webproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
)

type Proxy struct {
	ctx    context.Context
	lg     *log.Logger
	listen uint16
	conn   net.Conn
	src    string
	sport  uint16
	dest   string
	dport  uint16
	closed bool
	hdr    *nxthdr.NxtHdr
}

func NewListener(ctx context.Context, lg *log.Logger, port uint16) *Proxy {
	return &Proxy{ctx: ctx, lg: lg, listen: port}
}

func makeHdr(p *Proxy) *nxthdr.NxtHdr {
	flow := nxthdr.NxtFlow{}
	flow.Source = p.src
	flow.Sport = uint32(p.sport)
	flow.Dest = p.dest
	flow.Dport = uint32(p.dport)
	flow.DestAgent = p.dest
	flow.Type = nxthdr.NxtFlow_L4
	flow.Proto = common.TCP
	hdr := nxthdr.NxtHdr{}
	hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: &flow}
	return &hdr
}

func hijackHttp(p *Proxy, c chan common.NxtStream, w http.ResponseWriter, r *http.Request) {
	dhost, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		s := fmt.Sprintf("Unable get host/port from %s", r.Host)
		http.Error(w, s, http.StatusInternalServerError)
		return
	}
	dport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		s := fmt.Sprintf("Unable get host/port from %s", r.Host)
		http.Error(w, s, http.StatusInternalServerError)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Unable to hijack", http.StatusInternalServerError)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	shost, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		s := fmt.Sprintf("Unable get local host/port from %s", conn.RemoteAddr().String())
		http.Error(w, s, http.StatusInternalServerError)
		return
	}
	sport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		s := fmt.Sprintf("Unable get local host/port from %s", conn.RemoteAddr().String())
		http.Error(w, s, http.StatusInternalServerError)
		return
	}
	newP := Proxy{src: shost, sport: uint16(sport), dest: dhost, dport: uint16(dport), conn: conn}
	newP.hdr = makeHdr(&newP)
	c <- common.NxtStream{Parent: uuid.New(), Stream: &newP}
}

func (p *Proxy) Listen(c chan common.NxtStream) {
	addr := fmt.Sprintf(":%d", p.listen)
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				w.WriteHeader(http.StatusOK)
				hijackHttp(p, c, w, r)
			} else {
				// We just support connect requests here, not sure when/why
				// someone would send plain http to us, we "can" handle it
				// if required later
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	server.ListenAndServe()
}

func (p *Proxy) Dial(sChan chan common.NxtStream) *common.NxtError {
	panic("proxy is accept-only, no dial support")
}

func (p *Proxy) Close() *common.NxtError {
	if !p.closed {
		p.conn.Close()
		p.closed = true
	}
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
		_, err := p.conn.Write(b)
		if err != nil {
			return common.Err(common.CONNECTION_ERR, err)
		}
	}
	return nil
}

func (p *Proxy) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	buf := make([]byte, common.MAXBUF)
	n, err := p.conn.Read(buf)
	if err != nil {
		if err != io.EOF || n == 0 {
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
		}
	}
	return p.hdr, net.Buffers{buf[:n]}, nil
}

func (p *Proxy) SetReadDeadline(t time.Time) *common.NxtError {
	return nil
}
