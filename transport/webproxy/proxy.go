package webproxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
)

type Proxy struct {
	port   uint16
	conn   net.Conn
	closed bool
	header http.Header
}

func NewListener(port uint16) *Proxy {
	return &Proxy{port: port, header: http.Header{}}
}

func hijackHttp(p *Proxy, w http.ResponseWriter, r *http.Request) {
	for k, v := range r.Header {
		p.header[k] = v
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
	p.conn = conn
}

func (p *Proxy) Listen(c chan common.NxtStream) {
	addr := fmt.Sprintf(":%d", p.port)
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				w.WriteHeader(http.StatusOK)
				hijackHttp(p, w, r)
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

func makeHdr(p *Proxy) *nxthdr.NxtHdr {
	return &nxthdr.NxtHdr{}
}

func makeConnect(p *Proxy) []byte {
	return []byte{}
}

func (p *Proxy) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	// Send the initial connect headers on the first read
	if len(p.header) != 0 {
		connect := makeConnect(p)
		hdr := makeHdr(p)
		// Now reset the headers so its not sent again
		p.header = http.Header{}
		return hdr, net.Buffers{connect}, nil
	}
	buf := make([]byte, common.MAXBUF)
	n, err := p.conn.Read(buf)
	if err != nil {
		return nil, nil, common.Err(common.CONNECTION_ERR, err)
	}
	return makeHdr(p), net.Buffers{buf[0:n]}, nil
}
