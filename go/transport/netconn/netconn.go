package netconn

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
)

// NetConn dresses up a golang net.Conn as a common.Transport.
type NetConn struct {
	lg     *log.Logger
	ctx    context.Context
	proto  string
	dest   string
	port   uint32
	conn   net.Conn
	closed bool
}

func NewClient(ctx context.Context, lg *log.Logger, proto string, dest string, port uint32) *NetConn {
	return &NetConn{lg: lg, ctx: ctx, proto: proto, dest: dest, port: port}
}

func (n *NetConn) Listen(c chan common.NxtStream) {
	// TODO to implement a listen
	panic("We dont support Listen yet")
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
	if n.IsClosed() == false {
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
	buf := make([]byte, common.MAXBUF)
	r, err := n.conn.Read(buf[0:common.MAXBUF])
	if err != nil {
		if err != io.EOF || r == 0 {
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
		}
	}
	return nil, net.Buffers{buf[0:r]}, nil
}

func (n *NetConn) SetReadDeadline(t time.Time) *common.NxtError {
	e := n.conn.SetReadDeadline(t)
	if e != nil {
		return common.Err(common.GENERAL_ERR, e)
	}
	return nil
}
