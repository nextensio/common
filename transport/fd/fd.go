package fd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
)

// fd implements a raw packet device thats a file descriptor - it can be for example
// a tun interface to which all packet read writes are using a file descriptor. And
// all the vpnService (android) / networkExtension (ios) APIs also seems to return a
// file descriptor. That gives an idea where this can be used.
// TODO: Today the fd is assumed to provide a L3 ip packet, but it can be easily
// extended to also be aware of an L2 ethernet header if required. Just need to give
// some l2 info to the NewClient when fd is created.
//
// NOTE: the fd is assumed to be in blocking more. That is, if we ask some bytes to
// be written to it, it will block till all the bytes are written. And if we as to
// read from the fd, it will block till there is at least one byte to return. So if
// we are getting an fd from android vpnservice for example, we would have to call
// vpnService Builder setBlocking() to make sure that fd is blocking, and whatever
// equivalent on ios networkExtension and windows etc..
type Fd struct {
	f      *os.File
	closed bool
}

func NewClient(ctx context.Context, fd uintptr) *Fd {
	f := os.NewFile(fd, "pipe")
	return &Fd{f: f}
}

func (f *Fd) Listen(c chan common.NxtStream) {
	// fd has no server and listen etc.., just Dial which is equivalent of Open()
	panic("Call dial on fd")
}

func (f *Fd) Dial(sChan chan common.NxtStream) *common.NxtError {
	// Its a no-op, nothing to do
	return nil
}

func (f *Fd) Close() *common.NxtError {
	f.Close()
	return nil
}

func (f *Fd) IsClosed() bool {
	return f.closed
}

func (f *Fd) NewStream(hdr http.Header) common.Transport {
	panic("Fd has no streams!")
}

func (f *Fd) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {
	if f.closed {
		return common.Err(common.CONNECTION_ERR, nil)
	}
	for _, b := range buf {
		// fd is assumed to be blocking, so it has to write all thats asked to be written
		n, err := f.f.Write(b)
		if err != nil {
			fmt.Println("Write", len(buf), n, err)
			return common.Err(common.CONNECTION_ERR, err)
		}
	}
	return nil
}

// Read the packet, strip ethernet headers and send it to the reader. Send
// only the ipv4 packets to the reader
func (f *Fd) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	if f.closed {
		return nil, nil, common.Err(common.CONNECTION_ERR, nil)
	}
	buf := make([]byte, common.MAXBUF)
	n, err := f.f.Read(buf)
	if err != nil {
		return nil, nil, common.Err(common.CONNECTION_ERR, err)
	}
	return nil, net.Buffers{buf[0:n]}, nil
}

func (f *Fd) SetReadDeadline(t time.Time) *common.NxtError {
	return nil
}