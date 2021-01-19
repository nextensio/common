package ethernet

import (
	"net"
	"net/http"
	"time"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
)

type Ethernet struct {
	closed bool
}

func (e *Ethernet) Listen(c chan common.NxtStream) {
	return
}

func (e *Ethernet) Dial(sChan chan common.NxtStream) *common.NxtError {
	return nil
}

func (e *Ethernet) Close() *common.NxtError {
	e.closed = true
	return nil
}

func (e *Ethernet) IsClosed() bool {
	return e.closed
}

func (e *Ethernet) NewStream(hdr http.Header) common.Transport {
	return e
}

func (e *Ethernet) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {
	return nil
}

func (e *Ethernet) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	return nil, nil, nil
}

func (e *Ethernet) SetReadDeadline(t time.Time) *common.NxtError {
	return nil
}
