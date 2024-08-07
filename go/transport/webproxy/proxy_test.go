package webproxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"testing"

	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
)

var pool common.NxtPool

const MAXBUF = 2048 * 3

// To try this proxy, do "go test" and then say the below for example
// https_proxy="http://127.0.0.1:8080" curl -k https://google.com
// Or just configure your browser to use 127.0.0.1:8080 as a proxy and
// just browse
func netToProxy(dest net.Conn, p common.Transport) {
	for {
		b := common.GetBuf(pool)
		n, err := dest.Read(b.Buf)
		if err != nil {
			fmt.Println("Error reading from dest", err)
			p.Close()
			return
		}
		e := p.Write(nil, &common.NxtBufs{Slices: net.Buffers{b.Buf[:n]}, Bufs: []*common.NxtBuf{b}})
		if e != nil {
			fmt.Println("Error writing to proxy", e)
			dest.Close()
			return
		}
	}
}

func proxyToNet(p common.Transport) {
	var dest net.Conn
	for {
		hdr, buf, err := p.Read()
		if err != nil {
			fmt.Println("Proxy read error")
			if dest != nil {
				fmt.Println("Close net conn")
				dest.Close()
			}
			return
		}
		flow := hdr.Hdr.(*nxthdr.NxtHdr_Flow).Flow
		if dest == nil {
			addr := fmt.Sprintf("%s:%d", flow.Dest, flow.Dport)
			var e error
			dest, e = net.Dial("tcp", addr)
			if e != nil {
				fmt.Println("Error dialling", addr, e)
				p.Close()
				return
			}
			go netToProxy(dest, p)
		}
		for _, b := range buf.Slices {
			_, err := dest.Write(b)
			if err != nil {
				fmt.Println("Error writing to dest", err)
				p.Close()
				return
			}
		}
	}
}
func TestProxy(t *testing.T) {
	pool = common.NewPool(MAXBUF)
	mainCtx := context.Background()
	lg := log.New(os.Stdout, "test", 0)
	p := NewListener(mainCtx, lg, pool, 8080)
	c := make(chan common.NxtStream)
	go p.Listen(c)
	for {
		select {
		case s := <-c:
			fmt.Println("New Session")
			go proxyToNet(s.Stream)
		}
	}
}
