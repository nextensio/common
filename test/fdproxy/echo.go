package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"unsafe"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/transport/fd"
	"gitlab.com/nextensio/common/transport/proxy"
	"golang.org/x/sys/unix"
)

func createTun() int {
	nfd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	old, err := unix.FcntlInt(uintptr(nfd), unix.F_GETFL, 0)
	if err != nil {
		panic(err)
	}
	_, err = unix.FcntlInt(uintptr(nfd), unix.F_SETFL, old & ^unix.O_NONBLOCK)
	if err != nil {
		panic(err)
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	var flags uint16 = unix.IFF_TUN | unix.IFF_NO_PI
	name := []byte("tun0")
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags
	fmt.Println(string(ifr[:unix.IFNAMSIZ]))
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(nfd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		panic(fmt.Errorf("ioctl errno: %d", errno))
	}

	return nfd
}

func proxyEcho(p common.Transport) {
	for {
		hdr, data, err := p.Read()
		if err != nil {
			log.Println("Stream close, Proxy read error", err)
			return
		}
		err = p.Write(hdr, data)
		if err != nil {
			log.Println("Stream close, Proxy write err", err)
			return
		}
	}
}

// NOTE: This proxy needs to be run as sudo since it tries to create interfaces
// We expect the user to do the following once this proxy runs
// 1. ifconfig tun0 up
// 2. ifconfig tun0 1.1.1.1 netmask 255.255.255.0
// 3. route add default gw 1.1.1.1
// At this point you can do a netcat 3.4.5.6 80 and type something in
// and see it echoed back
func main() {
	mainCtx := context.Background()
	nfd := createTun()
	f := fd.NewClient(mainCtx, uintptr(nfd))
	c := make(chan common.NxtStream)
	f.Dial(c)
	p := proxy.NewListener(f, net.ParseIP("1.1.1.1"))
	go p.Listen(c)
	for {
		select {
		case msg := <-c:
			fmt.Println("New stream")
			go proxyEcho(msg.Stream)
		}
	}
}
