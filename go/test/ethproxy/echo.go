package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/transport/ethernet"
	proxy "gitlab.com/nextensio/common/go/transport/l3proxy"
)

func defaultIntf() (string, net.IP) {

	file, err := os.Open("/proc/net/route")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// get field containing gateway address
		tokens := strings.Split(scanner.Text(), "\t")

		flags := "0x" + tokens[3]
		f, _ := strconv.ParseInt(flags, 0, 64)
		if f&0x3 == 0 { // RTF_GATEWAY|RTF_UP
			continue
		}

		gatewayHex := "0x" + tokens[2]
		// cast hex address to uint32
		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)

		// make net.IP address from uint32
		ipd32 := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipd32, d32)
		return tokens[0], ipd32
	}

	return "", nil
}

func myIP(device string) net.IP {
	intf, err := net.InterfaceByName(device)
	if err != nil {
		return nil
	}

	var ip net.IP
	addrs, _ := intf.Addrs()
Loop:
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			// TODO: Handle IPv6
			if v.IP.To4() != nil {
				ip = v.IP.To4()
				break Loop
			}
		case *net.IPAddr:
			// TODO: Handle IPv6
			if v.IP.To4() != nil {
				ip = v.IP.To4()
				break Loop
			}
		}
	}
	// Cant find ip address of interface
	if len(ip) == 0 {
		return nil
	}

	return ip
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

// NOTE: This proxy needs to be run as sudo since it tries to access interfaces
// This proxy is going to scan for the default ethernet interface, typically
// this test proxy is run inside a docker container with just an eth0, so it
// will pick the eth0. Now from another container, we point its default route
// to be this container, and then from the other container we can use netcat
// to test by doing a netcat 3.4.5.6 80 and type something in and see it echoed back
func main() {
	mainCtx := context.Background()
	intf, nhop := defaultIntf()
	if nhop == nil {
		panic("Cannot find default interface")
	}
	ip := myIP(intf)
	if ip == nil {
		panic("Cannot find my ip")
	}
	lg := log.New(os.Stdout, "test", 0)
	e := ethernet.NewClient(mainCtx, lg, intf, nhop)
	c := make(chan common.NxtStream)
	e.Dial(c)
	p := proxy.NewListener(mainCtx, lg, e, ip)
	go p.Listen(c)
	for {
		select {
		case msg := <-c:
			fmt.Println("New stream")
			go proxyEcho(msg.Stream)
		}
	}
}
