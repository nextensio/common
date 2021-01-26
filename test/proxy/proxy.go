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

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/transport/ethernet"
	"gitlab.com/nextensio/common/transport/proxy"
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
	e := ethernet.NewClient(mainCtx, intf, nhop)
	c := make(chan common.NxtStream)
	e.Dial(c)
	p := proxy.NewListener(e, ip)
	go p.Listen(c)
	for {
		select {
		case msg := <-c:
			fmt.Println("New stream")
			go proxyEcho(msg.Stream)
		}
	}
}
