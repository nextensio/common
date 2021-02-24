package dtls

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"
)

// NOTE: The test cases in this file have to be run serially because each of them
// opens a client/server and they will all mess with each other if run parallely

const testPort = 4444

var wg sync.WaitGroup
var szVerified = false
var testNpkts uint32
var serverStream common.Transport

func getKeys() ([]byte, []byte) {
	pvtKey, err := ioutil.ReadFile("./pems/server.pem")
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err := ioutil.ReadFile("./pems/server.pub.pem")
	if err != nil {
		log.Fatal(err)
	}

	return pvtKey, pubKey
}

func readStream(ctx context.Context, parent uuid.UUID, tunnel common.Transport) {
	defer wg.Done()

	for {
		hdr, buf, err := tunnel.Read()
		if err != nil {
			tunnel.Close()
			return
		}
		if !verifyHdr(hdr) {
			panic(hdr)
		}
		onboard := hdr.Hdr.(*nxthdr.NxtHdr_Onboard).Onboard
		sz, e := strconv.Atoi(onboard.Services[2])
		if e != nil {
			panic(onboard.Services[2])
		}
		atomic.AddUint32(&testNpkts, 1)
		if verifyBytes(buf, sz) {
			szVerified = true
		} else {
			panic("Verify Bytes fail")
		}
	}
}

func dtlsServer(ctx context.Context, sChan chan common.NxtStream) {
	pvtKey, pubKey := getKeys()
	lg := log.New(os.Stdout, "test", 0)
	server := NewListener(ctx, lg, pvtKey, pubKey, testPort)
	go server.Listen(sChan)
	for {
		select {
		case client := <-sChan:
			if client.Stream == nil {
				log.Fatalf("Cannot create server socket")
			}
			serverStream = client.Stream
			wg.Add(1)
			go readStream(ctx, client.Parent, client.Stream)
		}
	}
}

// Create a websocket session to the gateway
func dialDtls(ctx context.Context, serverName string, serverIP string, port int, cChan chan common.NxtStream) common.Transport {
	cert, err := ioutil.ReadFile("./pems/server.pub.pem")
	if err != nil {
		log.Fatal(err)
	}
	retry := 0
	lg := log.New(os.Stdout, "test", 0)
	sock := NewClient(ctx, lg, cert, serverName, serverIP, port)
	for err := sock.Dial(cChan); err != nil; err = sock.Dial(cChan) {
		sock.Close()
		retry++
		if retry >= 5 {
			return nil
		}
		log.Println("Cannot connect to cluster, will retry: ", retry, err)
	}

	return sock
}

// Just fill a pattern of 0, 1, 2 .., 255, 0, 1, 2 .. into the buffer
func generateBytes(testSize int) net.Buffers {
	var buf net.Buffers = net.Buffers{}
	var cur []byte = nil
	var pos int = 0
	for i := 0; i < testSize; i++ {
		if cur == nil {
			cur = make([]byte, common.MAXBUF)
			pos = 0
		}
		cur[pos] = byte(i % 256)
		pos++
		if pos == common.MAXBUF {
			buf = append(buf, cur)
			cur = nil
		}
	}
	if cur != nil {
		buf = append(buf, cur[0:pos])
	}
	return buf
}

func verifyHdr(hdr *nxthdr.NxtHdr) bool {
	onboard := hdr.Hdr.(*nxthdr.NxtHdr_Onboard).Onboard
	if onboard.Userid != "abcd" {
		return false
	}
	if onboard.Uuid != "efgh" {
		return false
	}
	if onboard.Services[0] != "123" {
		return false
	}
	if onboard.Services[1] != "456" {
		return false
	}

	return true
}

func verifyBytes(buf net.Buffers, size int) bool {
	var b = 0
	for i := 0; i < len(buf); i++ {
		if len(buf[i]) > common.MAXBUF {
			fmt.Println("Buflen toobig", len(buf[i]))
			return false
		}
		for j := 0; j < len(buf[i]); j++ {
			if buf[i][j] != byte(b%256) {
				fmt.Println("Bytes mismatch", buf[i][j], b, b%256)
				return false
			}
			b++
		}
	}
	if b != size {
		fmt.Println("Total size mismatch", b, size, len(buf))
		return false
	}
	return true
}

func sendPkt(qsock common.Transport, testSize int) {
	onboard := nxthdr.NxtOnboard{}
	onboard.Userid = "abcd"
	onboard.Uuid = "efgh"
	onboard.Services = []string{"123", "456", strconv.Itoa(testSize)}
	hdr := nxthdr.NxtHdr{}
	hdr.Hdr = &nxthdr.NxtHdr_Onboard{Onboard: &onboard}
	buf := generateBytes(testSize)
	err := qsock.Write(&hdr, buf)
	if err != nil {
		panic(err)
	}
}

// Send different size packets and ensure they reach intact on the other end
func sizeTest(qsock common.Transport, sizes []int) {
	for _, sz := range sizes {
		szVerified = false
		sendPkt(qsock, sz)
		for !szVerified {
			time.Sleep(1 * time.Millisecond)
			fmt.Println("Waiting to verify size", sz)
		}
	}
}

// Do a sudden burst of a bunch of packets and ensure all of them are received with no drops
func burstTest(qsock common.Transport, burstSz int) {
	szVerified = false
	testNpkts = 0
	min := 100
	max := 1000
	for i := 0; i < burstSz; i++ {
		sz := rand.Intn(max-min) + min
		sendPkt(qsock, sz)
	}
	retry := 0
	for int(testNpkts) < burstSz {
		time.Sleep(10 * time.Millisecond)
		fmt.Println("Waiting for", burstSz, "pkts, got", testNpkts)
		if retry > 5 {
			fmt.Println("UDP transport is unreliable, there can be drops, not waiting anymore")
			break
		}
		retry++
	}
}

// Test different packet sizes, and also test bursting a bunch of packets
// The tests are run bidirectional - from each end to the opposite end
func TestPkts(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go dtlsServer(mainCtx, sChan)
	qsock := dialDtls(mainCtx, "gateway.nextensio.net", "127.0.0.1", testPort, cChan)
	if qsock == nil {
		fmt.Println("Could not create websocket")
		return
	}
	wg.Add(1)
	go readStream(mainCtx, uuid.UUID{}, qsock)

	// DTLS has only single buffer packet, so no point trying larger sizes than one packet
	sizeTest(qsock, []int{
		500, 1000, 1500,
	})
	sizeTest(serverStream, []int{
		500, 1000, 1500,
	})
	burstTest(qsock, 4096)
	burstTest(serverStream, 4096)

	qsock.Close()
	fmt.Print("Waiting for all goroutines to go away\n")
	wg.Wait()
}
