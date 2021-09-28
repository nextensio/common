package nhttp2

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
)

// NOTE: The test cases in this file have to be run serially because each of them
// opens a client/server and they will all mess with each other if run parallely

var testPort = 4444
var wg sync.WaitGroup
var szVerified = false
var testNpkts uint32
var slock sync.Mutex
var serverStream []common.Transport

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

func http2sockServer(ctx context.Context, encrypted bool, sChan chan common.NxtStream) {
	defer wg.Done()
	var pvtKey []byte
	var pubKey []byte
	if encrypted {
		pvtKey, pubKey = getKeys()
	}
	lg := log.New(os.Stdout, "test", 0)
	server := NewListener(ctx, lg, pvtKey, pubKey, testPort, nil)
	go server.Listen(sChan)
	for {
		select {
		case client := <-sChan:
			if client.Stream == nil {
				log.Fatalf("Cannot create server socket")
			}
			slock.Lock()
			serverStream = append(serverStream, client.Stream)
			slock.Unlock()
			wg.Add(1)
			go readStream(ctx, client.Parent, client.Stream)
		}
	}
}

// Create a http2socket session to the gateway
func dialHttp2sock(ctx context.Context, encrypted bool, serverName string, serverIP string, port int, cChan chan common.NxtStream, clocksync int) common.Transport {
	var cert []byte
	if encrypted {
		var err error
		cert, err = ioutil.ReadFile("./pems/server.pub.pem")
		if err != nil {
			log.Fatal(err)
		}
	}
	retry := 0
	hdrs := make(http.Header)
	lg := log.New(os.Stdout, "test", 0)
	sock := NewClient(ctx, lg, cert, serverName, serverIP, port, hdrs, nil, 0, clocksync)
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

func sendPkt(hsock common.Transport, testSize int) {
	onboard := nxthdr.NxtOnboard{}
	onboard.Userid = "abcd"
	onboard.Uuid = "efgh"
	onboard.Services = []string{"123", "456", strconv.Itoa(testSize)}
	hdr := nxthdr.NxtHdr{}
	hdr.Hdr = &nxthdr.NxtHdr_Onboard{Onboard: &onboard}
	buf := generateBytes(testSize)
	err := hsock.Write(&hdr, buf)
	if err != nil {
		panic(err)
	}
}

// Send different size packets and ensure they reach intact on the other end
func sizeTest(hsock common.Transport, sizes []int) {
	for _, sz := range sizes {
		szVerified = false
		sendPkt(hsock, sz)
		for !szVerified {
			time.Sleep(1 * time.Millisecond)
			fmt.Println("Waiting to verify size", sz)
		}
	}
}

// Do a sudden burst of a bunch of packets and ensure all of them are received with no drops
func burstTest(hsock common.Transport, burstSz int) {
	szVerified = false
	testNpkts = 0
	min := 500
	max := 15500
	for i := 0; i < burstSz; i++ {
		sz := rand.Intn(max-min) + min
		sendPkt(hsock, sz)
	}
	for int(testNpkts) < burstSz {
		time.Sleep(10 * time.Millisecond)
		fmt.Println("Waiting for", burstSz, "pkts, got", testNpkts)
	}
}

// Plain text HTTP2: Test different packet sizes, and also test bursting a bunch of packets
// The tests are run bidirectional - from each end to the opposite end
func Test1PktsPlainText(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go http2sockServer(mainCtx, false, sChan)
	time.Sleep(time.Second)
	hsock := dialHttp2sock(mainCtx, false, "gateway.nextensio.net", "127.0.0.1", testPort, cChan, 10)
	if hsock == nil {
		fmt.Println("Could not create http2socket")
		return
	}
	sizeTest(hsock, []int{
		1000, common.MAXBUF, common.MAXBUF + 1, 2 * common.MAXBUF,
		2*common.MAXBUF + 1, 2*common.MAXBUF + 100, 4*common.MAXBUF + 123, 7*common.MAXBUF + 100},
	)

	burstTest(hsock, 4096)

	hsock.Close()
	fmt.Print("Waiting for all goroutines to go away\n")
	wg.Wait()
}

// Test different packet sizes, and also test bursting a bunch of packets
// The tests are run bidirectional - from each end to the opposite end
func Test2Pkts(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go http2sockServer(mainCtx, true, sChan)
	time.Sleep(time.Second)
	hsock := dialHttp2sock(mainCtx, true, "gateway.nextensio.net", "127.0.0.1", testPort, cChan, 10)
	if hsock == nil {
		fmt.Println("Could not create http2socket")
		return
	}
	sizeTest(hsock, []int{
		1000, common.MAXBUF, common.MAXBUF + 1, 2 * common.MAXBUF,
		2*common.MAXBUF + 1, 2*common.MAXBUF + 100, 4*common.MAXBUF + 123, 7*common.MAXBUF + 100},
	)

	burstTest(hsock, 4096)

	hsock.Close()
	fmt.Print("Waiting for all goroutines to go away\n")
	wg.Wait()
}

func streamsTest(streams []common.Transport) {
	for _, hsock := range streams {
		szVerified = false
		sendPkt(hsock, 1000)
		for !szVerified {
			//fmt.Println("Waiting to verify size on stream", i)
			time.Sleep(1 * time.Millisecond)
		}
	}
}

// Test ability to create and delete streams from the client side
func Test3ClientStreams(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go http2sockServer(mainCtx, true, sChan)
	time.Sleep(time.Second)
	hsock := dialHttp2sock(mainCtx, true, "gateway.nextensio.net", "127.0.0.1", testPort, cChan, 0)
	if hsock == nil {
		fmt.Println("Could not create http2socket")
		return
	}

	streams := []common.Transport{hsock}
	for i := 0; i < 9; i++ {
		h := hsock.NewStream(nil)
		streams = append(streams, h)
		cast := h.(*HttpStream)
		for cast.nthreads != 2 {
			fmt.Println("Stream", i, "waiting for 2 threads", cast.nthreads)
			time.Sleep(1 * time.Millisecond)
		}
	}
	sCast := serverStream[0].(*HttpStream)
	for sCast.listener.nthreads != 20 {
		fmt.Println("Expecting 20 threads, current is", sCast.listener.nthreads)
		time.Sleep(1 * time.Millisecond)
	}
	streamsTest(streams)

	// Verify the goroutines to go away on both server and client end
	for i := 0; i < 10; i++ {
		cast := streams[i].(*HttpStream)
		// One goroutine we added for the client.Do() and one that http2 lib has for the req.Body.Read()
		cthreads := cast.nthreads - 2
		sthreads := sCast.listener.nthreads - 2
		streams[i].Close()
		for cast.nthreads != cthreads {
			fmt.Println("Waiting for client", i, "thread count from", cast.nthreads, "to", cthreads)
			time.Sleep(1 * time.Millisecond)
		}
		for sCast.listener.nthreads != sthreads {
			fmt.Println("Waiting for server", i, "thread count from", sCast.nthreads, "to", sthreads)
			time.Sleep(1 * time.Millisecond)
		}
	}

	// all streams are closed, now a read/write should return error
	for i := 0; i < 10; i++ {
		hdr := &nxthdr.NxtHdr{}
		err := streams[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
		if err == nil {
			panic(i)
		}
		_, _, err = serverStream[i].Read()
		if err == nil {
			panic(i)
		}
	}
	fmt.Print("Waiting for all goroutines to go away\n")
	wg.Wait()
}

func totalClientStreams(streams []common.Transport) int {
	total := 0
	for i := 0; i < len(streams); i++ {
		cast := streams[i].(*HttpStream)
		total += int(cast.nthreads)
	}

	return total
}

// Test ability to create streams from the client side and delete streams from server side
// Remember we cannot create http2 streams from server to client
func Test4ClientStreamsServerClose(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go http2sockServer(mainCtx, true, sChan)
	time.Sleep(time.Second)
	hsock := dialHttp2sock(mainCtx, true, "gateway.nextensio.net", "127.0.0.1", testPort, cChan, 0)
	if hsock == nil {
		fmt.Println("Could not create http2socket")
		return
	}

	streams := []common.Transport{hsock}
	for i := 0; i < 9; i++ {
		h := hsock.NewStream(nil)
		streams = append(streams, h)
		cast := h.(*HttpStream)
		for cast.nthreads != 2 {
			fmt.Println("Stream", i, "waiting for 2 threads", cast.nthreads)
			time.Sleep(1 * time.Millisecond)
		}
	}
	sCast := serverStream[0].(*HttpStream)
	for sCast.listener.nthreads != 20 {
		fmt.Println("Expecting 20 threads, current is", sCast.listener.nthreads)
		time.Sleep(1 * time.Millisecond)
	}

	// Verify the goroutines to go away on both server and client end
	for i := 0; i < 10; i++ {
		// One goroutine we added for the client.Do() and one that http2 lib has for the req.Body.Read()
		cthreads := totalClientStreams(streams) - 2
		sthreads := sCast.listener.nthreads - 2
		serverStream[i].Close()
		for totalClientStreams(streams) != cthreads {
			fmt.Println("Waiting for client", i, "thread count from", totalClientStreams(streams), "to", cthreads)
			time.Sleep(1 * time.Millisecond)
		}
		for sCast.listener.nthreads != sthreads {
			fmt.Println("Waiting for server", i, "thread count from", sCast.nthreads, "to", sthreads)
			time.Sleep(1 * time.Millisecond)
		}
	}

	// all streams are closed, now a read/write should return error
	for i := 0; i < 10; i++ {
		hdr := &nxthdr.NxtHdr{}
		err := streams[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
		if err == nil {
			panic(i)
		}
		_, _, err = serverStream[i].Read()
		if err == nil {
			panic(i)
		}
	}
	fmt.Print("Waiting for all goroutines to go away\n")
	wg.Wait()
}

func Test5ClockSync(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go http2sockServer(mainCtx, false, sChan)
	time.Sleep(time.Second)
	hsock := dialHttp2sock(mainCtx, false, "gateway.nextensio.net", "127.0.0.1", testPort, cChan, 10)
	if hsock == nil {
		fmt.Println("Could not create http2socket")
		return
	}

	for len(serverStream) == 0 {
		time.Sleep(time.Second)
	}
	s := serverStream[0].(*HttpStream)
	c := hsock.(*HttpStream)
	// Give some time for RTT to accumulate
	time.Sleep(time.Second)

	if c.nthreads != 3 {
		fmt.Println("Total threads not expected", c.nthreads)
		panic(0)
	}

	// 10 ms interval means we should have 100 rtts, ie at least 80
	if len(c.rtts) < 80 || c.rtt == 0 {
		t.Error("Bad rtt counts", len(c.rtts), s.rtt)
		panic(0)
	}
	fmt.Println("Client rtt: ", c.Timing().Rtt, " Server rtt: ", s.Timing().Rtt, " Count: ", len(c.rtts))

	hsock.Close()
	time.Sleep(time.Second)

	fmt.Println("Waiting for all goroutines to go away")
	wg.Wait()
	for c.nthreads != 0 {
		fmt.Println("Waiting for all threads to go away")
		time.Sleep(100 * time.Millisecond)
	}
}
