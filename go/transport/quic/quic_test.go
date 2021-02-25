package quic

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
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
)

// NOTE: The test cases in this file have to be run serially because each of them
// opens a client/server and they will all mess with each other if run parallely

const testPort = 4444

var wg sync.WaitGroup
var szVerified = false
var testNpkts uint32
var slock sync.Mutex
var serverStream []common.Transport
var clientStream []common.Transport

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

func quicServer(ctx context.Context, sChan chan common.NxtStream) {
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
			slock.Lock()
			serverStream = append(serverStream, client.Stream)
			slock.Unlock()
			wg.Add(1)
			go readStream(ctx, client.Parent, client.Stream)
		}
	}
}

// Create a websocket session to the gateway
func dialQuic(ctx context.Context, serverName string, serverIP string, port int, cChan chan common.NxtStream) common.Transport {
	cert, err := ioutil.ReadFile("./pems/server.pub.pem")
	if err != nil {
		log.Fatal(err)
	}
	retry := 0
	lg := log.New(os.Stdout, "test", 0)
	sock := NewClient(ctx, lg, cert, serverIP, port)
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
	min := 500
	max := 15500
	for i := 0; i < burstSz; i++ {
		sz := rand.Intn(max-min) + min
		sendPkt(qsock, sz)
	}
	for int(testNpkts) < burstSz {
		time.Sleep(10 * time.Millisecond)
		fmt.Println("Waiting for", burstSz, "pkts, got", testNpkts)
	}
}

// Test different packet sizes, and also test bursting a bunch of packets
// The tests are run bidirectional - from each end to the opposite end
func Test2Pkts(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go quicServer(mainCtx, sChan)
	qsock := dialQuic(mainCtx, "gateway.nextensio.net", "127.0.0.1", testPort, cChan)
	if qsock == nil {
		fmt.Println("Could not create websocket")
		return
	}
	wg.Add(1)
	go readStream(mainCtx, uuid.UUID{}, qsock)

	sizeTest(qsock, []int{
		1000, common.MAXBUF, common.MAXBUF + 1, 2 * common.MAXBUF,
		2*common.MAXBUF + 1, 2*common.MAXBUF + 100, 4*common.MAXBUF + 123, 7*common.MAXBUF + 100},
	)
	sizeTest(serverStream[0], []int{
		1000, common.MAXBUF, common.MAXBUF + 1, 2 * common.MAXBUF,
		2*common.MAXBUF + 1, 2*common.MAXBUF + 100, 4*common.MAXBUF + 123, 7*common.MAXBUF + 100},
	)
	burstTest(qsock, 4096)
	burstTest(serverStream[0], 4096)

	qsock.Close()
	fmt.Print("Waiting for all goroutines to go away\n")
	wg.Wait()
}

func streamsTest(streams []common.Transport) {
	for _, qsock := range streams {
		szVerified = false
		sendPkt(qsock, 1000)
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
	go quicServer(mainCtx, sChan)
	qsock := dialQuic(mainCtx, "gateway.nextensio.net", "127.0.0.1", testPort, cChan)
	if qsock == nil {
		fmt.Println("Could not create websocket")
		return
	}

	streams := []common.Transport{qsock}
	for i := 0; i < 9; i++ {
		s := qsock.NewStream(nil)
		streams = append(streams, s)
	}
	streamsTest(streams)

	for len(serverStream) != 10 {
		fmt.Println("Waiting for 10 server streams", len(serverStream))
		time.Sleep(1 * time.Millisecond)
	}

	// after streams are closed,  a read/write should return error
	for i := 0; i < 10; i++ {
		streams[i].Close()
	}
	for i := 0; i < 10; i++ {
		hdr := &nxthdr.NxtHdr{}
		err := streams[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
		if err == nil {
			panic(i)
		}
		_, _, err = streams[i].Read()
		if err == nil {
			panic(i)
		}
		err = serverStream[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
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

// Test ability to create streams from the client side and delete from server side
// NOTE & TODO: There seems to be a bug in the go-quic implementation where a server side close
// seems to behave wierd - first the server side read seems to hang, which we have noted as
// a bug in an earlier test case, and also the client side doesnt seem to be closed at all, the
// read writes from client side works just fine!
func Test3aClientStreamsServerClose(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go quicServer(mainCtx, sChan)
	qsock := dialQuic(mainCtx, "gateway.nextensio.net", "127.0.0.1", testPort, cChan)
	if qsock == nil {
		fmt.Println("Could not create websocket")
		return
	}

	streams := []common.Transport{qsock}
	for i := 0; i < 9; i++ {
		s := qsock.NewStream(nil)
		streams = append(streams, s)
	}
	streamsTest(streams)

	for len(serverStream) != 10 {
		fmt.Println("Waiting for 10 server streams", len(serverStream))
		time.Sleep(1 * time.Millisecond)
	}
	// after streams are closed,  a read/write should return error
	for i := 0; i < 10; i++ {
		serverStream[i].Close()
	}
	for i := 0; i < 10; i++ {
		hdr := &nxthdr.NxtHdr{}

		err := streams[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
		if err == nil {
			panic(i)
		}
		_, _, err = streams[i].Read()
		if err == nil {
			panic(i)
		}
		err = serverStream[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
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

func watchClientStreams(ctx context.Context, cChan chan common.NxtStream) {
	for {
		select {
		case client := <-cChan:
			if client.Stream == nil {
				log.Fatalf("Cannot create server socket")
			}
			wg.Add(1)
			slock.Lock()
			clientStream = append(clientStream, client.Stream)
			slock.Unlock()
			go readStream(ctx, uuid.UUID{}, client.Stream)
		}
	}
}

// Test ability to create and delete streams from the server side
func Test1ServerStreams(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go quicServer(mainCtx, sChan)
	qsock := dialQuic(mainCtx, "gateway.nextensio.net", "127.0.0.1", testPort, cChan)
	if qsock == nil {
		fmt.Println("Could not create websocket")
		return
	}
	clientStream = append(clientStream, qsock)

	// The server side stream will be created only if it gets a packet with that
	// streamid, send one pkt with streamid 0
	streamsTest([]common.Transport{qsock})

	wg.Add(1)
	go readStream(mainCtx, uuid.UUID{}, qsock)
	go watchClientStreams(mainCtx, cChan)

	streams := []common.Transport{serverStream[0]}
	for i := 0; i < 9; i++ {
		s := serverStream[0].NewStream(nil)
		streams = append(streams, s)
	}
	streamsTest(streams)

	for len(clientStream) != 10 {
		fmt.Println("Waiting for 10 server streams", len(clientStream))
		time.Sleep(1 * time.Millisecond)
	}
	// after streams are closed,  a read/write should return error
	for i := 0; i < 10; i++ {
		err := streams[i].Close()
		if err != nil {
			panic(err)
		}
	}
	for i := 0; i < 10; i++ {
		hdr := &nxthdr.NxtHdr{}
		err := streams[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
		if err == nil {
			panic(i)
		}
		/* Server side stream close is horribly buggy looks like, see comments in other
		test cases about the same. This read will just hang, and the client side write
		and read below works just fine whereas we expect it to fail
		_, _, err = streams[i].Read()
		if err == nil {
			panic(i)
		}
		err = clientStream[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
		if err == nil {
			panic(i)
		}
		_, _, err = clientStream[i].Read()
		if err == nil {
			panic(i)
		}*/
	}

	fmt.Print("Waiting for all goroutines to go away\n")
	wg.Wait()
}

// Test ability to create streams from the server side and delete them from client side
// NOTE & TODO: The server side streams closed on client side ends up with all kinds of
// issues where one end doesnt know the other end is closed. The go-quic lib needs to fix
// all this before we can revisit this
func Test1aServerStreamsClientClose(t *testing.T) {
	mainCtx := context.Background()
	cChan := make(chan common.NxtStream)
	sChan := make(chan common.NxtStream)
	go quicServer(mainCtx, sChan)
	qsock := dialQuic(mainCtx, "gateway.nextensio.net", "127.0.0.1", testPort, cChan)
	if qsock == nil {
		fmt.Println("Could not create websocket")
		return
	}
	clientStream = append(clientStream, qsock)

	// The server side stream will be created only if it gets a packet with that
	// streamid, send one pkt with streamid 0
	streamsTest([]common.Transport{qsock})

	wg.Add(1)
	go readStream(mainCtx, uuid.UUID{}, qsock)
	go watchClientStreams(mainCtx, cChan)

	streams := []common.Transport{serverStream[0]}
	for i := 0; i < 9; i++ {
		s := serverStream[0].NewStream(nil)
		streams = append(streams, s)
	}
	streamsTest(streams)

	for len(clientStream) != 10 {
		fmt.Println("Waiting for 10 server streams", len(clientStream))
		time.Sleep(1 * time.Millisecond)
	}
	// after streams are closed,  a read/write should return error
	for i := 0; i < 10; i++ {
		err := clientStream[i].Close()
		if err != nil {
			panic(err)
		}
	}
	for i := 0; i < 10; i++ {
		hdr := &nxthdr.NxtHdr{}
		err := streams[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
		if err == nil {
			panic(i)
		}
		_, _, err = streams[i].Read()
		if err == nil {
			panic(i)
		}
		err = clientStream[i].Write(hdr, net.Buffers{[]byte{1, 2, 3}})
		if err == nil {
			panic(i)
		}
		_, _, err = clientStream[i].Read()
		if err == nil {
			panic(i)
		}
	}

	fmt.Print("Waiting for all goroutines to go away\n")
	wg.Wait()
}
