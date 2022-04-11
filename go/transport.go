package common

import (
	"net"
	"net/http"
	"sync"
	"time"

	"gitlab.com/nextensio/common/go/messages/nxthdr"

	"github.com/google/gopacket"
	"github.com/google/uuid"
)

const (
	TCP  = 6
	UDP  = 17
	ICMP = 1
	HTTP = 0
)

const (
	// Just created
	TCP_INIT = iota
	// SYN sent
	TCP_SYN
	// SYN seen, SYN ACK seen
	TCP_SYN_ACK
	// SYN seen, SYN_ACK seen, ACK seen
	TCP_ACK
	// RESET or FIN seen
	TCP_CLOSED
)

// This is the number of bytes needed to encode the nextensio header length. 4 bytes should
// be plenty, we will never have a header that big !!
const MAXVARINT_BUF = 4

var LazyNoCopy = gopacket.DecodeOptions{Lazy: true, NoCopy: true}

type NxtBuf struct {
	refcount int32
	Buf      []byte
	pool     *sync.Pool
}

type NxtBufs struct {
	Slices net.Buffers
	Bufs   []*NxtBuf
}

type TimeInfo struct {
	Rtt uint64
}

// The concept of a "parent" is mostly useful/used on the server side. On the server side,
// the Listen/Accept will accept a "session" from an endpoint (agent/connector/pod), and then
// that endpoint will create more streams over that session. But to keep things simple, we
// do not expose the "session" anywhere, all the listen/accept APIs return streams and deal
// with just streams. So the "Parent" uuid just tells us that "all these sessions are associated"
// with the same Parent session xyz
type NxtStream struct {
	Parent uuid.UUID
	Stream Transport
	Http   *http.Header
}

// A nextensio transport consists of "sessions" and "streams". Think of a session to be
// a TCP/UDP connection. And think of a stream to be channels that are multiplexed over the
// same TCP/UDP connection. The concept of sessions and streams as the same as in the Quic
// protocol or grpc protocol or rsocket protocol etc.. Also a transport shall have the standard
// nomenclature of a "client" who initiates a session and a "server" who listens/accepts
// sessions. But that is about sessions, once a session is established, either client or server
// should be able to initiate a stream to the other end by calling NewStream().
//
// The APIs here have been modelled mostly after the golang-Quic APIs which have the standard
// dial/listen etc.. and the stream specific NewStream(). The general programming model is that
// each stream will have its own goroutine reading data from the stream, and it can write to
// any number of other streams. The reads and writes are all blocking in nature. Again this not
// any model we are proposing, the entire golang net.Conn framework follows this standard model
//
// NOTE on net.Buffers: As we can see below, the Read() and Write() APIs work with NxtBufs / net.Buffers,
// which assumes that data is split into multiple chunks and not necessarily always one big buffer.
// Now why is that ?? This is nothing new - its the age old problem in packet forwarding. We will
// end up queueing these buffers in different places when we hit flow control. And in that case,
// if all our buffers are the same huge size, then it means we will eat up a TON of memory if not
// all the buffers are completely filled with data. And hence the use of net.Buffers here to give
// the option of splitting data into multiple smaller buffers.
// And for those who might complain or raise concerns on whether this is needed: well these APIs
// do not prevent you from using one big buffer, thats effectively a net.Buffer with one buffer,
// if you feel thats right for your transport by all means do so. But the API/design has to provide
// the option of having a multi buffer data
type Transport interface {
	// Listen is called on the server, it will wait for an incoming client connection,
	// and returns (via the channel) a transport that corresponds to the client
	// Listen will block till a new client connection comes in, so typically we
	// end up spawning a goroutine calling Listen()
	Listen(chan NxtStream)

	// The call to Dial() will block and return a stream from client to server once its available.
	// Dial() will also spawn a goroutine for accepting streams initiated by server to client,
	// and will write those streams to the channel
	Dial(chan NxtStream, method string) *NxtError

	// If this is a multiplexed transport, NewStream will create a "stream" that gets multiplexed
	// over the same "session" - the concept of streams and sessions is the same as in QUIC or GRPC
	// If this is not a multiplexed tranposrt, NewStream will just return the input stream, ie nothing
	// "new" gets created. This api is a blocking API.
	//
	// Parameters:
	// first parameter http.Header: The new stream might want some additional headers to initiate
	// the stream. If none required for the particular transport, this can be supplied as nil too
	NewStream(http.Header) Transport

	// Close this stream. Close can also be called from multiple goroutines parallely, so Close()
	// should be implemented in a thread safe way. Also close can be called any number of times
	// on a session and it should not cause any problems or crash etc..
	Close() *NxtError
	// Is this stream closed ?
	IsClosed() bool

	// If this stream is closed, also close the stream mentioned in the parameter to this API.
	// A typical I/O goroutine is as below
	// go doIO() {
	//     data = rx.Read()
	//     tx.Write()
	// }
	// So here, the rx.Read() will block, and the goroutine will not know if the tx stream is
	// closed. If the tx stream is closed, the entire goroutine should exit even if there is
	// no further Rx data. This can be achieved by saying tx.CloseCascade(rx), so that if the
	// tx stream's state machine finds it closed, it will also close rx and then the whole
	// goroutine will unblock and exit
	CloseCascade(Transport)

	// Set timeout for read, the Read() call returns with a net.Timeout error after the timeout
	SetReadDeadline(time.Time) *NxtError

	//
	// Return Values:
	// first return: the Nextsio header information associated with the payload
	// second return: the array of buffers containing the data
	// third return error: if error is not nil, the read failed
	//
	// MultiThreading Note: Read() for a transport is expected to be invoked only from one goroutine,
	// Reading same transport from multiple goroutines will produce unexpected results
	//
	// NOTE: The Read() API should NOT return io.EOF along with non-zero bytes of data. The net.conn
	// framework in go does allow that, but here we enforce that any non-nil error returned means
	// that there is no valid data returned. So wherever we use Read() on net.Conn, we need to check
	// for io.EOF and data len != 0, but with nextensio transport we dont need to check that
	Read() (*nxthdr.NxtHdr, *NxtBufs, *NxtError)

	// Parameters:
	// first parameter nxthdr: the nextensio headers to push before the payload
	// second parameter array of buffers:  the array of buffers containing data to write
	// NOTE: The transport has an option of using whatever mechanism to convey the
	// nxthdr information, it can use protobuf or it can use http headers or whatever
	// it deems appropriate for that transport.
	//
	// Return Values:
	// first return error: if error is not nil, then the write failed
	//
	// NOTE1: MultiThreading: Write() to a transport is expected to happen from multiple threads/goroutines,
	// the implementation should ensure that Write() is thread safe by taking proper locks of whatever
	// other mechanisms required for thread safety
	//
	// NOTE2: The buffer given to write is "consumed" by write, ie the writer cannot use that buffer
	// again, if they do, that will corrupt the data that gets sent
	Write(*nxthdr.NxtHdr, *NxtBufs) *NxtError

	Timing() TimeInfo
}
