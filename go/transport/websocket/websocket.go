package websock

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
	"google.golang.org/protobuf/proto"
)

const (
	streamData   = 0
	streamClose  = 1
	streamWindow = 2
)

const (
	pongWait   = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10
)

// On the read front, gorilla websocket library is pretty un-optimized - it will first
// read into its own internal read buffer and then when we ask for data it will copy
// the data to our buffers - so there is a double copy. It need not have been that way,
// they should be able to just read into the buffers we provide. We might have to fix
// that some day. So till then, we provide a humongous buffer into which gorilla can
// just read in the entire data and then we can read it into our own smaller buffers. Note that
// even if this humongous buffer ends up being smaller than our max data size, its just fine,
// nothing goes wrong, gorilla just reads in multiple batches thats all.
//
// On the write front, we have an option to avoid the double copy and instead just let
// the library call the write systemcall multiple times, by using the WriteNext API. And
// that will avoid the double copy if it finds the data >= 2*buffer size, and hence the
// reason why the half sized write buffer here. Again, im sure we will have to do quite a
// bit of performance tuning work in the gorilla library, so these are by no means the
// set-in-stone values, it can and will change as and when we learn more.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  common.MAXBUF,
	WriteBufferSize: common.MAXBUF / 2,
}

// Streams will not get/send data of the same size always, so assuming we get
// at least MTU (1500) sized data at any point, and say window size is 16K, this will
// get us to 15K of data queued up for a stream. But if the stream sends too small data
// in a too bursty fashion, then well the stream wont be able to send data upto the
// window size. That in a way might be what we dont want either - ideally we dont want a stream
// thats sending bursty small sized data.
// NOTE: Its obvious why we cant set this number to randomly lage values, because obviously
// that means we will queue up a lot of data in memory. So this will impact how many streams
// we can have on the system given the memory we have
const dataQlen = 100

// The format of a data stream sent on this transport is as follows
// [protobuf header length][protobuf headers] [payload].
type webSession struct {
	server     bool
	wlock      sync.Mutex
	conn       *websocket.Conn
	nextStream uint64
	slock      sync.Mutex
	streams    map[uint64]*WebStream
	nthreads   int32
}

type nxtData struct {
	hdr  *nxthdr.NxtHdr
	data net.Buffers
}

type WebStream struct {
	ctx           context.Context
	lg            *log.Logger
	serverIP      string
	serverName    string
	port          int
	pvtKey        []byte
	pubKey        []byte
	caCert        []byte
	requestHeader http.Header
	stream        uint64
	session       *webSession
	closed        bool
	rxData        chan nxtData
	txData        chan nxtData
	sendClose     chan bool
	streamClosed  chan struct{}
	cascade       common.Transport
}

func NewListener(ctx context.Context, lg *log.Logger, pvtKey []byte, pubKey []byte, port int) *WebStream {
	return &WebStream{
		ctx: ctx, lg: lg, pvtKey: pvtKey, pubKey: pubKey, port: port,
	}
}

// requestHeader: These are the http headers that are sent from client to server when a new websocket is initiated
func NewClient(ctx context.Context, lg *log.Logger, cacert []byte, serverName string, serverIP string, port int, requestHeader http.Header) *WebStream {
	return &WebStream{
		ctx: ctx, lg: lg, caCert: cacert, serverName: serverName, serverIP: serverIP, port: port, requestHeader: requestHeader,
	}
}

func nxtRead(session *webSession) (uint64, *nxtData, int, *common.NxtError) {

	messageType, r, err := session.conn.NextReader()
	if err != nil {
		return 0, nil, 0, common.Err(common.CONNECTION_ERR, err)
	}
	if messageType != websocket.BinaryMessage {
		return 0, nil, 0, common.Err(common.CONNECTION_ERR, nil)
	}

	// Read in all the data. Note that the NextReader() does not necessarily
	// fill up the entire data in one read even though the buffer has space,
	// it might need multiple reads to fill up a buffer
	total := 0
	var bufs [][]byte
	buf := make([]byte, common.MAXBUF)
	data := &nxtData{data: net.Buffers{}, hdr: &nxthdr.NxtHdr{}}
	for {
		n, err := r.Read(buf[total:])
		total += n
		if err == io.EOF || total >= common.MAXBUF {
			bufs = append(bufs, buf[0:total])
			total = 0
			if err != io.EOF {
				buf = make([]byte, common.MAXBUF)
			} else {
				break
			}
		}
	}
	buf = nil

	// Decode the protobuf header. The protobuf header should fit in one buffer
	// And every message on this transport should at least have the nextensio
	// header even if there is no payload
	hdrLen, hbytes := binary.Uvarint(bufs[0][0:])
	if hbytes <= 0 {
		return 0, nil, 0, common.Err(common.GENERAL_ERR, nil)
	}
	datOff := hbytes + int(hdrLen)
	err = proto.Unmarshal(bufs[0][hbytes:datOff], data.hdr)
	if err != nil {
		return 0, nil, 0, common.Err(common.GENERAL_ERR, err)
	}
	data.data = append(net.Buffers{bufs[0][datOff:]}, bufs[1:]...)
	dtype := streamData
	// TODO: Flow control message type to be checked once its available
	if data.hdr.Streamop == nxthdr.NxtHdr_CLOSE {
		dtype = streamClose
	}

	return data.hdr.Streamid, data, dtype, nil
}

func nxtWriteData(stream *WebStream, data nxtData) *common.NxtError {

	// This is what identifies us as a stream to the other end
	data.hdr.Streamid = stream.stream
	data.hdr.Streamop = nxthdr.NxtHdr_NOOP

	// Encode nextensio header and the header length
	out, err := proto.Marshal(data.hdr)
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}
	hdrlen := len(out)
	var varint [common.MAXVARINT_BUF]byte
	plen := binary.PutUvarint(varint[0:], uint64(hdrlen))
	newbuf := make([]byte, plen+hdrlen)
	copy(newbuf[0:], varint[0:plen])
	copy(newbuf[plen:], out)

	stream.session.wlock.Lock()
	w, err := stream.session.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		stream.session.wlock.Unlock()
		return common.Err(common.GENERAL_ERR, err)
	}
	nbuf := append(net.Buffers{newbuf}, data.data...)
	_, err = nbuf.WriteTo(w)
	if err != nil {
		stream.session.wlock.Unlock()
		stream.lg.Println("Stream write error", stream.stream, err)
		return common.Err(common.GENERAL_ERR, err)
	}
	err = w.Close()
	if err != nil {
		stream.session.wlock.Unlock()
		stream.lg.Println("Stream write close error", stream.stream, err)
		return common.Err(common.GENERAL_ERR, err)
	}
	stream.session.wlock.Unlock()

	return nil
}

func nxtWriteClose(stream *WebStream) *common.NxtError {
	hdr := nxthdr.NxtHdr{Streamid: stream.stream, Streamop: nxthdr.NxtHdr_CLOSE}
	// Encode nextensio header and the header length
	out, err := proto.Marshal(&hdr)
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}
	hdrlen := len(out)
	var varint [common.MAXVARINT_BUF]byte
	plen := binary.PutUvarint(varint[0:], uint64(hdrlen))
	newbuf := make([]byte, plen+hdrlen)
	copy(newbuf[0:], varint[0:plen])
	copy(newbuf[plen:], out)

	stream.session.wlock.Lock()
	w, err := stream.session.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		stream.session.wlock.Unlock()
		return common.Err(common.GENERAL_ERR, err)
	}
	nbuf := net.Buffers{newbuf}
	_, err = nbuf.WriteTo(w)
	if err != nil {
		stream.session.wlock.Unlock()
		return common.Err(common.GENERAL_ERR, err)
	}
	err = w.Close()
	if err != nil {
		stream.session.wlock.Unlock()
		return common.Err(common.GENERAL_ERR, err)
	}
	stream.session.wlock.Unlock()

	return nil
}

func closeAllStreams(session *webSession) {
	session.slock.Lock()
	for _, v := range session.streams {
		v.Close()
	}
	session.slock.Unlock()
}

func sessionRead(ctx context.Context, lg *log.Logger, session *webSession, c chan common.NxtStream) {
	Suuid := uuid.New()
	for {
		sid, data, dtype, err := nxtRead(session)
		if err != nil {
			lg.Println("Session read error", err)
			closeAllStreams(session)
			session.conn.Close()
			return
		}
		session.slock.Lock()
		var stream *WebStream = session.streams[sid]
		session.slock.Unlock()
		if stream == nil {
			rxData := make(chan nxtData, dataQlen)
			txData := make(chan nxtData, dataQlen)
			sendClose := make(chan bool)
			streamClosed := make(chan struct{})
			stream = &WebStream{
				ctx: ctx, rxData: rxData, txData: txData, sendClose: sendClose, streamClosed: streamClosed,
				stream: sid, session: session, lg: lg,
			}
			session.slock.Lock()
			session.streams[sid] = stream
			session.slock.Unlock()
			c <- common.NxtStream{Parent: Suuid, Stream: stream}
			atomic.AddInt32(&session.nthreads, 1)
			go streamWrite(stream)
		}
		switch dtype {
		case streamData:
			// TODO: We should never end up blocking here. But read the comments above dataQlen
			// We can end up blocking here if theres a stream that sends a lot of small data. So we
			// should be monitoring this queue and reducing the window size when the queue hits a
			// threshold of say full upto 50% of dataQlen. Ie we should generate a window update
			// if one of the two conditions is met
			// 1. We have not received a lot of bytes but still this queue is close to filling up,
			//    like say 50% of the queue depth, so send a window update shrinking the window
			// 2. We are close to receiving all the bytes in the previously advertised window,
			//    like say we received 90% of the bytes, so send a window update expanding the window
			select {
			case stream.rxData <- *data:
			case <-stream.streamClosed:
			}
		case streamClose:
			stream.Close()
			// We delete the stream from the hashmap. Close must be the last message on this stream,
			// since we do not want this to be created again by another packet that comes after this
			// with a closed stream id
			session.slock.Lock()
			delete(session.streams, sid)
			session.slock.Unlock()
		case streamWindow:
			//TODO: we got a window update, use this to control when the transmit side can send data
		}
	}
}

func streamWrite(h *WebStream) {
	for {
		err := false
		select {
		case err = <-h.sendClose:
			// Drain all tx data before closing
		Loop:
			for {
				select {
				case data := <-h.txData:
					// TODO: check if we have window enough to send, otherwise block till we get enough window.
					// Blocking here will block the txData channel and will automatically block whoever is writing
					// to it etc.. and it will cascade that block all the way to the other end
					if nxtWriteData(h, data) != nil {
						err = true
						break Loop
					}
				default:
					err = true
					break Loop
				}
			}
		case data := <-h.txData:
			// TODO: check if we have window enough to send, otherwise block till we get enough window.
			// Blocking here will block the txData channel and will automatically block whoever is writing
			// to it etc.. and it will cascade that block all the way to the other end
			if nxtWriteData(h, data) != nil {
				err = true
			}
		}
		if err {
			if !h.closed {
				h.closed = true
				// Send a close message to the other end, this is the last message on this channel
				nxtWriteClose(h)
				// Wakeup all writers hung on txData channel
				close(h.streamClosed)
			}
			// Close is the last tx message on this channel and then we are done sending messages
			atomic.AddInt32(&h.session.nthreads, -1)
			return
		}
	}
}

func wsPing(session *webSession) {
	for {
		session.wlock.Lock()
		err := session.conn.WriteMessage(websocket.PingMessage, nil)
		session.wlock.Unlock()
		if err != nil {
			return
		}
		time.Sleep(pingPeriod)
	}
}

func wsEndpoint(h *WebStream, c chan common.NxtStream, w http.ResponseWriter, r *http.Request) {
	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}

	s, e := upgrader.Upgrade(w, r, nil)
	if e != nil {
		h.lg.Println("upgrade error", e)
		return
	}
	var session *webSession = &webSession{
		server:     true,
		conn:       s,
		nextStream: 0,
		streams:    make(map[uint64]*WebStream),
	}
	go sessionRead(h.ctx, h.lg, session, c)
	go wsPing(session)
}

func (h *WebStream) Listen(c chan common.NxtStream) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		wsEndpoint(h, c, w, r)
	})
	addr := ":" + strconv.Itoa(h.port)

	if len(h.pubKey) != 0 {
		tlsCert, err := tls.X509KeyPair(h.pubKey, h.pvtKey)
		if err != nil {
			panic(err)
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"nextensio-websocket"},
		}
		server := http.Server{
			Addr: addr, Handler: mux,
			TLSConfig: config,
		}
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			h.lg.Println("Http listen failed")
			return
		}
	} else {
		server := http.Server{
			Addr: addr, Handler: mux,
		}
		err := server.ListenAndServe()
		if err != nil {
			h.lg.Println("Http listen failed", err)
			return
		}
	}
}

func (h *WebStream) Dial(sChan chan common.NxtStream) *common.NxtError {

	addr := h.serverIP + ":" + strconv.Itoa(h.port)
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		ReadBufferSize:   common.MAXBUF,
		WriteBufferSize:  common.MAXBUF / 2,
	}
	var u url.URL

	if len(h.caCert) != 0 {
		certificate, err := selfsign.GenerateSelfSignedWithDNS(h.serverName, h.serverName)
		if err != nil {
			return common.Err(common.GENERAL_ERR, err)
		}
		rootCertificate, err := common.LoadCertificate(h.caCert)
		if err != nil {
			return common.Err(common.GENERAL_ERR, err)
		}
		certPool := x509.NewCertPool()
		cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
		if err != nil {
			return common.Err(common.GENERAL_ERR, err)
		}
		certPool.AddCert(cert)
		tlsConf := &tls.Config{
			Certificates: []tls.Certificate{certificate},
			RootCAs:      certPool,
			ServerName:   h.serverName,
			MinVersion:   tls.VersionTLS12,
			//InsecureSkipVerify: true,
		}
		dialer.TLSClientConfig = tlsConf
		u = url.URL{Scheme: "wss", Host: addr, Path: "/"}
	} else {
		u = url.URL{Scheme: "ws", Host: addr, Path: "/"}
	}

	s, _, err := dialer.Dial(u.String(), h.requestHeader)
	if err != nil {
		h.lg.Println("Cannot dial websocket", addr, err)
		return common.Err(common.CONNECTION_ERR, err)
	}

	var session *webSession = &webSession{
		server:     false,
		conn:       s,
		nextStream: 0,
		streams:    make(map[uint64]*WebStream),
	}
	session.streams[0] = h

	h.rxData = make(chan nxtData, dataQlen)
	h.txData = make(chan nxtData, dataQlen)
	h.sendClose = make(chan bool)
	h.streamClosed = make(chan struct{})
	h.session = session
	h.stream = 0

	go sessionRead(h.ctx, h.lg, session, sChan)
	atomic.AddInt32(&session.nthreads, 1)
	go streamWrite(h)

	return nil
}

// The closing protocol is as follows basically its a two-way handshake
// 1. We declare our end closed by setting the closed to true and waking up anyone
//    hung on rxData/txData channel
// 2. Now we have to let the other end know by sending a message that it too has to close.
//    This will be the last message from us on this channel
// 3. Then we will wait till the other end sends its last message on the channel to be a
//    close message, and on receiving that we will finally take the session out of the
//    hashtables/datastructures, because we know there wont be any more packets on that stream
//    from the other end
func (h *WebStream) Close() *common.NxtError {
	if h.session == nil {
		return nil
	}

	// Ideally this cascade close needs to happen only if the Close() is coming from
	// within the state machine here where the state machine decides to close the session.
	// If a user manually calls Close, the user can manually remember that they have to
	// cascade-close this session and do it themselves, but the semantics today is such
	// that state machine or manual, we cascade close anyways. And that will remain to be
	// the semantics because users are expecting that behaviour.
	if h.cascade != nil {
		h.cascade.Close()
	}

	select {
	case h.sendClose <- true:
		return nil
	case <-h.streamClosed:
		return nil
	}
}

func (h *WebStream) IsClosed() bool {
	return h.closed
}

func (h *WebStream) CloseCascade(cascade common.Transport) {
	h.cascade = cascade
}

func (h *WebStream) SetReadDeadline(time.Time) *common.NxtError {
	return nil
}

func (h *WebStream) NewStream(hdr http.Header) common.Transport {
	rxData := make(chan nxtData, dataQlen)
	txData := make(chan nxtData, dataQlen)
	sendClose := make(chan bool)
	streamClosed := make(chan struct{})
	sid := atomic.AddUint64(&h.session.nextStream, 1)
	// server has odd number streamids and client is even, just to prevent overlap
	if h.session.server {
		sid = sid*2 + 1
	} else {
		sid = sid * 2
	}
	stream := WebStream{
		rxData: rxData, txData: txData, sendClose: sendClose, streamClosed: streamClosed,
		stream: sid, session: h.session, lg: h.lg,
	}
	h.session.slock.Lock()
	h.session.streams[sid] = &stream
	h.session.slock.Unlock()
	atomic.AddInt32(&h.session.nthreads, 1)
	go streamWrite(&stream)
	return &stream
}

func (h *WebStream) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	select {
	case data := <-h.rxData:
		return data.hdr, data.data, nil
	case <-h.streamClosed:
		// Stream is closed, drain all Rx if any, before returning error
		select {
		case data := <-h.rxData:
			return data.hdr, data.data, nil
		default:
			return nil, nil, common.Err(common.CONNECTION_ERR, nil)
		}
	}
}

func (h *WebStream) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {

	// After the channel is closed, we might be able to queue up data on the txData
	// channel because it is a buffered channel, it will get cleaned up by golang GC,
	// but why let it queue up if we know channel is closed
	select {
	case <-h.streamClosed:
		// Stream is closed
		return common.Err(common.CONNECTION_ERR, nil)
	default:
	}

	select {
	case h.txData <- nxtData{data: buf, hdr: hdr}:
		return nil
	case <-h.streamClosed:
		// Stream is closed
		return common.Err(common.CONNECTION_ERR, nil)
	}
}
