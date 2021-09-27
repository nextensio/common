package nhttp2

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/proto"
)

// An http2 stream has the following limitations
// 1. It is unidirectional - from client to server
// 2. Client can write, server can read
//
// Of course http2 allows bidirectional streams, but the stream still has to be
// initiated from client to server, which is a limitatoin for nextensio use cases.
// From nextensio point of a view, a transport is bidirectional for us only if we
// can create streams from both directions (like http3/quic). So till then we limit
// the use case of http2 to scenarios where there is client as writer and server as
// reader.

type nxtData struct {
	hdr  *nxthdr.NxtHdr
	data net.Buffers
}

type httpBody struct {
	h      *HttpStream
	txChan chan nxtData
	bufs   net.Buffers
	idx    int
	off    int
	once   bool
}

// The format of a data stream sent on this transport is as follows
// [total length] [protbuf hdr length] [protobuf header] [payload]
// The total length field is a varint (variable integer) encoded length of what comes after it,
// excluding the size used up for encoding total length itself.
// The protobuf header length varint encodes the size of the protobuf header
// The protobuf header itself has all nextensio informatoin
// The payload is the actual application data
type HttpStream struct {
	ctx           context.Context
	lg            *log.Logger
	httpServer    *http.Server
	serverIP      string
	serverName    string
	port          int
	pvtKey        []byte
	pubKey        []byte
	caCert        []byte
	requestHeader http.Header
	streamClosed  chan struct{}
	closed        bool
	closeLock     sync.Mutex
	server        bool
	primary       bool
	serverBody    io.ReadCloser
	rxData        chan nxtData
	txData        httpBody
	sChan         chan common.NxtStream // unused
	nthreads      int32
	totThreads    *int32
	listener      *HttpStream
	cascade       common.Transport
	client        *http.Client
	addr          string
	sid           uuid.UUID
	rttTotal      *uint64
	rttCnt        *int
	clocksync     int
}

type Timing struct {
	Uuid       uuid.UUID `json:"uuid"`
	ServerTime uint64    `json:"servertime"`
	ClientTime uint64    `json:"clienttime"`
	RttTotal   uint64    `json:"rtttotal"`
	RttCount   int       `json:"rttcnt"`
}

var sessionLock sync.RWMutex
var sessions map[uuid.UUID]*HttpStream

func NewListener(ctx context.Context, lg *log.Logger, pvtKey []byte, pubKey []byte, port int, totThreads *int32) *HttpStream {
	return &HttpStream{
		ctx: ctx, lg: lg, pvtKey: pvtKey, pubKey: pubKey, port: port,
		addr:       ":" + strconv.Itoa(port),
		totThreads: totThreads,
		server:     true,
	}
}

// requestHeader: These are the http headers that are sent from client to server when a new http2 stream is initiated
func NewClient(ctx context.Context, lg *log.Logger, cacert []byte, serverName string, serverIP string, port int, requestHeader http.Header, totThreads *int32, clocksync int) *HttpStream {
	var rttTotal uint64
	var rttCnt int
	h := HttpStream{
		ctx: ctx, lg: lg, caCert: cacert, serverName: serverName, serverIP: serverIP, port: port,
		requestHeader: requestHeader,
		streamClosed:  make(chan struct{}),
		totThreads:    totThreads,
		rttTotal:      &rttTotal,
		rttCnt:        &rttCnt,
		server:        false,
		sid:           uuid.New(),
		primary:       true,
		clocksync:     clocksync,
	}
	h.txData = httpBody{h: &h, txChan: make(chan nxtData)}

	h.client = &http.Client{}
	if len(h.caCert) != 0 {
		h.addr = "https://" + h.serverIP + ":" + strconv.Itoa(h.port)
		certificate, err := selfsign.GenerateSelfSignedWithDNS(h.serverName, h.serverName)
		if err != nil {
			return nil
		}
		rootCertificate, err := common.LoadCertificate(h.caCert)
		if err != nil {
			return nil
		}
		certPool := x509.NewCertPool()
		cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
		if err != nil {
			return nil
		}
		certPool.AddCert(cert)
		tlsConf := &tls.Config{
			Certificates: []tls.Certificate{certificate},
			RootCAs:      certPool,
			ServerName:   h.serverName,
			NextProtos:   []string{http2.NextProtoTLS},
		}
		h.client.Transport = &http2.Transport{
			TLSClientConfig: tlsConf,
		}
	} else {
		h.addr = "http://" + h.serverIP + ":" + strconv.Itoa(h.port)
		h.client.Transport = &http2.Transport{
			// So http2.Transport doesn't complain the URL scheme isn't 'https'
			AllowHTTP: true,
			// Pretend we are dialing a TLS endpoint.
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		}
	}
	return &h
}

// The http2 stream remains open forever, as long as the nextensio flow corresponding to the stream
// needs it to be open. And the nextensio flow keeps sending its data over this http2 stream chunked
// and written into the body. That means, when we read from the request body below, we are NOT
// supposed to get an io.EOF error because the body never ends! So if read returns an error that means
// the stream itself is closed
func bodyRead(stream *HttpStream, w http.ResponseWriter, r *http.Request) {
	for {
		nbufs := make([][]byte, 0)
		lenBytes := 0
		hdr := &nxthdr.NxtHdr{}
		buf := make([]byte, common.MAXBUF)

		var totLen uint64 = 0
		var tbytes int = 0
		// First figure out the total length of this data stream. The total length is varint
		// encoded at the beginning of the packet, we dont know the size of the varint encoding,
		// so we try to figure that out here.
		// TODO: This can be more efficient without having to do as many reads. These reads
		// wont really be system calls since the quic lib internally will have buffered this
		// data and it will be a memcopy, but still we dont have to make as many Reads(). We
		// can just read in say 3 bytes and see which byte has LSB 0 bit to figure out end of
		// varint encoding
		for {
			_, err := r.Body.Read(buf[lenBytes : lenBytes+1])
			if err != nil {
				stream.Close()
				atomic.AddInt32(&stream.listener.nthreads, -1)
				if stream.totThreads != nil {
					atomic.AddInt32(stream.totThreads, -1)
				}
				return
			}
			lenBytes++
			totLen, tbytes = binary.Uvarint(buf[0:lenBytes])
			if tbytes > 0 {
				break
			}
		}

		// Read the rest of the data into the current buffer and keep adding more buffers
		// if the data wont fit in the current buffer. The rest of the data includes nextensio
		// headers and payload
		offset := lenBytes
		end := 0
		for remaining := int(totLen); remaining > 0; {
			// Can the remaining data fit in this one buffer ?
			if remaining > len(buf[offset:]) {
				end = len(buf)
			} else {
				end = offset + remaining
			}
			n, err := r.Body.Read(buf[offset:end])
			// io.EOF can have a nonzero number of bytes read which we have to process
			if err != nil && err != io.EOF {
				stream.Close()
				atomic.AddInt32(&stream.listener.nthreads, -1)
				if stream.totThreads != nil {
					atomic.AddInt32(stream.totThreads, -1)
				}
				return
			}
			remaining -= n
			offset += n
			if err == io.EOF && remaining > 0 {
				// well, stream ended and we havent got all our bytes, so close the stream
				stream.Close()
				atomic.AddInt32(&stream.listener.nthreads, -1)
				if stream.totThreads != nil {
					atomic.AddInt32(stream.totThreads, -1)
				}
				return
			}
			if offset == end {
				nbufs = append(nbufs, buf[0:end])
				if remaining != 0 {
					buf = make([]byte, common.MAXBUF)
					offset = 0
				}
			}
		}

		// The nextensio header HAS to fit in one buffer, so look for that in the first buffer.
		// Look for the length of the encoded nextensio headers first, and then the header itself
		hdrLen, hbytes := binary.Uvarint(nbufs[0][lenBytes:])
		if hbytes <= 0 {
			stream.Close()
			atomic.AddInt32(&stream.listener.nthreads, -1)
			if stream.totThreads != nil {
				atomic.AddInt32(stream.totThreads, -1)
			}
			return
		}
		lenBytes += hbytes
		err := proto.Unmarshal(nbufs[0][lenBytes:lenBytes+int(hdrLen)], hdr)
		if err != nil {
			stream.Close()
			atomic.AddInt32(&stream.listener.nthreads, -1)
			if stream.totThreads != nil {
				atomic.AddInt32(stream.totThreads, -1)
			}
			return
		}
		lenBytes += int(hdrLen)
		retLen := int(totLen-hdrLen) - hbytes

		retBuf := net.Buffers{}
		if retLen != 0 {
			retBuf = net.Buffers{nbufs[0][lenBytes:]}
			retBuf = append(retBuf, nbufs[1:]...)
		}
		select {
		case stream.rxData <- nxtData{hdr: hdr, data: retBuf}:
		case <-stream.streamClosed:
			atomic.AddInt32(&stream.listener.nthreads, -1)
			if stream.totThreads != nil {
				atomic.AddInt32(stream.totThreads, -1)
			}
			return
		}
	}
}

// Timing is sent periodically, so failure here is not fatal
func recvTiming(w http.ResponseWriter, r *http.Request) {
	var data Timing

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionLock.Lock()
	if sessions != nil {
		s := sessions[data.Uuid]
		if s != nil {
			*s.rttTotal = data.RttTotal
			*s.rttCnt = data.RttCount
		}
	}
	sessionLock.Unlock()

	data.ClientTime = uint64(time.Now().UnixNano())
	js, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-type", "application/json")
	w.Write(js)
}

func httpHandler(h *HttpStream, c chan common.NxtStream, w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 {
		panic("We are expecting http2 with prior knowledge")
	}

	if r.URL.Path == "/timing" {
		recvTiming(w, r)
		return
	}

	atomic.AddInt32(&h.nthreads, 1)
	if h.totThreads != nil {
		atomic.AddInt32(h.totThreads, 1)
	}
	rxData := make(chan nxtData)
	var rttTotal uint64
	var rttCnt int
	stream := &HttpStream{
		ctx: h.ctx, lg: h.lg, rxData: rxData, server: true, serverBody: r.Body,
		listener: h, streamClosed: make(chan struct{}),
		totThreads: h.totThreads,
		rttTotal:   &rttTotal, rttCnt: &rttCnt,
	}

	session := r.Header.Get("x-nextensio-transport-sid")
	if s, e := uuid.Parse(session); e == nil {
		stream.sid = s
	} else {
		h.lg.Println("Session without sid", e, s)
		http.Error(w, "Session without sid", http.StatusInternalServerError)
		return
	}
	primary := r.Header.Get("x-nextensio-transport-primary")
	if primary == "true" {
		sessionLock.Lock()
		if sessions == nil {
			sessions = make(map[uuid.UUID]*HttpStream)
		}
		sessions[stream.sid] = stream
		sessionLock.Unlock()
	}

	c <- common.NxtStream{Parent: stream.sid, Stream: stream, Http: &r.Header}

	atomic.AddInt32(&h.nthreads, 1)
	if h.totThreads != nil {
		atomic.AddInt32(h.totThreads, 1)
	}
	go bodyRead(stream, w, r)
	for {
		select {
		case <-stream.streamClosed:
			w.Header().Set("Connection", "close")
			w.Write([]byte("stream closed"))
			stream.Close()
			atomic.AddInt32(&h.nthreads, -1)
			if h.totThreads != nil {
				atomic.AddInt32(h.totThreads, -1)
			}
			if primary == "true" {
				sessionLock.Lock()
				delete(sessions, stream.sid)
				sessionLock.Unlock()
			}
			return
		}
	}
}

func (h *HttpStream) Listen(c chan common.NxtStream) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpHandler(h, c, w, r)
	})
	addr := ":" + strconv.Itoa(h.port)

	if len(h.pubKey) != 0 {
		tlsCert, err := tls.X509KeyPair(h.pubKey, h.pvtKey)
		if err != nil {
			panic(err)
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"nextensio-http2"},
		}
		server := http.Server{
			Addr: addr, Handler: mux,
			TLSConfig: config,
		}
		h.httpServer = &server
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			h.lg.Println("Https listen failed", err)
			return
		}
	} else {
		s2 := http2.Server{}
		server := http.Server{
			Addr: addr, Handler: h2c.NewHandler(mux, &s2),
		}
		h.httpServer = &server
		err := server.ListenAndServe()
		if err != nil {
			h.lg.Println("Http listen failed", err)
			return
		}
	}
}

// NOTE: The timing sync is periodically attempted, so a failure here is
// not fatal
func (h *HttpStream) sendTiming() {
	var data Timing

	data.Uuid = h.sid
	data.RttTotal = *h.rttTotal
	data.RttCount = *h.rttCnt
	data.ServerTime = uint64(time.Now().UnixNano())
	js, err := json.Marshal(data)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", h.addr+"/timing", bytes.NewReader(js))
	if err != nil {
		return
	}
	if h.requestHeader != nil {
		for key, val := range h.requestHeader {
			for _, v := range val {
				req.Header.Add(key, v)
			}
		}
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}

	start := time.Unix(0, int64(data.ServerTime))
	elapsed := time.Since(start).Nanoseconds()
	*h.rttTotal += uint64(elapsed)
	*h.rttCnt += 1
}

func periodicTiming(h *HttpStream) {
	atomic.AddInt32(&h.nthreads, 1)
	if h.totThreads != nil {
		atomic.AddInt32(h.totThreads, 1)
	}
	for {
		if h.IsClosed() {
			atomic.AddInt32(&h.nthreads, -1)
			if h.totThreads != nil {
				atomic.AddInt32(h.totThreads, -1)
			}
			return
		}
		h.sendTiming()
		time.Sleep(time.Duration(h.clocksync) * time.Millisecond)
	}
}

// NOTE: sChan is not used here because http2 lib we have cannot create streams
// from server to client as of today. The sChan is only useful in notifying
// client about new streams initiated from server
func (h *HttpStream) Dial(sChan chan common.NxtStream) *common.NxtError {
	req, err := http.NewRequest("POST", h.addr, &h.txData)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	if h.requestHeader != nil {
		for key, val := range h.requestHeader {
			for _, v := range val {
				req.Header.Add(key, v)
			}
		}
	}
	req.Header.Add("x-nextensio-transport-sid", h.sid.String())
	if h.primary {
		req.Header.Add("x-nextensio-transport-primary", "true")
	}

	// The client.Do ends up launching two goroutines, one for reading
	// body and transmitting it, one for reading the response headers and
	// response body. And the client.Do itself ends up in a forever loop
	// waiting for the complete response or waiting for any kind of response
	// errors etc.. In golang net/http2 sources, see roundTrip() API in file
	// http2/transport.go for details. So the applications call the stream Write()
	// API which queues data into a channel which is read by the request body reader
	// in the goroutine we described above. Since as of today this is a unidirectional
	// stream, we dont care about the response at all
	atomic.AddInt32(&h.nthreads, 1)
	if h.totThreads != nil {
		atomic.AddInt32(h.totThreads, 1)
	}
	go func(h *HttpStream) {
		resp, err := h.client.Do(req)
		if err == nil {
			// TODO: Not sure if the http2 lib also does a Body.Close() for any reason
			// and if so this will be a multi threaded operation, and we have to find out
			// if Body.Close() is thread safe and if not figure out some way
			resp.Body.Close()
		}
		h.Close()
		atomic.AddInt32(&h.nthreads, -1)
		if h.totThreads != nil {
			atomic.AddInt32(h.totThreads, -1)
		}
	}(h)

	if h.primary && h.clocksync != 0 {
		go periodicTiming(h)
	}

	h.sChan = sChan

	return nil
}

func (b *httpBody) readData(data nxtData) error {
	total := 0
	for _, b := range data.data {
		total += len(b)
	}
	data.hdr.Datalen = uint32(total)

	// Encode nextensio header and the header length
	out, err := proto.Marshal(data.hdr)
	if err != nil {
		atomic.AddInt32(&b.h.nthreads, -1)
		if b.h.totThreads != nil {
			atomic.AddInt32(b.h.totThreads, -1)
		}
		return err
	}
	hdrlen := len(out)
	var varint1 [common.MAXVARINT_BUF]byte
	plen1 := binary.PutUvarint(varint1[0:], uint64(hdrlen))
	dataLen := plen1 + hdrlen
	dataLen += total
	// Encode the total length including nextensio headers, header length and payload
	var varint2 [common.MAXVARINT_BUF]byte
	plen2 := binary.PutUvarint(varint2[0:], uint64(dataLen))

	hdrs := make([]byte, plen2+plen1+hdrlen)
	copy(hdrs[0:], varint2[0:plen2])
	copy(hdrs[plen2:], varint1[0:plen1])
	copy(hdrs[plen2+plen1:], out)
	newbuf := append(net.Buffers{hdrs}, data.data...)
	b.bufs = newbuf
	b.idx = 0
	b.off = 0

	return nil
}

// Send one nextensio frame worth of data each time Read() is called, if there
// are no nextensio frames, block till one is available
func (b *httpBody) Read(p []byte) (n int, err error) {

	if !b.once {
		atomic.AddInt32(&b.h.nthreads, 1)
		if b.h.totThreads != nil {
			atomic.AddInt32(b.h.totThreads, 1)
		}
		b.once = true
	}
	if b.bufs == nil {
		select {
		case data := <-b.txChan:
			err := b.readData(data)
			if err != nil {
				return 0, err
			}
		case <-b.h.streamClosed:
			// Drain and send all the queued up tx data before closing
			select {
			case data := <-b.txChan:
				err := b.readData(data)
				if err != nil {
					return 0, err
				}
			default:
				atomic.AddInt32(&b.h.nthreads, -1)
				if b.h.totThreads != nil {
					atomic.AddInt32(b.h.totThreads, -1)
				}
				return 0, io.EOF
			}
		}
	}

	total := 0
	for {
		avail := len(p[total:])
		curbuf := b.bufs[b.idx][b.off:]
		curlen := len(curbuf)
		if avail > curlen {
			copy(p[total:], curbuf[0:])
			total += curlen
			b.off = 0
			b.idx++
			// Check if we have transmitted the entire frame, if so we exit
			// and transmit the next frame in the next body read.
			if b.idx == len(b.bufs) {
				b.bufs = nil
				break
			}
		} else {
			copy(p[total:], curbuf[0:avail])
			total += avail
			b.off += avail
			// If we have not transmitted the entire frame, but we have run out of
			// space in the Read() buffer provided by http library, we will break
			// out and resume sending this frame in the next body read.
			break
		}
	}

	return total, nil
}

func (h *HttpStream) Close() *common.NxtError {
	if h.httpServer != nil {
		err := (*h.httpServer).Close()
		if err != nil {
			return common.Err(common.CONNECTION_ERR, err)
		}
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

	// Closing a closed channel again will result in panic, hence having to use the closeLock
	// if multiple people attempt close parallely
	h.closeLock.Lock()
	if !h.closed {
		h.closed = true
		// On the client side This will unblock the client Body reader
		close(h.streamClosed)
	}
	h.closeLock.Unlock()

	return nil
}

func (h *HttpStream) IsClosed() bool {
	return h.closed
}

func (h *HttpStream) CloseCascade(cascade common.Transport) {
	h.cascade = cascade
}

func (h *HttpStream) SetReadDeadline(time.Time) *common.NxtError {
	return nil
}

func (h *HttpStream) NewStream(hdr http.Header) common.Transport {
	if h.server {
		panic("http2 NewStreams is only on client")
	}
	if hdr == nil {
		hdr = make(http.Header)
	}
	// For those keys in the parent not in the child, copy the values to the child
	for k, vs := range h.requestHeader {
		if _, ok := hdr[k]; !ok {
			for _, v := range vs {
				hdr.Add(k, v)
			}
		}
	}

	nh := HttpStream{
		ctx: h.ctx, lg: h.lg, caCert: h.caCert, serverName: h.serverName, serverIP: h.serverIP, port: h.port,
		requestHeader: hdr,
		streamClosed:  make(chan struct{}),
		totThreads:    h.totThreads,
		rttTotal:      h.rttTotal,
		rttCnt:        h.rttCnt,
		sid:           h.sid,
		server:        h.server,
		primary:       false,
	}
	nh.txData = httpBody{h: &nh, txChan: make(chan nxtData)}
	nh.addr = h.addr
	nh.client = h.client
	if nh.Dial(h.sChan) != nil {
		return nil
	}
	return &nh
}

func (h *HttpStream) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {
	if !h.server {
		panic("http2 client is write only")
	}

	select {
	case data := <-h.rxData:
		return data.hdr, data.data, nil
	case <-h.streamClosed:
		// Drain out the data that was read before the session was closed
		select {
		case data := <-h.rxData:
			return data.hdr, data.data, nil
		default:
			// Stream is closed, no more data to flush out
			return nil, nil, common.Err(common.CONNECTION_ERR, nil)
		}
	}
}

func (h *HttpStream) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {
	if h.server {
		panic("http2 server is read only")
	}
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
	case h.txData.txChan <- nxtData{data: buf, hdr: hdr}:
		return nil
	case <-h.streamClosed:
		// Stream is closed
		return common.Err(common.CONNECTION_ERR, nil)
	}
}

func (h *HttpStream) Timing() common.TimeInfo {
	var rtt uint64
	var drift int64
	if !h.server {
		cnt := *h.rttCnt
		if cnt != 0 {
			rtt = *h.rttTotal / uint64(cnt)
		}
	} else {
		sessionLock.Lock()
		if sessions != nil {
			s := sessions[h.sid]
			if s != nil {
				cnt := *s.rttCnt
				if cnt != 0 {
					rtt = *s.rttTotal / uint64(cnt)
				}
			}
		}
		sessionLock.Unlock()
	}
	return common.TimeInfo{Rtt: rtt, Drift: drift}
}
