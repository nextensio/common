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
	"strings"
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
	data *common.NxtBufs
}

type httpBody struct {
	h      *HttpStream
	txChan chan nxtData
	bufs   *common.NxtBufs
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
	pool          common.NxtPool
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
	rtts          []uint64
	rtt           uint64
	rttTotal      uint64
	keepalive     int
	clocksync     int
	initTime      time.Time
	parent        *HttpStream
	http2Only     bool
	nxtHttp       bool // true if nextensio specific http
}

type Timing struct {
	Uuid       uuid.UUID `json:"uuid"`
	ServerTime uint64    `json:"servertime"`
	Rtt        uint64    `json:"rtt"`
}

// if http2Only is true, we will panic on getting an http1.1 stream. If its false, we will handle both http2 and http1.1
func NewListener(ctx context.Context, lg *log.Logger, pool common.NxtPool, pvtKey []byte, pubKey []byte, port int, totThreads *int32, http2Only bool, nxtHttp bool) *HttpStream {
	return &HttpStream{
		ctx: ctx, lg: lg, pool: pool, pvtKey: pvtKey, pubKey: pubKey, port: port,
		addr:       ":" + strconv.Itoa(port),
		totThreads: totThreads,
		server:     true, http2Only: http2Only, nxtHttp: nxtHttp,
	}
}

// requestHeader: These are the http headers that are sent from client to server when a new http2 stream is initiated
func NewClient(ctx context.Context, lg *log.Logger, pool common.NxtPool, cacert []byte, serverName string,
	serverIP string, port int, requestHeader http.Header, totThreads *int32, keepalive int, clocksync int, http2Only bool) *HttpStream {
	h := HttpStream{
		ctx: ctx, lg: lg, pool: pool, caCert: cacert, serverName: serverName, serverIP: serverIP, port: port,
		requestHeader: requestHeader,
		streamClosed:  make(chan struct{}),
		totThreads:    totThreads,
		server:        false,
		sid:           uuid.New(),
		keepalive:     keepalive,
		clocksync:     clocksync,
		initTime:      time.Now(),
		http2Only:     http2Only,
		nxtHttp:       true,
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

// In kubernetes, there can be multiple "replicas" in a given pod,
// sendTiming/recvTiming is calculating rtts each time with one of the
// pods in the replicas, as decided by envoy's loadbalancing algo. So
// over time what we get is an average across all the replicas. The
// rtt sendTiming and rtt calculation is done from the http client end,
// now how do we ensure that the timing info is conveyed to every single
// replica in the pod in the http server end ? We cant, there is no way
// to address each pod independently, and we dont really want to do that,
// we dont want to get into the business of addressing pods independently.
// So the only option we have is to include the rtt in the header with
// every packet sent from the client end, its ugly but thats all we can do,
// and its not just with http2, any transport we use in an istio environment
// with loadbalancing will have this trouble
func setRtt(stream *HttpStream, rtt uint64) {
	if stream.server {
		stream.rtt = rtt
	}
}

// Read the body of a HTTP request from a normal browser, ie., not a nextensio
// agent. This is a standard http request body without any nextensio headers
// embedded.
func bodyReadAgentLess(stream *HttpStream, w http.ResponseWriter, r *http.Request) {
	headersAdded := false
	for {
		nbufs := make([][]byte, 0)
		nxtBufs := make([]*common.NxtBuf, 0)
		buf := common.GetBuf(stream.pool)

		var totLen int = 0
		// For a direct connection from a browser, there are no nextensio headers.
		// The body is the http content. So no need to parse out special headers.
		// Read the data into the current buffer and keep adding more buffers
		// if the data wont fit in the current buffer.
		for {
			n, err := r.Body.Read((*buf).Buf[0:])
			if err != nil && err != io.EOF {
				// some error that is not end of file. Terminate.
				stream.Close()
				atomic.AddInt32(&stream.listener.nthreads, -1)
				if stream.totThreads != nil {
					atomic.AddInt32(stream.totThreads, -1)
				}
				return
			}
			totLen += n
			nbufs = append(nbufs, (*buf).Buf[0:n])
			nxtBufs = append(nxtBufs, buf)
			if n == len((*buf).Buf) && err != io.EOF {
				buf = common.GetBuf(stream.pool)
			} else {
				break
			}
		}

		retBuf := net.Buffers{}
		if totLen != 0 {
			retBuf = append(retBuf, nbufs[0:]...)
		}
		retData := common.NxtBufs{
			Slices: retBuf,
			Bufs:   nxtBufs,
		}

		// NOTE ASHWIN: This will need change. Because customer can have URLs to many different
		// dest ports like 8888 or 8080 etc.. So there are two possible approaches A or B
		// A. Minion listens on each of those ports - we know what those ports are since we make
		//    customer configure the service + port on controller, and even the istio ingress needs
		//    that same thing under the "hosts: .." section. I am talking about the proper working
		//    model of agentless here, not larry's waste of time portal nonsense (that I dont care about)
		// B. Minion listens on ONE port always - like 8888 - and we make istio ingress gateway do a
		//    port change such that whatever comes in, gets forwarded to minion on port 8888, and the
		//    original dest port (say 8080) is saved in some http header that istio adds like
		//    X-Nextensio-Orignal-Dport or something. I dont know if this is all do-able in istio and
		//    how complex that is, if its too complex, option A is not too hard, we just need to get
		//    the controller configs for what services customer has configured and listen on each
		//    of those ports
		host, port, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
			if r.TLS != nil {
				port = "443"
			} else {
				port = "80"
			}
		}
		p, _ := strconv.Atoi(port)
		sip := ""
		sport := ""
		s := 0
		fwd := r.Header.Get("X-Forwarded-For")
		if fwd != "" {
			// If we got an array... grab the first IP
			ips := strings.Split(fwd, ", ")
			if len(ips) > 1 {
				fwd = ips[0]
			}
			var e error
			sip, sport, e = net.SplitHostPort(fwd)
			if e == nil {
				s, _ = strconv.Atoi(sport)
			} else {
				sip = fwd
				s = 0
			}
		} else {
			var e error
			sip, sport, e = net.SplitHostPort(r.RemoteAddr)
			if e == nil {
				s, _ = strconv.Atoi(sport)
			} else {
				sip = r.RemoteAddr
				s = 0
			}
		}

		flow := nxthdr.NxtFlow{}
		flow.Source = sip
		flow.Sport = uint32(s)
		flow.Dest = host
		flow.Dport = uint32(p)
		flow.DestSvc = flow.Dest
		flow.Type = nxthdr.NxtFlow_L4
		flow.Proto = common.HTTP
		flow.HttpHost = host
		flow.HttpMethod = r.Method
		flow.HttpProtoMajor = uint32(r.ProtoMajor)
		flow.HttpProtoMinor = uint32(r.ProtoMinor)
		keys := []string{}
		values := []string{}
		// Http headers just need to be added one time so that the connector
		// on getting the first flow header will have these headers to open an
		// http request to the flow.Dest
		if !headersAdded {
			for k, _ := range r.Header {
				keys = append(keys, k)
				values = append(values, r.Header.Get(k))
			}
			flow.HttpKeys = keys
			flow.HttpValues = values
		}
		hdr := nxthdr.NxtHdr{}
		hdr.Hdr = &nxthdr.NxtHdr_Flow{Flow: &flow}

		// NOTE ASHWIN: So here the minion code will get the NxtHdr hdr, and then you dont have
		// to worry about anything till the packet hits the connector, the encoding/decoding all
		// happens like how the usual protobuf encoding/decoding happens.
		// Once the flow hits the connector, when you create the flow for the very first time,
		// if you see that flow.Proto == common.HTTP, then you open the http2.NewClient() with
		// the requestHeader parameter as the flow.HttpKeys + flow.HttpValues, thats about it.
		// So note that you will be using this module as an http "client" on connector, so the
		// readData() API will come into play for sending data client to server, and the readData()
		// API does protobuf encoding today, so you might have to create a readDataAgentless()
		// without any protobuf stuff.
		select {
		case stream.rxData <- nxtData{hdr: &hdr, data: &retData}:
		case <-stream.streamClosed:
			atomic.AddInt32(&stream.listener.nthreads, -1)
			if stream.totThreads != nil {
				atomic.AddInt32(stream.totThreads, -1)
			}
			return
		}
	}
}

// Read the body of a http request body originating from a nextensio agent. The body consists of
// a protobuf header plus the original http message. The protobuf header is preceded by a total
// length and then a length of the protobuf header. These length values are used to extract the
// protobuf header (there are multiple types) and the actual http frame.
// The http2 stream remains open forever, as long as the nextensio flow corresponding to the stream
// needs it to be open. And the nextensio flow keeps sending its data over this http2 stream chunked
// and written into the body. That means, when we read from the request body below, we are NOT
// supposed to get an io.EOF error because the body never ends! So if read returns an error that means
// the stream itself is closed
func bodyRead(stream *HttpStream, w http.ResponseWriter, r *http.Request) {
	for {
		nbufs := make([][]byte, 0)
		nxtBufs := make([]*common.NxtBuf, 0)
		lenBytes := 0
		hdr := &nxthdr.NxtHdr{}
		buf := common.GetBuf(stream.pool)

		var totLen uint64 = 0
		var tbytes int = 0
		// First figure out the total length of this data stream. The total length is varint
		// encoded at the beginning of the packet, we dont know the size of the varint encoding,
		// so we try to figure that out here.
		// TODO: This can be more efficient without having to do as many reads. These reads
		// wont really be system calls since the http2 lib internally will have buffered this
		// data and it will be a memcopy, but still we dont have to make as many Reads(). We
		// can just read in say 3 bytes and see which byte has LSB 0 bit to figure out end of
		// varint encoding
		for {
			_, err := r.Body.Read((*buf).Buf[lenBytes : lenBytes+1])
			if err != nil {
				stream.Close()
				atomic.AddInt32(&stream.listener.nthreads, -1)
				if stream.totThreads != nil {
					atomic.AddInt32(stream.totThreads, -1)
				}
				return
			}
			lenBytes++
			totLen, tbytes = binary.Uvarint((*buf).Buf[0:lenBytes])
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
			if remaining > len((*buf).Buf[offset:]) {
				end = len((*buf).Buf)
			} else {
				end = offset + remaining
			}
			n, err := r.Body.Read((*buf).Buf[offset:end])
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
				nbufs = append(nbufs, (*buf).Buf[0:end])
				nxtBufs = append(nxtBufs, buf)
				if remaining != 0 {
					buf = common.GetBuf(stream.pool)
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
		retData := common.NxtBufs{
			Slices: retBuf,
			Bufs:   nxtBufs,
		}

		setRtt(stream, hdr.Rtt)

		switch hdr.Hdr.(type) {
		case *nxthdr.NxtHdr_Keepalive:
			// Nothing to do, client sends it just to keep the session "warm"
		default:
			select {
			case stream.rxData <- nxtData{hdr: hdr, data: &retData}:
			case <-stream.streamClosed:
				atomic.AddInt32(&stream.listener.nthreads, -1)
				if stream.totThreads != nil {
					atomic.AddInt32(stream.totThreads, -1)
				}
				return
			}
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

	js, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-type", "application/json")
	w.Write(js)
}

func httpHandler(h *HttpStream, c chan common.NxtStream, w http.ResponseWriter, r *http.Request) {
	if h.http2Only && r.ProtoMajor != 2 {
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
	stream := &HttpStream{
		ctx: h.ctx, lg: h.lg, pool: h.pool, rxData: rxData, server: true, serverBody: r.Body,
		listener: h, streamClosed: make(chan struct{}),
		totThreads: h.totThreads, http2Only: h.http2Only, nxtHttp: h.nxtHttp,
	}

	// When both end points are nextensio, we expect a x-nextensio-transport-sid to be set
	// by the client initiating a stream to the server. The sid is basically the client
	// indicating its "parent session" (like one identifying a user connected to gateway)
	// and the streams are all associated with that "parent" (i.e user for example). But this
	// lib can also be used in a case where the client is an agentless browser, i.e. client
	// is not a nextensio endpoint. So in which case well there is no "parent" session, its just
	// independent streams even though it might all be from the same user. So we just fill in
	// a new uuid for each of those streams
	stream.sid = uuid.New()
	if h.nxtHttp {
		session := r.Header.Get("x-nextensio-transport-sid")
		if s, e := uuid.Parse(session); e == nil {
			stream.sid = s
		}
	}

	c <- common.NxtStream{Parent: stream.sid, Stream: stream, Http: &r.Header}

	atomic.AddInt32(&h.nthreads, 1)
	if h.totThreads != nil {
		atomic.AddInt32(h.totThreads, 1)
	}
	if h.nxtHttp {
		// Nextensio specific http. Body contains nextensio header in protobuf format
		// with length info about header and body.
		go bodyRead(stream, w, r)
	} else {
		// Standard http body, nothing special embedded in body
		go bodyReadAgentLess(stream, w, r)
	}
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

// In kubernetes, there can be multiple "replicas" in a given pod,
// sendTiming/recvTiming is calculating rtts each time with one of the
// pods in the replicas, as decided by envoy's loadbalancing algo. So
// over time what we get is an average across all the replicas
// NOTE: The timing sync is periodically attempted, so a failure here is
// not fatal
func (h *HttpStream) sendTiming() {
	var data Timing

	data.Uuid = h.sid
	data.Rtt = h.rtt
	data.ServerTime = uint64(time.Now().Sub(h.initTime).Nanoseconds())
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

	elapsed := uint64(time.Now().Sub(h.initTime).Nanoseconds()) - data.ServerTime
	h.rtts = append(h.rtts, elapsed)
	h.rttTotal += elapsed
	// sliding window, so each of the rtts here "might" have been measured
	// with a different pod
	if len(h.rtts) > 100 {
		h.rttTotal -= h.rtts[0]
		h.rtts = h.rtts[1:]
	}
	h.rtt = h.rttTotal / uint64(len(h.rtts))
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
	method := "POST"
	sc := <-sChan
	if sc.Request != nil && sc.Request.Method != "" {
		method = sc.Request.Method
	}
	req, err := http.NewRequest(method, h.addr, &h.txData)
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

	if h.clocksync != 0 {
		go periodicTiming(h)
	}

	h.sChan = sChan

	return nil
}

func (b *httpBody) readDataAgentLess(data nxtData) error {
	newbuf := append(net.Buffers{}, data.data.Slices...)
	b.bufs = &common.NxtBufs{Slices: newbuf, Bufs: data.data.Bufs}
	b.idx = 0
	b.off = 0

	return nil
}

func (b *httpBody) readData(data nxtData) error {
	if data.hdr == nil {
		return b.readDataAgentLess(data)
	}
	total := 0
	for _, b := range data.data.Slices {
		total += len(b)
	}
	data.hdr.Rtt = b.h.Timing().Rtt
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
	newbuf := append(net.Buffers{hdrs}, data.data.Slices...)
	b.bufs = &common.NxtBufs{Slices: newbuf, Bufs: data.data.Bufs}
	b.idx = 0
	b.off = 0

	return nil
}

func (b *httpBody) nxtWriteKeepalive() error {
	hdr := nxthdr.NxtHdr{}
	// We don't maintain a streamid in case of http2, http2 manages that
	hdr.Streamid = 0
	hdr.Datalen = 0
	hdr.Rtt = b.h.Timing().Rtt
	hdr.Hdr = &nxthdr.NxtHdr_Keepalive{}

	// Encode nextensio header and the header length
	out, err := proto.Marshal(&hdr)
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
	// Encode the total length including nextensio headers, header length and payload
	var varint2 [common.MAXVARINT_BUF]byte
	plen2 := binary.PutUvarint(varint2[0:], uint64(dataLen))

	hdrs := make([]byte, plen2+plen1+hdrlen)
	copy(hdrs[0:], varint2[0:plen2])
	copy(hdrs[plen2:], varint1[0:plen1])
	copy(hdrs[plen2+plen1:], out)
	b.bufs = &common.NxtBufs{Slices: net.Buffers{hdrs}, Bufs: nil}
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
	// 100 years, wish there was some time value for-ever-infinity
	keepalive := 876000 * time.Hour
	if b.h.keepalive != 0 {
		keepalive = time.Duration(b.h.keepalive) * time.Millisecond
	}
	keepTimer := time.NewTimer(keepalive)
	defer keepTimer.Stop()

	if b.bufs == nil {
		select {
		case <-keepTimer.C:
			keepTimer.Reset(keepalive)
			err := b.nxtWriteKeepalive()
			if err != nil {
				return 0, err
			}
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
		curbuf := (*b.bufs).Slices[b.idx][b.off:]
		curlen := len(curbuf)
		if avail > curlen {
			copy(p[total:], curbuf[0:])
			total += curlen
			b.off = 0
			b.idx++
			// Check if we have transmitted the entire frame, if so we exit
			// and transmit the next frame in the next body read.
			if b.idx == len((*b.bufs).Slices) {
				common.PutBufs((*b.bufs).Bufs)
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

	parent := h
	if h.parent != nil {
		parent = h.parent
	}
	nh := HttpStream{
		ctx: h.ctx, lg: h.lg, pool: h.pool, caCert: h.caCert, serverName: h.serverName, serverIP: h.serverIP, port: h.port,
		requestHeader: hdr,
		streamClosed:  make(chan struct{}),
		totThreads:    h.totThreads,
		sid:           h.sid,
		server:        false,
		parent:        parent,
		clocksync:     0, // Only the first stream (NewClient) does clocksync
		keepalive:     0, // Only the first stream (NewClient) does keepalive
		http2Only:     h.http2Only,
		nxtHttp:       h.nxtHttp,
	}
	nh.txData = httpBody{h: &nh, txChan: make(chan nxtData)}
	nh.addr = h.addr
	nh.client = h.client
	if nh.Dial(h.sChan) != nil {
		return nil
	}
	return &nh
}

func (h *HttpStream) Read() (*nxthdr.NxtHdr, *common.NxtBufs, *common.NxtError) {
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

func (h *HttpStream) Write(hdr *nxthdr.NxtHdr, buf *common.NxtBufs) *common.NxtError {
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
	if h.parent != nil {
		return common.TimeInfo{Rtt: h.parent.rtt}
	} else {
		return common.TimeInfo{Rtt: h.rtt}
	}
}
