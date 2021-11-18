package websock

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	b64 "encoding/base64"

	"github.com/google/uuid"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	common "gitlab.com/nextensio/common/go"
	"gitlab.com/nextensio/common/go/messages/nxthdr"
	"google.golang.org/protobuf/proto"
)

const (
	streamData      = 0
	streamClose     = 1
	streamKeepAlive = 2
	streamClockSync = 3
)

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
	conn       net.Conn
	nextStream uint64
	slock      sync.Mutex
	streams    map[uint64]*WebStream
	nthreads   int32
	keepalive  int
	keepcount  int
	clocksync  int
	closed     bool
	keepRx     int
	rtts       []uint64
	rttTotal   uint64
	rtt        uint64
	initTime   time.Time
	pool       common.NxtPool
}

type nxtData struct {
	hdr  *nxthdr.NxtHdr
	data *common.NxtBufs
}

type WebStream struct {
	ctx           context.Context
	lg            *log.Logger
	pool          common.NxtPool
	listener      *net.Listener
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
	keepalive     int
	keepcount     int
	clocksync     int
}

func NewListener(ctx context.Context, lg *log.Logger, pool common.NxtPool, pvtKey []byte, pubKey []byte, port int, keepalive int, keepcount int, clocksync int) *WebStream {
	return &WebStream{
		ctx: ctx, lg: lg, pool: pool, pvtKey: pvtKey, pubKey: pubKey, port: port, keepalive: keepalive, keepcount: keepcount, clocksync: clocksync,
	}
}

// requestHeader: These are the http headers that are sent from client to server when a new websocket is initiated
func NewClient(ctx context.Context, lg *log.Logger, pool common.NxtPool, cacert []byte, serverName string, serverIP string, port int, requestHeader http.Header,
	keepalive int) *WebStream {
	return &WebStream{
		ctx: ctx, lg: lg, pool: pool, caCert: cacert, serverName: serverName, serverIP: serverIP, port: port, requestHeader: requestHeader,
		keepalive: keepalive, keepcount: 0,
	}
}

func nxtRead(session *webSession) (uint64, *nxtData, int, *common.NxtError) {
	// We dont want to end up reading a bunch of data in and then figure out that some of
	// the data is for the next frame. Then we have to buffer that data etc.. and the code
	// becomes more complicated. So the song and dance below is to first figure out exactly
	// what is the nextensio header length, then read in that much amount of data and decode
	// the header and then find the datalength and then read in the data. To read the header
	// exactly and prevent over-reading (for same reasons as above), we read two bytes at
	// a time. Most of the times the header length will fit in two bytes. Also the smallest
	// nextensio header can be just two bytes (a Close frame), so the smallest frame here
	// can be 1 byte of header length and 2 bytes of headers and 0 bytes of data.
	var hlenBuf [common.MAXVARINT_BUF]byte
	for i := 0; i < len(hlenBuf); i++ {
		hlenBuf[i] = 0
	}
	total := 0
	for {
		if total == len(hlenBuf) {
			// Well this is some wierd junk packet with junk length, close this session
			return 0, nil, 0, common.Err(common.CONNECTION_ERR, nil)
		}
		end := total + 2
		if end > len(hlenBuf) {
			end = len(hlenBuf)
		}
		r, err := session.conn.Read(hlenBuf[total:end])
		total += r
		if err != nil && (err != io.EOF || r == 0) {
			return 0, nil, 0, common.Err(common.CONNECTION_ERR, err)
		}
		complete := false
		// The demarcation of a varint encoding is a byte with MSB bit 0
		for i := 0; i < total; i++ {
			if hlenBuf[i]&0x80 == 0 {
				complete = true
				break
			}
		}
		if complete {
			break
		}
	}
	hdrLen, hbytes := binary.Uvarint(hlenBuf[0:])
	if hbytes <= 0 || hbytes > total {
		return 0, nil, 0, common.Err(common.CONNECTION_ERR, nil)
	}

	// Just sanity check for ridiculous values so we dont end up affecting
	// all sessions
	if hdrLen > 64*1024 {
		return 0, nil, 0, common.Err(common.CONNECTION_ERR, nil)
	}
	var nxtBuf *common.NxtBuf
	var hdrbuf []byte
	if uint(hdrLen) > session.pool.Size {
		hdrbuf = make([]byte, hdrLen)
	} else {
		nxtBuf = common.GetBuf(session.pool)
		hdrbuf = (*nxtBuf).Buf
	}

	// We read not only the header length varint encoding, but maybe one byte of
	// the header itself, copy that into the header buf
	total = total - hbytes
	if total > 0 {
		copy(hdrbuf[0:], hlenBuf[hbytes:hbytes+total])
	}

	// read the complete nxthdr.
	for {
		if total >= int(hdrLen) {
			break
		}
		r, err := session.conn.Read(hdrbuf[total:hdrLen])
		total += r
		if err != nil && (err != io.EOF || r == 0) {
			return 0, nil, 0, common.Err(common.CONNECTION_ERR, err)
		}
	}
	var hdr nxthdr.NxtHdr
	err := proto.Unmarshal(hdrbuf[0:hdrLen], &hdr)
	if err != nil {
		return 0, nil, 0, common.Err(common.CONNECTION_ERR, err)
	}
	// We are done with the header buf
	common.PutBuf(nxtBuf)
	// Just sanity check for ridiculous values so we dont end up affecting
	// all sessions
	if hdr.Datalen > 1024*1024 {
		return 0, nil, 0, common.Err(common.CONNECTION_ERR, nil)
	}
	// Read in all the data.
	total = 0
	off := 0
	end := 0
	nxtBuf = common.GetBuf(session.pool)
	databuf := (*nxtBuf).Buf
	data := &nxtData{data: &common.NxtBufs{Slices: net.Buffers{}, Bufs: nil}, hdr: &hdr}
	for {
		remaining := int(hdr.Datalen) - total
		if remaining == 0 || off >= int(session.pool.Size) {
			if off != 0 {
				data.data.Slices = append(data.data.Slices, databuf[0:off])
				data.data.Bufs = append(data.data.Bufs, nxtBuf)
				if remaining != 0 {
					nxtBuf = common.GetBuf(session.pool)
					databuf = (*nxtBuf).Buf
					off = 0
				}
			}
		}
		if remaining == 0 {
			break
		}
		if off+remaining >= int(session.pool.Size) {
			end = int(session.pool.Size)
		} else {
			end = off + remaining
		}
		r, err := session.conn.Read(databuf[off:end])
		total += r
		off += r
		if err != nil && (err != io.EOF || r == 0) {
			return 0, nil, 0, common.Err(common.CONNECTION_ERR, err)
		}
	}

	dtype := streamData
	switch data.hdr.Hdr.(type) {
	case *nxthdr.NxtHdr_Close:
		dtype = streamClose
	case *nxthdr.NxtHdr_Keepalive:
		dtype = streamKeepAlive
	case *nxthdr.NxtHdr_Sync:
		dtype = streamClockSync
	}

	return data.hdr.Streamid, data, dtype, nil
}

func nxtWriteKeepalive(stream *WebStream) *common.NxtError {
	stream.session.wlock.Lock()
	defer stream.session.wlock.Unlock()

	hdr := nxthdr.NxtHdr{}
	// This is what identifies us as a stream to the other end
	hdr.Streamid = stream.stream
	hdr.Datalen = 0
	hdr.Hdr = &nxthdr.NxtHdr_Keepalive{}
	// Encode nextensio header and the header length
	out, err := proto.Marshal(&hdr)
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}
	hdrlen := len(out)
	var varint [common.MAXVARINT_BUF]byte
	plen := binary.PutUvarint(varint[0:], uint64(hdrlen))
	_, err = stream.session.conn.Write(varint[0:plen])
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	_, err = stream.session.conn.Write(out[0:])
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}

	return nil
}

func nxtWriteClockSync(stream *WebStream, serverTime uint64) *common.NxtError {
	stream.session.wlock.Lock()
	defer stream.session.wlock.Unlock()

	hdr := nxthdr.NxtHdr{}
	// This is what identifies us as a stream to the other end
	hdr.Streamid = stream.stream
	hdr.Datalen = 0
	hdr.Hdr = &nxthdr.NxtHdr_Sync{}
	sync := nxthdr.NxtClockSync{ServerTime: serverTime}
	hdr.Hdr.(*nxthdr.NxtHdr_Sync).Sync = &sync
	// Encode nextensio header and the header length
	out, err := proto.Marshal(&hdr)
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}
	hdrlen := len(out)
	var varint [common.MAXVARINT_BUF]byte
	plen := binary.PutUvarint(varint[0:], uint64(hdrlen))
	_, err = stream.session.conn.Write(varint[0:plen])
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	_, err = stream.session.conn.Write(out[0:])
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}

	return nil
}

// Note: If we write any byte of data on to the wire and THEN detect some
// kind of error, we have NO OPTION but to close the entire session because
// then we break the framing format on the wire. Hence make sure all validations
// happen before writing onto the wire. The only error we should expect after writing to
// the wire is some write error itself
// NOTE NOTE: data.data can be nil, ie there can be a packet with just header and no data
func nxtWriteData(stream *WebStream, data nxtData) *common.NxtError {

	stream.session.wlock.Lock()
	defer stream.session.wlock.Unlock()
	if data.data != nil {
		defer common.PutBufs(data.data.Bufs)
	}

	// This is what identifies us as a stream to the other end
	data.hdr.Streamid = stream.stream
	total := 0
	if data.data != nil {
		for _, b := range data.data.Slices {
			total += len(b)
		}
	}
	data.hdr.Datalen = uint32(total)

	// Encode nextensio header and the header length
	out, err := proto.Marshal(data.hdr)
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}
	hdrlen := len(out)
	var varint [common.MAXVARINT_BUF]byte
	plen := binary.PutUvarint(varint[0:], uint64(hdrlen))
	_, err = stream.session.conn.Write(varint[0:plen])
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	_, err = stream.session.conn.Write(out[0:])
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	if data.data != nil {
		for _, b := range data.data.Slices {
			_, err = stream.session.conn.Write(b[0:])
			if err != nil {
				return common.Err(common.CONNECTION_ERR, err)
			}
		}
	}

	return nil
}

// Note: If we write any byte of data on to the wire and THEN detect some
// kind of error, we have NO OPTION but to close the entire session because
// then we break the framing format on the wire. Hence make sure all validations
// happen before writing onto the wire. The only error we should expect after writing to
// the wire is some write error itself
func nxtWriteClose(stream *WebStream) *common.NxtError {
	stream.session.wlock.Lock()
	defer stream.session.wlock.Unlock()

	hdr := nxthdr.NxtHdr{Streamid: stream.stream, Hdr: &nxthdr.NxtHdr_Close{}, Datalen: 0}
	// Encode nextensio header and the header length
	out, err := proto.Marshal(&hdr)
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}
	hdrlen := len(out)
	var varint [common.MAXVARINT_BUF]byte
	plen := binary.PutUvarint(varint[0:], uint64(hdrlen))
	_, err = stream.session.conn.Write(varint[0:plen])
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	_, err = stream.session.conn.Write(out[0:])
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}

	return nil
}

func closeAllStreams(session *webSession) {
	session.slock.Lock()
	for _, v := range session.streams {
		v.Close()
	}
	session.slock.Unlock()
}

// Read byte by byte (not efficient yes) till we get a \r\n. We read
// byte by byte to avoid having to buffer extra data etc.. Keeps code simple
func upgradeParseServer(lg *log.Logger, session *webSession) *common.NxtError {
	var char [1]byte
	line := ""
	cr := false
	nl := false
	key := ""
	for {
		r, err := session.conn.Read(char[0:])
		if err != nil && (err != io.EOF || r == 0) {
			return common.Err(common.CONNECTION_ERR, err)
		}
		line = line + string(char[0])
		if char[0] == '\r' {
			cr = true
		}
		if char[0] == '\n' {
			nl = true
		}
		if cr && nl {
			if len(line) == 2 {
				// The last \r\n
				break
			} else {
				reg, _ := regexp.Compile("sec-websocket-key[\t ]*:[\t ]*(.+)[\t ]*\r\n")
				match := reg.FindStringSubmatch(line)
				if len(match) == 2 {
					key = match[1]
				} else {
					reg, _ := regexp.Compile("Sec-WebSocket-Key[\t ]*:[\t ]*(.+)[\t ]*\r\n")
					match := reg.FindStringSubmatch(line)
					if len(match) == 2 {
						key = match[1]
					}
				}
			}
			line = ""
			cr = false
			nl = false
		}
	}
	if key == "" {
		return common.Err(common.CONNECTION_ERR, nil)
	}
	data := key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	io.WriteString(h, data)
	sEnc := b64.StdEncoding.EncodeToString(h.Sum(nil))

	resp := "HTTP/1.1 101 Switching Protocols\r\n"
	resp += "Upgrade: websocket\r\n"
	resp += "Connection: Upgrade\r\n"
	resp += "Sec-WebSocket-Accept: " + sEnc + "\r\n"
	resp += "\r\n"
	_, err := session.conn.Write([]byte(resp))
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}

	return nil
}

// Read byte by byte (not efficient yes) till we get a \r\n. We read
// byte by byte to avoid having to buffer extra data etc.. Keeps code simple
func upgradeParseClient(lg *log.Logger, session *webSession) *common.NxtError {
	var char [1]byte
	line := ""
	cr := false
	nl := false
	for {
		r, err := session.conn.Read(char[0:])
		if err != nil && (err != io.EOF || r == 0) {
			return common.Err(common.CONNECTION_ERR, err)
		}
		line = line + string(char[0])
		if char[0] == '\r' {
			cr = true
		}
		if char[0] == '\n' {
			nl = true
		}
		if cr && nl {
			if len(line) == 2 {
				// The last \r\n
				break
			}
			line = ""
			cr = false
			nl = false
		}
	}

	return nil
}

func upgradeWrite(lg *log.Logger, stream *WebStream) *common.NxtError {
	req := "GET / HTTP/1.1\r\n"
	req += fmt.Sprintf("Host: %s:%d\r\n", stream.serverName, stream.port)
	req += "Upgrade: websocket\r\n"
	req += "Connection: Upgrade\r\n"
	req += "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	req += "Sec-WebSocket-Version: 13\r\n"
	req += "User-Agent: Go-http-client/1.1\r\n"
	for name, values := range stream.requestHeader {
		for _, value := range values {
			req += fmt.Sprintf("%s: %s\r\n", name, value)
		}
	}
	req += "\r\n"

	_, err := stream.session.conn.Write([]byte(req))
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}

	return nil
}

func sessionClose(session *webSession) {
	session.conn.Close()
	session.closed = true
}

func keepCheck(lg *log.Logger, session *webSession) {
	for {
		time.Sleep(time.Duration(session.keepalive) * time.Millisecond)
		if session.closed {
			return
		}
		if session.keepRx < session.keepcount {
			lg.Println("Keepalive timeout", session.keepRx, session.keepcount, session.keepalive)
			sessionClose(session)
			return
		}
		// We are just overwriting the value, there is no atomicity concern
		session.keepRx = 0
	}
}

func handleClockSync(stream *WebStream, data *nxtData) {
	sync := data.hdr.Hdr.(*nxthdr.NxtHdr_Sync).Sync
	if !stream.session.server {
		// Ignoring write errors here, clock sync is done periodically
		nxtWriteClockSync(stream, sync.ServerTime)
		return
	}
	elapsed := uint64(time.Now().Sub(stream.session.initTime).Nanoseconds()) - sync.ServerTime
	stream.session.rtts = append(stream.session.rtts, elapsed)
	stream.session.rttTotal += elapsed
	// sliding window
	if len(stream.session.rtts) > 100 {
		stream.session.rttTotal -= stream.session.rtts[0]
		stream.session.rtts = stream.session.rtts[1:]
	}
	stream.session.rtt = stream.session.rttTotal / uint64(len(stream.session.rtts))
}

func sessionRead(ctx context.Context, lg *log.Logger, session *webSession, c chan common.NxtStream) {
	if session.server {
		if session.keepalive != 0 {
			go keepCheck(lg, session)
		}
		err := upgradeParseServer(lg, session)
		if err != nil {
			lg.Println("Session upgrade read error", session.server, err)
			sessionClose(session)
			return
		}
	} else {
		err := upgradeParseClient(lg, session)
		if err != nil {
			lg.Println("Session upgrade read error", session.server, err)
			sessionClose(session)
			return
		}
	}

	Suuid := uuid.New()
	for {
		sid, data, dtype, err := nxtRead(session)
		if err != nil {
			lg.Println("Session read error", session.server, err)
			closeAllStreams(session)
			sessionClose(session)
			return
		}
		// Consider all data as keepalive
		session.keepRx++
		if dtype == streamKeepAlive {
			continue
		}

		session.slock.Lock()
		var stream *WebStream = session.streams[sid]
		session.slock.Unlock()

		if dtype == streamClockSync {
			if stream != nil {
				handleClockSync(stream, data)
			}
			continue
		}

		if stream == nil && dtype != streamClose {
			rxData := make(chan nxtData, dataQlen)
			txData := make(chan nxtData, dataQlen)
			sendClose := make(chan bool)
			streamClosed := make(chan struct{})
			stream = &WebStream{
				ctx: ctx, rxData: rxData, txData: txData, sendClose: sendClose, streamClosed: streamClosed,
				stream: sid, session: session, lg: lg, pool: session.pool, keepalive: 0, keepcount: 0, clocksync: session.clocksync,
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
			if stream != nil {
				stream.Close()
				// We delete the stream from the hashmap. Close must be the last message on this stream,
				// since we do not want this to be created again by another packet that comes after this
				// with a closed stream id
				session.slock.Lock()
				delete(session.streams, sid)
				session.slock.Unlock()
			}
			if sid == 0 {
				// stream 0 represents the session itself, if stream 0 is closed, then entire session is closed
				closeAllStreams(session)
				sessionClose(session)
				return
			}
		}
	}
}

// The close-protocol is that we send a message to the other end saying we are closing,
// the other end is supposed to get that message and stop sending any more messages and
// send us back a close message - so we "know" that the session sid entry can be removed
// If we dont follow that protocol and remove the sid immediately, the next pending packet
// from the other end can end up creating the stream/flow again. Now if the other end close
// message doesnt reach us (the other end might not retry the response close if it fails),
// we still need to cleanup  the sid after some timeout.
func closeClean(session *webSession, sid uint64) {
	time.Sleep(10 * time.Second)
	session.slock.Lock()
	delete(session.streams, sid)
	session.slock.Unlock()

	if sid == 0 {
		// stream 0 represents the session itself, if stream 0 is closed, then entire session is closed
		closeAllStreams(session)
		sessionClose(session)
	}
}

func streamWrite(h *WebStream) {
	// 100 years, wish there was some time value for-ever-infinitys
	keepalive := 876000 * time.Hour
	// Only clients send keepalives to server
	if !h.session.server && h.keepalive != 0 {
		keepalive = time.Duration(h.keepalive) * time.Millisecond
	}
	// 100 years, wish there was some time value for-ever-infinity
	clocksync := 876000 * time.Hour
	// Only servers send clocksync to client
	if h.session.server && h.clocksync != 0 && h.stream == 0 {
		clocksync = time.Duration(h.clocksync) * time.Millisecond
	}
	keepTimer := time.NewTimer(keepalive)
	defer keepTimer.Stop()
	syncTimer := time.NewTimer(clocksync)
	defer syncTimer.Stop()

	for {
		err := false
		select {
		case <-keepTimer.C:
			keepTimer.Reset(keepalive)
			if nxtWriteKeepalive(h) != nil {
				err = true
			}
		case <-syncTimer.C:
			syncTimer.Reset(clocksync)
			if nxtWriteClockSync(h, uint64(time.Now().Sub(h.session.initTime).Nanoseconds())) != nil {
				err = true
			}
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
				go closeClean(h.session, h.stream)
				// Wakeup all writers hung on txData channel
				close(h.streamClosed)
			}
			// Close is the last tx message on this channel and then we are done sending messages
			atomic.AddInt32(&h.session.nthreads, -1)
			return
		}
	}
}

func (h *WebStream) Listen(c chan common.NxtStream) {
	addr := ":" + strconv.Itoa(h.port)

	var tlsConfig *tls.Config
	if len(h.pubKey) != 0 {
		tlsCert, err := tls.X509KeyPair(h.pubKey, h.pvtKey)
		if err != nil {
			panic(err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"nextensio-websocket"},
		}
	}
	var listener net.Listener
	if tlsConfig != nil {
		listener, _ = tls.Listen("tcp", addr, tlsConfig)
	} else {
		listener, _ = net.Listen("tcp", addr)
	}
	h.listener = &listener
	for {
		conn, err := listener.Accept()
		if err != nil {
			h.lg.Println("Websocket listen failed", err, h.port)
			return
		}
		var session *webSession = &webSession{
			server:     true,
			conn:       conn,
			nextStream: 0,
			streams:    make(map[uint64]*WebStream),
			keepalive:  h.keepalive,
			keepcount:  h.keepcount,
			closed:     false,
			keepRx:     0,
			clocksync:  h.clocksync,
			initTime:   time.Now(),
			pool:       h.pool,
		}
		go sessionRead(h.ctx, h.lg, session, c)
	}
}

func (h *WebStream) Dial(sChan chan common.NxtStream) *common.NxtError {

	var tlsConf *tls.Config

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
		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			RootCAs:      certPool,
			ServerName:   h.serverName,
			MinVersion:   tls.VersionTLS12,
			//InsecureSkipVerify: true,
		}
	}
	addr := fmt.Sprintf("%s:%d", h.serverIP, h.port)
	var conn net.Conn
	var err error
	if tlsConf != nil {
		conn, err = tls.Dial("tcp", addr, tlsConf)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		h.lg.Println("Cannot dial websocket", h.serverIP, h.port, err)
		return common.Err(common.CONNECTION_ERR, err)
	}
	var session *webSession = &webSession{
		server:     false,
		conn:       conn,
		nextStream: 0,
		streams:    make(map[uint64]*WebStream),
		keepalive:  0,
		keepcount:  0,
		closed:     false,
		keepRx:     0,
		pool:       h.pool,
	}
	session.streams[0] = h

	h.rxData = make(chan nxtData, dataQlen)
	h.txData = make(chan nxtData, dataQlen)
	h.sendClose = make(chan bool)
	h.streamClosed = make(chan struct{})
	h.session = session
	h.stream = 0

	e := upgradeWrite(h.lg, h)
	if e != nil {
		h.lg.Println("Cannot write upgrade request")
		return e
	}

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
	if h.listener != nil {
		err := (*h.listener).Close()
		if err != nil {
			return common.Err(common.CONNECTION_ERR, err)
		}
		return nil
	}
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
		stream: sid, session: h.session, lg: h.lg, pool: h.pool, keepalive: 0, keepcount: 0, clocksync: h.clocksync,
	}
	h.session.slock.Lock()
	h.session.streams[sid] = &stream
	h.session.slock.Unlock()
	atomic.AddInt32(&h.session.nthreads, 1)
	go streamWrite(&stream)
	return &stream
}

func (h *WebStream) Read() (*nxthdr.NxtHdr, *common.NxtBufs, *common.NxtError) {
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

func (h *WebStream) Write(hdr *nxthdr.NxtHdr, buf *common.NxtBufs) *common.NxtError {

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

// The is servers clock minus clients clock (in Nanoseconds)
func (h *WebStream) Timing() common.TimeInfo {
	return common.TimeInfo{Rtt: h.session.rtt}
}
