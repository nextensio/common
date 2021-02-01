package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"

	"github.com/google/uuid"
	"github.com/lucas-clemente/quic-go"
	"google.golang.org/protobuf/proto"
)

// The format of a data stream sent on this transport is as follows
// [total length] [protbuf hdr length] [protobuf header] [payload]
// The total length field is a varint (variable integer) encoded length of what comes after it,
// excluding the size used up for encoding total length itself.
// The protobuf header length varint encodes the size of the protobuf header
// The protobuf header itself has all nextensio informatoin
// The payload is the actual application data
type Quic struct {
	ctx       context.Context
	server    string
	port      int
	pvtKey    []byte
	pubKey    []byte
	caCert    []byte
	session   quic.Session
	stream    quic.Stream
	closed    bool
	writeLock sync.Mutex
}

func (q *Quic) serverTLS() *tls.Config {
	tlsCert, err := tls.X509KeyPair(q.pubKey, q.pvtKey)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"nextensio-quic"},
	}
}

func NewListener(ctx context.Context, pvtKey []byte, pubKey []byte, port int) *Quic {
	return &Quic{ctx: ctx, pvtKey: pvtKey, pubKey: pubKey, port: port}
}

func NewClient(ctx context.Context, cacert []byte, server string, port int) *Quic {
	return &Quic{ctx: ctx, caCert: cacert, server: server, port: port}
}

func getStream(ctx context.Context, s quic.Session, c chan common.NxtStream) {
	Suuid := uuid.New()
	for {
		stream, err := s.AcceptStream(context.Background())
		if err != nil {
			fmt.Println("GetStream failed", err)
			return
		}
		transport := &Quic{ctx: ctx, session: s, stream: stream}
		c <- common.NxtStream{Parent: Suuid, Stream: transport}
	}
}

func (q *Quic) Listen(c chan common.NxtStream) {
	config := quic.Config{KeepAlive: true, MaxIncomingStreams: 1024 * 1024 * 1024}
	listener, err := quic.ListenAddr(":"+strconv.Itoa(q.port), q.serverTLS(), &config)
	if err != nil {
		return
	}
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		go getStream(q.ctx, sess, c)
	}
}

func acceptStream(ctx context.Context, session quic.Session, sChan chan common.NxtStream) {
	parent := uuid.New()
	for {
		stream, err := session.AcceptStream(ctx)
		if err != nil {
			return
		}
		transport := &Quic{ctx: ctx, session: session, stream: stream}
		sChan <- common.NxtStream{Parent: parent, Stream: transport}
	}
}

func (q *Quic) Dial(sChan chan common.NxtStream) *common.NxtError {
	addr := q.server + ":" + strconv.Itoa(q.port)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"nextensio-quic"},
	}
	config := quic.Config{KeepAlive: true, MaxIncomingStreams: 1024 * 1024 * 1024}
	session, err := quic.DialAddr(addr, tlsConf, &config)
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}
	q.session = session
	q.stream = stream

	go acceptStream(q.ctx, session, sChan)

	return nil
}

func (q *Quic) Close() *common.NxtError {
	var err error
	// TODO: Need to check go-quick source code to see if stream.Close() is thread safe,
	// if it is then we dont need this lock
	q.writeLock.Lock()
	if !q.closed {
		q.closed = true
		if q.stream != nil {
			err = q.stream.Close()
		}
	}
	q.writeLock.Unlock()
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	return nil
}

func (q *Quic) IsClosed() bool {
	return q.closed
}

func (q *Quic) NewStream(hdr http.Header) common.Transport {
	stream, err := q.session.OpenStreamSync(q.ctx)
	if err != nil {
		return nil
	}
	return &Quic{ctx: q.ctx, session: q.session, stream: stream}
}

func (q *Quic) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {
	// Encode nextensio header and the header length
	out, err := proto.Marshal(hdr)
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}
	hdrlen := len(out)
	var varint1 [common.MAXVARINT_BUF]byte
	plen1 := binary.PutUvarint(varint1[0:], uint64(hdrlen))
	dataLen := plen1 + hdrlen
	for i := 0; i < len(buf); i++ {
		dataLen += len(buf[i])
	}
	// Encode the total length including nextensio headers, header length and payload
	var varint2 [common.MAXVARINT_BUF]byte
	plen2 := binary.PutUvarint(varint2[0:], uint64(dataLen))

	hdrs := make([]byte, plen2+plen1+hdrlen)
	copy(hdrs[0:], varint2[0:plen2])
	copy(hdrs[plen2:], varint1[0:plen1])
	copy(hdrs[plen2+plen1:], out)
	newbuf := append(net.Buffers{hdrs}, buf...)

	// go-quic library Write() doesnt seem to be thread safe
	q.writeLock.Lock()
	_, err = newbuf.WriteTo(q.stream)
	q.writeLock.Unlock()
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	return nil
}

func (q *Quic) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {

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
		_, err := q.stream.Read(buf[lenBytes : lenBytes+1])
		if err != nil {
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
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
		n, err := q.stream.Read(buf[offset:end])
		if err != nil && err != io.EOF {
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
		}
		remaining -= n
		offset += n
		if err == io.EOF && remaining > 0 {
			// well, stream ended and we havent got all our bytes, so close the stream
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
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
		return nil, nil, common.Err(common.GENERAL_ERR, nil)
	}
	lenBytes += hbytes
	err := proto.Unmarshal(nbufs[0][lenBytes:lenBytes+int(hdrLen)], hdr)
	if err != nil {
		return nil, nil, common.Err(common.GENERAL_ERR, err)
	}
	lenBytes += int(hdrLen)
	retLen := int(totLen-hdrLen) - hbytes
	if retLen != 0 {
		netBuf := net.Buffers{nbufs[0][lenBytes:]}
		netBuf = append(netBuf, nbufs[1:]...)
		return hdr, netBuf, nil
	} else {
		return hdr, net.Buffers{}, nil
	}
}

func (q *Quic) SetReadDeadline(t time.Time) *common.NxtError {

	return nil
}
