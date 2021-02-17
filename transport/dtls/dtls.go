package dtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"gitlab.com/nextensio/common"
	"gitlab.com/nextensio/common/messages/nxthdr"

	"github.com/google/uuid"
	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"google.golang.org/protobuf/proto"
)

// The format of a data stream sent on this transport is as follows
// [protbuf hdr length] [protobuf header] [payload]
// The protobuf header length varint encodes the size of the protobuf header
// The protobuf header itself has all nextensio informatoin
// The payload is the actual application data
//
// NOTE: The dtls code today does not support multiple streams, there is just one session
// and one stream corresponding to that. dtls being unreliable udp/datagram based, is expected
// to be used primarily in the case of transporting L3 packets which needs only a single stream.
// In cases where we need a UDP based reliable transport with streams, consider using Quic
//
type Dtls struct {
	ctx        context.Context
	lg         *log.Logger
	serverIP   string
	serverName string
	port       int
	pvtKey     []byte
	pubKey     []byte
	caCert     []byte
	listener   net.Listener
	conn       *dtls.Conn
	closed     bool
}

func NewListener(ctx context.Context, lg *log.Logger, pvtKey []byte, pubKey []byte, port int) *Dtls {
	return &Dtls{ctx: ctx, lg: lg, pvtKey: pvtKey, pubKey: pubKey, port: port}
}

func NewClient(ctx context.Context, lg *log.Logger, cacert []byte, serverName string, serverIP string, port int) *Dtls {
	return &Dtls{ctx: ctx, lg: lg, caCert: cacert, serverIP: serverIP, serverName: serverName, port: port}
}

func (d *Dtls) Listen(c chan common.NxtStream) {
	err := listen(d)
	if err != nil {
		return
	}

	for {
		conn, err := d.listener.Accept()
		if err != nil {
			d.lg.Printf("Listen error %v", err)
			continue
		}
		client := &Dtls{conn: conn.(*dtls.Conn), lg: d.lg}
		c <- common.NxtStream{Parent: uuid.New(), Stream: client}
	}
}

func (d *Dtls) Dial(sChan chan common.NxtStream) *common.NxtError {

	addr := &net.UDPAddr{IP: net.ParseIP(d.serverIP), Port: d.port}

	certificate, err := selfsign.GenerateSelfSignedWithDNS(d.serverName, d.serverName)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}

	rootCertificate, err := common.LoadCertificate(d.caCert)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	certPool.AddCert(cert)

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		RootCAs:              certPool,
		ServerName:           d.serverName,
	}

	// Connect to a DTLS server
	ctx := d.ctx
	dtlsConn, err := dtls.DialWithContext(ctx, "udp", addr, config)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	d.conn = dtlsConn

	return nil
}

func (d *Dtls) Close() *common.NxtError {
	if d.conn != nil {
		d.closed = true
		err := d.conn.Close()
		if err != nil {
			return common.Err(common.CONNECTION_ERR, err)
		}
	}
	return nil
}

func (d *Dtls) IsClosed() bool {
	return d.closed
}

// DTLS cannot be used for multiplexing streams as of now
func (d *Dtls) NewStream(hdr http.Header) common.Transport {
	panic("dtls does not support new stream")
}

func (d *Dtls) Write(hdr *nxthdr.NxtHdr, buf net.Buffers) *common.NxtError {

	// Encode nextensio header and the header length
	out, err := proto.Marshal(hdr)
	if err != nil {
		return common.Err(common.GENERAL_ERR, err)
	}
	hdrlen := len(out)
	var varint [common.MAXVARINT_BUF]byte
	plen := binary.PutUvarint(varint[0:], uint64(hdrlen))
	dataLen := plen + hdrlen
	for i := 0; i < len(buf); i++ {
		dataLen += len(buf[0])
	}
	newbuf := make([]byte, dataLen)
	copy(newbuf[0:], varint[0:plen])
	copy(newbuf[plen:], out)
	offset := plen + hdrlen
	for i := 0; i < len(buf); i++ {
		copy(newbuf[offset:], buf[i])
		offset += len(buf[i])
	}
	// Unfortunately for datagram transports, the data has to be finally assembled into
	// one single frame before they can be transmitted, so the multi-buffer paradigm ends
	// up being slower for datagram transports, but works well for stream transports like
	// tcp or quic. Also dtls conn does not seem to provide the "WriteTo" interface or else
	// we could have said <multibuf>.WriteTo(d.conn) - that would still do the copy internally,
	// but at least it keeps the interface clean
	_, err = d.conn.Write(newbuf)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	return nil
}

func (d *Dtls) Read() (*nxthdr.NxtHdr, net.Buffers, *common.NxtError) {

	// This is a datagram socket, we will get the entire dataram in one read and we need
	// one big buffer for that
	buf := make([]byte, common.MAXBUF)
	hdr := &nxthdr.NxtHdr{}
	dataLen, err := d.conn.Read(buf[0:])
	if err != nil {
		if err != io.EOF || dataLen == 0 {
			return nil, nil, common.Err(common.CONNECTION_ERR, err)
		}
	}

	noff := 0
	hdrLen, hbytes := binary.Uvarint(buf[noff : noff+int(dataLen)])
	if hbytes <= 0 {
		return nil, nil, common.Err(common.GENERAL_ERR, nil)
	}
	noff += hbytes
	err = proto.Unmarshal(buf[noff:noff+int(hdrLen)], hdr)
	if err != nil {
		return nil, nil, common.Err(common.GENERAL_ERR, err)
	}
	noff += int(hdrLen)
	retLen := dataLen - int(hdrLen) - hbytes
	if retLen != 0 {
		return hdr, net.Buffers{buf[noff : noff+retLen]}, nil
	} else {
		return hdr, net.Buffers{}, nil
	}
}

func (d *Dtls) SetReadDeadline(t time.Time) *common.NxtError {
	err := d.conn.SetReadDeadline(t)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	return nil
}

func listen(d *Dtls) *common.NxtError {
	server := fmt.Sprintf(":%d", d.port)
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	ctx := d.ctx

	certificate, err := common.LoadKeyAndCertificate(d.pvtKey, d.pubKey)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:         []tls.Certificate{*certificate},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ClientAuth:           dtls.RequireAnyClientCert,
		// Create timeout context for accepted connection.
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, 30*time.Second)
		},
	}

	// Connect to a DTLS server
	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		return common.Err(common.CONNECTION_ERR, err)
	}
	d.listener = listener

	return nil
}
