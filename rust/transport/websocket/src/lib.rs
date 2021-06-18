use common::{
    nxthdr::{nxt_hdr::StreamOp, NxtHdr},
    varint_decode, varint_encode, varint_encode_len, NxtBufs, NxtErr,
    NxtErr::CONNECTION,
    NxtErr::ENOMEM,
    NxtErr::EWOULDBLOCK,
    NxtError, RawStream, RegType, MAXVARINT_BUF,
};
use log::error;
use mio::{Interest, Poll, Token};
use native_tls::{Certificate, TlsConnector, TlsConnectorBuilder, TlsStream};
use object_pool::{Pool, Reusable};
use prost::Message;
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{collections::HashMap, u64};
use std::{io::Cursor, io::Read, io::Write, sync::Arc};

// The format of the data that gets packed in a websocket is as below
// [length of nxt header][nxt header][payload]

//TODO: A websocket can be read and written to from seperate threads. The two values
//here which are not thread safe are the streams hashmap and the socket websocket
//structure itself. So we will need to lock those and hence the rx and tx will block
//on each other. If we truly want parallel Rx/Tx we should find a way to make these
//two to be non-locking
pub struct WebSession {
    port: usize,
    server_name: String,
    next_stream: AtomicU64,
    ca_cert: Vec<u8>,
    streams: HashMap<u64, WebStream>,
    server: bool,
    socket: Option<TlsStream<TcpStream>>,
    request_headers: HashMap<String, String>,
    pub tcp_stream: Option<RawStream>,
    close_pending: Vec<u64>,
    nonblocking: bool,
    pkt_pool: Arc<Pool<Vec<u8>>>,
    tcp_pool: Arc<Pool<Vec<u8>>>,
    pending_tx_data: Option<NxtBufs>,
    pending_tx_hdr: Option<Reusable<Vec<u8>>>,
    pending_tx_offset: usize,
    pending_rx_data: Option<Reusable<Vec<u8>>>,
    pending_rx_hdr: Option<NxtHdr>,
    pending_rx_offset: usize,
    rx_hdrlen: usize,
    dialed: bool,
    upgraded: bool,
    line: usize,
    cr: bool,
    nl: bool,
}

struct WebStream {}

impl WebSession {
    pub fn new_client(
        ca_cert: Vec<u8>,
        server_name: &str,
        port: usize,
        request_headers: HashMap<String, String>,
        nonblocking: bool,
        pkt_pool: Arc<Pool<Vec<u8>>>,
        tcp_pool: Arc<Pool<Vec<u8>>>,
    ) -> WebSession {
        let stream = WebStream {};
        let mut streams = HashMap::new();
        // First stream with streamid 0
        streams.insert(0, stream);
        WebSession {
            port,
            server_name: server_name.to_string(),
            next_stream: AtomicU64::new(0),
            ca_cert,
            streams,
            server: false,
            socket: None,
            request_headers,
            tcp_stream: None,
            close_pending: Vec::new(),
            nonblocking,
            pkt_pool,
            tcp_pool,
            pending_tx_data: None,
            pending_tx_hdr: None,
            pending_tx_offset: 0,
            pending_rx_data: None,
            pending_rx_hdr: None,
            pending_rx_offset: 0,
            rx_hdrlen: 0,
            dialed: false,
            upgraded: false,
            line: 0,
            cr: false,
            nl: false,
        }
    }

    fn write_upgrade(&mut self) -> Result<(), NxtError> {
        let mut req = "GET / HTTP/1.1\r\n".to_string();
        req.push_str(&format!("Host: {}:{}\r\n", self.server_name, self.port));
        req.push_str("Upgrade: websocket\r\n");
        req.push_str("Connection: Upgrade\r\n");
        req.push_str("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
        req.push_str("Sec-WebSocket-Version: 13\r\n");
        req.push_str("User-Agent: Go-http-client/1.1\r\n");
        for (k, v) in self.request_headers.iter() {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
        req.push_str("\r\n");
        if let Some(mut new) = common::pool_get(self.pkt_pool.clone()) {
            new.clear();
            new.extend_from_slice(&req.as_bytes());
            self.pending_tx_hdr = Some(new);
            self.pending_tx_offset = 0;
        } else {
            self.socket.as_mut().unwrap().shutdown().ok();
            return Err(NxtError {
                code: NxtErr::CONNECTION,
                detail: "OOB".to_string(),
            });
        }
        return retry_previous_pending(
            self.socket.as_mut().unwrap(),
            &mut self.pending_tx_hdr,
            &mut self.pending_tx_offset,
            &mut self.pending_tx_data,
        );
    }

    fn upgrade_parse_client(&mut self) -> Result<(), NxtError> {
        let mut buf: [u8; 1] = [0];

        loop {
            buf[0] = 0;
            match self.socket.as_mut().unwrap().read(&mut buf[..]) {
                Ok(size) => {
                    self.line += size;
                    if buf[0] == '\r' as u8 {
                        self.cr = true;
                    }
                    if buf[0] == '\n' as u8 {
                        self.nl = true;
                        if self.cr && self.nl && (self.line == 2) {
                            self.upgraded = true;
                            return Ok(());
                        }
                        self.cr = false;
                        self.nl = false;
                        self.line = 0;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(NxtError {
                        code: EWOULDBLOCK,
                        detail: "".to_string(),
                    })
                }
                Err(e) => {
                    return Err(NxtError {
                        code: CONNECTION,
                        detail: format!("{}", e),
                    })
                }
            }
        }
    }

    fn read_data(&mut self) -> Result<(), NxtError> {
        // Read in the nextensio data
        let datalen = self.pending_rx_hdr.as_ref().unwrap().datalen as usize;
        if let Some(buf) = self.pending_rx_data.as_mut() {
            while self.pending_rx_offset < datalen {
                let remaining = datalen - self.pending_rx_offset;
                match self
                    .socket
                    .as_mut()
                    .unwrap()
                    .read(&mut buf[self.pending_rx_offset..self.pending_rx_offset + remaining])
                {
                    Ok(size) => {
                        if size == 0 {
                            return Err(NxtError {
                                code: CONNECTION,
                                detail: "".to_string(),
                            });
                        }
                        self.pending_rx_offset += size;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err(NxtError {
                            code: EWOULDBLOCK,
                            detail: "".to_string(),
                        })
                    }
                    Err(e) => {
                        return Err(NxtError {
                            code: CONNECTION,
                            detail: format!("{}", e),
                        });
                    }
                }
            }
            Ok(())
        } else {
            return Err(NxtError {
                code: CONNECTION,
                detail: "".to_string(),
            });
        }
    }
    // NOTE & TODO: There are two assumptions being made here - that the entire
    // nextensio header and the entire payload will each fit in the buffer from
    // tcp_pool - to be precise, the assumption is that each of these items will
    // "individually" (not combined) fit in the buffer. Its easy to make the paload
    // to be multi-buffer aware since all of nextensio code supports multi-buf. But
    // for header, the prost decode api needs data in a single buff.
    fn read_message(&mut self) -> Result<(), NxtError> {
        if self.pending_rx_hdr.is_none() {
            if self.pending_rx_data.is_none() {
                if let Some(new) = common::pool_get(self.tcp_pool.clone()) {
                    self.pending_rx_data = Some(new);
                    self.pending_rx_offset = 0;
                    self.rx_hdrlen = 0;
                } else {
                    return Err(NxtError {
                        code: EWOULDBLOCK,
                        detail: "".to_string(),
                    });
                }
            }
            // first parse the nextensio header length which is encoded as a varint. We
            // read two bytes at a time to try and not over-read - as can be seen below,
            // the over-read bytes (which will be nextensio header itself) is moved to
            // offset 0 in the buffer. The smallest nextensio header can be two bytes
            // (a close stream header) and the smallest headerlength varint encoding
            // for that is 1 byte, so totally 3 bytes smallest
            if let Some(buf) = self.pending_rx_data.as_mut() {
                while self.rx_hdrlen == 0 {
                    match self
                        .socket
                        .as_mut()
                        .unwrap()
                        .read(&mut buf[self.pending_rx_offset..self.pending_rx_offset + 2])
                    {
                        Ok(size) => {
                            if size == 0 {
                                return Err(NxtError {
                                    code: CONNECTION,
                                    detail: "".to_string(),
                                });
                            }
                            self.pending_rx_offset += size;
                            if has_varint(&buf[0..self.pending_rx_offset]) {
                                let (hb, hl) = varint_decode(&buf[0..self.pending_rx_offset]);
                                // if we read extra, move it to the top
                                for i in 0..self.pending_rx_offset - hb {
                                    buf[i] = buf[hb + i];
                                }
                                self.rx_hdrlen = hl;
                                self.pending_rx_offset = self.pending_rx_offset - hb;
                                if self.rx_hdrlen > buf.capacity() {
                                    return Err(NxtError {
                                        code: CONNECTION,
                                        detail: "".to_string(),
                                    });
                                }
                                break;
                            }
                            if self.pending_rx_offset >= MAXVARINT_BUF {
                                return Err(NxtError {
                                    code: CONNECTION,
                                    detail: "".to_string(),
                                });
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            return Err(NxtError {
                                code: EWOULDBLOCK,
                                detail: "".to_string(),
                            })
                        }
                        Err(e) => {
                            return Err(NxtError {
                                code: CONNECTION,
                                detail: format!("{}", e),
                            });
                        }
                    }
                }
                // Read in the nextensio header
                while self.pending_rx_offset < self.rx_hdrlen {
                    let remaining = self.rx_hdrlen - self.pending_rx_offset;
                    match self
                        .socket
                        .as_mut()
                        .unwrap()
                        .read(&mut buf[self.pending_rx_offset..self.pending_rx_offset + remaining])
                    {
                        Ok(size) => {
                            if size == 0 {
                                return Err(NxtError {
                                    code: CONNECTION,
                                    detail: "".to_string(),
                                });
                            }
                            self.pending_rx_offset += size;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            return Err(NxtError {
                                code: EWOULDBLOCK,
                                detail: "".to_string(),
                            })
                        }
                        Err(e) => {
                            return Err(NxtError {
                                code: CONNECTION,
                                detail: format!("{}", e),
                            });
                        }
                    }
                }
                let b: &mut [u8] = &mut buf[0..self.rx_hdrlen];
                match NxtHdr::decode(&mut Cursor::new(b)) {
                    Ok(h) => {
                        if h.datalen as usize > buf.capacity() {
                            return Err(NxtError {
                                code: CONNECTION,
                                detail: "".to_string(),
                            });
                        }
                        unsafe {
                            buf.set_len(h.datalen as usize);
                        }
                        self.pending_rx_hdr = Some(h);
                        self.rx_hdrlen = 0;
                        self.pending_rx_offset = 0;
                    }
                    Err(e) => {
                        return Err(NxtError {
                            code: NxtErr::CONNECTION,
                            detail: format!("{}", e),
                        });
                    }
                }
            }
            return self.read_data();
        } else {
            return self.read_data();
        }
    }
}

fn has_varint(bytes: &[u8]) -> bool {
    for b in bytes.iter() {
        if b & 0x80 == 0 {
            return true;
        }
    }
    return false;
}

fn retry_previous_pending(
    socket: &mut TlsStream<TcpStream>,
    pending_tx_hdr: &mut Option<Reusable<Vec<u8>>>,
    pending_tx_offset: &mut usize,
    pending_tx_data: &mut Option<NxtBufs>,
) -> Result<(), NxtError> {
    if let Some(pending) = pending_tx_hdr.take() {
        match socket.write(&pending[*pending_tx_offset..]) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                *pending_tx_hdr = Some(pending);
                return Err(NxtError {
                    code: EWOULDBLOCK,
                    detail: "".to_string(),
                });
            }
            Err(e) => {
                return Err(NxtError {
                    code: CONNECTION,
                    detail: format!("{}", e),
                });
            }
            Ok(size) => {
                *pending_tx_offset += size;
                if *pending_tx_offset == pending.len() {
                    // pending_tx_hdr is None at this point
                    // break out and call write_data below if theres data to send
                } else {
                    *pending_tx_hdr = Some(pending);
                    return Err(NxtError {
                        code: EWOULDBLOCK,
                        detail: "".to_string(),
                    });
                }
            }
        }
    }

    if let Some(pending) = pending_tx_data.take() {
        return write_data(socket, pending, pending_tx_data);
    }

    return Ok(());
}

fn write_data(
    socket: &mut TlsStream<TcpStream>,
    mut data: NxtBufs,
    pending_tx_data: &mut Option<NxtBufs>,
) -> Result<(), NxtError> {
    while !data.bufs.is_empty() {
        let d = data.bufs.first().unwrap();
        match socket.write(&d[data.headroom..]) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                *pending_tx_data = Some(data);
                return Err(NxtError {
                    code: EWOULDBLOCK,
                    detail: "".to_string(),
                });
            }
            Err(e) => {
                return Err(NxtError {
                    code: CONNECTION,
                    detail: format!("{}", e),
                });
            }
            Ok(size) => {
                let remaining = d[data.headroom..].len() - size;
                if remaining == 0 {
                    data.bufs.remove(0);
                    data.headroom = 0;
                } else {
                    data.headroom += size;
                    *pending_tx_data = Some(data);
                    return Err(NxtError {
                        code: EWOULDBLOCK,
                        detail: "".to_string(),
                    });
                }
            }
        }
    }

    return Ok(());
}

fn write_header(
    socket: &mut TlsStream<TcpStream>,
    hdr: &mut NxtHdr,
    pending_tx_hdr: &mut Option<Reusable<Vec<u8>>>,
    pending_tx_offset: &mut usize,
    pending_tx_data: &mut Option<NxtBufs>,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
) -> Result<(), NxtError> {
    let hdrlen = hdr.encoded_len();
    let hbytes = varint_encode_len(hdrlen);
    // TODO and NOTE: There is a HUGE assumption here that the nextensio headers will fit in
    // one buffer from the pkt_pool
    if let Some(mut buf) = common::pool_get(pkt_pool.clone()) {
        varint_encode(hdrlen, &mut buf[0..hbytes]);
        let mut hdrbuf = &mut buf[hbytes..hbytes + hdrlen];
        hdr.encode(&mut hdrbuf).unwrap();
        unsafe {
            buf.set_len(hbytes + hdrlen);
        }
        *pending_tx_hdr = Some(buf);
        *pending_tx_offset = 0;
    } else {
        return Err(NxtError {
            code: NxtErr::ENOMEM,
            detail: "".to_string(),
        });
    }
    return retry_previous_pending(socket, pending_tx_hdr, pending_tx_offset, pending_tx_data);
}

fn close_all_streams(socket: &mut TlsStream<TcpStream>, streams: &mut HashMap<u64, WebStream>) {
    socket.shutdown().ok();
    streams.clear();
}

fn send_close(
    pending_tx_hdr: &mut Option<Reusable<Vec<u8>>>,
    pending_tx_offset: &mut usize,
    pending_tx_data: &mut Option<NxtBufs>,
    close_pending: &mut Vec<u64>,
    socket: &mut TlsStream<TcpStream>,
    streams: &mut HashMap<u64, WebStream>,
    stream: u64,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
) -> usize {
    let mut hdr = NxtHdr::default();
    hdr.streamid = stream;
    hdr.streamop = StreamOp::Close as i32;
    hdr.datalen = 0;

    // Already some header is waiting to be sent, so we just have to wait till thats sent,
    // give it a retry now
    match retry_previous_pending(socket, pending_tx_hdr, pending_tx_offset, pending_tx_data) {
        Ok(_) => {}
        Err(e) => match e.code {
            EWOULDBLOCK => {
                close_pending.push(stream);
                return 1;
            }
            _ => {
                close_all_streams(socket, streams);
                return 2;
            }
        },
    }

    match write_header(
        socket,
        &mut hdr,
        pending_tx_hdr,
        pending_tx_offset,
        pending_tx_data,
        &pkt_pool,
    ) {
        Ok(_) => return 0,
        Err(e) => match e.code {
            EWOULDBLOCK => {
                // The data has been put into pending_tx_hdr already
                return 1;
            }
            ENOMEM => {
                // The data could not get into pending_tx_hdr, add it back to close_pending list
                close_pending.push(stream);
                return 1;
            }
            _ => {
                close_all_streams(socket, streams);
                return 2;
            }
        },
    }
}

#[cfg(not(target_vendor = "apple"))]
fn tls_with_cert(ca_cert: &[u8]) -> Result<TlsConnectorBuilder, NxtError> {
    let cert = match Certificate::from_pem(ca_cert) {
        Err(e) => {
            return Err(NxtError {
                code: NxtErr::CONNECTION,
                detail: format!("{}", e),
            });
        }
        Ok(c) => c,
    };
    let mut tls = TlsConnector::builder();
    tls.add_root_certificate(cert);

    return Ok(tls);
}

// See the rust native-tls crate src/imp/security_framework.rs from_pem().
// For whatever reason its not implemented for ios. I am assuming its not a
// limitation but a missing support, we can add it ourselves at some point.
// For now we are using letsencrypt legit certs to talk from agent to gateway,
// so this is ok. But ideally we want the agent<-->gateway talk to be using
// self signed certs signed by the gateway, at that point we need to fix this
#[cfg(target_vendor = "apple")]
fn tls_with_cert(ca_cert: &[u8]) -> Result<TlsConnectorBuilder, NxtError> {
    let mut tls = TlsConnector::builder();

    return Ok(tls);
}

impl common::Transport for WebSession {
    fn dial(&mut self) -> Result<(), NxtError> {
        if !self.dialed {
            let svr = format!("{}:{}", self.server_name, self.port);
            let tls = match tls_with_cert(&self.ca_cert) {
                Err(e) => return Err(e),
                Ok(t) => t,
            };
            let connector = match tls.build() {
                Err(e) => {
                    return Err(NxtError {
                        code: NxtErr::CONNECTION,
                        detail: format!("{}", e),
                    });
                }
                Ok(c) => c,
            };
            let stream = TcpStream::connect(svr)?;
            self.socket = Some(connector.connect(&self.server_name, stream.try_clone()?)?);
            if self.nonblocking {
                stream.set_nonblocking(true)?;
            }
            self.tcp_stream = Some(RawStream::Tcp(mio::net::TcpStream::from_std(stream)));
            self.dialed = true;
            return self.write_upgrade();
        } else {
            return retry_previous_pending(
                self.socket.as_mut().unwrap(),
                &mut self.pending_tx_hdr,
                &mut self.pending_tx_offset,
                &mut self.pending_tx_data,
            );
        }
    }

    fn new_stream(&mut self) -> u64 {
        // fetch_add returns the OLD value
        let mut sid = self.next_stream.fetch_add(1, Ordering::Relaxed) + 1;
        // server has odd number streamids and client is even, just to prevent overlap
        if self.server {
            sid = 2 * sid + 1;
        } else {
            sid = 2 * sid;
        }
        let stream = WebStream {};
        self.streams.insert(sid, stream);
        sid
    }

    fn close(&mut self, stream: u64) -> Result<(), NxtError> {
        let socket = self.socket.as_mut().unwrap();
        if self.streams.contains_key(&stream) {
            self.streams.remove(&stream);
            if stream == 0 {
                // stream 0 is the "main" stream which corresponds to the connection itself,
                // closing stream 0 closes the entire connection
                close_all_streams(socket, &mut self.streams);
            } else {
                match send_close(
                    &mut self.pending_tx_hdr,
                    &mut self.pending_tx_offset,
                    &mut self.pending_tx_data,
                    &mut self.close_pending,
                    socket,
                    &mut self.streams,
                    stream,
                    &self.pkt_pool.clone(),
                ) {
                    0 => return Ok(()),
                    1 => {
                        return Err(NxtError {
                            code: NxtErr::EWOULDBLOCK,
                            detail: "pending send close".to_string(),
                        });
                    }
                    2 => {
                        return Err(NxtError {
                            code: NxtErr::CONNECTION,
                            detail: "".to_string(),
                        });
                    }
                    _ => panic!("Unexpected return code"),
                }
            }
        }
        Ok(())
    }

    fn is_closed(&self, stream: u64) -> bool {
        !self.streams.contains_key(&stream)
    }

    fn read(&mut self) -> Result<(u64, NxtBufs), NxtError> {
        if !self.upgraded {
            match self.upgrade_parse_client() {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        match self.read_message() {
            Ok(()) => {}
            Err(e) => match e.code {
                EWOULDBLOCK => {
                    return Err(e);
                }
                _ => {
                    close_all_streams(self.socket.as_mut().unwrap(), &mut self.streams);
                    return Err(e);
                }
            },
        }

        let socket = self.socket.as_mut().unwrap();
        let hdr = self.pending_rx_hdr.take().unwrap();
        let buf = self.pending_rx_data.take().unwrap();
        if hdr.streamop == StreamOp::Noop as i32 {
            if !self.streams.contains_key(&hdr.streamid) {
                let stream = WebStream {};
                self.streams.insert(hdr.streamid, stream);
            }
            return Ok((
                hdr.streamid,
                NxtBufs {
                    hdr: Some(hdr),
                    bufs: vec![buf],
                    headroom: 0,
                },
            ));
        } else if hdr.streamop == StreamOp::Close as i32 {
            if self.streams.contains_key(&hdr.streamid) {
                send_close(
                    &mut self.pending_tx_hdr,
                    &mut self.pending_tx_offset,
                    &mut self.pending_tx_data,
                    &mut self.close_pending,
                    socket,
                    &mut self.streams,
                    hdr.streamid,
                    &self.pkt_pool.clone(),
                );
                self.streams.remove(&hdr.streamid);
            }
            return Ok((
                hdr.streamid,
                NxtBufs {
                    hdr: Some(hdr),
                    bufs: vec![],
                    headroom: 0,
                },
            ));
        } else {
            error!("Unknown stream op {}", hdr.streamop);
            return Err(NxtError {
                code: NxtErr::EWOULDBLOCK,
                detail: "unknown stream op".to_string(),
            });
        }
    }

    // This is not the most optimal function around, the write_message() API expects one
    // big buffer, so we have to concatenate everything. It would have bee nice if tungsten
    // had taken a struct with a reader interface, like the golang gorilla websocket lib.
    fn write(&mut self, stream: u64, mut data: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        if !self.upgraded {
            return Err((
                Some(data),
                NxtError {
                    code: NxtErr::EWOULDBLOCK,
                    detail: "".to_string(),
                },
            ));
        }
        if !self.streams.contains_key(&stream) {
            return Err((
                None,
                NxtError {
                    code: NxtErr::CONNECTION,
                    detail: "stream not found".to_string(),
                },
            ));
        }
        let socket = self.socket.as_mut().unwrap();

        // There might be some pending stream close messages that we have to retry, this
        // is probably not the ideal place to retry this, but we dont want to expose to
        // the user another api to retry pending messages, hence doing it here
        while let Some(s) = self.close_pending.pop() {
            match send_close(
                &mut self.pending_tx_hdr,
                &mut self.pending_tx_offset,
                &mut self.pending_tx_data,
                &mut self.close_pending,
                socket,
                &mut self.streams,
                s,
                &self.pkt_pool.clone(),
            ) {
                0 => (),
                1 => {
                    return Err((
                        Some(data),
                        NxtError {
                            code: NxtErr::EWOULDBLOCK,
                            detail: "".to_string(),
                        },
                    ));
                }
                2 => {
                    return Err((
                        None,
                        NxtError {
                            code: NxtErr::CONNECTION,
                            detail: "".to_string(),
                        },
                    ));
                }
                _ => panic!("Unexpected return code"),
            }
        }

        // Already some header is waiting to be sent, so we just have to wait till thats sent,
        // give it a retry now
        match retry_previous_pending(
            socket,
            &mut self.pending_tx_hdr,
            &mut self.pending_tx_offset,
            &mut self.pending_tx_data,
        ) {
            Ok(_) => {}
            Err(e) => match e.code {
                EWOULDBLOCK => {
                    return Err((
                        Some(data),
                        NxtError {
                            code: NxtErr::EWOULDBLOCK,
                            detail: "".to_string(),
                        },
                    ));
                }
                _ => {
                    return Err((None, e));
                }
            },
        }

        // This might be the re-try of a previously attempted data, the previous attempt
        // might have sent the headers properly, hence the header might be legitimately None
        if let Some(mut hdr) = data.hdr.take() {
            let mut o = data.headroom;
            let mut datalen = 0;
            for d in data.bufs.iter() {
                datalen += d[o..].len();
                o = 0;
            }
            hdr.streamid = stream;
            hdr.streamop = StreamOp::Noop as i32;
            hdr.datalen = datalen as u32;
            match write_header(
                socket,
                &mut hdr,
                &mut self.pending_tx_hdr,
                &mut self.pending_tx_offset,
                &mut self.pending_tx_data,
                &self.pkt_pool,
            ) {
                Ok(_) => {}
                Err(e) => match e.code {
                    EWOULDBLOCK => {
                        self.pending_tx_data = Some(data);
                        // Returning ewouldblock will ensure that we are called again with
                        // empty data, so we will be 'driven' to complete what we queue here
                        return Err((
                            Some(NxtBufs {
                                hdr: None,
                                bufs: vec![],
                                headroom: 0,
                            }),
                            NxtError {
                                code: NxtErr::EWOULDBLOCK,
                                detail: "".to_string(),
                            },
                        ));
                    }
                    ENOMEM => {
                        // restore data.hdr, let sender retry
                        data.hdr = Some(hdr);
                        return Err((
                            Some(data),
                            NxtError {
                                code: NxtErr::EWOULDBLOCK,
                                detail: "pending send close".to_string(),
                            },
                        ));
                    }
                    _ => {
                        close_all_streams(socket, &mut self.streams);
                        return Err((
                            None,
                            NxtError {
                                code: NxtErr::CONNECTION,
                                detail: format!("{}", e),
                            },
                        ));
                    }
                },
            }
        }

        match write_data(socket, data, &mut self.pending_tx_data) {
            Ok(_) => {
                return Ok(());
            }
            Err(e) => match e.code {
                EWOULDBLOCK => {
                    // Returning ewouldblock will ensure that we are called again with
                    // empty data, so we will be 'driven' to complete what we queue here
                    return Err((
                        Some(NxtBufs {
                            hdr: None,
                            bufs: vec![],
                            headroom: 0,
                        }),
                        NxtError {
                            code: NxtErr::EWOULDBLOCK,
                            detail: "".to_string(),
                        },
                    ));
                }
                _ => {
                    return Err((
                        None,
                        NxtError {
                            code: NxtErr::CONNECTION,
                            detail: format!("{}", e),
                        },
                    ));
                }
            },
        }
    }

    fn event_register(
        &mut self,
        token: Token,
        poll: &mut Poll,
        register: RegType,
    ) -> Result<(), NxtError> {
        match register {
            RegType::Reg => match self.tcp_stream.as_mut().unwrap() {
                RawStream::Tcp(stream) => poll.registry().register(
                    stream,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
                _ => panic!("Only tcp expected"),
            },
            RegType::Dereg => match self.tcp_stream.as_mut().unwrap() {
                RawStream::Tcp(stream) => poll.registry().deregister(stream)?,
                _ => panic!("Only tcp expected"),
            },
            RegType::Rereg => match self.tcp_stream.as_mut().unwrap() {
                RawStream::Tcp(stream) => poll.registry().reregister(
                    stream,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
                _ => panic!("Only tcp expected"),
            },
        }
        Ok(())
    }
}
