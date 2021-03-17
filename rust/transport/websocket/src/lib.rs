use common::{
    nxthdr::{nxt_hdr::StreamOp, NxtHdr},
    varint_decode, varint_encode, varint_encode_len, NxtBufs, NxtErr, NxtError, RawStream, RegType,
};
use http::Request;
use mio::{Interest, Poll, Token};
use native_tls::{Certificate, TlsConnector, TlsStream};
use prost::Message;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{collections::HashMap, u64};
use tungstenite::WebSocket;

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
    socket: Option<WebSocket<TlsStream<std::net::TcpStream>>>,
    request_headers: HashMap<String, String>,
    pub tcp_stream: Option<RawStream>,
    close_pending: Vec<u64>,
    nonblocking: bool,
}

struct WebStream {}

impl WebSession {
    pub fn new_client(
        ca_cert: Vec<u8>,
        server_name: &str,
        port: usize,
        request_headers: HashMap<String, String>,
        nonblocking: bool,
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
        }
    }
}

fn close_all_streams(
    socket: &mut WebSocket<TlsStream<std::net::TcpStream>>,
    streams: &mut HashMap<u64, WebStream>,
) {
    socket.close(None).ok();
    streams.clear();
}

fn send_close(
    close_pending: &mut Vec<u64>,
    socket: &mut WebSocket<TlsStream<std::net::TcpStream>>,
    streams: &mut HashMap<u64, WebStream>,
    stream: u64,
) -> usize {
    let mut hdr = NxtHdr::default();
    hdr.streamid = stream;
    hdr.streamop = StreamOp::Close as i32;

    let hdrlen = hdr.encoded_len();
    let hbytes = varint_encode_len(hdrlen);
    let mut buf = vec![0; hdrlen + hbytes];
    varint_encode(hdrlen, &mut buf[0..hbytes]);
    let mut hdrbuf = &mut buf[hbytes..];
    hdr.encode(&mut hdrbuf).unwrap();

    match socket.write_message(tungstenite::Message::Binary(buf)) {
        Ok(_) => return 0,
        Err(e) => match &e {
            tungstenite::Error::Io(ee) if ee.kind() == std::io::ErrorKind::WouldBlock => {
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

impl common::Transport for WebSession {
    fn dial(&mut self) -> Result<(), NxtError> {
        let svr = format!("{}:{}", self.server_name, self.port);
        let mut request = Request::builder();
        request = request.uri(format!("wss://{}", svr));
        for (k, v) in self.request_headers.iter() {
            request = request.header(k, v);
        }

        let cert = match Certificate::from_pem(&self.ca_cert) {
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
        let connector = match tls.build() {
            Err(e) => {
                return Err(NxtError {
                    code: NxtErr::CONNECTION,
                    detail: format!("{}", e),
                });
            }
            Ok(c) => c,
        };
        let stream = std::net::TcpStream::connect(svr)?;
        let connected_stream = connector.connect(&self.server_name, stream.try_clone()?)?;
        let socket = match tungstenite::client(request.body(()).unwrap(), connected_stream) {
            Ok((s, _)) => s,
            Err(e) => {
                let err = format!("{}", e);
                return Err(NxtError {
                    code: NxtErr::CONNECTION,
                    detail: err,
                });
            }
        };
        if self.nonblocking {
            stream.set_nonblocking(true)?;
        }
        self.tcp_stream = Some(RawStream::Tcp(mio::net::TcpStream::from_std(stream)));
        self.socket = Some(socket);

        return Ok(());
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
                match send_close(&mut self.close_pending, socket, &mut self.streams, stream) {
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
        let socket = self.socket.as_mut().unwrap();
        loop {
            let msg;
            match socket.read_message() {
                Ok(m) => msg = m,

                Err(e) => match &e {
                    tungstenite::Error::Io(ee) if ee.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err(NxtError {
                            code: NxtErr::EWOULDBLOCK,
                            detail: format!("{}", e),
                        });
                    }
                    _ => {
                        close_all_streams(socket, &mut self.streams);
                        return Err(NxtError {
                            code: NxtErr::CONNECTION,
                            detail: format!("{}", e),
                        });
                    }
                },
            }
            match msg {
                // Binary data from websocket
                tungstenite::Message::Binary(data) => {
                    let (hbytes, hdrlen) = varint_decode(&data[0..]);
                    let hdr;
                    match NxtHdr::decode(&mut Cursor::new(&data[hbytes..hbytes + hdrlen])) {
                        Ok(h) => hdr = h,
                        Err(e) => {
                            // This has to be some corrupt packet, and we cant keep a session open with that,
                            // one dropped packet is one too many!
                            close_all_streams(socket, &mut self.streams);
                            return Err(NxtError {
                                code: NxtErr::EWOULDBLOCK,
                                detail: format!("{}", e),
                            });
                        }
                    }
                    if hdr.streamop == StreamOp::Noop as i32 {
                        if !self.streams.contains_key(&hdr.streamid) {
                            let stream = WebStream {};
                            self.streams.insert(hdr.streamid, stream);
                        }
                        return Ok((
                            hdr.streamid,
                            NxtBufs {
                                hdr: Some(hdr),
                                bufs: vec![data],
                                headroom: hbytes + hdrlen,
                            },
                        ));
                    } else if hdr.streamop == StreamOp::Close as i32 {
                        if self.streams.contains_key(&hdr.streamid) {
                            send_close(
                                &mut self.close_pending,
                                socket,
                                &mut self.streams,
                                hdr.streamid,
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
                    }
                }

                // Nothing to do on getting ping, the library handles a pong
                tungstenite::Message::Ping(_) => {}

                // Nothing to do on getting a pong
                tungstenite::Message::Pong(_) => {}

                // Other end closed, we close this end too
                tungstenite::Message::Close(_) => {
                    return Err(NxtError {
                        code: NxtErr::CONNECTION,
                        detail: "closed".to_string(),
                    });
                }

                // Whatremains is websocket text data, which we should not be getting
                _ => {
                    close_all_streams(socket, &mut self.streams);
                    return Err(NxtError {
                        code: NxtErr::CONNECTION,
                        detail: "unknown message".to_string(),
                    });
                }
            }
        }
    }

    // This is not the most optimal function around, the write_message() API expects one
    // big buffer, so we have to concatenate everything. It would have bee nice if tungsten
    // had taken a struct with a reader interface, like the golang gorilla websocket lib.
    fn write(&mut self, stream: u64, mut data: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
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
            match send_close(&mut self.close_pending, socket, &mut self.streams, s) {
                0 => (),
                1 => {
                    return Err((
                        Some(data),
                        NxtError {
                            code: NxtErr::EWOULDBLOCK,
                            detail: "pending send close".to_string(),
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

        let mut o = data.headroom;
        let mut datalen = 0;
        for d in data.bufs.iter() {
            datalen += d[o..].len();
            o = 0;
        }

        let mut hdr = data.hdr.as_mut().unwrap();
        hdr.streamid = stream;
        hdr.streamop = StreamOp::Noop as i32;
        let hdrlen = hdr.encoded_len();
        let hbytes = varint_encode_len(hdrlen);
        let mut buf = vec![0; hbytes + hdrlen + datalen];
        varint_encode(hdrlen, &mut buf[0..hbytes]);
        let mut hdrbuf = &mut buf[hbytes..hbytes + hdrlen];
        hdr.encode(&mut hdrbuf).unwrap();

        let mut start = hbytes + hdrlen;
        let mut o = data.headroom;
        for d in data.bufs.iter() {
            buf[start..].clone_from_slice(&d[o..]);
            start += &d[o..].len();
            o = 0;
        }

        match socket.write_message(tungstenite::Message::Binary(buf)) {
            Ok(_) => return Ok(()),
            Err(e) => match &e {
                tungstenite::Error::Io(ee) if ee.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err((
                        Some(data),
                        NxtError {
                            code: NxtErr::EWOULDBLOCK,
                            detail: format!("{}", e),
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
