use common::{
    as_u32_be, key_to_hdr, FlowV4Key, NxtBufs, NxtErr, NxtErr::CONNECTION, NxtErr::EWOULDBLOCK,
    NxtError, RawStream, RegType, Transport, MAXBUF,
};
use mio::{Interest, Poll, Token};
use std::{io::Read, io::Write};

pub struct WebProxy {
    closed: bool,
    key: FlowV4Key,
    socket: Option<RawStream>,
    connect_buf: Option<Vec<u8>>,
    connect_parsed: bool,
    rxlen: usize,
    txlen: usize,
}

const HTTP_OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

// this is a non-blocking version, there is no option for this to work in a
// blocking mode as of now.
impl WebProxy {
    fn new_client(port: usize) -> WebProxy {
        let mut key = FlowV4Key::default();
        key.sport = port as u16;
        WebProxy {
            closed: false,
            key,
            socket: None,
            connect_buf: None,
            connect_parsed: false,
            rxlen: 0,
            txlen: 0,
        }
    }
}

fn parse_crnl(buf: &[u8], len: usize, extra: usize) -> usize {
    0
}

fn parse_connect(buf: &[u8]) -> (u16, String) {
    (0, "".to_string())
}

impl common::Transport for WebProxy {
    fn listen(&mut self) -> Result<Box<dyn Transport>, NxtError> {
        if self.socket.is_none() {
            let addr: std::net::SocketAddr = format!("0.0.0.0:{}", self.key.sport).parse().unwrap();
            let listener = mio::net::TcpListener::bind(addr)?;
            self.socket = Some(RawStream::TcpLis(listener));
        }
        match self.socket.as_mut().unwrap() {
            RawStream::TcpLis(listener) => match listener.accept() {
                Ok((stream, addr)) => {
                    match addr.ip() {
                        std::net::IpAddr::V4(v4addr) => {
                            let key = FlowV4Key {
                                sip: as_u32_be(&v4addr.octets()),
                                sport: addr.port(),
                                dip: "".to_string(),
                                dport: 0,
                                proto: common::TCP,
                            };
                            return Ok(Box::new(WebProxy {
                                closed: false,
                                key,
                                connect_buf: Some(vec![0; MAXBUF]),
                                connect_parsed: false,
                                socket: Some(RawStream::Tcp(stream)),
                                rxlen: 0,
                                txlen: 0,
                            }));
                        }
                        _ => {
                            // We only support ipv4 as of today. The stream will get closed as its
                            // unused/dropped after this return
                            return Err(NxtError {
                                code: EWOULDBLOCK,
                                detail: "".to_string(),
                            });
                        }
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
                        detail: format!("{:?}", e),
                    })
                }
            },
            _ => panic!("Unexpected socket type"),
        }
    }

    fn new_stream(&mut self) -> u64 {
        // No new stream for tcp sockets
        0
    }

    fn close(&mut self, _: u64) -> Result<(), NxtError> {
        // sessions gets closed when object goes out of context and get dropped
        self.closed = true;
        Ok(())
    }

    fn is_closed(&self, _: u64) -> bool {
        self.closed
    }

    fn read(&mut self) -> Result<(u64, NxtBufs), NxtError> {
        match self.socket.as_mut().unwrap() {
            RawStream::Tcp(stream) => {
                let mut buf;
                if !self.connect_parsed {
                    buf = self.connect_buf.take().unwrap();
                } else {
                    buf = vec![0; MAXBUF];
                }
                match stream.read(&mut buf[self.rxlen..]) {
                    Ok(len) => {
                        if !self.connect_parsed {
                            let crnl = parse_crnl(&buf[0..], self.rxlen, len);
                            self.rxlen += len;
                            if crnl != 0 {
                                let (dport, dip) = parse_connect(&buf[0..crnl]);
                                if dport == 0 || dip == "" {
                                    return Err(NxtError {
                                        code: NxtErr::CONNECTION,
                                        detail: "Bad Connect".to_string(),
                                    });
                                }
                                self.key.dport = dport;
                                self.key.dip = dip;
                                self.connect_parsed = true;
                                if self.rxlen > crnl {
                                    unsafe { buf.set_len(self.rxlen) }
                                    return Ok((
                                        0,
                                        NxtBufs {
                                            hdr: Some(key_to_hdr(&self.key)),
                                            bufs: vec![buf],
                                            headroom: crnl,
                                        },
                                    ));
                                } else {
                                    return Err(NxtError {
                                        code: EWOULDBLOCK,
                                        detail: "".to_string(),
                                    });
                                }
                            } else {
                                // we have not yet received the entire CONNECT request, keep trying
                                self.connect_buf = Some(buf);
                                return Err(NxtError {
                                    code: EWOULDBLOCK,
                                    detail: "".to_string(),
                                });
                            }
                        } else {
                            unsafe { buf.set_len(len) }
                            return Ok((
                                0,
                                NxtBufs {
                                    hdr: Some(key_to_hdr(&self.key)),
                                    bufs: vec![buf],
                                    headroom: 0,
                                },
                            ));
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
            _ => panic!("Unexecpted socket type"),
        }
    }

    fn write(&mut self, _: u64, _: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        return Err((
            None,
            NxtError {
                code: NxtErr::CONNECTION,
                detail: "WebProxy trait".to_string(),
            },
        ));
    }

    fn event_register(
        &mut self,
        token: Token,
        poll: &mut Poll,
        register: RegType,
    ) -> Result<(), NxtError> {
        match self.socket.as_mut().unwrap() {
            RawStream::TcpLis(ref mut listener) => match register {
                RegType::Reg => poll.registry().register(
                    listener,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
                RegType::Dereg => poll.registry().deregister(listener)?,
                RegType::Rereg => poll.registry().reregister(
                    listener,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
            },
            RawStream::Tcp(ref mut stream) => match register {
                RegType::Reg => poll.registry().register(
                    stream,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
                RegType::Dereg => poll.registry().deregister(stream)?,
                RegType::Rereg => poll.registry().reregister(
                    stream,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
            },
            _ => panic!("Unexpected stream type"),
        }
        Ok(())
    }
}
