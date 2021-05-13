use common::{
    as_u32_be, key_to_hdr, parse_crnl, parse_host, FlowV4Key, NxtBufs, NxtErr, NxtErr::CONNECTION,
    NxtErr::EWOULDBLOCK, NxtError, RawStream, RegType, Transport,
};
use mio::{Interest, Poll, Token};
use object_pool::{Pool, Reusable};
use std::sync::Arc;
use std::{io::Read, io::Write};

const HTTP_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

pub struct WebProxy {
    closed: bool,
    key: FlowV4Key,
    socket: Option<RawStream>,
    connect_buf: Option<Reusable<Vec<u8>>>,
    connect_parsed: bool,
    buf_off: usize,
    pool: Arc<Pool<Vec<u8>>>,
}

// this is a non-blocking version, there is no option for this to work in a
// blocking mode as of now.
impl WebProxy {
    pub fn new_client(port: usize, pool: Arc<Pool<Vec<u8>>>) -> WebProxy {
        let mut key = FlowV4Key::default();
        key.sport = port as u16;
        WebProxy {
            closed: false,
            key,
            socket: None,
            connect_buf: None,
            connect_parsed: false,
            buf_off: 0,
            pool,
        }
    }
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
                    let connect_buf = match common::pool_get(self.pool.clone()) {
                        Some(b) => Some(b),
                        None => {
                            return Err(NxtError {
                                code: NxtErr::CONNECTION,
                                detail: "".to_string(),
                            });
                        }
                    };
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
                                connect_buf,
                                connect_parsed: false,
                                socket: Some(RawStream::Tcp(stream)),
                                buf_off: 0,
                                pool: self.pool.clone(),
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
                let offset;
                if !self.connect_parsed {
                    buf = self.connect_buf.take().unwrap();
                    offset = self.buf_off;
                } else {
                    buf = match common::pool_get(self.pool.clone()) {
                        Some(b) => b,
                        None => {
                            return Err(NxtError {
                                code: NxtErr::CONNECTION,
                                detail: "".to_string(),
                            });
                        }
                    };
                    offset = 0;
                }
                match stream.read(&mut buf[offset..]) {
                    Ok(len) => {
                        // Why would we get read of size 0 ? Even if its a non blocking
                        // socket, that should be an error WouldBlock
                        if len == 0 {
                            return Err(NxtError {
                                code: CONNECTION,
                                detail: "".to_string(),
                            });
                        }
                        if !self.connect_parsed {
                            self.buf_off += len;
                            let crnl = parse_crnl(&buf[0..self.buf_off]);
                            if crnl != 0 {
                                let (method, dport, dip) = parse_host(&buf[0..crnl]);
                                if dport == 0 || dip == "" {
                                    return Err(NxtError {
                                        code: NxtErr::CONNECTION,
                                        detail: "Bad Connect".to_string(),
                                    });
                                }
                                self.key.dport = dport as u16;
                                self.key.dip = dip;
                                self.connect_parsed = true;
                                if method == "CONNECT" {
                                    // We need to send an http-ok back
                                    buf[0..HTTP_OK.len()].copy_from_slice(HTTP_OK);
                                    unsafe { buf.set_len(HTTP_OK.len()) }
                                    self.connect_buf = Some(buf);
                                    self.buf_off = 0;
                                    // The connect request is an internal payload thats consumed here
                                    return Ok((
                                        0,
                                        NxtBufs {
                                            // The very first time we detect the destination, we return an nxthdr
                                            // as some place to return that info, after that nxthdr is just None
                                            hdr: Some(key_to_hdr(&self.key, &self.key.dip)),
                                            bufs: vec![],
                                            headroom: 0,
                                        },
                                    ));
                                } else if method == "GET" {
                                    unsafe { buf.set_len(crnl) }
                                    // The GET request is given back to the reader who will then transport it to
                                    // the final destination
                                    return Ok((
                                        0,
                                        NxtBufs {
                                            // The very first time we detect the destination, we return an nxthdr
                                            // as some place to return that info, after that nxthdr is just None
                                            hdr: Some(key_to_hdr(&self.key, &self.key.dip)),
                                            bufs: vec![buf],
                                            headroom: 0,
                                        },
                                    ));
                                } else {
                                    return Err(NxtError {
                                        code: CONNECTION,
                                        detail: "Unsupported method".to_string(),
                                    });
                                }
                            } else if self.buf_off < buf.capacity() {
                                // we have not yet received the entire CONNECT request, keep trying
                                self.connect_buf = Some(buf);
                                return Err(NxtError {
                                    code: EWOULDBLOCK,
                                    detail: "".to_string(),
                                });
                            } else {
                                // We dont expect connect req to need so much space!
                                return Err(NxtError {
                                    code: CONNECTION,
                                    detail: "".to_string(),
                                });
                            }
                        } else {
                            unsafe { buf.set_len(len) }
                            return Ok((
                                0,
                                NxtBufs {
                                    hdr: None,
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

    fn write(&mut self, _: u64, mut data: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        // If there is any pending http-ok to be sent, send that first before any other data is attempted
        if let Some(buf) = self.connect_buf.take() {
            match self.socket.as_mut().unwrap() {
                RawStream::Tcp(s) => match s.write(&buf[self.buf_off..]) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err((
                            Some(data),
                            NxtError {
                                code: EWOULDBLOCK,
                                detail: "".to_string(),
                            },
                        ));
                    }
                    Err(e) => {
                        return Err((
                            None,
                            NxtError {
                                code: CONNECTION,
                                detail: format!("{}", e),
                            },
                        ));
                    }
                    Ok(size) => {
                        self.buf_off += size;
                        if self.buf_off != buf.len() {
                            self.connect_buf = Some(buf);
                            return Err((
                                Some(data),
                                NxtError {
                                    code: EWOULDBLOCK,
                                    detail: "".to_string(),
                                },
                            ));
                        }
                    }
                },
                _ => panic!("Unexpected socket type"),
            }
        }

        while !data.bufs.is_empty() {
            let d = data.bufs.first().unwrap();
            match self.socket.as_mut().unwrap() {
                RawStream::Tcp(s) => match s.write(&d[data.headroom..]) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err((
                            Some(data),
                            NxtError {
                                code: EWOULDBLOCK,
                                detail: "".to_string(),
                            },
                        ));
                    }
                    Err(e) => {
                        return Err((
                            None,
                            NxtError {
                                code: CONNECTION,
                                detail: format!("{}", e),
                            },
                        ));
                    }
                    Ok(size) => {
                        let remaining = d[data.headroom..].len() - size;
                        if remaining == 0 {
                            data.bufs.remove(0);
                            data.headroom = 0;
                        } else {
                            data.headroom += size;
                            return Err((
                                Some(data),
                                NxtError {
                                    code: EWOULDBLOCK,
                                    detail: "".to_string(),
                                },
                            ));
                        }
                    }
                },
                _ => panic!("Unexpected socket type"),
            }
        }
        Ok(())
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
