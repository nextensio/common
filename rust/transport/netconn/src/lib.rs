use common::{NxtBufs, NxtErr::CONNECTION, NxtErr::EWOULDBLOCK, NxtError, RawStream, RegType};
use mio::{Interest, Poll, Token};
use std::net::UdpSocket;
use std::{io::Read, io::Write};
use std::{net::SocketAddr, net::TcpStream, net::ToSocketAddrs, time::Duration};

pub struct NetConn {
    closed: bool,
    server: String,
    port: usize,
    proto: usize,
    stream: Option<RawStream>,
    nonblocking: bool,
    connect_timeout: Option<Duration>,
}

impl NetConn {
    pub fn new_client(
        server: String,
        port: usize,
        proto: usize,
        nonblocking: bool,
        connect_timeout: Option<Duration>,
    ) -> NetConn {
        NetConn {
            server,
            port,
            proto,
            closed: false,
            stream: None,
            nonblocking,
            connect_timeout,
        }
    }
}

fn resolve_addr(dest_port: &str) -> Option<SocketAddr> {
    match dest_port.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => Some(addr),
            _ => None,
        },
        Err(_) => None,
    }
}

impl common::Transport for NetConn {
    fn dial(&mut self) -> Result<(), NxtError> {
        let dest_port = format!("{}:{}", self.server, self.port);
        let addr = resolve_addr(&dest_port);
        if addr.is_none() {
            return Err(NxtError {
                code: common::NxtErr::GENERAL,
                detail: "cannot resolve address".to_string(),
            });
        };
        let addr = addr.unwrap();
        if self.proto == common::TCP {
            if !self.nonblocking {
                let stream;
                if self.connect_timeout.is_some() {
                    stream = TcpStream::connect_timeout(&addr, self.connect_timeout.unwrap())?;
                } else {
                    stream = TcpStream::connect(&addr)?;
                }
                self.stream = Some(RawStream::Tcp(mio::net::TcpStream::from_std(stream)));
            } else {
                self.stream = Some(RawStream::Tcp(mio::net::TcpStream::connect(addr)?));
            }
        } else {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.connect(&addr)?;
            if self.nonblocking {
                socket.set_nonblocking(true)?;
            }
            self.stream = Some(RawStream::Udp(mio::net::UdpSocket::from_std(socket)));
        }
        return Ok(());
    }

    fn new_stream(&mut self) -> u64 {
        // No new stream for fd
        0
    }

    fn close(&mut self, _: u64) -> Result<(), NxtError> {
        match self.stream.as_mut().unwrap() {
            RawStream::Tcp(stream) => stream.shutdown(std::net::Shutdown::Both)?,
            RawStream::Udp(_) => {
                // The socket will be closed when the object itself goes out of contex(ie dropped)
            }
            _ => panic!("Unexpected stream type"),
        }
        Ok(())
    }

    fn is_closed(&self, _: u64) -> bool {
        self.closed
    }

    fn read(&mut self) -> Result<(u64, NxtBufs), NxtError> {
        let mut buf = vec![0; common::get_maxbuf()];
        match self.stream.as_mut().unwrap() {
            RawStream::Tcp(s) => match s.read(&mut buf[0..]) {
                Ok(size) => {
                    // Why would we get read of size 0 ? Even if its a non blocking
                    // socket, that should be an error WouldBlock
                    if size == 0 {
                        return Err(NxtError {
                            code: CONNECTION,
                            detail: "".to_string(),
                        });
                    }
                    unsafe { buf.set_len(size) }
                    return Ok((
                        0,
                        NxtBufs {
                            hdr: None,
                            bufs: vec![buf],
                            headroom: 0,
                        },
                    ));
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
            },
            RawStream::Udp(s) => match s.recv(&mut buf[0..]) {
                Ok(size) => {
                    unsafe { buf.set_len(size) }
                    return Ok((
                        0,
                        NxtBufs {
                            hdr: None,
                            bufs: vec![buf],
                            headroom: 0,
                        },
                    ));
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
            },
            _ => panic!("Unexpected stream type"),
        }
    }

    fn write(&mut self, _: u64, mut data: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        while !data.bufs.is_empty() {
            let d = data.bufs.first().unwrap();
            match self.stream.as_mut().unwrap() {
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
                RawStream::Udp(s) => match s.send(&d[data.headroom..]) {
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
                _ => panic!("Unexpected stream type"),
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
        match register {
            RegType::Reg => match self.stream.as_mut().unwrap() {
                RawStream::Tcp(stream) => poll.registry().register(
                    stream,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
                RawStream::Udp(stream) => poll.registry().register(
                    stream,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
                _ => panic!("Unexpected stream type"),
            },
            RegType::Dereg => match self.stream.as_mut().unwrap() {
                RawStream::Tcp(stream) => poll.registry().deregister(stream)?,
                RawStream::Udp(stream) => poll.registry().deregister(stream)?,
                _ => panic!("Unexpected stream type"),
            },
            RegType::Rereg => match self.stream.as_mut().unwrap() {
                RawStream::Tcp(stream) => poll.registry().reregister(
                    stream,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
                RawStream::Udp(stream) => poll.registry().reregister(
                    stream,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                )?,
                _ => panic!("Unexpected stream type"),
            },
        }
        Ok(())
    }
}
