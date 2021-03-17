use common::{as_u32_be, NxtBufs, NxtErr, NxtError, RawStream, RegType, Transport};
use mio::{Interest, Poll, Token};

pub struct WebProxy {
    closed: bool,
    sip: u32,
    sport: u16,
    dip: String,
    dport: u16,
    socket: Option<RawStream>,
    connect_buf: Option<Vec<u8>>,
    connect_parsed: bool,
}

// this is a non-blocking version, there is no option for this to work in a
// blocking mode as of now.
impl WebProxy {
    fn new_client(port: usize) -> WebProxy {
        WebProxy {
            closed: false,
            sip: 0,
            sport: port as u16,
            dip: "".to_string(),
            dport: 0,
            socket: None,
            connect_buf: None,
            connect_parsed: false,
        }
    }
}

impl common::Transport for WebProxy {
    fn listen(&mut self) -> Result<Box<dyn Transport>, NxtError> {
        if self.socket.is_none() {
            let addr: std::net::SocketAddr = format!("0.0.0.0:{}", self.sport).parse().unwrap();
            let listener = mio::net::TcpListener::bind(addr)?;
            self.socket = Some(RawStream::TcpLis(listener));
        }
        match self.socket.as_mut().unwrap() {
            RawStream::TcpLis(listener) => match listener.accept() {
                Ok((stream, addr)) => {
                    match addr.ip() {
                        std::net::IpAddr::V4(v4addr) => {
                            return Ok(Box::new(WebProxy {
                                closed: false,
                                sip: as_u32_be(&v4addr.octets()),
                                sport: addr.port(),
                                dip: "".to_string(),
                                dport: 0,
                                connect_buf: None,
                                connect_parsed: false,
                                socket: Some(RawStream::Tcp(stream)),
                            }));
                        }
                        _ => {
                            // We only support ipv4 as of today
                            return Err(NxtError {
                                code: NxtErr::EWOULDBLOCK,
                                detail: "".to_string(),
                            });
                        }
                    }
                }

                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(NxtError {
                        code: NxtErr::EWOULDBLOCK,
                        detail: "".to_string(),
                    })
                }
                Err(e) => {
                    return Err(NxtError {
                        code: NxtErr::CONNECTION,
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
        return Err(NxtError {
            code: NxtErr::CONNECTION,
            detail: "WebProxy trait".to_string(),
        });
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
