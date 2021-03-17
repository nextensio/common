use common::{NxtBufs, NxtErr, NxtError, RawStream, RegType, Transport};
use mio::{Interest, Poll, Token};

pub struct WebProxy {
    closed: bool,
    port: usize,
    socket: Option<RawStream>,
}

// this is a non-blocking version, there is no option for this to work in a
// blocking mode as of now.
impl WebProxy {
    fn new_client(port: usize) -> WebProxy {
        WebProxy {
            closed: false,
            port,
            socket: None,
        }
    }
}

impl common::Transport for WebProxy {
    fn listen(&mut self) -> Result<Box<dyn Transport>, NxtError> {
        if self.socket.is_none() {
            let addr: std::net::SocketAddr = format!("0.0.0.0:{}", self.port).parse().unwrap();
            let listener = mio::net::TcpListener::bind(addr)?;
            self.socket = Some(RawStream::TcpLis(listener));
        }
        match self.socket.as_mut().unwrap() {
            RawStream::TcpLis(listener) => match listener.accept() {
                Ok((stream, _)) => {
                    return Ok(Box::new(WebProxy {
                        closed: false,
                        port: 0,
                        socket: Some(RawStream::Tcp(stream)),
                    }));
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
