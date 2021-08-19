use std::sync::Arc;

use common::{NxtBufs, NxtErr, NxtErr::CONNECTION, NxtErr::EWOULDBLOCK, NxtError, RegType};
#[cfg(target_os = "windows")]
use mio::windows::NamedPipe;
use mio::{Interest, Poll, Token};
use object_pool::Pool;
use std::io::{Read, Write};

pub struct Pipe {
    _server: bool,
    pipe: NamedPipe,
    closed: bool,
    pool: Arc<Pool<Vec<u8>>>,
}

// This is a non-blocking pipe. Right now only server mode supported, its easy to add client mode too
#[cfg(target_os = "windows")]
impl Pipe {
    pub fn new_client(name: String, server: bool, pool: Arc<Pool<Vec<u8>>>) -> Option<Self> {
        if let Ok(pipe) = NamedPipe::new(&name) {
            Some(Pipe {
                _server: server,
                pipe,
                closed: false,
                pool,
            })
        } else {
            None
        }
    }
}

#[cfg(target_os = "windows")]
impl common::Transport for Pipe {
    fn dial(&mut self) -> Result<(), NxtError> {
        match self.pipe.connect() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(common::NxtError {
                    code: NxtErr::EWOULDBLOCK,
                    detail: format!("{}", e),
                });
            }
            Err(e) => {
                return Err(common::NxtError {
                    code: NxtErr::CONNECTION,
                    detail: format!("{}", e),
                });
            }
            Ok(_) => return Ok(()),
        }
    }

    fn new_stream(&mut self) -> u64 {
        // No new stream for pipe
        0
    }

    fn close(&mut self, _: u64) -> Result<(), NxtError> {
        if !self.closed {
            if let Ok(_) = self.pipe.disconnect() {
                self.closed = true;
                return Ok(());
            } else {
                return Err(common::NxtError {
                    code: NxtErr::CONNECTION,
                    detail: format!("{}", ""),
                });
            }
        }
        Ok(())
    }

    fn is_closed(&self, _: u64) -> bool {
        self.closed
    }

    fn read(&mut self) -> Result<(u64, NxtBufs), NxtError> {
        let mut buf = match common::pool_get(self.pool.clone()) {
            Some(b) => b,
            None => {
                return Err(NxtError {
                    code: NxtErr::EWOULDBLOCK,
                    detail: "".to_string(),
                });
            }
        };
        match self.pipe.read(&mut buf[0..]) {
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
        }
    }

    // Note that headroom applies to only the first buffer in the vector of buffers. Typically
    // we just get a single buffer to transmit, so its headroom plus just one buffer. But if its
    // more than one buffer, as we can see, the headroom is reset to 0 after the first buffer.
    fn write(&mut self, _: u64, mut data: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        while !data.bufs.is_empty() {
            let d = data.bufs.first().unwrap();
            match self.pipe.write(&d[data.headroom..]) {
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
            RegType::Reg => poll.registry().register(
                &mut self.pipe,
                token,
                Interest::READABLE | Interest::WRITABLE,
            )?,
            RegType::Dereg => poll.registry().deregister(&mut self.pipe)?,
            RegType::Rereg => poll.registry().reregister(
                &mut self.pipe,
                token,
                Interest::READABLE | Interest::WRITABLE,
            )?,
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
impl common::Transport for Fd {
    fn new_stream(&mut self) -> u64 {
        0
    }
    fn close(&mut self, _: u64) -> Result<(), NxtError> {
        Err(common::NxtError {
            code: common::NxtErr::GENERAL,
            detail: "unsupported".to_string(),
        })
    }
    fn is_closed(&self, _: u64) -> bool {
        true
    }

    fn read(&mut self) -> Result<(u64, NxtBufs), NxtError> {
        Err(common::NxtError {
            code: common::NxtErr::GENERAL,
            detail: "unsupported".to_string(),
        })
    }

    // On error EWOULDBLOCK/EAGAIN, write returns back the data that was unable to
    // be written so that the caller can try again. All other "non-retriable" errors
    // just returns None as the data with WriteError. Also the data that is returned on
    // EWOULDBLOCK might be different from (less than) the data that was passed in because
    // some of that data might have been transmitted
    fn write(&mut self, _: u64, _: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        Err((
            None,
            common::NxtError {
                code: common::NxtErr::GENERAL,
                detail: "unsupported".to_string(),
            },
        ))
    }
}

#[cfg(test)]
mod test;
