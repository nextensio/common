use std::sync::Arc;

use common::{get_maxbuf, NxtBufs, NxtErr, NxtError, RegType, HEADROOM};
use libc::c_void;
use log::error;
use mio::unix::SourceFd;
use mio::{Interest, Poll, Token};
use object_pool::Pool;

const AF_INET: u8 = 2;

pub struct Fd {
    fd: i32,
    //os platform: linux including android/desktops = 0, apple = 1
    platform: usize,
    _mtu: usize,
    closed: bool,
    pool: Arc<Pool<Vec<u8>>>,
}

// This is assumed to be a non-blocking fd

impl Fd {
    pub fn new_client(fd: i32, platform: usize, mtu: usize, pool: Arc<Pool<Vec<u8>>>) -> Self {
        Fd {
            fd,
            platform,
            _mtu: mtu,
            closed: false,
            pool,
        }
    }
}

impl common::Transport for Fd {
    fn dial(&mut self) -> Result<(), NxtError> {
        Ok(())
    }

    fn new_stream(&mut self) -> u64 {
        // No new stream for fd
        0
    }

    fn close(&mut self, _: u64) -> Result<(), NxtError> {
        if !self.closed {
            unsafe {
                libc::close(self.fd);
            }
            self.closed = true;
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
        unsafe {
            let mut headroom = HEADROOM;
            let ptr = buf.as_mut_ptr() as u64 + headroom as u64;
            let ptr = ptr as *mut c_void;
            match libc::read(self.fd, ptr, get_maxbuf() - headroom) {
                -1 => {
                    let e = std::io::Error::last_os_error();
                    match e.kind() {
                        std::io::ErrorKind::WouldBlock => {
                            return Err(NxtError {
                                code: NxtErr::EWOULDBLOCK,
                                detail: "".to_string(),
                            });
                        }
                        _ => {
                            self.close(0).ok();
                            return Err(NxtError {
                                code: NxtErr::CONNECTION,
                                detail: format!("{}", e),
                            });
                        }
                    }
                }
                size => {
                    // This is setting the "end" of the buffer. The data is
                    // from offset headroom till end of the buffer
                    buf.set_len(size as usize + headroom);
                    if self.platform == 1 {
                        // extend headroom by 4 bytes, ie ignore first 4 bytes
                        headroom += 4;
                    }
                    Ok((
                        0,
                        NxtBufs {
                            hdr: None,
                            bufs: vec![buf],
                            headroom,
                        },
                    ))
                }
            }
        }
    }

    // Note that headroom applies to only the first buffer in the vector of buffers. Typically
    // we just get a single buffer to transmit, so its headroom plus just one buffer. But if its
    // more than one buffer, as we can see, the headroom is reset to 0 after the first buffer.
    fn write(&mut self, _: u64, mut data: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        while !data.bufs.is_empty() {
            let ptr;
            let len;
            let mut dcloned: Vec<u8> = vec![0x0, 0x0, 0x0, AF_INET];
            // IOS/Macos tun implementation appends a 4-bytes protocol information header
            // to each packet. IFF_NO_PI option can prevent this (TODO) ??
            if self.platform == 1 {
                if data.headroom >= 4 {
                    error!("has headroom {}", data.headroom);
                    let d = data.bufs.first_mut().unwrap();
                    let h = data.headroom - 4;
                    d[h..h + 4].copy_from_slice(&dcloned[0..]);
                    ptr = d[h..].as_ptr() as *const libc::c_void;
                    len = d[h..].len();
                } else {
                    let d = data.bufs.first().unwrap();
                    dcloned.extend_from_slice(&d[data.headroom..]);
                    ptr = dcloned[0..].as_ptr() as *const libc::c_void;
                    len = dcloned[0..].len();
                }
            } else {
                let d = data.bufs.first().unwrap();
                ptr = d[data.headroom..].as_ptr() as *const libc::c_void;
                len = d[data.headroom..].len();
            }
            unsafe {
                match libc::write(self.fd, ptr, len) {
                    -1 => {
                        let e = std::io::Error::last_os_error();
                        match e.kind() {
                            std::io::ErrorKind::WouldBlock => {
                                return Err((
                                    Some(data),
                                    NxtError {
                                        code: NxtErr::EWOULDBLOCK,
                                        detail: "".to_string(),
                                    },
                                ));
                            }
                            _ => {
                                if let Some(errno) = e.raw_os_error() {
                                    if errno == 105 {
                                        // ENOBUFS: Not sure why rust doesnt include this in the
                                        // ErrorKind::Wouldblock category. Android phones complain about
                                        // this if we go close to the interface mtu
                                        return Err((
                                            Some(data),
                                            NxtError {
                                                code: NxtErr::EWOULDBLOCK,
                                                detail: "".to_string(),
                                            },
                                        ));
                                    } else if errno == 90 {
                                        // EMSGSIZE: Well we should never end up here with a packet larger
                                        // than the interface mtu. All we can do is drop the packet and log
                                        // a message
                                        return Ok(());
                                    }
                                }
                                // All other errors are bad (till we investigate and find they are not!).
                                self.close(0).ok();
                                return Err((
                                    None,
                                    NxtError {
                                        code: NxtErr::CONNECTION,
                                        detail: format!("{}", e),
                                    },
                                ));
                            }
                        }
                    }
                    txbytes => {
                        assert!(txbytes == len as isize);
                        data.bufs.remove(0);
                        data.headroom = 0;
                    }
                }
            }
            // The libc::write() might be referring to dcloned, we need it alive till
            // libc::write is over with
            drop(dcloned);
        }
        return Ok(());
    }

    fn event_register(
        &mut self,
        token: Token,
        poll: &mut Poll,
        register: RegType,
    ) -> Result<(), NxtError> {
        match register {
            RegType::Reg => poll.registry().register(
                &mut SourceFd(&self.fd),
                token,
                Interest::READABLE | Interest::WRITABLE,
            )?,
            RegType::Dereg => poll.registry().deregister(&mut SourceFd(&self.fd))?,
            RegType::Rereg => poll.registry().reregister(
                &mut SourceFd(&self.fd),
                token,
                Interest::READABLE | Interest::WRITABLE,
            )?,
        }
        Ok(())
    }
}
