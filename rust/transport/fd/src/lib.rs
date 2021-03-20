use common::{NxtBufs, NxtErr, NxtError, RegType, HEADROOM, MAXBUF};
use libc::c_void;
use mio::unix::SourceFd;
use mio::{Interest, Poll, Token};

const AF_INET: u8 = 2;

pub struct Fd {
    fd: i32,
    //os platform: linux including android/desktops = 0, apple = 1
    platform: usize,
    closed: bool,
}

// This is assumed to be a non-blocking fd

impl Fd {
    pub fn new_client(fd: i32, platform: usize) -> Self {
        Fd {
            fd,
            platform,
            closed: false,
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
        let mut buf: Vec<u8> = Vec::with_capacity(MAXBUF);
        unsafe {
            let mut headroom = HEADROOM;
            let ptr = buf.as_mut_ptr() as u64 + headroom as u64;
            let ptr = ptr as *mut c_void;
            match libc::read(self.fd, ptr, MAXBUF - headroom) {
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
                    buf.set_len(size as usize + headroom);
                    if self.platform == 1 {
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

    fn write(&mut self, _: u64, mut data: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        while !data.bufs.is_empty() {
            let mut d = data.bufs.first().unwrap();
            let mut dcloned: Vec<u8>;

            // IOS/Macos tun implementation appends a 4-bytes protocol information header
            // to each packet. IFF_NO_PI option can prevent this (TODO) ?? Also if there is
            // headroom >= 4 bytes, we can just slap in this data in the headroom instead
            if self.platform == 1 {
                dcloned = vec![0x0, 0x0, 0x0, AF_INET];
                dcloned.extend_from_slice(&d[data.headroom..]);
                d = &dcloned;
            }
            let ptr = d[data.headroom..].as_ptr() as *const libc::c_void;
            let len = d[data.headroom..].len();
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
                    len => {
                        assert!(len == d[data.headroom..].len() as isize);
                        data.bufs.remove(0);
                        data.headroom = 0;
                    }
                }
            }
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
