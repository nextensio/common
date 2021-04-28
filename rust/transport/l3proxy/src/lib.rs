use common::{
    get_maxbuf, FlowV4Key, NxtBufs, NxtErr, NxtErr::CONNECTION, NxtErr::EWOULDBLOCK, NxtError, TCP,
    UDP,
};
use smoltcp::iface::InterfaceBuilder;
use smoltcp::socket::TcpSocket;
use smoltcp::socket::TcpSocketBuffer;
use smoltcp::socket::UdpSocket;
use smoltcp::socket::{UdpPacketMetadata, UdpSocketBuffer};
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint};
use smoltcp::Error;
use smoltcp::{
    phy::packetq::PacketQ, phy::Medium, socket::SocketHandle, socket::SocketRef, socket::SocketSet,
};
use std::collections::VecDeque;
use std::net::Ipv4Addr;

// NOTE: See pub enum ManagedSlice in slice.rs in the smoltcp code,
// the lifetime here is for the 'Borrowed' variant of that enum in
// the mode where smoltcp does not use std lib and cannot do allocations.
// Here we use stdlib and for us the lifetime will just end up being 'static
// and hence it wont cause too many headaches with the borrow checker
pub struct Socket<'a> {
    onesock: SocketSet<'a>,
    closed: bool,
    established: bool,
    ip_addrs: [IpCidr; 1],
    mtu: usize,
    handle: SocketHandle,
    proto: usize,
    endpoint: Option<IpEndpoint>,
}

impl<'a> Socket<'a> {
    pub fn new_client(tuple: &FlowV4Key, mtu: usize) -> Self {
        let mut onesock = SocketSet::new(Vec::with_capacity(1));
        let handle;
        if tuple.proto == TCP {
            let rx = TcpSocketBuffer::new(vec![0; 2 * get_maxbuf()]);
            let tx = TcpSocketBuffer::new(vec![0; 2 * get_maxbuf()]);
            let mut socket = TcpSocket::new(rx, tx);
            socket.listen(tuple.dport).unwrap();
            handle = onesock.add(socket);
        } else {
            // Smoltcp needs a "continguous" buffer in the case of udp, see enqueue() in
            // packet_buffer.rs in smoltcp. So we need a size of 2*mtu so that there is
            // always space for one full packet all the time
            let rx = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 2 * mtu]);
            let tx = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 2 * mtu]);
            let mut socket = UdpSocket::new(rx, tx);
            socket.bind(tuple.dport).unwrap();
            handle = onesock.add(socket);
        }
        let dest: Ipv4Addr = tuple.dip.parse().unwrap();
        let octets = dest.octets();
        let dest = IpAddress::v4(octets[0], octets[1], octets[2], octets[3]);
        Socket {
            onesock,
            closed: false,
            established: false,
            ip_addrs: [IpCidr::new(dest, 32)],
            mtu,
            handle,
            proto: tuple.proto,
            endpoint: None,
        }
    }
}

fn close_udp(_: SocketRef<UdpSocket>, closed: &mut bool) -> Result<(), NxtError> {
    if !*closed {
        *closed = true;
    }
    Ok(())
}

fn close_tcp(mut sock: SocketRef<TcpSocket>, closed: &mut bool) -> Result<(), NxtError> {
    if !*closed {
        *closed = true;
        sock.close();
    }
    Ok(())
}

impl<'a> common::Transport for Socket<'a> {
    fn dial(&mut self) -> Result<(), NxtError> {
        Ok(())
    }

    fn new_stream(&mut self) -> u64 {
        // No new stream for a socket
        0
    }

    fn close(&mut self, _: u64) -> Result<(), NxtError> {
        if self.proto == common::UDP {
            let sock = self.onesock.get::<UdpSocket>(self.handle);
            close_udp(sock, &mut self.closed)
        } else {
            let sock = self.onesock.get::<TcpSocket>(self.handle);
            close_tcp(sock, &mut self.closed)
        }
    }

    fn is_closed(&self, _: u64) -> bool {
        self.closed
    }

    fn read(&mut self) -> Result<(u64, NxtBufs), NxtError> {
        if self.closed {
            return Err(NxtError {
                code: CONNECTION,
                detail: "".to_string(),
            });
        }
        if self.proto == common::UDP {
            let mut sock = self.onesock.get::<UdpSocket>(self.handle);
            match sock.recv() {
                Ok((data, endpoint)) => {
                    if self.endpoint.is_none() {
                        self.endpoint = Some(endpoint);
                    }
                    return Ok((
                        0,
                        NxtBufs {
                            hdr: None,
                            bufs: vec![data.to_vec()],
                            headroom: 0,
                        },
                    ));
                }
                Err(e) => match e {
                    Error::Exhausted => {
                        return Err(NxtError {
                            code: EWOULDBLOCK,
                            detail: "".to_string(),
                        });
                    }
                    _ => {
                        close_udp(sock, &mut self.closed).ok();
                        return Err(NxtError {
                            code: CONNECTION,
                            detail: format!("{}", e),
                        });
                    }
                },
            }
        } else {
            let mut sock = self.onesock.get::<TcpSocket>(self.handle);
            if !sock.may_recv() || !sock.may_send() {
                if self.established {
                    // TODO: we treat half closed as an error, do we really need to support that ??
                    close_tcp(sock, &mut self.closed).ok();
                    return Err(NxtError {
                        code: CONNECTION,
                        detail: "".to_string(),
                    });
                } else {
                    // Wait for the session to be established first
                    return Err(NxtError {
                        code: EWOULDBLOCK,
                        detail: "".to_string(),
                    });
                }
            }
            self.established = true;
            if !sock.can_recv() {
                return Err(NxtError {
                    code: EWOULDBLOCK,
                    detail: "".to_string(),
                });
            }
            let ret = sock.recv(|buffer| {
                let recvd_len = buffer.len();
                let data = buffer.to_vec();
                (recvd_len, data)
            });
            match ret {
                Ok(data) => {
                    return Ok((
                        0,
                        NxtBufs {
                            hdr: None,
                            bufs: vec![data],
                            headroom: 0,
                        },
                    ))
                }
                Err(e) => {
                    close_tcp(sock, &mut self.closed).ok();
                    return Err(NxtError {
                        code: CONNECTION,
                        detail: format!("{}", e),
                    });
                }
            }
        }
    }

    fn write(&mut self, _: u64, mut data: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)> {
        if self.closed {
            return Err((
                None,
                NxtError {
                    code: NxtErr::CONNECTION,
                    detail: "".to_string(),
                },
            ));
        }
        if self.proto == UDP {
            let mut sock = self.onesock.get::<UdpSocket>(self.handle);
            if let Some(endpoint) = self.endpoint.as_ref() {
                while !data.bufs.is_empty() {
                    let d = data.bufs.first().unwrap();
                    match sock.send_slice(&d[data.headroom..], *endpoint) {
                        Err(e) => match e {
                            Error::Exhausted => {
                                return Err((
                                    Some(data),
                                    NxtError {
                                        code: EWOULDBLOCK,
                                        detail: "".to_string(),
                                    },
                                ));
                            }
                            _ => {
                                close_udp(sock, &mut self.closed).ok();
                                return Err((
                                    None,
                                    NxtError {
                                        code: CONNECTION,
                                        detail: format!("{}", e),
                                    },
                                ));
                            }
                        },
                        Ok(()) => {
                            data.bufs.remove(0);
                            data.headroom = 0;
                        }
                    }
                }
            } else {
                close_udp(sock, &mut self.closed).ok();
                return Err((
                    None,
                    NxtError {
                        code: NxtErr::CONNECTION,
                        detail: "no endpoint".to_string(),
                    },
                ));
            }
        } else {
            let mut sock = self.onesock.get::<TcpSocket>(self.handle);
            if !sock.may_recv() || !sock.may_send() {
                if self.established {
                    // TODO: we treat half closed as an error, do we really need to support that ??
                    close_tcp(sock, &mut self.closed).ok();
                    return Err((
                        None,
                        NxtError {
                            code: CONNECTION,
                            detail: "".to_string(),
                        },
                    ));
                } else {
                    // Wait for the session to be established first
                    return Err((
                        Some(data),
                        NxtError {
                            code: EWOULDBLOCK,
                            detail: "".to_string(),
                        },
                    ));
                }
            }
            self.established = true;
            while !data.bufs.is_empty() {
                let d = data.bufs.first().unwrap();
                match sock.send_slice(&d[data.headroom..]) {
                    Err(e) => {
                        close_tcp(sock, &mut self.closed).ok();
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
        }
        Ok(())
    }

    fn poll(&mut self, rx: &mut VecDeque<(usize, Vec<u8>)>, tx: &mut VecDeque<(usize, Vec<u8>)>) {
        let pktq = PacketQ::new(Medium::Ip, self.mtu, rx, tx, 0);
        // The below is some cycles that can be saved if smolltcp were to expose the
        // interface.device to us. So we dont have to keep building this each time, we
        // can keep it built and just swap out the queues here
        let mut interface = InterfaceBuilder::new(pktq)
            .ip_addrs(self.ip_addrs)
            .finalize();
        interface
            .poll(
                &mut self.onesock,
                smoltcp::time::Instant::from(std::time::Instant::now()),
            )
            .ok();
    }
}
