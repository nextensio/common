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
    tx_mtu: usize,
    handle: SocketHandle,
    proto: usize,
    endpoint: Option<IpEndpoint>,
    has_rxbuf: bool,
    has_txbuf: bool,
}

impl<'a> Socket<'a> {
    pub fn new_client(tuple: &FlowV4Key, rx_mtu: usize, tx_mtu: usize) -> Self {
        let mut onesock = SocketSet::new(Vec::with_capacity(1));
        let handle;
        let mut has_rxbuf = true;
        let mut has_txbuf = true;
        if tuple.proto == TCP {
            let rx = TcpSocketBuffer::new(vec![0; get_maxbuf()]);
            let tx = TcpSocketBuffer::new(vec![0; get_maxbuf()]);
            let mut socket = TcpSocket::new(rx, tx, rx_mtu);
            socket.listen(tuple.dport).unwrap();
            handle = onesock.add(socket);
        } else {
            // We will allocate buffers when needed for udp, ie when packet arrives
            has_rxbuf = false;
            has_txbuf = false;
            let rx = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![]);
            let tx = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![]);
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
            tx_mtu,
            handle,
            proto: tuple.proto,
            endpoint: None,
            has_rxbuf,
            has_txbuf,
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
            let ret = sock.recv_buffer_owned();
            match ret {
                Some((mut data, len, endpoint)) => {
                    self.has_rxbuf = false;
                    if len > 0 {
                        unsafe {
                            data.set_len(len);
                        }
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
                    } else {
                        return Err(NxtError {
                            code: EWOULDBLOCK,
                            detail: "".to_string(),
                        });
                    }
                }
                None => {
                    return Err(NxtError {
                        code: EWOULDBLOCK,
                        detail: "".to_string(),
                    });
                }
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
            let ret = sock.recv_buffer_owned(false);
            match ret {
                Some((mut data, len)) => {
                    self.has_rxbuf = false;
                    if len > 0 {
                        unsafe {
                            data.set_len(len);
                        }
                        return Ok((
                            0,
                            NxtBufs {
                                hdr: None,
                                bufs: vec![data],
                                headroom: 0,
                            },
                        ));
                    } else {
                        return Err(NxtError {
                            code: EWOULDBLOCK,
                            detail: "".to_string(),
                        });
                    }
                }
                None => {
                    return Err(NxtError {
                        code: EWOULDBLOCK,
                        detail: "".to_string(),
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
            // For udp, we get a new buffer for each new packet, we cant keep appending
            // to the old buffer like we do in tcp because udp is not a "stream" transport.
            // If the old buffer had data, it just gets freed when we set the new one, so
            // we lose the data, too bad - but it wont happen because the caller usually transmits
            // as soon as it has data
            let tbuf = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; get_maxbuf()]);
            sock.set_tx_buffer(tbuf);
            self.has_txbuf = true;
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
            if !self.has_txbuf {
                let tbuf = TcpSocketBuffer::new(vec![0; get_maxbuf()]);
                sock.set_tx_buffer(tbuf);
                self.has_txbuf = true;
            }
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

    // The iphone is EXTREMELY stingy with memory, the entire datapath including code and data
    // has to fit in 15Mb. So we have no option but to be very rough with reclaiming unused memory
    fn poll(&mut self, rx: &mut VecDeque<(usize, Vec<u8>)>, tx: &mut VecDeque<(usize, Vec<u8>)>) {
        let tcp = self.proto == common::TCP;
        // There is some packet going into tcp/udp, it might have data or it might be just tcp ACK
        // with no data, we dont know that here (well we can if we parse), we give the flow
        // a buffer anyways. We will take it back if there was no data written to it. For udp
        // if there is a packet then there is data for sure.
        if tcp {
            if rx.len() != 0 && !self.has_rxbuf {
                let mut sock = self.onesock.get::<TcpSocket>(self.handle);
                let rbuf = TcpSocketBuffer::new(vec![0; get_maxbuf()]);
                sock.set_rx_buffer(rbuf);
                self.has_rxbuf = true;
            }
        } else {
            if rx.len() != 0 && !self.has_rxbuf {
                let mut sock = self.onesock.get::<UdpSocket>(self.handle);
                let rbuf =
                    UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; get_maxbuf()]);
                sock.set_rx_buffer(rbuf);
                self.has_rxbuf = true;
            }
        }

        let pktq = PacketQ::new(Medium::Ip, self.tx_mtu, rx, tx, 0);
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

        if tcp {
            // Some packets are generated to be transmitted, if all of the tcp data has
            // been transmitted, reclaim the buffers
            let mut sock = self.onesock.get::<TcpSocket>(self.handle);
            if self.has_txbuf {
                if sock.send_buffer_owned(false).is_some() {
                    self.has_txbuf = false;
                }
            }
            if !sock.recv_has_data() {
                // Maybe we just gave an ACK with no data, to the socket. The receive buffers
                // are empty, reclaim them
                if sock.recv_buffer_owned(false).is_some() {
                    self.has_rxbuf = false;
                }
            }
        } else {
            // udp data doesnt have to wait for any conditions to be sent, as soon as poll
            // is done, the udp data will be packet-ized in the tx packet queue and we can
            // dispose off the data buffer
            let mut sock = self.onesock.get::<UdpSocket>(self.handle);
            sock.send_buffer_owned();
            self.has_txbuf = false;
            if !sock.recv_has_data() {
                sock.recv_buffer_owned();
                self.has_rxbuf = false;
            }
        }
    }

    fn idle(&mut self, force: bool) -> bool {
        if self.proto == common::TCP {
            let mut sock = self.onesock.get::<TcpSocket>(self.handle);
            if force {
                sock.send_buffer_owned(true);
                sock.recv_buffer_owned(true);
                self.has_rxbuf = false;
                self.has_txbuf = false;
                return true;
            }
            return !self.has_rxbuf && !self.has_txbuf;
        } else {
            let mut sock = self.onesock.get::<UdpSocket>(self.handle);
            if force {
                sock.send_buffer_owned();
                sock.recv_buffer_owned();
                self.has_rxbuf = false;
                self.has_txbuf = false;
                return true;
            }
            return !self.has_rxbuf && !self.has_txbuf;
        }
    }
}
