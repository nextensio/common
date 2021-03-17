use etherparse::InternetSlice::*;
use etherparse::SlicedPacket;
use etherparse::TransportSlice::*;
use mio::{Poll, Token};
use std::{collections::VecDeque, fmt, net::Ipv4Addr, time::Duration};

pub mod nxthdr {
    include!(concat!(env!("OUT_DIR"), "/nxthdr.rs"));
}
use nxthdr::{nxt_hdr::Hdr, NxtFlow, NxtHdr};

pub const MAXBUF: usize = 2048;
pub const HEADROOM: usize = 500;
pub const TCP: usize = 6;
pub const UDP: usize = 17;

#[derive(Default, Hash, Eq, PartialEq)]
pub struct FlowV4Key {
    pub sip: u32,
    pub sport: u16,
    pub dip: u32,
    pub dport: u16,
    pub proto: usize,
}

impl Copy for FlowV4Key {}

impl Clone for FlowV4Key {
    fn clone(&self) -> FlowV4Key {
        *self
    }
}

impl fmt::Display for FlowV4Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let dest = Ipv4Addr::new(
            ((self.dip >> 24) & 0xFF) as u8,
            ((self.dip >> 16) & 0xFF) as u8,
            ((self.dip >> 8) & 0xFF) as u8,
            (self.dip & 0xFF) as u8,
        );
        let src = Ipv4Addr::new(
            ((self.sip >> 24) & 0xFF) as u8,
            ((self.sip >> 16) & 0xFF) as u8,
            ((self.sip >> 8) & 0xFF) as u8,
            (self.sip & 0xFF) as u8,
        );
        write!(
            f,
            "src: {}, sport: {}, dst: {}, dport: {}, proto: {}",
            src, self.sport, dest, self.dport, self.proto
        )
    }
}

#[derive(Copy, Clone)]
pub enum NxtErr {
    GENERAL,
    CONNECTION,
    EWOULDBLOCK,
}

pub struct NxtError {
    pub code: NxtErr,
    pub detail: String,
}

impl fmt::Display for NxtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "code: {}, detail: {}", self.code as u8, self.detail)
    }
}

impl fmt::Debug for NxtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "code: {}, detail: {}", self.code as u8, self.detail)
    }
}

impl From<native_tls::HandshakeError<std::net::TcpStream>> for NxtError {
    fn from(error: native_tls::HandshakeError<std::net::TcpStream>) -> Self {
        NxtError {
            code: NxtErr::CONNECTION,
            detail: error.to_string(),
        }
    }
}

impl From<native_tls::Error> for NxtError {
    fn from(error: native_tls::Error) -> Self {
        NxtError {
            code: NxtErr::CONNECTION,
            detail: error.to_string(),
        }
    }
}

impl From<std::io::Error> for NxtError {
    fn from(error: std::io::Error) -> Self {
        NxtError {
            code: NxtErr::CONNECTION,
            detail: error.to_string(),
        }
    }
}

pub enum RawStream {
    TcpLis(mio::net::TcpListener),
    Tcp(mio::net::TcpStream),
    Udp(mio::net::UdpSocket),
}

pub enum RegType {
    Reg,
    Dereg,
    Rereg,
}

// These are a chain of "owned buffers" (ie not pointers) which contain nextensio data.
// The reason for being "owned" as opposed to being a pointer is because this data can
// get queued up in various queues in the pipeline, so the ownership gets transferred.
// The reason why its a chain of buffers is so that we can avoid allocating one large
// buffer to hold for example max possible tcp data but really having only a tiny bit
// of data in it. The headroom is basically free space in the very first buffer in the
// chain, ie first_buffer[0..headroom] is empty and data starts at first_buffer[headroom]
pub struct NxtBufs {
    pub hdr: Option<NxtHdr>,
    pub bufs: Vec<Vec<u8>>,
    pub headroom: usize,
}

pub trait Transport {
    fn dial(&mut self) -> Result<(), NxtError> {
        Err(NxtError {
            code: NxtErr::CONNECTION,
            detail: "unimplemented".to_string(),
        })
    }
    fn listen(&mut self) -> Result<Box<dyn Transport>, NxtError> {
        Err(NxtError {
            code: NxtErr::CONNECTION,
            detail: "unimplemented".to_string(),
        })
    }
    fn new_stream(&mut self) -> u64;
    fn close(&mut self, stream: u64) -> Result<(), NxtError>;
    fn is_closed(&self, stream: u64) -> bool;

    fn read(&mut self) -> Result<(u64, NxtBufs), NxtError>;

    // On error EWOULDBLOCK/EAGAIN, write returns back the data that was unable to
    // be written so that the caller can try again. All other "non-retriable" errors
    // just returns None as the data with WriteError. Also the data that is returned on
    // EWOULDBLOCK might be different from (less than) the data that was passed in because
    // some of that data might have been transmitted
    fn write(&mut self, stream: u64, data: NxtBufs) -> Result<(), (Option<NxtBufs>, NxtError)>;

    // This is an optional API to set the transport in non blocking mode and optionally
    // register it with an MIO poller
    fn event_register(&mut self, _: Token, _: &mut Poll, _: RegType) -> Result<(), NxtError> {
        Err(NxtError {
            code: NxtErr::CONNECTION,
            detail: "unimplemented".to_string(),
        })
    }

    // This is an optional implementations. This is meant for transports which have
    // 'control' data (like tcp fin, rst, syn, ack etc..) which needs to be
    // provided to the underlying protocol behind the transport (via the rx queue)
    // and similarly to transmit stuff generated by the protocol by gathering it
    // in a tx queue. Note that all the previous APIs dealt with real 'payload'
    // over the transport and nothing else
    fn poll(&mut self, _: &mut VecDeque<(usize, Vec<u8>)>, _: &mut VecDeque<(usize, Vec<u8>)>) {}
}

pub fn varint_decode(bytes: &[u8]) -> (usize, usize) {
    let mut number: usize = 0;
    let mut hbytes = 0;
    for b in bytes {
        number = number | (((b & 0x7f) as usize) << (7 * hbytes)) as usize;
        hbytes = hbytes + 1;
        if (b & 0x80) == 0 {
            break;
        }
    }
    return (hbytes, number);
}

pub fn varint_encode_len(mut number: usize) -> usize {
    let mut hbytes = 0;
    loop {
        hbytes += 1;
        number = number >> 7;
        if number == 0 {
            break;
        }
    }
    return hbytes;
}

pub fn varint_encode(mut number: usize, bytes: &mut [u8]) -> usize {
    let mut hbytes = 0;
    loop {
        if number > 127 {
            bytes[hbytes] = (0x80 | (number & 0x7f)) as u8;
        } else {
            bytes[hbytes] = (number & 0x7F) as u8;
        }
        hbytes += 1;
        number = number >> 7;
        if number == 0 {
            break;
        }
    }
    return hbytes;
}

pub fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24)
        | ((array[1] as u32) << 16)
        | ((array[2] as u32) << 8)
        | ((array[3] as u32) << 0)
}

pub fn decode_ipv4(ip: &[u8]) -> Option<FlowV4Key> {
    let mut key: FlowV4Key = FlowV4Key::default();

    match SlicedPacket::from_ip(ip) {
        Err(_) => return None,
        Ok(value) => {
            match value.ip {
                Some(Ipv4(value)) => {
                    key.sip = as_u32_be(&value.source_addr().octets());
                    key.dip = as_u32_be(&value.destination_addr().octets());
                }
                _ => return None,
            }
            match value.transport {
                Some(Udp(value)) => {
                    key.proto = UDP;
                    key.sport = value.source_port();
                    key.dport = value.destination_port();
                }
                Some(Tcp(value)) => {
                    key.proto = TCP;
                    key.sport = value.source_port();
                    key.dport = value.destination_port();
                }
                None => return None,
            }
        }
    }

    return Some(key);
}

pub fn key_to_hdr(key: &FlowV4Key) -> NxtHdr {
    let dest = Ipv4Addr::new(
        ((key.dip >> 24) & 0xFF) as u8,
        ((key.dip >> 16) & 0xFF) as u8,
        ((key.dip >> 8) & 0xFF) as u8,
        (key.dip & 0xFF) as u8,
    );
    let src = Ipv4Addr::new(
        ((key.sip >> 24) & 0xFF) as u8,
        ((key.sip >> 16) & 0xFF) as u8,
        ((key.sip >> 8) & 0xFF) as u8,
        (key.sip & 0xFF) as u8,
    );

    let mut flow: NxtFlow = NxtFlow::default();
    flow.proto = key.proto as u32;
    flow.dest = dest.to_string();
    flow.dport = key.dport as u32;
    flow.source = src.to_string();
    flow.sport = key.sport as u32;
    let mut hdr = NxtHdr::default();
    hdr.hdr = Some(Hdr::Flow(flow));

    return hdr;
}

#[cfg(test)]
mod test;
