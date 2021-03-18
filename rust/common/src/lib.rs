use etherparse::InternetSlice::*;
use etherparse::SlicedPacket;
use etherparse::TransportSlice::*;
use mio::{Poll, Token};
use std::{collections::VecDeque, fmt, net::Ipv4Addr};

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
    pub dip: String,
    pub dport: u16,
    pub proto: usize,
}

impl Clone for FlowV4Key {
    fn clone(&self) -> FlowV4Key {
        FlowV4Key {
            sip: self.sip,
            sport: self.sport,
            dip: self.dip.clone(),
            dport: self.dport,
            proto: self.proto,
        }
    }
}

impl fmt::Display for FlowV4Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let src = Ipv4Addr::new(
            ((self.sip >> 24) & 0xFF) as u8,
            ((self.sip >> 16) & 0xFF) as u8,
            ((self.sip >> 8) & 0xFF) as u8,
            (self.sip & 0xFF) as u8,
        );
        write!(
            f,
            "src: {}, sport: {}, dst: {}, dport: {}, proto: {}",
            src, self.sport, self.dip, self.dport, self.proto
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
                    let octets = &value.destination_addr().octets();
                    key.dip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).to_string();
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
    let src = Ipv4Addr::new(
        ((key.sip >> 24) & 0xFF) as u8,
        ((key.sip >> 16) & 0xFF) as u8,
        ((key.sip >> 8) & 0xFF) as u8,
        (key.sip & 0xFF) as u8,
    );

    let mut flow: NxtFlow = NxtFlow::default();
    flow.proto = key.proto as u32;
    flow.dest = key.dip.clone();
    flow.dport = key.dport as u32;
    flow.source = src.to_string();
    flow.sport = key.sport as u32;
    let mut hdr = NxtHdr::default();
    hdr.hdr = Some(Hdr::Flow(flow));

    return hdr;
}

pub fn hdr_to_key(hdr: &NxtHdr) -> Option<FlowV4Key> {
    match hdr.hdr.as_ref().unwrap() {
        Hdr::Flow(flow) => {
            let sipb: Result<Ipv4Addr, _> = flow.source.parse();
            let dip = flow.dest.clone();
            // This has to be a corrupt packet, otherwise we can have a
            // garbage ip address come in. We cant keep the session/tun open
            // with even one garbage packet coming in on it
            if sipb.is_err() {
                return None;
            }
            let sip = as_u32_be(&sipb.unwrap().octets());
            return Some(FlowV4Key {
                sip,
                dip,
                sport: flow.sport as u16,
                dport: flow.dport as u16,
                proto: flow.proto as usize,
            });
        }
        _ => return None,
    }
}

fn nlcrnl(v: &[u8]) -> bool {
    if v[0] == '\n' as u8 && v[1] == '\r' as u8 && v[2] == '\n' as u8 {
        return true;
    }
    return false;
}

pub fn parse_crnl(buf: &[u8]) -> usize {
    // Look for the sequence '\n\r\n' - ie a CRLF on a line by itself
    // A brute force check here without maintaining any state, for every
    // set of three bytes, check if they are \n\r\n
    for i in 0..buf.len() {
        if i >= 2 {
            if nlcrnl(&buf[i - 2..i + 1]) {
                return i + 1;
            }
        }
        if i >= 1 && i + 1 < buf.len() {
            if nlcrnl(&buf[i - 1..i + 2]) {
                return i + 2;
            }
        }
        if i + 2 < buf.len() {
            if nlcrnl(&buf[i..i + 3]) {
                return i + 3;
            }
        }
    }
    return 0;
}

pub fn parse_host(methods: &[&str], buf: &[u8]) -> (usize, String) {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(_) => {
            if !methods.is_empty() {
                if req.method.is_none() {
                    return (0, "".to_string());
                }
                let mut found = false;
                let method = req.method.unwrap().to_uppercase();
                for m in methods {
                    if method == *m {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return (0, "".to_string());
                }
            }
            for h in headers.iter() {
                if h.name.to_uppercase() == "HOST" {
                    let host = std::str::from_utf8(h.value);
                    if host.is_err() {
                        return (0, "".to_string());
                    }
                    let host = host.unwrap();
                    match host.find(":") {
                        Some(o) => {
                            let dest = &host[0..o];
                            let port = &host[o + 1..];
                            let p = port.parse::<usize>();
                            if p.is_err() {
                                return (0, "".to_string());
                            }
                            return (p.unwrap(), dest.to_string());
                        }
                        None => return (0, host.to_string()),
                    }
                }
            }
        }
        Err(_) => return (0, "".to_string()),
    }
    return (0, "".to_string());
}

#[cfg(test)]
mod test;
