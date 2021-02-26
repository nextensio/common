use std::path::StripPrefixError;

pub enum NxtErr {
    GENERAL_ERR,
    CONNECTION_ERR,
}
pub struct NxtError {
    pub code: NxtErr,
    pub detail: String,
}

pub struct NxtHdr {}

pub trait Transport {
    fn Dial(&mut self) -> Result<(), NxtError>;
    fn NewStream(&mut self) -> u64;
    fn Close(&mut self, stream: u64) -> Result<(), NxtError>;
    fn IsClosed(&self, stream: u64) -> bool;
    fn Read(&mut self) -> Result<(u64, NxtHdr, Vec<Vec<u8>>), NxtError>;
    fn Write(&mut self, stream: u64, hdr: &NxtHdr) -> Result<(), NxtError>;
}
