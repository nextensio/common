pub enum NxtErr {
    GENERAL_ERR,
    CONNECTION_ERR,
}
pub struct NxtError {
    pub code: NxtErr,
}

pub struct NxtHdr {}

pub trait Transport {
    fn Dial(&mut self);
    fn NewStream(&mut self) -> Box<dyn Transport>;
    fn Close(&mut self) -> Result<(), NxtError>;
    fn IsClosed(&self) -> bool;
    fn Read(&mut self) -> Result<(NxtHdr, Vec<Vec<u8>>), NxtError>;
    fn Write(&mut self, hdr: &NxtHdr) -> Result<(), NxtError>;
}
