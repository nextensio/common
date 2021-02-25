use common::{NxtErr, Transport};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

struct WebSession {
    port: usize,
    serverName: String,
    nextStream: AtomicU64,
    caCert: Vec<u8>,
    streams: HashMap<u64, WebStream>,
    server: bool,
}
struct WebStream {
    closed: bool,
}

impl WebStream {
    fn NewClient(
        caCert: Vec<u8>,
        servername: &str,
        port: usize,
    ) -> (Box<dyn common::Transport>, u64) {
        let stream = WebStream { closed: false };
        let mut streams = HashMap::new();
        // First stream with streamid 0
        streams.insert(0, stream);
        (
            Box::new(WebSession {
                port,
                serverName: servername.to_string(),
                caCert,
                streams,
                nextStream: AtomicU64::new(0),
                server: false,
            }),
            0,
        )
    }
}

impl common::Transport for WebSession {
    fn Dial(&mut self) {}

    fn NewStream(&mut self) -> u64 {
        let sid;
        // server has odd number streamids and client is even, just to prevent overlap
        if self.server {
            sid = 2 * self.nextStream.fetch_add(1, Ordering::Relaxed) + 1;
        } else {
            sid = 2 * self.nextStream.fetch_add(1, Ordering::Relaxed);
        }
        let stream = WebStream { closed: false };
        self.streams.insert(sid, stream);
        sid
    }

    fn Close(&mut self, stream: u64) -> Result<(), common::NxtError> {
        Ok(())
    }

    fn IsClosed(&self, stream: u64) -> bool {
        false
    }

    fn Read(&mut self) -> Result<(u64, common::NxtHdr, Vec<Vec<u8>>), common::NxtError> {
        Err(common::NxtError {
            code: common::NxtErr::GENERAL_ERR,
        })
    }
    fn Write(&mut self, stream: u64, hdr: &common::NxtHdr) -> Result<(), common::NxtError> {
        Ok(())
    }
}
