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
    streams: HashMap<u64, Arc<WebStream>>,
}
struct WebStream {
    server: bool,
    stream: u64,
    closed: bool,
    session: Arc<Mutex<WebSession>>,
}

impl common::Transport for WebStream {
    fn Dial(&mut self) {}

    fn NewStream(&mut self) -> Box<dyn Transport> {
        let s = self.session.lock().unwrap();
        let sid;
        // server has odd number streamids and client is even, just to prevent overlap
        if self.server {
            sid = 2 * s.nextStream.fetch_add(1, Ordering::Relaxed) + 1;
        } else {
            sid = 2 * s.nextStream.fetch_add(1, Ordering::Relaxed);
        }
        drop(s);
        Box::new(WebStream {
            server: false,
            stream: sid,
            closed: false,
            session: self.session.clone(),
        })
    }

    fn Close(&mut self) -> Result<(), common::NxtError> {
        Ok(())
    }

    fn IsClosed(&self) -> bool {
        self.closed
    }

    fn Read(&mut self) -> Result<(common::NxtHdr, Vec<Vec<u8>>), common::NxtError> {
        Err(common::NxtError {
            code: common::NxtErr::GENERAL_ERR,
        })
    }
    fn Write(&mut self, hdr: &common::NxtHdr) -> Result<(), common::NxtError> {
        Ok(())
    }
}
