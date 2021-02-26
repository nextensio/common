use common::{NxtErr, NxtError, Transport};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use tungstenite::{connect, Message};
use url::Url;

struct WebSession {
    port: usize,
    serverName: String,
    nextStream: AtomicU64,
    secure: bool,
    streams: HashMap<u64, WebStream>,
    server: bool,
}
struct WebStream {
    closed: bool,
}

impl WebStream {
    fn NewClient(secure: bool, servername: &str, port: usize) -> (Box<dyn common::Transport>, u64) {
        let stream = WebStream { closed: false };
        let mut streams = HashMap::new();
        // First stream with streamid 0
        streams.insert(0, stream);
        (
            Box::new(WebSession {
                port,
                serverName: servername.to_string(),
                secure,
                streams,
                nextStream: AtomicU64::new(0),
                server: false,
            }),
            0,
        )
    }
}

impl common::Transport for WebSession {
    fn Dial(&mut self) -> Result<(), common::NxtError> {
        let mut server;
        if self.secure {
            server = format!("wss://{}:{}", self.serverName, self.port);
        } else {
            server = format!("ws://{}:{}", self.serverName, self.port);
        }
        let (mut socket, response);
        match connect(Url::parse(&server).unwrap()) {
            Ok((s, r)) => {
                socket = s;
                response = r;
            }
            Err(e) => {
                let err = format!("{}", e);
                return Err(common::NxtError {
                    code: common::NxtErr::CONNECTION_ERR,
                    detail: err,
                });
            }
        }

        println!("Connected to the server");
        println!("Response HTTP code: {}", response.status());
        println!("Response contains the following headers:");
        for (ref header, _value) in response.headers() {
            println!("* {}", header);
        }

        return Ok(());
    }

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
            detail: "".to_string(),
        })
    }
    fn Write(&mut self, stream: u64, hdr: &common::NxtHdr) -> Result<(), common::NxtError> {
        Ok(())
    }
}
