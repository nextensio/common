use std::collections::VecDeque;
use std::vec::Vec;

use object_pool::{try_pull, Pool, Reusable};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::{Error, Result};
use std::sync::Arc;

/// A PacketQ device. Just an rx and tx queues. The packets are supplied
/// to smoltcp via the rx queue and packets from smoltcp go into txq which
/// is consumed by the caller who does a poll(). So obviouly the queues are
/// supplied to the new() here
//#[derive(Debug)]
pub struct PacketQ<'q> {
    pub rx: &'q mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    pub tx: &'q mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    medium: Medium,
    rx_mtu: usize,
    tx_mtu: usize,
    tx_headroom: usize,
    pool: Arc<Pool<Vec<u8>>>,
}

#[allow(clippy::new_without_default)]
impl<'q> PacketQ<'q> {
    /// Creates a PacketQ device.
    ///
    /// Receive from the rx Q and transmit to the tx Q
    #[allow(unused)]
    pub fn new(
        medium: Medium,
        rx_mtu: usize,
        tx_mtu: usize,
        rx: &'q mut VecDeque<(usize, Reusable<Vec<u8>>)>,
        tx: &'q mut VecDeque<(usize, Reusable<Vec<u8>>)>,
        tx_headroom: usize,
        pool: Arc<Pool<Vec<u8>>>,
    ) -> PacketQ<'q> {
        PacketQ {
            rx,
            tx,
            medium,
            rx_mtu,
            tx_mtu,
            tx_headroom,
            pool,
        }
    }
}

impl<'a, 'q> Device<'a> for PacketQ<'q> {
    type RxToken = RxToken;
    type TxToken = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities::new(self.medium, self.rx_mtu, self.tx_mtu)
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.rx.pop_front().map(move |buffer| {
            let rx = RxToken {
                headroom: buffer.0,
                buffer: buffer.1,
            };
            let tx = TxToken {
                headroom: self.tx_headroom,
                queue: self.tx,
                pool: self.pool.clone(),
            };
            (rx, tx)
        })
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            headroom: self.tx_headroom,
            queue: self.tx,
            pool: self.pool.clone(),
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Reusable<Vec<u8>>,
    headroom: usize,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        f(&mut self.buffer[self.headroom..])
    }
}

#[doc(hidden)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    headroom: usize,
    pool: Arc<Pool<Vec<u8>>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        if let Some(mut buffer) = try_pull(self.pool) {
            buffer.clear();
            buffer.resize(len + self.headroom, 0);
            let result = f(&mut buffer[self.headroom..]);
            self.queue.push_back((self.headroom, buffer));
            result
        } else {
            Err(Error::Exhausted)
        }
    }
}
