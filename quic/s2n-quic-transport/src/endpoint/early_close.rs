// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{connection, endpoint};
use alloc::collections::BTreeMap;
use s2n_quic_core::{
    connection::PeerId,
    event::{self},
    inet::ExplicitCongestionNotification,
    io::tx,
    path,
    path::MINIMUM_MTU,
    time,
    time::Timestamp,
};

#[derive(Debug)]
pub struct Dispatch<Path: path::Handle> {
    transmissions: BTreeMap<PeerId, Transmission<Path>>,
    sent_transmissions: BTreeMap<PeerId, Transmission<Path>>,
}

impl<Path: path::Handle> Default for Dispatch<Path> {
    fn default() -> Self {
        Self::new(endpoint::DEFAULT_MAX_PEERS)
    }
}

impl<Path: path::Handle> Dispatch<Path> {
    pub fn new(max_peers: usize) -> Self {
        Self {
            transmissions: BTreeMap::new(),
            sent_transmissions: BTreeMap::new(),
        }
    }

    pub fn queue(&mut self, cid: PeerId, path: Path, error: connection::Error) {
        match error {
            s2n_quic_core::connection::Error::Transport { .. } => (),
            _ => return,
        }

        if let Some((cid, mut transmission)) = self.sent_transmissions.remove_entry(&cid) {
            transmission.sent = None;
            self.transmissions.insert(cid, transmission);
            return;
        }

        self.transmissions
            .entry(cid)
            .or_insert_with(|| Transmission::new(path));
    }

    pub fn on_transmit<Tx: tx::Queue<Handle = Path>, Pub: event::EndpointPublisher>(
        &mut self,
        queue: &mut Tx,
        now: Timestamp,
        _publisher: &mut Pub,
    ) {
        self.cleanup(now);

        let expensive_key_list: Vec<PeerId> =
            self.transmissions.keys().into_iter().copied().collect();

        for cid in expensive_key_list {
            let (cid, mut transmission) = self.transmissions.remove_entry(&cid).unwrap();
            match queue.push(&transmission) {
                Ok(tx::Outcome { .. }) => {
                    self.transmissions.remove(&cid);
                    transmission.sent = Some(now);
                    self.sent_transmissions.insert(cid, transmission);
                    // TODO emit event
                }
                Err(_) => {
                    return;
                }
            }
        }
    }

    fn cleanup(&mut self, now: Timestamp) {
        let expensive_key_list: Vec<PeerId> = self
            .sent_transmissions
            .keys()
            .into_iter()
            .copied()
            .collect();
        for cid in expensive_key_list {
            let (cid, transmission) = self.sent_transmissions.remove_entry(&cid).unwrap();

            if transmission.is_expired(now) {
                self.sent_transmissions.remove(&cid);
            }
        }
    }
}

pub struct Transmission<Path: path::Handle> {
    path: Path,
    packet: [u8; MINIMUM_MTU as usize],
    packet_len: usize,
    /// Records when the transmission was sent and how long to cache the
    /// transmission
    sent: Option<Timestamp>,
}

impl<Handle: path::Handle> core::fmt::Debug for Transmission<Handle> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Transmission")
            .field("remote_address", &self.path.remote_address())
            .field("local_address", &self.path.local_address())
            // .field("packet_len", &self.packet_len)
            // .field("packet", &&self.packet[0..self.packet_len])
            .finish()
    }
}

impl<Path: path::Handle> Transmission<Path> {
    pub fn new(path: Path) -> Self {
        todo!()
        // Some(Self {
        //     path,
        //     packet: packet_buf,
        //     packet_len,
        // })
    }

    /// Check when the ConnectionClose frame was sent and if it should be removed
    /// from the sent_transmissions buffer.
    pub fn is_expired(&self, now: Timestamp) -> bool {
        if let Some(sent) = self.sent {
            return sent > now;
        }
        false
    }
}

impl<Path: path::Handle> AsRef<[u8]> for Transmission<Path> {
    fn as_ref(&self) -> &[u8] {
        &self.packet[..self.packet_len]
    }
}

impl<Path: path::Handle> tx::Message for &Transmission<Path> {
    type Handle = Path;

    #[inline]
    fn path_handle(&self) -> &Self::Handle {
        &self.path
    }

    #[inline]
    fn ecn(&mut self) -> ExplicitCongestionNotification {
        Default::default()
    }

    #[inline]
    fn delay(&mut self) -> time::Duration {
        Default::default()
    }

    #[inline]
    fn ipv6_flow_label(&mut self) -> u32 {
        0
    }

    #[inline]
    fn can_gso(&self) -> bool {
        true
    }

    #[inline]
    fn write_payload(&mut self, buffer: &mut [u8], _gso_offset: usize) -> usize {
        let packet = self.as_ref();
        buffer[..packet.len()].copy_from_slice(packet);
        packet.len()
    }
}
