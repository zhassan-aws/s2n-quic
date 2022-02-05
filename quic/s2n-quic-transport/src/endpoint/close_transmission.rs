// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{connection, endpoint};
use alloc::collections::BTreeMap;
use s2n_quic_core::{
    connection::PeerId,
    event::{self, Timestamp},
    inet::ExplicitCongestionNotification,
    io::tx,
    path,
    path::MINIMUM_MTU,
    time,
};

#[derive(Debug)]
pub struct Dispatch<Path: path::Handle> {
    transmissions: BTreeMap<PeerId, Transmission<Path>>,
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
        }
    }

    pub fn queue(&mut self, cid: PeerId, path: Path, error: connection::Error) {
        // if !error.is_transport_error() {
        //   return;
        // }

        match self.transmissions.get_mut(&cid) {
            Some(transmission) => {
                if transmission.is_expired() {
                    transmission.sent = None;
                }
                // match transmission.sent {
                //   Some(timestamp) if timestamp.is_expired() => {
                //     transmission.sent = None;
                //   }
                //   Some(timestamp) => ()
                //   None => (), // already queued
                // }

                return;
            }
            None => {
                let transmission = Transmission::new(path);
                self.transmissions.insert(cid, transmission);
            }
        }
    }

    pub fn on_transmit<Tx: tx::Queue<Handle = Path>, Pub: event::EndpointPublisher>(
        &mut self,
        queue: &mut Tx,
        _publisher: &mut Pub,
    ) {
        // while let Some((cid, transmission)) = self.transmissions.pop_first() {
        //     if let None = transmission.sent {
        //         // transmission.sent = Some(now);
        //         match queue.push(&transmission) {
        //             Ok(tx::Outcome { .. }) => {
        //                 // TODO emit event
        //             }
        //             Err(_) => {
        //                 self.transmissions.insert(cid, transmission);
        //                 return;
        //             }
        //         }
        //     }
        // }

        for cid in self.transmissions.keys() {
            self.transmissions.entry(*cid);
        }

        for (cid, transmission) in self.transmissions.into_iter() {
            // if transmission.is_expired() {
            //     self.transmissions.remove(cid);
            // }

            if let None = transmission.sent {
                // transmission.sent = Some(now);
                match queue.push(&transmission) {
                    Ok(tx::Outcome { .. }) => {
                        // TODO emit event
                    }
                    Err(_) => {
                        self.transmissions.insert(cid, transmission);
                        return;
                    }
                }
            }
        }
    }
}

pub struct Transmission<Path: path::Handle> {
    path: Path,
    packet: [u8; MINIMUM_MTU as usize],
    packet_len: usize,
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

    pub fn is_expired(&self) -> bool {
        todo!()
    }
}

impl<Path: path::Handle> AsRef<[u8]> for Transmission<Path> {
    fn as_ref(&self) -> &[u8] {
        // &self.packet[..self.packet_len]
        todo!()
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
