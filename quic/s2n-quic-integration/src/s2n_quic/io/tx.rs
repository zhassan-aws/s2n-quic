use crate::packet::Packet;
use anyhow::Error;
use bach::graph::{channel::Sender, NodeId};
use core::{
    task::{Context, Poll},
    time::Duration,
};
use s2n_quic_core::{inet::SocketAddress, io::tx};

#[derive(Debug)]
pub struct Tx {
    capacity: usize,
    mtu: usize,
    buffer: Vec<Entry>,
    sender: Sender<Packet>,
    address: SocketAddress,
}

impl Tx {
    pub fn new(sender: Sender<Packet>) -> Self {
        Self {
            capacity: 1024,
            mtu: 1500,
            buffer: vec![],
            sender,
            address: Default::default(),
        }
    }
}

impl<'a> tx::Tx<'a> for Tx {
    type Queue = Queue<'a>;
    type Error = Error;

    const SUPPORTS_ECN: bool = true;

    const SUPPORTS_PACING: bool = true;

    const SUPPORTS_FLOW_LABELS: bool = true;

    fn queue(&'a mut self) -> Self::Queue {
        Queue(self)
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn poll_transmit(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, Self::Error>> {
        debug_assert!(!self.buffer.is_empty());

        let mut buffer = core::mem::replace(&mut self.buffer, vec![]);
        let mut entries = buffer.drain(..);

        let mut count = 0;
        while let Some(entry) = entries.next() {
            // TODO delay
            match self.sender.send(entry.node_id, entry.packet) {
                Ok(()) => count += 1,
                Err(packet) => {
                    self.buffer.push(Entry {
                        delay: entry.delay,
                        node_id: entry.node_id,
                        packet,
                    });
                    self.buffer.extend(entries);
                    return Ok(count).into();
                }
            }
        }

        Ok(count).into()
    }
}

pub struct Queue<'a>(&'a mut Tx);

impl<'a> tx::Queue for Queue<'a> {
    type Entry = Entry;

    fn push<M: tx::Message>(&mut self, message: M) -> Result<usize, tx::Error> {
        if self.0.buffer.len() == self.0.capacity {
            return Err(tx::Error::AtCapacity);
        }

        let mut entry = Entry {
            delay: Duration::from_secs(0),
            node_id: todo!(),
            packet: Packet {
                source_address: self.0.address,
                destination_address: Default::default(),
                ecn: Default::default(),
                ipv6_flow_label: 0,
                payload: vec![0; self.0.mtu],
            },
        };

        let len = tx::Entry::set(&mut entry, message)?;

        self.0.buffer.push(entry);

        Ok(len)
    }

    fn as_slice_mut(&mut self) -> &mut [Self::Entry] {
        &mut self.0.buffer[..]
    }

    fn capacity(&self) -> usize {
        self.0.capacity - self.0.buffer.len()
    }

    fn len(&self) -> usize {
        self.0.buffer.len()
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    delay: Duration,
    node_id: NodeId,
    packet: Packet,
}

impl tx::Entry for Entry {
    fn set<M: tx::Message>(&mut self, mut message: M) -> Result<usize, tx::Error> {
        self.delay = message.delay();
        self.packet.set(message)
    }

    fn payload(&self) -> &[u8] {
        self.packet.payload()
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        self.packet.payload_mut()
    }
}
