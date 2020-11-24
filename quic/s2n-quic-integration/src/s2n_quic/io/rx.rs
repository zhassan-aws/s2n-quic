use crate::packet::Packet;
use anyhow::{anyhow, Error};
use bach::graph::{channel::Receiver, Message};
use core::task::{Context, Poll};
use futures::ready;
use s2n_quic_core::io::rx;

#[derive(Debug)]
pub struct Rx {
    rx: Receiver<Packet>,
    buffer: Vec<Packet>,
    capacity: usize,
}

impl Rx {
    pub fn new(rx: Receiver<Packet>) -> Self {
        Self {
            rx,
            buffer: vec![],
            capacity: 1024,
        }
    }

    fn push(&mut self, message: Message<Packet>) {
        // TODO keep track of node_id => IP mapping
        self.buffer.push(message.body);
    }
}

impl<'a> rx::Rx<'a> for Rx {
    type Queue = Queue<'a>;
    type Error = Error;

    fn queue(&'a mut self) -> Self::Queue {
        Queue(&mut self.buffer)
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn poll_receive(&mut self, cx: &mut Context) -> Poll<Result<usize, Self::Error>> {
        let mut count = 0;

        if self.capacity == self.buffer.len() {
            return Ok(0).into();
        }

        // try polling once
        match ready!(self.rx.poll_receive(cx)) {
            Some(packet) => {
                self.push(packet);
                count += 1;
            }
            None => {
                return Err(anyhow!("rx stream closed")).into();
            }
        }

        // take as many as we can
        while self.capacity != self.buffer.len() {
            match self.rx.try_receive() {
                Some(packet) => {
                    self.push(packet);
                    count += 1;
                }
                None => break,
            }
        }

        Ok(count).into()
    }
}

pub struct Queue<'a>(&'a mut Vec<Packet>);

impl<'a> rx::Queue for Queue<'a> {
    type Entry = Packet;

    fn as_slice_mut(&mut self) -> &mut [Self::Entry] {
        &mut self.0[..]
    }

    fn finish(&mut self, count: usize) {
        self.0.drain(..count);
    }
}
