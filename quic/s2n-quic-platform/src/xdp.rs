use core::{num::NonZeroU32, ops::Range};
use s2n_codec::{Encoder, EncoderBuffer};
use s2n_quic_core::io::{rx, tx};
use std::os::unix::io::{AsRawFd, RawFd};
use xsk_rs::{
    CompQueue, FillQueue, FrameDesc, RxQueue, Socket, SocketConfig, TxQueue, Umem, UmemConfig,
};

// Put umem at bottom so drop order is correct
pub struct SocketState<'umem> {
    pub tx: Tx<'umem>,
    pub rx: Rx<'umem>,
    pub umem: Umem<'umem>,
}

impl<'umem> SocketState<'umem> {
    pub fn default(if_name: &str, queue_id: u32) -> std::io::Result<Self> {
        let frame_count = NonZeroU32::new(2048).unwrap();
        let use_pages = false;
        let umem_config = UmemConfig::default(frame_count, use_pages);
        let socket_config = SocketConfig::default();
        Self::build(umem_config, socket_config, if_name, queue_id)
    }

    pub fn build(
        umem_config: UmemConfig,
        socket_config: SocketConfig,
        if_name: &str,
        queue_id: u32,
    ) -> std::io::Result<Self> {
        let (mut umem, mut fill_q, comp_q, mut frame_descs) =
            Umem::builder(umem_config).create_mmap()?.create_umem()?;

        // TODO handle error conversion
        let (tx_q, rx_q) = Socket::new(socket_config, &mut umem, if_name, queue_id)
            .expect("could not create socket");

        let idx = frame_descs.len() / 2;
        let tx_frames = FrameRing::new(frame_descs.split_off(idx));
        let mut rx_frames = FrameRing::new(frame_descs);

        // let the NIC know it can receive on these descriptions
        rx_frames.consume_to_device(&mut fill_q);

        let rx = Rx {
            dev_queue: fill_q,
            user_queue: rx_q,
            frames: rx_frames,
        };
        let tx = Tx {
            dev_queue: comp_q,
            user_queue: tx_q,
            frames: tx_frames,
        };

        Ok(Self { umem, tx, rx })
    }
}

pub struct Rx<'umem> {
    dev_queue: FillQueue<'umem>,
    user_queue: RxQueue<'umem>,
    frames: FrameRing<'umem>,
}

impl<'umem> Rx<'umem> {
    pub fn rx_queue<'a>(&'a mut self, umem: &'a mut Umem<'umem>) -> UserRxQueue<'a, 'umem> {
        UserRxQueue { rx: self, umem }
    }
}

impl<'umem> AsRawFd for Rx<'umem> {
    fn as_raw_fd(&self) -> RawFd {
        self.user_queue.as_raw_fd()
    }
}

pub struct UserRxQueue<'a, 'umem> {
    rx: &'a mut Rx<'umem>,
    umem: &'a mut Umem<'umem>,
}

/*
impl<'a, 'umem> rx::Queue for UserRxQueue<'a, 'umem> {
    type Entry = Dummy;
}
*/

pub struct Tx<'umem> {
    dev_queue: CompQueue<'umem>,
    user_queue: TxQueue<'umem>,
    frames: FrameRing<'umem>,
}

unsafe impl Send for Tx<'_> {}
unsafe impl Sync for Tx<'_> {}

impl<'umem> Tx<'umem> {
    pub fn tx_queue<'a>(&'a mut self, umem: &'a mut Umem<'umem>) -> UserTxQueue<'a, 'umem> {
        UserTxQueue { tx: self, umem }
    }

    pub fn do_io(&mut self) -> std::io::Result<usize> {
        let mut len = 0;
        len += self.frames.produce_to_device(&mut self.user_queue)?;
        len += self.frames.produce_to_user(&mut self.dev_queue)?;
        Ok(len)
    }

    pub fn occupied_len(&self) -> usize {
        self.frames.consumed_len + self.frames.device_len
    }
}

impl<'umem> AsRawFd for Tx<'umem> {
    fn as_raw_fd(&self) -> i32 {
        self.user_queue.as_raw_fd()
    }
}

pub struct UserTxQueue<'a, 'umem> {
    tx: &'a mut Tx<'umem>,
    umem: &'a mut Umem<'umem>,
}

impl<'a, 'umem> tx::Queue for UserTxQueue<'a, 'umem> {
    type Entry = DummyEntry;

    fn push<M: tx::Message>(&mut self, mut message: M) -> Result<usize, tx::Error> {
        let umem = &mut self.umem;
        let mtu = umem.mtu();
        self.tx.frames.push(move |frame| {
            let region = unsafe { umem.umem_region_mut(&frame.addr(), &mtu) };

            let mut encoder = EncoderBuffer::new(region);

            let eth = hex_literal::hex!("60 45 cb 6b 43 46 3c 7c 3f 81 7a 7c 08 00");
            encoder.encode(&&eth[..]);

            let addr = message.remote_address();

            encoder.encode(&0b0100_0101u8);
            encoder.encode(&0u8);
            let ip_length = encoder.len()..encoder.len() + 2;
            encoder.encode(&0u16);
            encoder.encode(
                &&hex_literal::hex!(
                    "
                    00 00
                    40
                    00
                    40
                    11
                    "
                )[..],
            );
            let ip_checksum = encoder.len()..encoder.len() + 2;
            encoder.encode(&0u16);

            let mut ip_addrs = hex_literal::hex!(
                "
                c0 a8 56 b2
                c0 a8 56 b5"
            );
            encoder.encode(&&ip_addrs[..]);

            // src port
            encoder.encode(&4433u16);
            // dest port
            encoder.encode(&addr.port());
            // UDP length
            let udp_length = encoder.len()..encoder.len() + 2;
            encoder.encode(&0u16);
            // UDP checksum
            let udp_checksum = encoder.len()..encoder.len() + 2;
            encoder.encode(&0u16);

            let (header, payload) = encoder.split_mut();
            let len = message.write_payload(payload);

            if len == 0 {
                return 0;
            }

            header[ip_length].copy_from_slice(&(len as u16 + 28).to_be_bytes()[..]);
            header[udp_length].copy_from_slice(&(len as u16 + 8).to_be_bytes()[..]);

            // TODO compute checksums
            eprint!("L{} ", len);

            len
        })
    }

    fn as_slice_mut(&mut self) -> &mut [Self::Entry] {
        todo!()
    }

    fn capacity(&self) -> usize {
        self.tx.frames.user_len
    }

    fn len(&self) -> usize {
        self.tx.frames.consumed_len
    }
}

struct FrameRing<'umem> {
    frames: Vec<FrameDesc<'umem>>,
    user_head: usize,
    user_len: usize,
    consumed_head: usize,
    consumed_len: usize,
    device_head: usize,
    device_len: usize,
}

impl<'umem> FrameRing<'umem> {
    pub fn new(frames: Vec<FrameDesc<'umem>>) -> Self {
        let user_len = frames.len();
        Self {
            frames,
            user_head: 0,
            user_len,
            consumed_head: 0,
            consumed_len: 0,
            device_head: 0,
            device_len: 0,
        }
    }

    pub fn push<F: FnOnce(&FrameDesc<'umem>) -> usize>(
        &mut self,
        f: F,
    ) -> Result<usize, tx::Error> {
        if self.user_len == 0 {
            return Err(tx::Error::AtCapacity);
        }

        let frame = &mut self.frames[self.user_head];
        let frame_len = f(&frame);

        if frame_len == 0 {
            return Err(tx::Error::EmptyPayload);
        }

        frame.set_len(frame_len);

        self.user_to_consumed(1);

        Ok(frame_len)
    }

    /// Moves filled packets to the device for transmission
    pub fn produce_to_device(&mut self, queue: &mut TxQueue<'umem>) -> std::io::Result<usize> {
        let (first, second) = self.consumed_ranges();
        let iter = Iter {
            first: self.frames[first].iter(),
            second: self.frames[second].iter(),
        };

        let len = unsafe { queue.produce_and_wakeup(iter) }?;

        eprint!("CD{} ", len);

        self.consumed_to_device(len);

        Ok(len)
    }

    /// Moves sent packet slots to be available for new packet transmission
    pub fn produce_to_user(&mut self, queue: &mut CompQueue<'umem>) -> std::io::Result<usize> {
        let (a, b) = self.device_ranges();
        let mut len = 0;
        len += queue.consume(&mut self.frames[a]);
        len += queue.consume(&mut self.frames[b]);
        self.device_to_user(len);

        eprint!("DU{} ", len);

        Ok(len)
    }

    /// Moves received packets to be available for user consumption
    pub fn consume_to_user(&mut self, queue: &mut RxQueue<'umem>) -> std::io::Result<usize> {
        let (a, b) = self.device_ranges();
        let mut len = 0;
        len += queue.consume(&mut self.frames[a]);
        len += queue.consume(&mut self.frames[b]);
        self.device_to_user(len);

        Ok(len)
    }

    /// Moves consumed packet slots to be available for the device
    pub fn consume_to_device(&mut self, rx: &mut FillQueue<'umem>) -> usize {
        let (first, second) = self.consumed_ranges();
        let iter = Iter {
            first: self.frames[first].iter(),
            second: self.frames[second].iter(),
        };

        let len = unsafe { rx.produce(iter) };

        self.consumed_to_device(len);

        len
    }

    fn pop(&mut self) -> Option<&FrameDesc<'umem>> {
        if self.user_len == 0 {
            return None;
        }

        let user_head = self.user_head;
        self.user_to_consumed(1);

        let frame = &self.frames[user_head];

        Some(frame)
    }

    fn user_to_consumed(&mut self, amount: usize) {
        self.user_head = (self.user_head + amount) % self.frames.len();
        self.user_len -= amount;
        self.consumed_len += amount;
    }

    fn consumed_to_device(&mut self, amount: usize) {
        self.consumed_head = (self.consumed_head + amount) % self.frames.len();
        self.consumed_len -= amount;
        self.device_len += amount;
    }

    fn device_to_user(&mut self, amount: usize) {
        self.device_head = (self.device_head + amount) % self.frames.len();
        self.device_len -= amount;
        self.user_len += amount;
    }

    fn user_ranges(&self) -> (Range<usize>, Range<usize>) {
        self.ranges(self.user_head, self.device_head)
    }

    fn consumed_ranges(&self) -> (Range<usize>, Range<usize>) {
        self.ranges(self.consumed_head, self.user_head)
    }

    fn device_ranges(&self) -> (Range<usize>, Range<usize>) {
        self.ranges(self.device_head, self.consumed_head)
    }

    fn ranges(&self, head: usize, tail: usize) -> (Range<usize>, Range<usize>) {
        if let Some(second_len) = tail.checked_sub(self.frames.len()) {
            (head..self.frames.len(), 0..second_len)
        } else {
            (head..tail, 0..0)
        }
    }
}

struct Iter<'a, 'umem> {
    first: core::slice::Iter<'a, FrameDesc<'umem>>,
    second: core::slice::Iter<'a, FrameDesc<'umem>>,
}

impl<'a, 'umem> Iterator for Iter<'a, 'umem> {
    type Item = &'a FrameDesc<'umem>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first) = self.first.next() {
            return Some(first);
        }

        if let Some(second) = self.second.next() {
            return Some(second);
        }

        None
    }
}

impl<'a, 'umem> ExactSizeIterator for Iter<'a, 'umem> {
    fn len(&self) -> usize {
        self.first.len() + self.second.len()
    }
}

pub struct DummyEntry;

impl tx::Entry for DummyEntry {
    fn set<M: tx::Message>(&mut self, message: M) -> Result<usize, tx::Error> {
        todo!()
    }

    fn payload(&self) -> &[u8] {
        todo!()
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_socket_test() {
        let socket = SocketState::default("veth-adv03", 0);
    }
}
