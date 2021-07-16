use core::{
    convert::{TryFrom, TryInto},
    num::NonZeroU32,
    ops::Range,
};
use pcap_file::pcap::PcapWriter;
use s2n_codec::{DecoderBufferMut, DecoderError, Encoder, EncoderBuffer};
use s2n_quic_core::{
    inet::{ExplicitCongestionNotification, SocketAddress},
    io::{rx, tx},
};
use std::{
    collections::VecDeque,
    os::unix::io::{AsRawFd, RawFd},
};
use xsk_rs::{
    BindFlags, CompQueue, FillQueue, FrameDesc, LibbpfFlags, RxQueue, Socket, SocketConfig,
    TxQueue, Umem, UmemConfig, XdpFlags,
};

mod bpf {
    include!("./xdp/.output/kern.skel.rs");
}

// Put umem at bottom so drop order is correct
pub struct SocketState<'umem> {
    pub tx: Tx<'umem>,
    pub rx: Rx<'umem>,
    pub umem: Umem<'umem>,
    link: libbpf_rs::Link,
}

unsafe impl Send for SocketState<'_> {}

impl<'umem> SocketState<'umem> {
    pub fn default(if_name: &str, queue_id: u32) -> std::io::Result<Self> {
        let use_huge_pages = false;
        let umem_config = UmemConfig::new(
            NonZeroU32::new(4 * 1024).unwrap(),
            NonZeroU32::new(libbpf_sys::XSK_UMEM__DEFAULT_FRAME_SIZE).unwrap(),
            libbpf_sys::XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
            libbpf_sys::XSK_RING_CONS__DEFAULT_NUM_DESCS,
            libbpf_sys::XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            use_huge_pages,
        )
        .unwrap();

        let socket_config = SocketConfig::new(
            libbpf_sys::XSK_RING_CONS__DEFAULT_NUM_DESCS,
            libbpf_sys::XSK_RING_PROD__DEFAULT_NUM_DESCS,
            LibbpfFlags::XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
            XdpFlags::XDP_FLAGS_HW_MODE,
            BindFlags::XDP_USE_NEED_WAKEUP,
        )
        .unwrap();

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

        let rlim = libc::rlimit {
            rlim_cur: libc::rlim_t::MAX,
            rlim_max: libc::rlim_t::MAX,
        };
        libc!(setrlimit(libc::RLIMIT_MEMLOCK, &rlim))?;

        // TODO handle error conversion
        let (tx_q, mut rx_q) = Socket::new(socket_config, &mut umem, if_name, queue_id)
            .expect("could not create socket");
        let fd = rx_q.fd().fd();

        let open_skel = bpf::XdpPassKernSkelBuilder::default().open().unwrap();
        let mut skel = open_skel.load().unwrap();

        skel.attach().unwrap();
        let link = skel.progs_mut().xdp_sock_prog().attach_xdp(3).unwrap();

        let mut maps = skel.maps_mut();

        maps.xsks_map()
            .update(
                &0i32.to_ne_bytes(),
                &fd.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )
            .unwrap();

        let idx = frame_descs.len() / 2;
        let mut rx_frames = FrameRing::new(frame_descs.split_off(idx));
        let mut tx_frames = FrameRing::new(frame_descs);

        // let the NIC know it can receive on these descriptions
        rx_frames.user_to_consumed(rx_frames.user_len);
        dbg!(rx_frames.rx_device(&mut fill_q));

        for frame in tx_frames.frames.iter_mut() {
            frame.set_addr(frame.addr() + libbpf_sys::XDP_PACKET_HEADROOM as usize);
        }

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

        let socket = Self { umem, tx, rx, link };

        socket.check_integrity();

        Ok(socket)
    }

    pub fn tx_queue(&mut self) -> UserTxQueue<'_, 'umem> {
        self.tx.tx_queue(&mut self.umem)
    }

    pub fn rx_queue(&mut self) -> UserRxQueue<'_, 'umem> {
        self.rx.rx_queue(&mut self.umem)
    }

    pub fn should_poll_read(&self) -> bool {
        self.check_integrity();

        let mut should_poll = self.rx.dev_queue.needs_wakeup();

        // try to read if we have any capacity in the user queue
        should_poll |= self.rx.frames.user_len != self.rx.frames.frames.len();

        should_poll
    }

    pub fn should_poll_write(&self) -> bool {
        let mut should_poll = false;

        // try to write if we've filled any packets
        should_poll |= self.tx.frames.consumed_len > 0;

        // or if there are any pending packets on the device
        should_poll |= self.tx.frames.device_len > 0;

        should_poll
    }

    fn check_integrity(&self) {
        /*
        if cfg!(debug_assertions) {
            use std::collections::HashSet;

            let mtu = libbpf_sys::XSK_UMEM__DEFAULT_FRAME_SIZE as usize;

            let rx_addrs: HashSet<_> = self
                .rx
                .frames
                .frames
                .iter()
                .map(|frame| frame.addr() / mtu)
                .collect();
            let tx_addrs: HashSet<_> = self
                .tx
                .frames
                .frames
                .iter()
                .map(|frame| frame.addr() / mtu)
                .collect();

            assert!(
                rx_addrs.is_disjoint(&tx_addrs),
                "{:?}",
                rx_addrs.intersection(&tx_addrs)
            );
        }
        */
    }
}

impl<'umem> AsRawFd for SocketState<'umem> {
    fn as_raw_fd(&self) -> RawFd {
        self.rx.as_raw_fd()
    }
}

impl<'umem> Drop for SocketState<'umem> {
    fn drop(&mut self) {
        let fd = self.as_raw_fd();
        /*
        let mut sock =
            aya::maps::SockMap::try_from(self.prog.map_mut("xsks_map").unwrap()).unwrap();
        sock.set(0, &fd, 0).unwrap();
        */
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

    pub fn do_io(&mut self) -> std::io::Result<(usize, usize)> {
        let device_len = self.frames.rx_device(&mut self.dev_queue);

        if self.dev_queue.needs_wakeup() {
            eprint!("RW ");
            self.dev_queue.wakeup(self.user_queue.fd(), 0)?;
        }

        let user_len = self.frames.rx_user(&mut self.user_queue)?;

        Ok((user_len, device_len))
    }

    pub fn free_len(&self) -> usize {
        self.frames.user_len
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

impl<'a, 'umem> UserRxQueue<'a, 'umem> {
    pub fn is_empty(&self) -> bool {
        self.rx.frames.user_len == 0
    }
}

impl<'a, 'umem> rx::Queue for UserRxQueue<'a, 'umem> {
    type Entry = RxEntry<'umem>;

    fn pop(&mut self) -> Option<Self::Entry> {
        loop {
            let desc = self.rx.frames.pop()?;

            let payload = unsafe { self.umem.umem_region_mut(&desc.addr(), &desc.len()) };
            let payload =
                unsafe { core::slice::from_raw_parts_mut(payload.as_mut_ptr(), payload.len()) };

            if let Ok(entry) = RxEntry::new(payload) {
                return Some(entry);
            }
        }
    }

    fn len(&self) -> usize {
        self.rx.frames.user_len
    }
}

pub struct RxEntry<'umem> {
    address: SocketAddress,
    payload: &'umem mut [u8],
}

impl<'umem> RxEntry<'umem> {
    pub fn new(bytes: &'umem mut [u8]) -> Result<Self, DecoderError> {
        let buffer = DecoderBufferMut::new(bytes);
        let (ethernet, buffer) = buffer.decode::<s2n_quic_core::inet::ethernet::Header>()?;

        if !ethernet.ty().is_ipv4() {
            return Err(DecoderError::InvariantViolation("ipv6"));
        }

        let (ipv4, buffer) = buffer.decode::<s2n_quic_core::inet::ipv4::Header>()?;

        if !ipv4.protocol().is_udp() {
            return Err(DecoderError::InvariantViolation("not udp"));
        }

        if ipv4.ihl() != 5 {
            return Err(DecoderError::InvariantViolation("ip options unsupported"));
        }

        let (udp, buffer) = buffer.decode::<s2n_quic_core::inet::udp::Header>()?;

        if udp.destination() != 4433 {
            return Err(DecoderError::InvariantViolation("invalid destination"));
        }

        let address: SocketAddress = (ipv4.source(), udp.source()).into();

        let payload = buffer.into_less_safe_slice();

        Ok(Self { address, payload })
    }
}

impl<'umem> rx::Entry for RxEntry<'umem> {
    fn remote_address(&self) -> Option<SocketAddress> {
        Some(self.address)
    }

    fn ecn(&self) -> ExplicitCongestionNotification {
        Default::default()
    }

    fn payload(&self) -> &[u8] {
        self.payload
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        self.payload
    }
}

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

    pub fn do_io(&mut self) -> std::io::Result<(usize, usize)> {
        let user_len = self.frames.produce_to_user(&mut self.dev_queue);
        let device_len = self.frames.produce_to_device(&mut self.user_queue);

        if self.user_queue.needs_wakeup() {
            eprint!("TW ");
            self.user_queue.wakeup()?;
        }

        let user_len = user_len?;
        let device_len = device_len?;

        Ok((user_len, device_len))
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

            let macbook = hex_literal::hex!("18 7e b9 05 f2 de");
            let realtec = hex_literal::hex!("3c 7c 3f 81 7a 7c");
            let i7 = hex_literal::hex!("60 45 cb 6b 43 46");
            let igb = hex_literal::hex!("3c 7c 3f 81 7a 7b");

            encoder.encode(&&macbook[..]);
            encoder.encode(&&igb[..]);
            encoder.encode(&&[8u8, 0u8][..]);

            let addr = match message.remote_address() {
                SocketAddress::IpV4(addr) => addr,
                _ => return 0,
            };

            let ip_start = encoder.len();
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

            encoder.encode(&&[192, 168, 0, 17][..]);
            // encoder.encode(&&[169, 254, 253, 160][..]);
            encoder.encode(&addr.ip());
            let ip_range = ip_start..encoder.len();

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
            let payload_len = message.write_payload(payload);

            if payload_len == 0 {
                return 0;
            }

            header[ip_length].copy_from_slice(&(payload_len as u16 + 28).to_be_bytes()[..]);
            header[udp_length].copy_from_slice(&(payload_len as u16 + 8).to_be_bytes()[..]);
            let ip_checksum_value = checksum::compute(&header[ip_range]);
            header[ip_checksum].copy_from_slice(&ip_checksum_value.to_be_bytes());

            header.len() + payload_len
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

mod checksum {
    use s2n_codec::DecoderBuffer;

    fn u32_to_u16(value: u32) -> u16 {
        let value = (value & 0xffff) + (value >> 16);
        let value = (value & 0xffff) + (value >> 16);
        value as u16
    }

    pub fn compute(data: &[u8]) -> u16 {
        let mut acc = 0;

        let mut buffer = DecoderBuffer::new(data);

        // TODO optimize with u64 and u32

        while let Ok((value, remaining)) = buffer.decode::<u16>() {
            acc += u16::to_be(value) as u32;
            buffer = remaining;
        }

        if let Ok((value, _)) = buffer.decode::<u8>() {
            acc += (value as u32) << 8;
        }

        u16::from_be(!u32_to_u16(acc))
    }

    #[test]
    fn example_test() {
        let packet =
            hex_literal::hex!("45 00 04 cc 00 00 40 00 40 11 00 00 c0 a8 56 b2 c0 a8 56 b5");
        let actual = compute(&packet);
        let expected = 0x0769;
        assert_eq!(
            actual, expected,
            "\n  actual: {:16b}\nexpected: {:16b}",
            actual, expected
        );
    }
}

#[derive(Debug)]
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
        frame.set_len(0);
        let frame_len = f(frame);

        if frame_len == 0 {
            //eprint!("0 ");
            return Err(tx::Error::EmptyPayload);
        }

        //eprint!("+ ");
        frame.set_len(frame_len);

        self.user_to_consumed(1);

        Ok(frame_len)
    }

    /// Moves filled packets to the device for transmission
    pub fn produce_to_device(&mut self, queue: &mut TxQueue<'umem>) -> std::io::Result<usize> {
        let ranges = self.consumed_ranges();
        let iter = self.iter(ranges);

        if iter.len() == 0 {
            return Ok(0);
        }

        let len = unsafe { queue.produce_and_wakeup(iter) }?;

        // tell the caller it needs to poll for write ready
        if len == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ""));
        }

        self.consumed_to_device(len);

        Ok(len)
    }

    /// Moves sent packet slots to be available for new packet transmission
    pub fn produce_to_user(&mut self, queue: &mut CompQueue<'umem>) -> std::io::Result<usize> {
        let ranges = self.device_ranges();
        let iter = self.iter_mut(ranges);

        if iter.len() == 0 {
            return Ok(0);
        }

        let len = queue.consume(iter);

        // tell the caller it needs to poll for write ready
        if len == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ""));
        }

        let ranges = self.device_ranges();
        let iter = self.iter_mut(ranges);

        for frame in iter {
            let addr = frame.addr();
            let m = addr % libbpf_sys::XSK_UMEM__DEFAULT_FRAME_SIZE as usize;
            if m != libbpf_sys::XDP_PACKET_HEADROOM as usize {
                let addr = addr / libbpf_sys::XSK_UMEM__DEFAULT_FRAME_SIZE as usize
                    * libbpf_sys::XSK_UMEM__DEFAULT_FRAME_SIZE as usize
                    + libbpf_sys::XDP_PACKET_HEADROOM as usize;
                frame.set_addr(addr);
                dbg!(frame.len());
            }
        }

        self.device_to_user(len);

        Ok(len)
    }

    /// Moves received packets to be available for user consumption
    pub fn rx_user(&mut self, queue: &mut RxQueue<'umem>) -> std::io::Result<usize> {
        let ranges = self.device_ranges();
        let iter = self.iter_mut(ranges);

        if iter.len() == 0 {
            return Ok(0);
        }

        let len = queue.consume(iter);

        // tell the caller it needs to poll for read ready
        if len == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ""));
        }

        self.device_to_user(len);

        Ok(len)
    }

    /// Moves consumed packet slots to be available for the device
    pub fn rx_device(&mut self, rx: &mut FillQueue<'umem>) -> usize {
        let ranges = self.consumed_ranges();
        let iter = self.iter_mut(ranges);

        struct RxDevIter<'a, 'umem>(IterMut<'a, 'umem>);

        impl<'a, 'umem> Iterator for RxDevIter<'a, 'umem> {
            type Item = &'a FrameDesc<'umem>;

            fn next(&mut self) -> Option<Self::Item> {
                let frame = self.0.next()?;
                // ensure we are at the start of the frame
                let addr = frame.addr() / libbpf_sys::XSK_UMEM__DEFAULT_FRAME_SIZE as usize
                    * libbpf_sys::XSK_UMEM__DEFAULT_FRAME_SIZE as usize;
                frame.set_addr(addr);
                frame.set_len(libbpf_sys::XSK_UMEM__DEFAULT_FRAME_SIZE as usize);

                Some(frame)
            }
        }

        impl<'a, 'umem> ExactSizeIterator for RxDevIter<'a, 'umem> {
            fn len(&self) -> usize {
                self.0.len()
            }
        }

        let iter = RxDevIter(iter);

        let iter_len = iter.len();
        if iter_len == 0 {
            return 0;
        }

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
        //eprint!("- ");

        Some(frame)
    }

    fn user_to_consumed(&mut self, amount: usize) {
        self.user_head = (self.user_head + amount) % self.frames.len();
        self.user_len -= amount;
        self.consumed_len += amount;

        self.check_integrity();
    }

    fn consumed_to_device(&mut self, amount: usize) {
        self.consumed_head = (self.consumed_head + amount) % self.frames.len();
        self.consumed_len -= amount;
        self.device_len += amount;

        self.check_integrity();
    }

    fn device_to_user(&mut self, amount: usize) {
        self.device_head = (self.device_head + amount) % self.frames.len();
        self.device_len -= amount;
        self.user_len += amount;

        self.check_integrity();
    }

    fn user_ranges(&self) -> (Range<usize>, Range<usize>) {
        self.ranges(self.user_head, self.user_len)
    }

    fn consumed_ranges(&self) -> (Range<usize>, Range<usize>) {
        self.ranges(self.consumed_head, self.consumed_len)
    }

    fn device_ranges(&self) -> (Range<usize>, Range<usize>) {
        self.ranges(self.device_head, self.device_len)
    }

    fn iter<'a>(&'a self, (first, second): (Range<usize>, Range<usize>)) -> Iter<'a, 'umem> {
        let (first, second) = if second.end != 0 {
            let (b, a) = self.frames.split_at(first.start);
            (a, &b[..second.end])
        } else {
            let a = &self.frames[first];
            let (a, b) = a.split_at(a.len());
            (a, b)
        };

        Iter {
            first: first.iter(),
            second: second.iter(),
        }
    }

    fn iter_mut<'a>(
        &'a mut self,
        (first, second): (Range<usize>, Range<usize>),
    ) -> IterMut<'a, 'umem> {
        let (first, second) = if second.end != 0 {
            let (b, a) = self.frames.split_at_mut(first.start);
            (a, &mut b[..second.end])
        } else {
            let a = &mut self.frames[first];
            let (a, b) = a.split_at_mut(a.len());
            (a, b)
        };
        IterMut {
            first: first.iter_mut(),
            second: second.iter_mut(),
        }
    }

    fn ranges(&self, head: usize, len: usize) -> (Range<usize>, Range<usize>) {
        let tail = head + len;
        if let Some(second_len) = tail.checked_sub(self.frames.len()) {
            (head..self.frames.len(), 0..second_len)
        } else {
            (head..tail, 0..0)
        }
    }

    fn check_integrity(&self) {
        if cfg!(debug_assertions) {
            use std::collections::HashSet;

            let mut len = 0;
            len += self.user_len;
            len += self.consumed_len;
            len += self.device_len;
            assert_eq!(self.frames.len(), len);

            /*
            let user: HashSet<_> = self
                .iter(self.user_ranges())
                .map(|frame| frame.addr())
                .collect();
            let consumed: HashSet<_> = self
                .iter(self.consumed_ranges())
                .map(|frame| frame.addr())
                .collect();
            let device: HashSet<_> = self
                .iter(self.device_ranges())
                .map(|frame| frame.addr())
                .collect();

            assert!(
                user.is_disjoint(&consumed),
                "{:?}",
                user.intersection(&consumed)
            );
            assert!(
                consumed.is_disjoint(&device),
                "{:?}",
                consumed.intersection(&device)
            );
            assert!(
                device.is_disjoint(&user),
                "{:?} device: {:?}; user: {:?}",
                device.intersection(&user),
                self.device_ranges(),
                self.user_ranges(),
            );
            */
        }
    }

    fn dump(&self) {
        eprintln!(
            "user {}({}); consumed {}({}); device {}({})",
            self.user_head,
            self.user_len,
            self.consumed_head,
            self.consumed_len,
            self.device_head,
            self.device_len
        );
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

struct IterMut<'a, 'umem> {
    first: core::slice::IterMut<'a, FrameDesc<'umem>>,
    second: core::slice::IterMut<'a, FrameDesc<'umem>>,
}

impl<'a, 'umem> Iterator for IterMut<'a, 'umem> {
    type Item = &'a mut FrameDesc<'umem>;

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

impl<'a, 'umem> ExactSizeIterator for IterMut<'a, 'umem> {
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
