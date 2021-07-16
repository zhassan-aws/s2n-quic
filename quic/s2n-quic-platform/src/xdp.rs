use core::{
    convert::{TryFrom, TryInto},
    num::NonZeroU32,
    ops::Range,
};
use s2n_codec::{DecoderBufferMut, DecoderError, Encoder, EncoderBuffer};
use s2n_quic_core::{
    inet::{ExplicitCongestionNotification, SocketAddress},
    io::{rx, tx},
};
use std::{
    collections::VecDeque,
    ffi::CStr,
    io,
    os::unix::io::{AsRawFd, RawFd},
};

mod bpf {
    include!("./xdp/.output/kern.skel.rs");
}

mod af_xdp;

// Put umem at bottom so drop order is correct
pub struct SocketState {
    socket: af_xdp::Socket,
    link: libbpf_rs::Link,
}

unsafe impl Send for SocketState {}

impl SocketState {
    pub fn new(if_name: &CStr, queue_id: u32) -> io::Result<Self> {
        let rlim = libc::rlimit {
            rlim_cur: libc::rlim_t::MAX,
            rlim_max: libc::rlim_t::MAX,
        };
        libc!(setrlimit(libc::RLIMIT_MEMLOCK, &rlim))?;

        let socket = af_xdp::Socket::new(if_name, queue_id)?;

        let open_skel = bpf::XdpPassKernSkelBuilder::default().open().unwrap();
        let mut skel = open_skel.load().unwrap();

        skel.attach().unwrap();
        let link = skel.progs_mut().xdp_sock_prog().attach_xdp(3).unwrap();

        let mut maps = skel.maps_mut();

        maps.xsks_map()
            .update(
                &0i32.to_ne_bytes(),
                &socket.as_raw_fd().to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )
            .unwrap();

        let socket = Self { socket, link };

        Ok(socket)
    }

    pub fn tx_queue(&mut self) -> TxQueue {
        TxQueue(self.socket.tx_queue())
    }

    pub fn rx_queue(&mut self) -> RxQueue {
        RxQueue(self.socket.rx_queue())
    }

    pub fn should_poll_read(&self) -> bool {
        self.socket.should_poll_rx()
    }

    pub fn should_poll_write(&self) -> bool {
        self.socket.should_poll_tx()
    }

    pub fn poll_rx(&mut self) -> io::Result<()> {
        self.socket.poll_rx()
    }

    pub fn poll_tx(&mut self) -> io::Result<()> {
        self.socket.poll_tx()
    }
}

impl AsRawFd for SocketState {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl Drop for SocketState {
    fn drop(&mut self) {
        let fd = self.as_raw_fd();
        // TODO remove bpf program
    }
}

pub struct RxQueue<'a>(af_xdp::RxQueue<'a>);

impl<'a> rx::Queue for RxQueue<'a> {
    type Entry = RxEntry<'a>;

    fn pop(&mut self) -> Option<Self::Entry> {
        loop {
            let payload = self.0.next()?;
            if let Ok(entry) = RxEntry::new(payload) {
                return Some(entry);
            } else {
                eprint!("* ");
            }
        }
    }

    fn len(&self) -> usize {
        self.0.len()
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

pub struct TxQueue<'a>(af_xdp::TxQueue<'a>);

impl<'a> tx::Queue for TxQueue<'a> {
    type Entry = DummyEntry;

    fn push<M: tx::Message>(&mut self, mut message: M) -> Result<usize, tx::Error> {
        self.0
            .push(move |region| {
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
            .map(|buffer| buffer.len())
    }

    fn as_slice_mut(&mut self) -> &mut [Self::Entry] {
        todo!()
    }

    fn capacity(&self) -> usize {
        // TODO
        1
    }

    fn len(&self) -> usize {
        self.0.len()
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
