use core::{fmt, task::Poll};
use libbpf_sys::*;
use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use s2n_quic_core::{
    frame::Frame,
    io::{rx, tx},
};
use std::{
    ffi::CStr,
    io,
    mem::MaybeUninit,
    os::unix::io::{AsRawFd, RawFd},
    time::Instant,
};

pub struct Tuning {
    rx_batch_size: u32,
    rx_fill_size: u32,
    tx_batch_size: u32,
    tx_mtu: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            rx_batch_size: u32::MAX,
            rx_fill_size: 1024,
            tx_batch_size: u32::MAX,
            tx_mtu: 1550,
        }
    }
}

pub struct Socket {
    rx: xsk_ring_cons,
    tx: xsk_ring_prod,
    umem: Umem,
    config: xsk_socket_config,
    xsk: *mut xsk_socket,
    tx_frames: FrameQueue,
    rx_frames: FrameQueue,

    next_rx_index: Option<u32>,
    outstanding_tx: u64,
    tx_reservation: Option<*mut xdp_desc>,
    tx_at_capacity: bool,
    tx_poll_state: TxPoll,

    tuning: Tuning,
    stats: Stats,
}

#[derive(Debug, Default)]
struct Stats {
    rx: StatDir,
    tx: StatDir,
    last_print_time: Option<Instant>,
}

macro_rules! col {
    ($f:ident, $value:expr) => {
        write!($f, "{:10}|", $value)
    };
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        StatDir::header(f)?;
        writeln!(f)?;
        col!(f, "RX")?;
        write!(f, "{}", self.rx)?;
        writeln!(f)?;
        col!(f, "TX")?;
        write!(f, "{}", self.tx)?;
        writeln!(f)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct StatDir {
    double_free: usize,
    pending_packets: usize,
    packets: usize,
    bytes: usize,
    polls: usize,
    free_frames: f32,
    outstanding: usize,
}

impl StatDir {
    fn header(f: &mut fmt::Formatter) -> fmt::Result {
        col!(f, "")?;
        col!(f, "pending")?;
        col!(f, "packets")?;
        col!(f, "pdiff")?;
        col!(f, "bytes")?;
        col!(f, "polls")?;
        col!(f, "free frms")?;
        col!(f, "dfree")?;
        col!(f, "total")?;
        col!(f, "outstnd")?;
        Ok(())
    }
}

impl fmt::Display for StatDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        col!(f, self.pending_packets)?;
        col!(f, self.packets)?;
        col!(f, self.pending_packets - self.packets)?;
        col!(f, self.bytes)?;
        col!(f, self.polls)?;
        col!(f, format_args!("{:9}%", self.free_frames as u32))?;
        col!(f, self.double_free)?;
        col!(f, self.pending_packets - self.packets + self.double_free)?;
        col!(f, self.outstanding)?;
        Ok(())
    }
}

impl Socket {
    pub fn new(if_name: &CStr, queue_id: u32) -> io::Result<Self> {
        let frame_count = std::env::var("FRAME_COUNT")
            .map(|v| v.parse().unwrap())
            .unwrap_or((XSK_RING_PROD__DEFAULT_NUM_DESCS * 8) as usize);
        let rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        let tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
        let fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
        let comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        let frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
        let frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
        let xdp_flags = XDP_FLAGS_HW_MODE | XDP_FLAGS_DRV_MODE;
        let bind_flags = XDP_USE_NEED_WAKEUP as _;
        let libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

        let umem_config = xsk_umem_config {
            fill_size,
            comp_size,
            frame_size,
            frame_headroom,
            flags: XSK_UMEM__DEFAULT_FLAGS,
        };

        let socket_config = xsk_socket_config {
            rx_size,
            tx_size,
            xdp_flags,
            bind_flags,
            libbpf_flags,
        };

        let tuning = Tuning {
            rx_fill_size: fill_size,
            ..Tuning::default()
        };

        let (umem, rx_frames, tx_frames) = Umem::create(frame_count, umem_config)?;

        let mut xsk = core::ptr::null_mut();
        let mut tx = MaybeUninit::uninit();
        let mut rx = MaybeUninit::uninit();

        let status = unsafe {
            xsk_socket__create(
                &mut xsk,
                if_name.as_ptr(),
                queue_id,
                umem.umem,
                rx.as_mut_ptr(),
                tx.as_mut_ptr(),
                &socket_config,
            )
        };

        if status < 0 {
            return Err(io::Error::last_os_error());
        }

        let rx = unsafe { rx.assume_init() };
        let tx = unsafe { tx.assume_init() };

        let mut socket = Self {
            rx,
            tx,
            config: socket_config,
            umem,
            xsk,
            tx_frames,
            rx_frames,
            next_rx_index: None,
            outstanding_tx: 0,
            tx_reservation: None,
            tx_at_capacity: false,
            tx_poll_state: TxPoll::Empty,
            tuning,
            stats: Stats::default(),
        };

        // Fill the socket up so it can start receiving packets
        socket.umem.device_fill(&mut socket.rx_frames);
        socket.stats.rx.pending_packets += socket.rx_frames.len();

        Ok(socket)
    }

    pub fn rx_queue(&mut self) -> RxQueue {
        RxQueue {
            consumed_len: 0,
            socket: self,
        }
    }

    pub fn tx_queue(&mut self) -> TxQueue {
        if std::env::var("PRINT_STATS").is_ok() {
            self.print_stats();
        }
        TxQueue {
            transmitted_len: 0,
            socket: self,
        }
    }

    pub fn poll_rx(&mut self) -> Poll<bool> {
        // check to see if we have any available packets to ready
        if self.next_rx_index.is_none() {
            self.next_rx_index = self.pop_rx_index();
        }

        // notify the caller to poll if we have available capacity in the frames
        if self.next_rx_index.is_none() {
            self.stats.rx.polls += 1;
            Poll::Pending
        } else {
            Poll::Ready(self.rx_frames.has_capacity())
        }
    }

    fn pop_rx_index(&mut self) -> Option<u32> {
        let mut recv_idx = 0;
        let has_item = unsafe { _xsk_ring_cons__peek(&mut self.rx, 1, &mut recv_idx) };

        if has_item == 1 {
            Some(recv_idx)
        } else {
            None
        }
    }

    pub fn should_poll_tx(&self) -> bool {
        let needs_wakeup = unsafe { _xsk_ring_prod__needs_wakeup(&self.tx) } != 0;
        let has_transmissions = self.outstanding_tx > 0;
        has_transmissions && needs_wakeup
    }

    pub fn poll_tx(&mut self) -> TxPoll {
        if self.tx_poll_state == TxPoll::Empty {
            return TxPoll::Empty;
        }

        let completed = self.umem.device_complete(
            &mut self.tx_frames,
            self.outstanding_tx as _,
            &mut self.stats,
        );

        self.stats.tx.packets += completed as usize;
        self.outstanding_tx -= completed;

        // if we no longer have any outstanding transmissions, then we're empty
        if self.outstanding_tx == 0 {
            self.tx_poll_state = TxPoll::Empty;
        }

        match &mut self.tx_poll_state {
            TxPoll::Empty => TxPoll::Empty,
            TxPoll::Poll { should_wake } => TxPoll::Poll {
                should_wake: core::mem::take(should_wake),
            },
        }
    }

    fn print_stats(&mut self) {
        let now = Instant::now();
        if let Some(time) = self.stats.last_print_time {
            if (now - time) < core::time::Duration::from_secs(1) {
                return;
            }
        }
        self.stats.tx.outstanding = self.outstanding_tx as _;
        self.stats.rx.free_frames = self.rx_frames.free_perc();
        self.stats.tx.free_frames = self.tx_frames.free_perc();
        eprintln!("{}", self.stats,);
        self.stats.last_print_time = Some(now);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TxPoll {
    /// There are no outstanding transmissions
    Empty,
    /// The caller should issue a poll call to the sockets' file descriptor
    Poll {
        /// The caller should wake the application when progress is made
        should_wake: bool,
    },
}

impl TxPoll {
    fn on_transmit(&mut self) {
        match self {
            Self::Empty => *self = Self::Poll { should_wake: false },
            _ => {}
        }
    }

    fn on_blocked(&mut self) {
        *self = Self::Poll { should_wake: true }
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        unsafe { xsk_socket__fd(self.xsk) }
    }
}

// TODO impl drop

struct Umem {
    fill_queue: xsk_ring_prod,
    completion_queue: xsk_ring_cons,
    config: xsk_umem_config,
    umem: *mut xsk_umem,
    buffer: Buffer,
}

impl Umem {
    pub fn create(
        frame_count: usize,
        config: xsk_umem_config,
    ) -> io::Result<(Self, FrameQueue, FrameQueue)> {
        let frame_size = config.frame_size as usize;
        let buffer_size = frame_count * frame_size;
        let mut buffer = Buffer::new(buffer_size, false)?;
        let rx_frames = FrameQueue::new(frame_count / 2, frame_size, 0);
        let tx_frames = FrameQueue::new(frame_count / 2, frame_size, (frame_size / 2) as u64);

        let mut umem = core::ptr::null_mut();
        let mut fill_queue = MaybeUninit::uninit();
        let mut completion_queue = MaybeUninit::uninit();

        let status = unsafe {
            xsk_umem__create(
                &mut umem,
                buffer.as_mut_ptr(),
                buffer.len() as _,
                fill_queue.as_mut_ptr(),
                completion_queue.as_mut_ptr(),
                &config,
            )
        };

        if status < 0 {
            return Err(io::Error::last_os_error());
        }

        let fill_queue = unsafe { fill_queue.assume_init() };
        let completion_queue = unsafe { completion_queue.assume_init() };

        let umem = Self {
            fill_queue,
            completion_queue,
            config,
            umem,
            buffer,
        };

        Ok((umem, rx_frames, tx_frames))
    }

    /// Transfers frames to the device for RX
    #[inline(never)]
    fn device_fill(&mut self, frames: &mut FrameQueue) -> u32 {
        let mut filled_frames = 0;

        while frames.has_capacity() {
            let mut index = 0;
            let has_item = unsafe { _xsk_ring_prod__reserve(&mut self.fill_queue, 1, &mut index) };

            if has_item != 1 {
                break;
            }

            filled_frames += 1;

            let addr = frames.alloc().expect("frame capacity checked");
            unsafe { *_xsk_ring_prod__fill_addr(&mut self.fill_queue, index) = addr }
        }

        unsafe {
            _xsk_ring_prod__submit(&mut self.fill_queue, filled_frames as _);
        }

        filled_frames
    }

    /// Transfers frames from the device for TX
    #[inline(never)]
    fn device_complete(
        &mut self,
        frames: &mut FrameQueue,
        outstanding_tx: u32,
        stats: &mut Stats,
    ) -> u64 {
        let peek_len = unsafe { _xsk_cons_nb_avail(&mut self.completion_queue, outstanding_tx) };

        if peek_len <= 0 {
            return 0;
        }

        let mut index = 0;
        let completed =
            unsafe { _xsk_ring_cons__peek(&mut self.completion_queue, peek_len as _, &mut index) };

        if completed == 0 {
            return 0;
        }

        for offset in 0..(completed as _) {
            let addr =
                unsafe { *_xsk_ring_cons__comp_addr(&self.completion_queue, index + offset) };

            if frames.free(addr).is_err() {
                stats.tx.double_free += 1;
            }
        }

        unsafe {
            _xsk_ring_cons__release(&mut self.completion_queue, completed);
        }

        completed
    }
}

pub struct RxQueue<'a> {
    consumed_len: usize,
    socket: &'a mut Socket,
}

impl<'a> RxQueue<'a> {
    pub fn is_empty(&self) -> bool {
        self.socket.next_rx_index.is_none()
    }
}

impl<'a> Iterator for RxQueue<'a> {
    type Item = &'a mut [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.socket.next_rx_index.take()?;

        let desc = unsafe { &*_xsk_ring_cons__rx_desc(&self.socket.rx, index) };
        let addr = desc.addr;
        let len = desc.len as usize;

        let data = self.socket.umem.buffer.pointer_for_addr(addr);
        let data = unsafe { core::slice::from_raw_parts_mut(data, len) };

        if self.socket.rx_frames.free(addr).is_err() {
            self.socket.stats.rx.double_free += 1;
        }

        self.consumed_len += 1;
        self.socket.stats.rx.packets += 1;
        self.socket.stats.rx.bytes += data.len();

        // fetch the next available rx index
        self.socket.next_rx_index = self.socket.pop_rx_index();

        Some(data)
    }
}

impl<'a> Drop for RxQueue<'a> {
    fn drop(&mut self) {
        let consumed = self.consumed_len;
        if consumed > 0 {
            unsafe {
                _xsk_ring_cons__release(&mut self.socket.rx, consumed as _);
            }

            // give the device any consumed frames
            self.socket.stats.rx.pending_packets +=
                self.socket.umem.device_fill(&mut self.socket.rx_frames) as usize;
        }
    }
}

pub struct TxQueue<'a> {
    transmitted_len: u32,
    socket: &'a mut Socket,
}

impl<'a> TxQueue<'a> {
    pub fn push<F: FnOnce(&mut [u8]) -> usize>(
        &mut self,
        write: F,
    ) -> Result<&'a mut [u8], tx::Error> {
        let frame = if let Some(frame) = self.socket.tx_reservation.take() {
            unsafe { &mut *frame }
        } else {
            if self.transmitted_len > self.socket.tuning.tx_batch_size
                || !self.socket.tx_frames.has_capacity()
            {
                self.socket.tx_poll_state.on_blocked();
                return Err(tx::Error::AtCapacity);
            }

            let mut index = 0;
            let reservation =
                unsafe { _xsk_ring_prod__reserve(&mut self.socket.tx, 1, &mut index) };

            // no more free slots
            if reservation != 1 {
                self.socket.tx_poll_state.on_blocked();
                return Err(tx::Error::AtCapacity);
            }

            let desc = unsafe { &mut *_xsk_ring_prod__tx_desc(&mut self.socket.tx, index) };
            desc.addr = self.socket.tx_frames.alloc().unwrap() + XDP_PACKET_HEADROOM as u64;

            desc
        };

        let addr = frame.addr;
        let len = self.socket.tuning.tx_mtu as usize;

        let data = self.socket.umem.buffer.pointer_for_addr(addr);
        let data = unsafe { core::slice::from_raw_parts_mut(data, len) };

        let len = write(data);
        frame.len = len as _;

        if len == 0 {
            self.socket.tx_reservation = Some(frame);
            return Err(tx::Error::EmptyPayload);
        }

        self.transmitted_len += 1;
        self.socket.outstanding_tx += 1;
        self.socket.stats.tx.pending_packets += 1;
        self.socket.stats.tx.bytes += len;

        Ok(data)
    }

    pub fn len(&self) -> usize {
        self.transmitted_len as _
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> Drop for TxQueue<'a> {
    fn drop(&mut self) {
        let consumed = self.transmitted_len;
        if consumed > 0 {
            self.socket.tx_poll_state.on_transmit();
            unsafe {
                _xsk_ring_prod__submit(&mut self.socket.tx, consumed as _);
            }
        }
    }
}

struct FrameQueue {
    free: Box<[bool]>,
    queue: std::collections::VecDeque<u64>,
    frame_size: usize,
    offset: u64,
}

impl FrameQueue {
    pub fn new(len: usize, frame_size: usize, offset: u64) -> Self {
        let free = vec![true; len].into_boxed_slice();

        let queue = (0..(len as u64)).collect::<_>();

        Self {
            free,
            queue,
            frame_size,
            offset,
        }
    }

    pub fn alloc(&mut self) -> Option<u64> {
        let frame = self.queue.pop_front()?;

        self.free[frame as usize] = false;

        self.check_integrity();

        let addr = (frame + self.offset) * self.frame_size as u64;

        Some(addr)
    }

    pub fn free(&mut self, addr: u64) -> Result<(), ()> {
        let frame = addr / self.frame_size as u64;
        let frame = if let Some(frame) = frame.checked_sub(self.offset) {
            frame
        } else {
            return Err(());
        };

        if self.free[frame as usize] {
            return Err(());
        }

        self.free[frame as usize] = true;
        self.queue.push_back(frame);

        self.check_integrity();

        Ok(())
    }

    pub fn remaining_capacity(&self) -> usize {
        self.queue.len()
    }

    pub fn has_capacity(&self) -> bool {
        !self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.free.len() - self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.free.len() == self.queue.len()
    }

    pub fn free_perc(&self) -> f32 {
        (self.queue.len() as f32 / self.free.len() as f32) * 100.
    }

    fn check_integrity(&self) {
        return;
        if cfg!(debug_assertions) {
            use std::collections::HashSet;

            let frames: HashSet<_> = self.queue.iter().copied().collect();
            for (frame, is_free) in self.free.iter().copied().enumerate() {
                assert_eq!(is_free, frames.contains(&(frame as u64)));
            }
        }
    }
}

#[derive(Debug, Default)]
struct Outstanding {
    index: u32,
    len: u32,
}

impl Iterator for Outstanding {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        self.len = self.len.checked_sub(1)?;
        let index = self.index;
        self.index = index + 1;
        Some(index)
    }
}

pub struct Buffer {
    buffer: *mut libc::c_void,
    len: usize,
}

unsafe impl Send for Buffer {}

impl Buffer {
    pub fn new(len: usize, use_huge_pages: bool) -> io::Result<Self> {
        let prot = PROT_READ | PROT_WRITE;

        let mut flags = MAP_ANONYMOUS | MAP_PRIVATE;

        if use_huge_pages {
            flags |= MAP_HUGETLB;
        }

        let buffer = unsafe { libc::mmap(core::ptr::null_mut(), len, prot, flags, -1, 0) };

        if buffer == MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { len, buffer })
        }
    }

    pub fn pointer_for_addr(&self, addr: u64) -> *mut u8 {
        unsafe { _xsk_umem__get_data(self.buffer, addr) as *mut u8 }
    }

    pub fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.buffer
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let _ = unsafe { libc::munmap(self.buffer, self.len) };
    }
}
