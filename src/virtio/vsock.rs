// Virtio-vsock device — userspace backend.
//
// Processes vsock packets directly in userspace (no vhost-vsock kernel module).
// This allows VM fork/restore to work correctly: the VMM fully controls the
// vsock connection state and can inject transport reset events for clean
// reconnection after fork.
//
// Data path: guest agent ↔ vsock virtqueues ↔ this device ↔ unix socket pair ↔ agent_listener

use std::collections::VecDeque;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use super::{DeviceType, QueueInfo, VirtioDevice};

// Feature bits.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// Config space: 8 bytes (guest_cid as le64).
const CONFIG_SPACE_SIZE: usize = 8;

// Queue indices.
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
const _EVENT_QUEUE: u16 = 2;
const NUM_QUEUES: usize = 3;
const QUEUE_MAX_SIZE: u16 = 128;

// Vsock packet header (44 bytes, matches Linux virtio_vsock_hdr).
const HDR_SIZE: usize = 44;
const VSOCK_HOST_CID: u64 = 2;
const VSOCK_TYPE_STREAM: u16 = 1;

// Operations.
const OP_REQUEST: u16 = 1;
const OP_RESPONSE: u16 = 2;
const OP_RST: u16 = 3;
const OP_SHUTDOWN: u16 = 4;
const OP_RW: u16 = 5;
const OP_CREDIT_UPDATE: u16 = 6;
const OP_CREDIT_REQUEST: u16 = 7;

// Descriptor flags.
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VsockHdr {
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    len: u32,
    type_: u16,
    op: u16,
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
}

impl VsockHdr {
    fn read_from(data: &[u8]) -> Option<Self> {
        if data.len() < HDR_SIZE { return None; }
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) })
    }

    fn write_to(&self, data: &mut [u8]) -> usize {
        if data.len() < HDR_SIZE { return 0; }
        unsafe {
            std::ptr::write_unaligned(data.as_mut_ptr() as *mut Self, *self);
        }
        HDR_SIZE
    }
}

/// An active vsock connection.
struct VsockConn {
    guest_port: u32,
    host_port: u32,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    tx_cnt: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
}

impl VsockConn {
    fn peer_free(&self) -> u32 {
        self.peer_buf_alloc.saturating_sub(self.tx_cnt.wrapping_sub(self.peer_fwd_cnt))
    }
}

/// A virtio-vsock device with userspace packet processing.
pub struct VirtioVsock {
    guest_cid: u64,
    acked_features_low: u32,
    acked_features_high: u32,
    activated: bool,

    // Guest memory and queue configuration (from prepare_activate).
    queue_configs: Vec<QueueInfo>,
    guest_mem: *mut u8,
    guest_mem_size: u64,
    hole_start: u64,
    hole_end: u64,

    // Per-queue tracking (last_avail_idx, last_used_idx).
    last_avail: [u16; NUM_QUEUES],
    last_used: [u16; NUM_QUEUES],

    // Connection state.
    conn: Option<VsockConn>,
    pending_rx: VecDeque<Vec<u8>>, // complete packets (hdr + payload) to deliver to guest

    // Unix socket pair for bridging to agent_listener.
    // host_fd is used by the agent_listener (exposed via take_host_fd).
    // device_fd is used by this device for reading/writing agent data.
    device_fd: RawFd,
    host_fd: RawFd,

    // Eventfd signaled by the RX poll thread when agent data is available.
    // The VMM polls this to trigger process_queue(RX).
    rx_eventfd: RawFd,

    // Interrupt signaling: callback set by the VMM.
    irq_signal: Option<Arc<IrqSignal>>,
}

/// Interrupt signaling from device to guest (set by VMM before activation).
pub struct IrqSignal {
    pub interrupt_status: Arc<AtomicU32>,
    pub signal_fn: Box<dyn Fn() + Send + Sync>,
}

impl IrqSignal {
    pub fn signal(&self) {
        self.interrupt_status.fetch_or(1, Ordering::Release);
        (self.signal_fn)();
    }
}

// SAFETY: raw pointers are managed exclusively by the VMM.
unsafe impl Send for VirtioVsock {}

impl VirtioVsock {
    /// Create a new userspace vsock device.
    pub fn new(guest_cid: u64) -> anyhow::Result<Self> {
        if guest_cid < 3 {
            anyhow::bail!("vsock guest CID must be >= 3, got {guest_cid}");
        }

        // Create Unix socket pair for agent communication.
        let mut fds = [0i32; 2];
        #[cfg(target_os = "linux")]
        let sock_type = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let sock_type = libc::SOCK_STREAM;
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, sock_type, 0, fds.as_mut_ptr()) };
        if ret < 0 {
            anyhow::bail!("socketpair failed: {}", std::io::Error::last_os_error());
        }

        // Set non-blocking on the device side so writes/reads don't stall the MMIO handler.
        unsafe {
            let flags = libc::fcntl(fds[0], libc::F_GETFL);
            libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK);
            // Increase socket buffer to avoid data loss on non-blocking writes
            let buf_size: libc::c_int = 256 * 1024;
            libc::setsockopt(fds[0], libc::SOL_SOCKET, libc::SO_SNDBUF,
                &buf_size as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t);
            libc::setsockopt(fds[1], libc::SOL_SOCKET, libc::SO_RCVBUF,
                &buf_size as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        }

        #[cfg(target_os = "linux")]
        let rx_eventfd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        #[cfg(not(target_os = "linux"))]
        let rx_eventfd = -1i32;

        tracing::info!("virtio-vsock: created (guest_cid={guest_cid}, userspace backend)");

        Ok(Self {
            guest_cid,
            acked_features_low: 0,
            acked_features_high: 0,
            activated: false,
            queue_configs: Vec::new(),
            guest_mem: std::ptr::null_mut(),
            guest_mem_size: 0,
            hole_start: 0,
            hole_end: 0,
            last_avail: [0; NUM_QUEUES],
            last_used: [0; NUM_QUEUES],
            conn: None,
            pending_rx: VecDeque::new(),
            device_fd: fds[0],
            host_fd: fds[1],
            rx_eventfd,
            irq_signal: None,
        })
    }

    pub fn guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Take the host-side fd of the socket pair (for agent_listener).
    /// Returns -1 if already taken.
    pub fn take_host_fd(&mut self) -> RawFd {
        let fd = self.host_fd;
        self.host_fd = -1;
        fd
    }

    /// Set the IRQ signaling mechanism (must be called before activation).
    pub fn set_irq_signal(&mut self, signal: Arc<IrqSignal>) {
        self.irq_signal = Some(signal);
    }

    /// Get the device-side socket fd (for polling when agent data arrives).
    pub fn device_fd(&self) -> RawFd {
        self.device_fd
    }

    /// Get the eventfd that should be signaled to trigger RX processing.
    pub fn rx_eventfd(&self) -> RawFd {
        self.rx_eventfd
    }

    // --- GPA translation ---

    fn gpa_to_ptr(&self, gpa: u64) -> *mut u8 {
        let offset = if self.hole_start > 0 && gpa >= self.hole_end {
            self.hole_start + (gpa - self.hole_end)
        } else {
            gpa
        };
        unsafe { self.guest_mem.add(offset as usize) }
    }

    fn guest_slice(&self, gpa: u64, len: u64) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.gpa_to_ptr(gpa), len as usize) }
    }

    fn guest_slice_mut(&self, gpa: u64, len: u64) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.gpa_to_ptr(gpa), len as usize) }
    }

    // --- Virtqueue operations ---

    fn read_avail_idx(&self, qi: usize) -> u16 {
        let qc = &self.queue_configs[qi];
        unsafe { *(self.gpa_to_ptr(qc.avail_addr + 2) as *const u16) }
    }

    fn read_avail_ring_entry(&self, qi: usize, idx: u16) -> u16 {
        let qc = &self.queue_configs[qi];
        let size = qc.size;
        let ring_offset = 4 + (idx % size) as u64 * 2;
        unsafe { *(self.gpa_to_ptr(qc.avail_addr + ring_offset) as *const u16) }
    }

    fn read_descriptor(&self, qi: usize, idx: u16) -> (u64, u32, u16, u16) {
        let qc = &self.queue_configs[qi];
        let desc_ptr = self.gpa_to_ptr(qc.desc_addr + idx as u64 * 16);
        unsafe {
            let addr = *(desc_ptr as *const u64);
            let len = *(desc_ptr.add(8) as *const u32);
            let flags = *(desc_ptr.add(12) as *const u16);
            let next = *(desc_ptr.add(14) as *const u16);
            (addr, len, flags, next)
        }
    }

    fn write_used_entry(&self, qi: usize, used_idx: u16, desc_idx: u16, len: u32) {
        let qc = &self.queue_configs[qi];
        let size = qc.size;
        let entry_offset = 4 + (used_idx % size) as u64 * 8;
        let ptr = self.gpa_to_ptr(qc.used_addr + entry_offset);
        unsafe {
            *(ptr as *mut u32) = desc_idx as u32;
            *(ptr.add(4) as *mut u32) = len;
        }
    }

    fn write_used_idx(&self, qi: usize, idx: u16) {
        let qc = &self.queue_configs[qi];
        std::sync::atomic::fence(Ordering::Release);
        unsafe { *(self.gpa_to_ptr(qc.used_addr + 2) as *mut u16) = idx; }
    }

    // --- Packet building ---

    fn make_hdr(&self, conn: &VsockConn, op: u16, payload_len: u32) -> VsockHdr {
        VsockHdr {
            src_cid: VSOCK_HOST_CID.to_le(),
            dst_cid: self.guest_cid.to_le(),
            src_port: conn.host_port.to_le(),
            dst_port: conn.guest_port.to_le(),
            len: payload_len.to_le(),
            type_: VSOCK_TYPE_STREAM.to_le(),
            op: op.to_le(),
            flags: 0,
            buf_alloc: conn.buf_alloc.to_le(),
            fwd_cnt: conn.fwd_cnt.to_le(),
        }
    }

    fn enqueue_hdr(&mut self, op: u16) {
        if let Some(ref conn) = self.conn {
            let hdr = self.make_hdr(conn, op, 0);
            let mut pkt = vec![0u8; HDR_SIZE];
            hdr.write_to(&mut pkt);
            self.pending_rx.push_back(pkt);
        }
    }

    fn enqueue_rst_for(&mut self, guest_port: u32, host_port: u32) {
        let hdr = VsockHdr {
            src_cid: VSOCK_HOST_CID.to_le(),
            dst_cid: self.guest_cid.to_le(),
            src_port: host_port.to_le(),
            dst_port: guest_port.to_le(),
            len: 0,
            type_: VSOCK_TYPE_STREAM.to_le(),
            op: OP_RST.to_le(),
            ..Default::default()
        };
        let mut pkt = vec![0u8; HDR_SIZE];
        hdr.write_to(&mut pkt);
        self.pending_rx.push_back(pkt);
    }

    // --- TX processing (guest → host) ---

    fn process_tx(&mut self) {
        let qi = TX_QUEUE as usize;
        if qi >= self.queue_configs.len() { return; }

        let avail_idx = self.read_avail_idx(qi);
        while self.last_avail[qi] != avail_idx {
            let desc_idx = self.read_avail_ring_entry(qi, self.last_avail[qi]);
            self.last_avail[qi] = self.last_avail[qi].wrapping_add(1);

            // Walk descriptor chain and gather all readable data.
            let mut data = Vec::new();
            let mut idx = desc_idx;
            loop {
                let (addr, len, flags, next) = self.read_descriptor(qi, idx);
                if flags & VRING_DESC_F_WRITE == 0 {
                    data.extend_from_slice(self.guest_slice(addr, len as u64));
                }
                if flags & VRING_DESC_F_NEXT != 0 {
                    idx = next;
                } else {
                    break;
                }
            }

            // Return descriptor to used ring (TX is read-only, 0 bytes written).
            self.write_used_entry(qi, self.last_used[qi], desc_idx, 0);
            self.last_used[qi] = self.last_used[qi].wrapping_add(1);
            self.write_used_idx(qi, self.last_used[qi]);

            // Parse vsock header.
            if let Some(hdr) = VsockHdr::read_from(&data) {
                let op = u16::from_le(hdr.op);
                let src_port = u32::from_le(hdr.src_port);
                let dst_port = u32::from_le(hdr.dst_port);
                let payload_len = u32::from_le(hdr.len) as usize;
                let payload = if payload_len > 0 && data.len() >= HDR_SIZE + payload_len {
                    &data[HDR_SIZE..HDR_SIZE + payload_len]
                } else {
                    &[]
                };

                self.handle_tx_op(op, src_port, dst_port, payload, &hdr);
            }
        }
    }

    fn handle_tx_op(&mut self, op: u16, guest_port: u32, host_port: u32, payload: &[u8], hdr: &VsockHdr) {
        tracing::info!(
            "vsock TX op={op} guest_port={guest_port} host_port={host_port} payload_len={}",
            payload.len()
        );
        match op {
            OP_REQUEST => {
                // Guest wants to connect. Close any existing connection first
                // and drain stale data from the unix socket.
                if self.conn.is_some() {
                    self.conn = None;
                }
                self.pending_rx.clear();
                // Drain stale data from device_fd so the listener gets a clean stream
                if self.device_fd >= 0 {
                    let mut drain = [0u8; 4096];
                    loop {
                        let n = unsafe { libc::read(self.device_fd, drain.as_mut_ptr() as *mut libc::c_void, drain.len()) };
                        if n <= 0 { break; }
                    }
                }
                self.conn = Some(VsockConn {
                    guest_port,
                    host_port,
                    peer_buf_alloc: u32::from_le(hdr.buf_alloc),
                    peer_fwd_cnt: u32::from_le(hdr.fwd_cnt),
                    tx_cnt: 0,
                    buf_alloc: 64 * 1024,
                    fwd_cnt: 0,
                });
                tracing::info!("vsock: connection from guest port {guest_port} to host port {host_port}");
                self.enqueue_hdr(OP_RESPONSE);
            }
            OP_RW => {
                if let Some(ref mut conn) = self.conn {
                    if conn.guest_port != guest_port {
                        self.enqueue_rst_for(guest_port, host_port);
                        return;
                    }
                    conn.peer_buf_alloc = u32::from_le(hdr.buf_alloc);
                    conn.peer_fwd_cnt = u32::from_le(hdr.fwd_cnt);
                    conn.fwd_cnt = conn.fwd_cnt.wrapping_add(payload.len() as u32);
                    // Forward data to agent via unix socket (blocking write).
                    if !payload.is_empty() && self.device_fd >= 0 {
                        let mut written = 0;
                        while written < payload.len() {
                            let n = unsafe {
                                libc::write(
                                    self.device_fd,
                                    payload[written..].as_ptr() as *const libc::c_void,
                                    payload.len() - written,
                                )
                            };
                            if n <= 0 { break; }
                            written += n as usize;
                        }
                    }
                } else {
                    self.enqueue_rst_for(guest_port, host_port);
                }
            }
            OP_SHUTDOWN | OP_RST => {
                if let Some(ref conn) = self.conn {
                    if conn.guest_port == guest_port {
                        tracing::info!("vsock: guest disconnected (port {guest_port}, op={op})");
                        self.enqueue_rst_for(guest_port, host_port);
                        self.conn = None;
                    }
                }
            }
            OP_CREDIT_UPDATE => {
                if let Some(ref mut conn) = self.conn {
                    conn.peer_buf_alloc = u32::from_le(hdr.buf_alloc);
                    conn.peer_fwd_cnt = u32::from_le(hdr.fwd_cnt);
                }
            }
            OP_CREDIT_REQUEST => {
                if self.conn.is_some() {
                    self.enqueue_hdr(OP_CREDIT_UPDATE);
                }
            }
            _ => {}
        }
    }

    // --- RX processing (host → guest) ---

    fn process_rx(&mut self) {
        let qi = RX_QUEUE as usize;
        if qi >= self.queue_configs.len() { return; }

        // Read any pending data from the agent unix socket.
        self.read_agent_data();

        // Fill RX descriptors with pending packets.
        let avail_idx = self.read_avail_idx(qi);
        while self.last_avail[qi] != avail_idx && !self.pending_rx.is_empty() {
            let desc_idx = self.read_avail_ring_entry(qi, self.last_avail[qi]);
            self.last_avail[qi] = self.last_avail[qi].wrapping_add(1);

            let pkt = self.pending_rx.pop_front().unwrap();

            // Walk descriptor chain to find writable buffers and copy packet data.
            let mut remaining = &pkt[..];
            let mut idx = desc_idx;
            let mut total_written = 0u32;
            loop {
                let (addr, len, flags, next) = self.read_descriptor(qi, idx);
                if flags & VRING_DESC_F_WRITE != 0 && !remaining.is_empty() {
                    let buf = self.guest_slice_mut(addr, len as u64);
                    let n = remaining.len().min(buf.len());
                    buf[..n].copy_from_slice(&remaining[..n]);
                    remaining = &remaining[n..];
                    total_written += n as u32;
                }
                if flags & VRING_DESC_F_NEXT != 0 {
                    idx = next;
                } else {
                    break;
                }
            }

            self.write_used_entry(qi, self.last_used[qi], desc_idx, total_written);
            self.last_used[qi] = self.last_used[qi].wrapping_add(1);
            self.write_used_idx(qi, self.last_used[qi]);
        }
    }

    fn read_agent_data(&mut self) {
        if self.device_fd < 0 || self.conn.is_none() {
            return;
        }

        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::read(
                    self.device_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 { break; }

            let data = &buf[..n as usize];
            let conn = self.conn.as_ref().unwrap();

            // Check credit.
            let can_send = conn.peer_free().min(data.len() as u32) as usize;
            if can_send == 0 {
                // No credit — request more.
                self.enqueue_hdr(OP_CREDIT_REQUEST);
                break;
            }

            let send = &data[..can_send];
            let hdr = self.make_hdr(conn, OP_RW, send.len() as u32);
            let mut pkt = vec![0u8; HDR_SIZE + send.len()];
            hdr.write_to(&mut pkt);
            pkt[HDR_SIZE..].copy_from_slice(send);
            self.pending_rx.push_back(pkt);

            if let Some(ref mut conn) = self.conn {
                conn.tx_cnt = conn.tx_cnt.wrapping_add(send.len() as u32);
            }
        }
    }

    fn signal_guest(&self) {
        if let Some(ref signal) = self.irq_signal {
            signal.signal();
        }
    }

    /// Send VIRTIO_VSOCK_EVENT_TRANSPORT_RESET through the event queue.
    /// Called during snapshot creation to close guest connections.
    pub fn send_transport_reset(&mut self) {
        let qi = _EVENT_QUEUE as usize;
        if qi >= self.queue_configs.len() { return; }
        if self.guest_mem.is_null() { return; }

        let avail_idx = self.read_avail_idx(qi);
        if self.last_avail[qi] == avail_idx {
            tracing::warn!("vsock: no available event queue buffers for transport reset");
            return;
        }

        let desc_idx = self.read_avail_ring_entry(qi, self.last_avail[qi]);
        self.last_avail[qi] = self.last_avail[qi].wrapping_add(1);

        let (addr, len, flags, _next) = self.read_descriptor(qi, desc_idx);
        if flags & VRING_DESC_F_WRITE != 0 && len >= 4 {
            // Write VIRTIO_VSOCK_EVENT_TRANSPORT_RESET (id = 0).
            let buf = self.guest_slice_mut(addr, 4);
            buf[..4].copy_from_slice(&0u32.to_le_bytes());
        }

        self.write_used_entry(qi, self.last_used[qi], desc_idx, 4);
        self.last_used[qi] = self.last_used[qi].wrapping_add(1);
        self.write_used_idx(qi, self.last_used[qi]);

        // Drop any active connection.
        self.conn = None;
        self.pending_rx.clear();

        tracing::info!("vsock: transport reset event sent");
    }
}

impl VirtioDevice for VirtioVsock {
    fn device_type(&self) -> DeviceType {
        DeviceType::Vsock
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &[QUEUE_MAX_SIZE, QUEUE_MAX_SIZE, QUEUE_MAX_SIZE]
    }

    fn features(&self, page: u32) -> u32 {
        let all = VIRTIO_F_VERSION_1;
        match page {
            0 => (all & 0xFFFF_FFFF) as u32,
            1 => ((all >> 32) & 0xFFFF_FFFF) as u32,
            _ => 0,
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        match page {
            0 => self.acked_features_low = value,
            1 => self.acked_features_high = value,
            _ => {}
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config = [0u8; CONFIG_SPACE_SIZE];
        config[0..8].copy_from_slice(&self.guest_cid.to_le_bytes());
        let start = offset as usize;
        let end = start.min(config.len()) + data.len().min(config.len().saturating_sub(start));
        if start < config.len() {
            let n = end - start;
            data[..n].copy_from_slice(&config[start..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn prepare_activate(&mut self, queues: &[QueueInfo], guest_mem: *mut u8, mem_size: u64) {
        self.queue_configs = queues.to_vec();
        self.guest_mem = guest_mem;
        self.guest_mem_size = mem_size;

        // Initialize queue indices from guest memory.
        for (qi, qc) in queues.iter().enumerate() {
            if qi < NUM_QUEUES && !guest_mem.is_null() && qc.avail_addr != 0 {
                let avail_idx = unsafe {
                    *(self.gpa_to_ptr(qc.avail_addr + 2) as *const u16)
                };
                let used_idx = unsafe {
                    *(self.gpa_to_ptr(qc.used_addr + 2) as *const u16)
                };
                self.last_used[qi] = used_idx;
                if qi == TX_QUEUE as usize {
                    // TX: start from avail_idx to skip already-posted buffers.
                    self.last_avail[qi] = avail_idx;
                } else {
                    // RX + EVT: start from used_idx so we can use pre-posted buffers.
                    self.last_avail[qi] = used_idx;
                }
            }
        }
    }

    fn set_memory_hole(&mut self, hole_start: u64, hole_end: u64) {
        self.hole_start = hole_start;
        self.hole_end = hole_end;
    }

    fn activate(&mut self) -> anyhow::Result<()> {
        self.activated = true;
        tracing::info!("virtio-vsock: activated (guest_cid={}, userspace)", self.guest_cid);
        Ok(())
    }

    fn process_queue(&mut self, queue_index: u16) -> anyhow::Result<()> {
        if !self.activated || self.guest_mem.is_null() { return Ok(()); }

        match queue_index {
            TX_QUEUE => {
                self.process_tx();
                // Also process RX to deliver any responses generated by TX.
                self.process_rx();
                if !self.pending_rx.is_empty() || self.last_used[TX_QUEUE as usize] != self.last_avail[TX_QUEUE as usize] {
                    self.signal_guest();
                } else {
                    // Always signal after TX/RX processing so guest sees used buffers.
                    self.signal_guest();
                }
            }
            RX_QUEUE => {
                self.process_rx();
                if self.last_used[RX_QUEUE as usize] != self.read_avail_idx(RX_QUEUE as usize) {
                    // We consumed some RX buffers.
                    self.signal_guest();
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn transport_processes_queue(&self, _queue_index: u16) -> bool {
        false // device handles all queue processing internally
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    fn reset(&mut self) {
        self.acked_features_low = 0;
        self.acked_features_high = 0;
        self.activated = false;
        self.conn = None;
        self.pending_rx.clear();
    }

    fn snapshot_state(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "guest_cid": self.guest_cid,
            "acked_features_low": self.acked_features_low,
            "acked_features_high": self.acked_features_high,
        })).unwrap_or_default()
    }

    fn restore_state(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() { return Ok(()); }
        let state: serde_json::Value = serde_json::from_slice(data)?;
        if let Some(v) = state.get("acked_features_low").and_then(|v| v.as_u64()) {
            self.acked_features_low = v as u32;
        }
        if let Some(v) = state.get("acked_features_high").and_then(|v| v.as_u64()) {
            self.acked_features_high = v as u32;
        }
        Ok(())
    }
}

impl Drop for VirtioVsock {
    fn drop(&mut self) {
        for fd in [self.device_fd, self.host_fd, self.rx_eventfd] {
            if fd >= 0 { unsafe { libc::close(fd); } }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cid_validation() {
        assert!(VirtioVsock::new(0).is_err());
        assert!(VirtioVsock::new(1).is_err());
        assert!(VirtioVsock::new(2).is_err());
        assert!(VirtioVsock::new(3).is_ok());
    }

    #[test]
    fn test_config_space_cid() {
        let dev = VirtioVsock::new(42).unwrap();
        let mut buf = [0u8; 8];
        dev.read_config(0, &mut buf);
        assert_eq!(u64::from_le_bytes(buf), 42);
    }

    #[test]
    fn test_device_type() {
        let dev = VirtioVsock::new(3).unwrap();
        assert_eq!(dev.device_type(), DeviceType::Vsock);
    }

    #[test]
    fn test_queue_count() {
        let dev = VirtioVsock::new(3).unwrap();
        assert_eq!(dev.queue_max_sizes().len(), 3);
    }

    #[test]
    fn test_hdr_size() {
        assert_eq!(std::mem::size_of::<VsockHdr>(), HDR_SIZE);
    }

    #[test]
    fn test_take_host_fd() {
        let mut dev = VirtioVsock::new(3).unwrap();
        let fd = dev.take_host_fd();
        assert!(fd >= 0);
        assert_eq!(dev.take_host_fd(), -1); // second call returns -1
        unsafe { libc::close(fd); }
    }
}
