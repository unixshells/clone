// Virtio-net device with vhost-net kernel data path.
//
// The device handles config space, feature negotiation, and the MMIO
// register interface. On activation, it sets up /dev/vhost-net so the
// kernel handles the actual packet I/O directly between TAP and guest
// memory — no VMM involvement on the data path.
//
// Falls back to userspace TX/RX processing when vhost-net is unavailable
// (non-Linux, tests with fd=-1).

use std::os::unix::io::RawFd;

use super::queue::{DescriptorChain, Virtqueue, VRING_DESC_F_WRITE, VRING_DESC_F_NEXT};
use super::{DeviceType, QueueInfo, VirtioDevice};

// --- Feature bits (virtio spec 5.1.3) ---

/// Device has a given MAC address.
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// Device reports link status in config space.
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
/// Virtio 1.0+ requirement.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// --- Config space layout (virtio spec 5.1.4) ---
// Bytes 0-5:   mac[6]
// Bytes 6-7:   status (u16, le)

const CONFIG_SPACE_SIZE: u64 = 8;

/// Link status bit: link is up.
const VIRTIO_NET_S_LINK_UP: u16 = 1;

// Queue indices.
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

/// Maximum queue size for net device virtqueues.
const QUEUE_MAX_SIZE: u16 = 256;

/// Size of the virtio_net_hdr_v1 (used with VIRTIO_F_VERSION_1).
const VIRTIO_NET_HDR_SIZE: usize = 12;

// --- vhost ioctl numbers (Linux) ---
#[cfg(target_os = "linux")]
mod vhost {
    pub const SET_OWNER: libc::c_ulong = 0xAF01;
    pub const GET_FEATURES: libc::c_ulong = 0x8008_AF00;
    pub const SET_FEATURES: libc::c_ulong = 0x4008_AF00;
    pub const SET_MEM_TABLE: libc::c_ulong = 0x4008_AF03;
    pub const SET_VRING_NUM: libc::c_ulong = 0x4008_AF10;
    pub const SET_VRING_ADDR: libc::c_ulong = 0x4028_AF11;
    pub const SET_VRING_BASE: libc::c_ulong = 0x4008_AF12;
    pub const SET_VRING_KICK: libc::c_ulong = 0x4008_AF20;
    pub const SET_VRING_CALL: libc::c_ulong = 0x4008_AF21;
    pub const NET_SET_BACKEND: libc::c_ulong = 0x4008_AF30;

    #[repr(C)]
    pub struct VringState {
        pub index: u32,
        pub num: u32,
    }

    #[repr(C)]
    pub struct VringAddr {
        pub index: u32,
        pub flags: u32,
        pub desc_user_addr: u64,
        pub used_user_addr: u64,
        pub avail_user_addr: u64,
        pub log_guest_addr: u64,
    }

    #[repr(C)]
    pub struct VringFile {
        pub index: u32,
        pub fd: i32,
    }

    #[repr(C)]
    pub struct MemoryRegion {
        pub guest_phys_addr: u64,
        pub memory_size: u64,
        pub userspace_addr: u64,
        pub flags_padding: u64,
    }

    #[repr(C)]
    pub struct Memory {
        pub nregions: u32,
        pub padding: u32,
        pub regions: [MemoryRegion; 1],
    }

    #[repr(C)]
    pub struct Memory2 {
        pub nregions: u32,
        pub padding: u32,
        pub regions: [MemoryRegion; 2],
    }
}

/// A virtio-net device backed by a TAP file descriptor.
///
/// When `vm_fd >= 0` (Linux with KVM), activation sets up vhost-net
/// for kernel-level data path bypass. Otherwise falls back to
/// userspace descriptor chain processing.
pub struct VirtioNet {
    /// TAP device file descriptor (owned, will be closed on drop).
    tap_fd: RawFd,

    /// MAC address (6 bytes).
    mac: [u8; 6],

    /// Link status.
    link_up: bool,

    /// Acknowledged feature bits (low 32 bits).
    acked_features_low: u32,
    /// Acknowledged feature bits (high 32 bits).
    acked_features_high: u32,

    /// Whether the device has been activated.
    activated: bool,

    // --- vhost-net state ---

    /// KVM VM file descriptor (raw, borrowed — not owned).
    vm_fd: RawFd,
    /// IRQ number assigned by the MMIO bus.
    irq: u32,
    /// /dev/vhost-net file descriptor (owned).
    vhost_fd: RawFd,
    /// Kick eventfds (VMM → vhost kernel), one per queue.
    kick_fds: [RawFd; 2],
    /// Call eventfds (vhost kernel → KVM IRQ), one per queue.
    call_fds: [RawFd; 2],

    // --- Queue config from transport (set in prepare_activate) ---
    queue_configs: Vec<QueueInfo>,
    guest_mem: *mut u8,
    guest_mem_size: u64,
    /// GPA of the start of the mapped region (0 on x86, RAM_BASE on arm64).
    mem_base: u64,
    hole_start: u64,
    hole_end: u64,
}

// SAFETY: The raw pointers are managed exclusively by the VMM.
unsafe impl Send for VirtioNet {}

impl VirtioNet {
    fn gpa_to_hva(&self, gpa: u64) -> u64 {
        let base = self.guest_mem as u64;
        let gpa = match gpa.checked_sub(self.mem_base) {
            Some(g) => g,
            None => return base,
        };
        if self.hole_start == 0 || gpa < self.hole_start {
            base + gpa
        } else if gpa >= self.hole_end {
            base + self.hole_start + (gpa - self.hole_end)
        } else {
            base + gpa
        }
    }
    /// Create a new virtio-net device with the given TAP fd and MAC address.
    ///
    /// Call `set_vm_info()` before registration to enable vhost-net.
    pub fn new(tap_fd: RawFd, mac: [u8; 6]) -> Self {
        Self {
            tap_fd,
            mac,
            link_up: true,
            acked_features_low: 0,
            acked_features_high: 0,
            activated: false,
            vm_fd: -1,
            irq: 0,
            vhost_fd: -1,
            kick_fds: [-1; 2],
            call_fds: [-1; 2],
            queue_configs: Vec::new(),
            guest_mem: std::ptr::null_mut(),
            guest_mem_size: 0,
            mem_base: 0,
            hole_start: 0,
            hole_end: 0,
        }
    }

    /// Set the KVM VM fd and IRQ for vhost-net setup.
    /// Must be called before the device is moved into the MMIO bus.
    /// Pre-creates call eventfds so the VMM can set up the monitoring thread.
    pub fn set_vm_info(&mut self, vm_fd: RawFd, irq: u32) {
        self.vm_fd = vm_fd;
        self.irq = irq;
        // Pre-create call eventfds — the VMM reads these via call_fds()
        // to set up the interrupt monitoring thread before the device activates.
        #[cfg(target_os = "linux")]
        {
            self.call_fds[0] = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
            self.call_fds[1] = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        }
    }

    /// Returns the call eventfds (vhost → VMM notification).
    /// The VMM polls these and injects IRQs when signaled.
    pub fn call_fds(&self) -> [RawFd; 2] {
        self.call_fds
    }

    /// Returns the TAP file descriptor.
    pub fn tap_fd(&self) -> RawFd {
        self.tap_fd
    }

    /// Replace TAP fd and disable vhost. Used after fork to swap the template's
    /// stale TAP for a fresh one and switch to userspace net processing.
    pub fn set_tap_fd(&mut self, fd: RawFd) {
        if self.vhost_fd >= 0 {
            unsafe { libc::close(self.vhost_fd); }
            self.vhost_fd = -1;
        }
        for &kfd in &self.kick_fds {
            if kfd >= 0 { unsafe { libc::close(kfd); } }
        }
        for &cfd in &self.call_fds {
            if cfd >= 0 { unsafe { libc::close(cfd); } }
        }
        self.kick_fds = [-1; 2];
        self.call_fds = [-1; 2];
        self.tap_fd = fd;
    }

    /// Returns the MAC address.
    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    /// Update the MAC address (used after fork to assign a unique MAC).
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }

    /// Whether vhost-net is active (kernel handles data path).
    pub fn is_vhost(&self) -> bool {
        self.vhost_fd >= 0
    }

    /// Set up vhost-net kernel data path.
    ///
    /// Opens /dev/vhost-net, configures memory table and virtqueues,
    /// creates eventfds for kick/call, and registers call eventfds
    /// with KVM_IRQFD for automatic interrupt injection.
    #[cfg(target_os = "linux")]
    fn setup_vhost_net(&mut self) -> anyhow::Result<()> {
        use std::ffi::CString;

        // 1. Open /dev/vhost-net
        let path = CString::new("/dev/vhost-net").unwrap();
        let vhost_fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if vhost_fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to open /dev/vhost-net: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.vhost_fd = vhost_fd;

        // 2. VHOST_SET_OWNER
        let ret = unsafe { crate::sys::ioctl(vhost_fd, vhost::SET_OWNER as u64, std::ptr::null_mut()) };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "VHOST_SET_OWNER failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // 3. VHOST_GET_FEATURES then SET intersection with driver-negotiated features
        let mut vhost_features: u64 = 0;
        if unsafe {
            crate::sys::ioctl(vhost_fd, vhost::GET_FEATURES as u64, &mut vhost_features as *mut u64 as *const _ as *mut libc::c_void)
        } < 0
        {
            return Err(anyhow::anyhow!(
                "VHOST_GET_FEATURES failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let driver_features: u64 =
            (self.acked_features_low as u64) | ((self.acked_features_high as u64) << 32);
        // VHOST_NET_F_VIRTIO_NET_HDR (bit 27) is a vhost-specific feature
        // (not guest-visible) that tells vhost-net to prepend/strip the
        // virtio_net_hdr in RX/TX buffers. Always request it if supported.
        const VHOST_NET_F_VIRTIO_NET_HDR: u64 = 1 << 27;
        let features =
            (driver_features & vhost_features) | (vhost_features & VHOST_NET_F_VIRTIO_NET_HDR);
        tracing::info!(
            "vhost-net: features vhost={:#x} driver={:#x} negotiated={:#x}",
            vhost_features,
            driver_features,
            features
        );

        if unsafe { crate::sys::ioctl(vhost_fd, vhost::SET_FEATURES as u64, &features as *const u64 as *const _ as *mut libc::c_void) } < 0 {
            return Err(anyhow::anyhow!(
                "VHOST_SET_FEATURES failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // 4. VHOST_SET_MEM_TABLE — guest memory regions
        let ret = if self.hole_start > 0 {
            let above_hole_size = self.guest_mem_size - self.hole_start;
            let mem_table = vhost::Memory2 {
                nregions: 2,
                padding: 0,
                regions: [
                    vhost::MemoryRegion {
                        guest_phys_addr: 0,
                        memory_size: self.hole_start,
                        userspace_addr: self.guest_mem as u64,
                        flags_padding: 0,
                    },
                    vhost::MemoryRegion {
                        guest_phys_addr: self.hole_end,
                        memory_size: above_hole_size,
                        userspace_addr: (self.guest_mem as u64) + self.hole_start,
                        flags_padding: 0,
                    },
                ],
            };
            unsafe { crate::sys::ioctl(vhost_fd, vhost::SET_MEM_TABLE as u64, &mem_table as *const vhost::Memory2 as *const _ as *mut libc::c_void) }
        } else {
            let mem_table = vhost::Memory {
                nregions: 1,
                padding: 0,
                regions: [vhost::MemoryRegion {
                    guest_phys_addr: 0,
                    memory_size: self.guest_mem_size,
                    userspace_addr: self.guest_mem as u64,
                    flags_padding: 0,
                }],
            };
            unsafe { crate::sys::ioctl(vhost_fd, vhost::SET_MEM_TABLE as u64, &mem_table as *const vhost::Memory as *const _ as *mut libc::c_void) }
        };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "VHOST_SET_MEM_TABLE failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // 5. Set up each queue (RX=0, TX=1)
        let guest_mem_base = self.guest_mem as u64;

        for qi in 0..2u32 {
            let qc = &self.queue_configs[qi as usize];

            // Create kick eventfd (VMM signals vhost when guest kicks queue)
            let kick_fd =
                unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if kick_fd < 0 {
                return Err(anyhow::anyhow!(
                    "eventfd(kick) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            self.kick_fds[qi as usize] = kick_fd;

            // Use pre-created call eventfd (created in set_vm_info)
            let call_fd = self.call_fds[qi as usize];

            // VHOST_SET_VRING_NUM
            let state = vhost::VringState {
                index: qi,
                num: qc.size as u32,
            };
            if unsafe { crate::sys::ioctl(vhost_fd, vhost::SET_VRING_NUM as u64, &state as *const _ as *mut libc::c_void) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_VRING_NUM(q={qi}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // VHOST_SET_VRING_ADDR — convert GPAs to host virtual addresses
            let addr = vhost::VringAddr {
                index: qi,
                flags: 0,
                desc_user_addr: self.gpa_to_hva(qc.desc_addr),
                used_user_addr: self.gpa_to_hva(qc.used_addr),
                avail_user_addr: self.gpa_to_hva(qc.avail_addr),
                log_guest_addr: 0,
            };
            if unsafe { crate::sys::ioctl(vhost_fd, vhost::SET_VRING_ADDR as u64, &addr as *const _ as *mut libc::c_void) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_VRING_ADDR(q={qi}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // VHOST_SET_VRING_BASE — read current avail_idx from guest memory
            // so the backend doesn't reprocess old descriptors after fork.
            let avail_idx = if !self.guest_mem.is_null() && qc.avail_addr != 0 {
                unsafe {
                    let hva = self.gpa_to_hva(qc.avail_addr + 2);
                    *(hva as *const u16) as u32
                }
            } else {
                0
            };
            let base = vhost::VringState {
                index: qi,
                num: avail_idx,
            };
            if unsafe { crate::sys::ioctl(vhost_fd, vhost::SET_VRING_BASE as u64, &base as *const _ as *mut libc::c_void) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_VRING_BASE(q={qi}, avail_idx={avail_idx}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // VHOST_SET_VRING_KICK
            let kick = vhost::VringFile {
                index: qi,
                fd: kick_fd,
            };
            if unsafe { crate::sys::ioctl(vhost_fd, vhost::SET_VRING_KICK as u64, &kick as *const _ as *mut libc::c_void) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_VRING_KICK(q={qi}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // VHOST_SET_VRING_CALL
            let call = vhost::VringFile {
                index: qi,
                fd: call_fd,
            };
            if unsafe { crate::sys::ioctl(vhost_fd, vhost::SET_VRING_CALL as u64, &call as *const _ as *mut libc::c_void) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_VRING_CALL(q={qi}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // VHOST_NET_SET_BACKEND — connect this queue to the TAP fd
            let backend = vhost::VringFile {
                index: qi,
                fd: self.tap_fd,
            };
            if unsafe { crate::sys::ioctl(vhost_fd, vhost::NET_SET_BACKEND as u64, &backend as *const _ as *mut libc::c_void) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_NET_SET_BACKEND(q={qi}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // Note: IRQ injection is handled by the VMM's call eventfd
            // monitoring thread, which polls call_fds, sets interrupt_status
            // on the MMIO transport, and injects IRQ via set_irq_line().
        }

        tracing::info!(
            "vhost-net: configured (tap_fd={}, vhost_fd={}, irq={})",
            self.tap_fd,
            self.vhost_fd,
            self.irq
        );

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn setup_vhost_net(&mut self) -> anyhow::Result<()> {
        tracing::warn!("vhost-net not available on this platform");
        Ok(())
    }

    /// Signal the kick eventfd for the given queue.
    fn kick_queue(&self, queue_index: u16) {
        let qi = queue_index as usize;
        if qi < 2 && self.kick_fds[qi] >= 0 {
            let val: u64 = 1;
            unsafe {
                libc::write(
                    self.kick_fds[qi],
                    &val as *const u64 as *const libc::c_void,
                    8,
                );
            }
        }
    }

    /// GPA → host pointer, accounting for MMIO hole.
    fn gpa_to_ptr(&self, gpa: u64) -> *mut u8 {
        // gpa is relative to mem_base (0 on x86, RAM_BASE on arm64).
        let gpa = match gpa.checked_sub(self.mem_base) {
            Some(g) => g,
            None => return std::ptr::null_mut(),
        };
        let offset = if self.hole_start > 0 && gpa >= self.hole_end {
            self.hole_start + (gpa - self.hole_end)
        } else {
            gpa
        };
        unsafe { self.guest_mem.add(offset as usize) }
    }

    /// Read an available RX descriptor index from the avail ring.
    fn rx_pop_avail(&self) -> Option<(u16, u16)> {
        if self.guest_mem.is_null() || self.queue_configs.is_empty() { return None; }
        let qc = &self.queue_configs[RX_QUEUE as usize];
        if qc.avail_addr == 0 { return None; }
        let avail_idx: u16 = unsafe { *(self.gpa_to_ptr(qc.avail_addr + 2) as *const u16) };
        let last = unsafe { *(self.gpa_to_ptr(qc.used_addr + 2) as *const u16) }; // used_idx = our "last consumed"
        // Use a simple approach: use used_idx as our last_avail tracker
        // (we always consume and immediately push to used)
        if avail_idx == last { return None; }
        let ring_idx = (last % qc.size) as u64;
        let desc_idx: u16 = unsafe { *(self.gpa_to_ptr(qc.avail_addr + 4 + ring_idx * 2) as *const u16) };
        Some((desc_idx, last))
    }

    /// Push an entry to the RX used ring and advance used_idx.
    fn rx_push_used(&self, desc_idx: u16, used_idx: u16, len: u32) {
        let qc = &self.queue_configs[RX_QUEUE as usize];
        let ring_idx = (used_idx % qc.size) as u64;
        let entry_ptr = self.gpa_to_ptr(qc.used_addr + 4 + ring_idx * 8);
        unsafe {
            *(entry_ptr as *mut u32) = desc_idx as u32;
            *(entry_ptr.add(4) as *mut u32) = len;
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        unsafe {
            *(self.gpa_to_ptr(qc.used_addr + 2) as *mut u16) = used_idx.wrapping_add(1);
        }
    }

    /// Read a descriptor from the RX descriptor table.
    fn rx_read_desc(&self, idx: u16) -> (u64, u32, u16, u16) {
        let qc = &self.queue_configs[RX_QUEUE as usize];
        let ptr = self.gpa_to_ptr(qc.desc_addr + idx as u64 * 16);
        unsafe {
            (*(ptr as *const u64), *(ptr.add(8) as *const u32),
             *(ptr.add(12) as *const u16), *(ptr.add(14) as *const u16))
        }
    }

    /// Process one incoming TAP packet: read from TAP, write to RX virtqueue.
    /// Returns true if a packet was delivered.
    pub fn process_rx_from_tap(&mut self) -> bool {
        let Some((desc_idx, used_idx)) = self.rx_pop_avail() else { return false };

        // Read packet from TAP (non-blocking)
        let mut buf = [0u8; 65535];
        let n = unsafe {
            libc::read(self.tap_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if n <= 0 { return false; }
        let frame = &buf[..n as usize];

        // Build virtio-net header (12 bytes of zeros for basic operation)
        let hdr = [0u8; VIRTIO_NET_HDR_SIZE];
        let total = hdr.len() + frame.len();

        // Walk descriptor chain, write header + frame into writable buffers
        let mut remaining_hdr = &hdr[..];
        let mut remaining_frame = frame;
        let mut idx = desc_idx;
        let mut written = 0u32;
        loop {
            let (addr, len, flags, next) = self.rx_read_desc(idx);
            if flags & VRING_DESC_F_WRITE != 0 {
                let buf = unsafe {
                    std::slice::from_raw_parts_mut(self.gpa_to_ptr(addr), len as usize)
                };
                let mut pos = 0;
                // Write header first
                if !remaining_hdr.is_empty() {
                    let n = remaining_hdr.len().min(buf.len());
                    buf[..n].copy_from_slice(&remaining_hdr[..n]);
                    remaining_hdr = &remaining_hdr[n..];
                    pos += n;
                }
                // Then frame data
                if pos < buf.len() && !remaining_frame.is_empty() {
                    let n = remaining_frame.len().min(buf.len() - pos);
                    buf[pos..pos + n].copy_from_slice(&remaining_frame[..n]);
                    remaining_frame = &remaining_frame[n..];
                    pos += n;
                }
                written += pos as u32;
            }
            if flags & VRING_DESC_F_NEXT != 0 {
                idx = next;
            } else {
                break;
            }
        }

        self.rx_push_used(desc_idx, used_idx, written);
        written > 0
    }

    /// Write a raw frame to the TAP fd (userspace fallback path).
    fn write_tap(&self, frame: &[u8]) -> anyhow::Result<usize> {
        let n = unsafe {
            libc::write(
                self.tap_fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
            )
        };
        if n < 0 {
            return Err(anyhow::anyhow!(
                "TAP write failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(n as usize)
    }

    /// Process a single TX descriptor chain (userspace fallback path).
    fn process_tx_chain(&mut self, chain: &DescriptorChain, vq: &Virtqueue) -> u32 {
        if chain.descriptors.is_empty() {
            return 0;
        }

        let mut frame = Vec::with_capacity(1514);
        let mut total_read = 0usize;

        for desc in &chain.descriptors {
            if desc.flags & VRING_DESC_F_WRITE != 0 {
                continue;
            }
            if let Some(data) = vq.read_descriptor_data(desc) {
                if total_read < VIRTIO_NET_HDR_SIZE {
                    let skip = VIRTIO_NET_HDR_SIZE - total_read;
                    if data.len() > skip {
                        frame.extend_from_slice(&data[skip..]);
                    }
                } else {
                    frame.extend_from_slice(data);
                }
                total_read += data.len();
            }
        }

        if !frame.is_empty() {
            if let Err(e) = self.write_tap(&frame) {
                tracing::warn!("virtio-net: TAP write failed: {e}");
            }
        }

        0
    }
}

impl VirtioDevice for VirtioNet {
    fn device_type(&self) -> DeviceType {
        DeviceType::Net
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &[QUEUE_MAX_SIZE, QUEUE_MAX_SIZE]
    }

    fn features(&self, page: u32) -> u32 {
        let all_features = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_F_VERSION_1;
        match page {
            0 => (all_features & 0xFFFF_FFFF) as u32,
            1 => ((all_features >> 32) & 0xFFFF_FFFF) as u32,
            _ => 0,
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        match page {
            0 => self.acked_features_low = value,
            1 => self.acked_features_high = value,
            _ => tracing::warn!("virtio-net: ack_features for unknown page {page}"),
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config = [0u8; CONFIG_SPACE_SIZE as usize];
        config[0..6].copy_from_slice(&self.mac);
        let status: u16 = if self.link_up { VIRTIO_NET_S_LINK_UP } else { 0 };
        config[6..8].copy_from_slice(&status.to_le_bytes());

        let end = std::cmp::min(offset as usize + data.len(), config.len());
        if (offset as usize) < end {
            let len = end - offset as usize;
            data[..len].copy_from_slice(&config[offset as usize..end]);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        tracing::debug!(
            "virtio-net: write_config offset={offset} len={} (ignored)",
            data.len()
        );
    }

    fn prepare_activate(&mut self, queues: &[QueueInfo], guest_mem: *mut u8, mem_size: u64) {
        self.queue_configs = queues.to_vec();
        self.guest_mem = guest_mem;
        self.guest_mem_size = mem_size;

        // Fix notification suppression for userspace net (non-vhost).
        // vhost-net negotiates VIRTIO_RING_F_EVENT_IDX and sets used_event
        // in the avail ring to suppress guest kicks. After fork without vhost,
        // we need the guest to kick via MMIO QUEUE_NOTIFY, so:
        // 1. Clear used ring flags (VRING_USED_F_NO_NOTIFY)
        // 2. Set avail_event in used ring to match avail_idx (always notify)
        if !self.is_vhost() && !guest_mem.is_null() {
            for qc in queues {
                if qc.used_addr == 0 || qc.avail_addr == 0 { continue; }
                // Clear used ring flags
                unsafe { *(self.gpa_to_ptr(qc.used_addr) as *mut u16) = 0; }
                // Read current used_idx and avail_idx
                let used_idx: u16 = unsafe { *(self.gpa_to_ptr(qc.used_addr + 2) as *const u16) };
                let avail_idx: u16 = unsafe { *(self.gpa_to_ptr(qc.avail_addr + 2) as *const u16) };
                // Set used_event (in avail ring, after the ring entries) to used_idx
                // so guest thinks we've consumed everything and MUST notify on next
                // avail ring layout: flags(2) + idx(2) + ring[size](2 each) + used_event(2)
                let used_event_offset = qc.avail_addr + 4 + qc.size as u64 * 2;
                unsafe { *(self.gpa_to_ptr(used_event_offset) as *mut u16) = used_idx; }
                // Set avail_event (in used ring, after the ring entries) to avail_idx
                // used ring layout: flags(2) + idx(2) + ring[size](8 each) + avail_event(2)
                let avail_event_offset = qc.used_addr + 4 + qc.size as u64 * 8;
                unsafe { *(self.gpa_to_ptr(avail_event_offset) as *mut u16) = avail_idx; }
            }
        }
    }

    fn set_memory_hole(&mut self, hole_start: u64, hole_end: u64) {
        self.hole_start = hole_start;
        self.hole_end = hole_end;
    }

    fn set_mem_base(&mut self, mem_base: u64) {
        self.mem_base = mem_base;
    }

    fn activate(&mut self) -> anyhow::Result<()> {
        self.activated = true;

        // Set up vhost-net if KVM VM fd is available
        if self.vm_fd >= 0 {
            self.setup_vhost_net()?;
        }

        tracing::info!(
            "virtio-net: activated (MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, vhost={})",
            self.mac[0],
            self.mac[1],
            self.mac[2],
            self.mac[3],
            self.mac[4],
            self.mac[5],
            self.is_vhost()
        );
        Ok(())
    }

    fn process_queue(&mut self, queue_index: u16) -> anyhow::Result<()> {
        if self.is_vhost() {
            // vhost-net: signal the kick eventfd so the kernel processes the queue
            self.kick_queue(queue_index);
            return Ok(());
        }
        // Userspace fallback
        match queue_index {
            RX_QUEUE => {
                tracing::trace!("virtio-net: rx queue kicked (buffers posted)");
            }
            TX_QUEUE => {
                tracing::trace!("virtio-net: tx queue kicked");
            }
            _ => {
                tracing::warn!("virtio-net: unknown queue index {queue_index}");
            }
        }
        Ok(())
    }

    fn transport_processes_queue(&self, queue_index: u16) -> bool {
        if self.is_vhost() {
            // vhost-net handles both RX and TX in kernel
            false
        } else {
            // Userspace: RX managed externally, TX processed by transport
            queue_index != RX_QUEUE
        }
    }

    fn process_descriptor_chain(
        &mut self,
        queue_index: u16,
        chain: &DescriptorChain,
        vq: &Virtqueue,
    ) -> u32 {
        match queue_index {
            TX_QUEUE => self.process_tx_chain(chain, vq),
            _ => 0,
        }
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    fn reset(&mut self) {
        self.acked_features_low = 0;
        self.acked_features_high = 0;
        self.activated = false;
        tracing::info!("virtio-net: reset");
    }

    fn snapshot_state(&self) -> Vec<u8> {
        let state = serde_json::json!({
            "mac": self.mac.to_vec(),
            "link_up": self.link_up,
            "acked_features_low": self.acked_features_low,
            "acked_features_high": self.acked_features_high,
        });
        serde_json::to_vec(&state).unwrap_or_default()
    }

    fn restore_state(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() { return Ok(()); }
        let state: serde_json::Value = serde_json::from_slice(data)?;
        if let Some(v) = state.get("link_up").and_then(|v| v.as_bool()) {
            self.link_up = v;
        }
        if let Some(v) = state.get("acked_features_low").and_then(|v| v.as_u64()) {
            self.acked_features_low = v as u32;
        }
        if let Some(v) = state.get("acked_features_high").and_then(|v| v.as_u64()) {
            self.acked_features_high = v as u32;
        }
        Ok(())
    }
}

impl Drop for VirtioNet {
    fn drop(&mut self) {
        // Close vhost-net fd
        if self.vhost_fd >= 0 {
            unsafe {
                libc::close(self.vhost_fd);
            }
        }
        // Close eventfds
        for &fd in self.kick_fds.iter().chain(self.call_fds.iter()) {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
        // Close TAP fd
        if self.tap_fd >= 0 {
            unsafe {
                libc::close(self.tap_fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_space_mac() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let dev = VirtioNet::new(-1, mac); // fd=-1 for testing only

        let mut buf = [0u8; 6];
        dev.read_config(0, &mut buf);
        assert_eq!(buf, mac);
    }

    #[test]
    fn test_config_space_status_link_up() {
        let dev = VirtioNet::new(-1, [0; 6]);
        let mut buf = [0u8; 2];
        dev.read_config(6, &mut buf);
        let status = u16::from_le_bytes(buf);
        assert_eq!(status, VIRTIO_NET_S_LINK_UP);
    }

    #[test]
    fn test_features() {
        let dev = VirtioNet::new(-1, [0; 6]);
        let low = dev.features(0);
        assert!(low & (1 << 5) != 0, "VIRTIO_NET_F_MAC should be set");
        assert!(low & (1 << 16) != 0, "VIRTIO_NET_F_STATUS should be set");
        let high = dev.features(1);
        assert!(high & 1 != 0, "VIRTIO_F_VERSION_1 should be set (bit 32)");
    }

    #[test]
    fn test_device_type() {
        let dev = VirtioNet::new(-1, [0; 6]);
        assert_eq!(dev.device_type(), DeviceType::Net);
    }

    #[test]
    fn test_queue_count() {
        let dev = VirtioNet::new(-1, [0; 6]);
        assert_eq!(dev.queue_max_sizes().len(), 2);
    }

    #[test]
    fn test_no_vhost_without_vm_info() {
        let dev = VirtioNet::new(-1, [0; 6]);
        assert!(!dev.is_vhost());
    }

    #[test]
    fn test_transport_processes_queue_userspace() {
        let dev = VirtioNet::new(-1, [0; 6]);
        // Userspace mode: transport should NOT process RX (external), but SHOULD process TX
        assert!(!dev.transport_processes_queue(RX_QUEUE));
        assert!(dev.transport_processes_queue(TX_QUEUE));
    }
}
