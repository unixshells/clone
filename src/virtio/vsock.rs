// Virtio-vsock device for host-guest communication.
//
// Used by the guest agent to report:
// - Activity state (active/idle)
// - Memory pressure (PSI metrics)
// - Process count and load average
//
// VMM sends back:
// - Balloon commands (inflate/deflate)
// - VM identity data on first boot
// - Shutdown/reboot signals
//
// Data path uses /dev/vhost-vsock on Linux for kernel-level
// packet routing between host and guest.

use std::os::unix::io::RawFd;

use super::{DeviceType, QueueInfo, VirtioDevice};

// --- Feature bits ---

/// Virtio 1.0+ requirement.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// --- Config space layout (virtio spec 5.10.4) ---
// Bytes 0-7: guest_cid (u64, le)
const CONFIG_SPACE_SIZE: usize = 8;

// Queue indices.
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
const EVENT_QUEUE: u16 = 2;
const NUM_QUEUES: usize = 3;

/// Maximum queue size for vsock virtqueues.
const QUEUE_MAX_SIZE: u16 = 128;

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
    pub const VSOCK_SET_GUEST_CID: libc::c_ulong = 0x4008_AF60;
    pub const VSOCK_SET_RUNNING: libc::c_ulong = 0x4004_AF61;

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

    /// Memory table with 2 regions (for split memory around MMIO hole).
    #[repr(C)]
    pub struct Memory2 {
        pub nregions: u32,
        pub padding: u32,
        pub regions: [MemoryRegion; 2],
    }
}

/// A virtio-vsock device.
///
/// Provides socket-based communication between host and guest.
/// On Linux, the data path is handled by /dev/vhost-vsock for
/// kernel-level packet routing.
pub struct VirtioVsock {
    /// Guest CID (Context Identifier). Must be >= 3.
    guest_cid: u64,

    /// vhost-vsock file descriptor (Linux only, owned).
    vhost_fd: RawFd,

    /// Acknowledged feature bits.
    acked_features_low: u32,
    acked_features_high: u32,

    /// Whether the device has been activated.
    activated: bool,

    /// Kick eventfds (VMM → vhost kernel), one per queue.
    kick_fds: [RawFd; NUM_QUEUES],
    /// Call eventfds (vhost kernel → VMM), one per queue.
    call_fds: [RawFd; NUM_QUEUES],

    /// Queue config from transport (set in prepare_activate).
    queue_configs: Vec<QueueInfo>,
    guest_mem: *mut u8,
    guest_mem_size: u64,
    hole_start: u64,
    hole_end: u64,

    /// KVM VM fd for irqfd/ioeventfd registration.
    vm_fd: RawFd,
    /// IRQ number for this device.
    irq: u32,
    /// MMIO base address for this device.
    mmio_base: u64,
}

// SAFETY: The raw pointer is managed exclusively by the VMM.
unsafe impl Send for VirtioVsock {}

impl VirtioVsock {
    /// Translate GPA to host virtual address, accounting for MMIO hole.
    fn gpa_to_hva(&self, gpa: u64) -> u64 {
        let base = self.guest_mem as u64;
        if self.hole_start == 0 || gpa < self.hole_start {
            base + gpa
        } else if gpa >= self.hole_end {
            base + self.hole_start + (gpa - self.hole_end)
        } else {
            base + gpa
        }
    }

    /// Create a new virtio-vsock device with the given guest CID.
    ///
    /// On Linux, opens /dev/vhost-vsock and claims the CID.
    pub fn new(guest_cid: u64) -> anyhow::Result<Self> {
        if guest_cid < 3 {
            anyhow::bail!("vsock guest CID must be >= 3, got {guest_cid}");
        }

        let vhost_fd = Self::open_vhost_vsock(guest_cid)?;

        // Pre-create call eventfds for RX (queue 0) and TX (queue 1).
        // These MUST exist before device activation so the VMM poll thread
        // (started in Vm::run()) has valid fds to monitor. If we create them
        // lazily in setup_vhost(), boot() reads [-1, -1] and the poll thread
        // never fires, breaking interrupt delivery for the RX path.
        #[cfg(target_os = "linux")]
        let (call_fd_rx, call_fd_tx) = {
            let rx = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            let tx = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if rx < 0 || tx < 0 {
                if rx >= 0 { unsafe { libc::close(rx); } }
                if tx >= 0 { unsafe { libc::close(tx); } }
                anyhow::bail!("Failed to create vsock call eventfds: {}", std::io::Error::last_os_error());
            }
            (rx, tx)
        };
        #[cfg(not(target_os = "linux"))]
        let (call_fd_rx, call_fd_tx) = (-1, -1);

        Ok(Self {
            guest_cid,
            vhost_fd,
            acked_features_low: 0,
            acked_features_high: 0,
            activated: false,
            kick_fds: [-1; NUM_QUEUES],
            call_fds: [call_fd_rx, call_fd_tx, -1],
            queue_configs: Vec::new(),
            guest_mem: std::ptr::null_mut(),
            guest_mem_size: 0,
            hole_start: 0,
            hole_end: 0,
            vm_fd: -1,
            irq: 0,
            mmio_base: 0,
        })
    }

    /// Open /dev/vhost-vsock and claim the guest CID.
    #[cfg(target_os = "linux")]
    fn open_vhost_vsock(guest_cid: u64) -> anyhow::Result<RawFd> {
        use std::ffi::CString;

        let path = CString::new("/dev/vhost-vsock").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to open /dev/vhost-vsock: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Claim the guest CID
        let cid: u64 = guest_cid;
        let ret =
            unsafe { libc::ioctl(fd, vhost::VSOCK_SET_GUEST_CID, &cid as *const u64) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow::anyhow!(
                "VHOST_VSOCK_SET_GUEST_CID failed: {err}"
            ));
        }

        tracing::info!("vhost-vsock: opened fd={fd}, guest_cid={guest_cid}");
        Ok(fd)
    }

    /// Stub for non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    fn open_vhost_vsock(guest_cid: u64) -> anyhow::Result<RawFd> {
        tracing::warn!(
            "vhost-vsock not available on this platform (guest_cid={guest_cid}), using stub"
        );
        Ok(-1)
    }

    /// Get the guest CID.
    pub fn guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Get the vhost fd.
    pub fn vhost_fd(&self) -> RawFd {
        self.vhost_fd
    }

    /// Get the call eventfds (vhost → VMM notification).
    /// These should be registered with KVM_IRQFD for automatic IRQ injection.
    pub fn call_fds(&self) -> &[RawFd; NUM_QUEUES] {
        &self.call_fds
    }

    /// Set KVM VM info for irqfd/ioeventfd registration.
    pub fn set_vm_info(&mut self, vm_fd: RawFd, irq: u32, mmio_base: u64) {
        self.vm_fd = vm_fd;
        self.irq = irq;
        self.mmio_base = mmio_base;
    }

    /// Set up the vhost backend (SET_OWNER, SET_MEM_TABLE, SET_VRING_*).
    #[cfg(target_os = "linux")]
    fn setup_vhost(&mut self) -> anyhow::Result<()> {
        let fd = self.vhost_fd;
        if fd < 0 {
            return Ok(());
        }

        // VHOST_SET_OWNER
        if unsafe { libc::ioctl(fd, vhost::SET_OWNER) } < 0 {
            return Err(anyhow::anyhow!(
                "VHOST_SET_OWNER failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // VHOST_GET_FEATURES → SET_FEATURES (intersect with driver)
        let mut vhost_features: u64 = 0;
        if unsafe { libc::ioctl(fd, vhost::GET_FEATURES, &mut vhost_features as *mut u64) }
            < 0
        {
            return Err(anyhow::anyhow!(
                "VHOST_GET_FEATURES failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let driver_features: u64 =
            (self.acked_features_low as u64) | ((self.acked_features_high as u64) << 32);
        let features = driver_features & vhost_features;
        tracing::info!(
            "vhost-vsock: features vhost={:#x} driver={:#x} negotiated={:#x}",
            vhost_features,
            driver_features,
            features
        );
        if unsafe { libc::ioctl(fd, vhost::SET_FEATURES, &features as *const u64) } < 0 {
            return Err(anyhow::anyhow!(
                "VHOST_SET_FEATURES failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // VHOST_SET_MEM_TABLE — describe guest memory regions to vhost kernel
        if self.hole_start > 0 {
            // Large VM: two regions around the MMIO hole
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
            if unsafe { libc::ioctl(fd, vhost::SET_MEM_TABLE, &mem_table as *const vhost::Memory2) }
                < 0
            {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_MEM_TABLE (2 regions) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        } else {
            // Small VM: single region
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
            if unsafe { libc::ioctl(fd, vhost::SET_MEM_TABLE, &mem_table as *const vhost::Memory) }
                < 0
            {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_MEM_TABLE failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        // Set up RX (0), TX (1), and event (2) queues.
        // All 3 queues MUST be configured because vhost_vsock_start() in the
        // kernel calls vhost_vq_access_ok() on every queue before it will
        // start processing packets. Without queue 2 (event), SET_RUNNING fails.
        // For the event queue (2), we set up a vring pointing to valid guest
        // memory but the queue is otherwise unused by the data path.
        let guest_mem_base = self.guest_mem as u64;
        let num_vhost_queues = self.queue_configs.len().min(NUM_QUEUES);
        tracing::info!(
            "vhost-vsock: setting up {num_vhost_queues} queues, guest_mem_base=0x{:x}",
            guest_mem_base
        );
        for qi in 0..num_vhost_queues as u32 {
            let qc = &self.queue_configs[qi as usize];

            // For the event queue (2), only set the vring addresses (no kick/call).
            // Use the guest-provided addresses but vhost won't actually use this queue.
            if qi == 2 {
                // VHOST_SET_VRING_NUM with size from guest config
                let state = vhost::VringState { index: qi, num: qc.size as u32 };
                unsafe { libc::ioctl(fd, vhost::SET_VRING_NUM, &state) };

                // VHOST_SET_VRING_ADDR
                let addr = vhost::VringAddr {
                    index: qi,
                    flags: 0,
                    desc_user_addr: self.gpa_to_hva(qc.desc_addr),
                    used_user_addr: self.gpa_to_hva(qc.used_addr),
                    avail_user_addr: self.gpa_to_hva(qc.avail_addr),
                    log_guest_addr: 0,
                };
                unsafe { libc::ioctl(fd, vhost::SET_VRING_ADDR, &addr) };

                // VHOST_SET_VRING_BASE
                let base = vhost::VringState { index: qi, num: 0 };
                unsafe { libc::ioctl(fd, vhost::SET_VRING_BASE, &base) };

                tracing::info!("vhost-vsock: queue {qi} (event) configured for access_ok");
                continue;
            }

            tracing::info!(
                "vhost-vsock: queue {} size={} desc=0x{:x} avail=0x{:x} used=0x{:x}",
                qi, qc.size, qc.desc_addr, qc.avail_addr, qc.used_addr
            );

            // Create kick eventfd
            let kick_fd =
                unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
            if kick_fd < 0 {
                return Err(anyhow::anyhow!(
                    "eventfd(kick) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            self.kick_fds[qi as usize] = kick_fd;

            // Use pre-created call eventfd (created in new() so the poll thread
            // has valid fds before activation).
            let call_fd = self.call_fds[qi as usize];
            debug_assert!(call_fd >= 0, "call_fd for queue {qi} not pre-created");

            // VHOST_SET_VRING_NUM
            let state = vhost::VringState {
                index: qi,
                num: qc.size as u32,
            };
            if unsafe { libc::ioctl(fd, vhost::SET_VRING_NUM, &state) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_VRING_NUM(q={qi}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // VHOST_SET_VRING_ADDR
            let addr = vhost::VringAddr {
                index: qi,
                flags: 0,
                desc_user_addr: self.gpa_to_hva(qc.desc_addr),
                used_user_addr: self.gpa_to_hva(qc.used_addr),
                avail_user_addr: self.gpa_to_hva(qc.avail_addr),
                log_guest_addr: 0,
            };
            if unsafe { libc::ioctl(fd, vhost::SET_VRING_ADDR, &addr) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_VRING_ADDR(q={qi}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // VHOST_SET_VRING_BASE
            let base = vhost::VringState {
                index: qi,
                num: 0,
            };
            if unsafe { libc::ioctl(fd, vhost::SET_VRING_BASE, &base) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_VRING_BASE(q={qi}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // VHOST_SET_VRING_KICK
            let kick = vhost::VringFile {
                index: qi,
                fd: kick_fd,
            };
            if unsafe { libc::ioctl(fd, vhost::SET_VRING_KICK, &kick) } < 0 {
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
            if unsafe { libc::ioctl(fd, vhost::SET_VRING_CALL, &call) } < 0 {
                return Err(anyhow::anyhow!(
                    "VHOST_SET_VRING_CALL(q={qi}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        // NOTE: We do NOT register KVM_IRQFD for vsock call_fds.
        // Instead, the VMM's vsock poll thread (vmm/mod.rs) monitors call_fds,
        // sets INTERRUPT_STATUS via the vhost_interrupt atomic, and then injects
        // the IRQ via set_irq_line. This ensures INTERRUPT_STATUS is set BEFORE
        // the IRQ fires, so the guest ISR sees the used-buffer notification bit
        // and processes the vring. With irqfd, the IRQ fires instantly (in-kernel)
        // but INTERRUPT_STATUS hasn't been set yet (userspace race), causing the
        // guest to ignore the interrupt and connections to time out.

        // NOTE: ioeventfd disabled — the VMM's process_queue() handles kicks via MMIO trap.
        // This ensures the VMM sees all QUEUE_NOTIFY writes.

        // VHOST_VSOCK_SET_RUNNING — start processing packets
        let running: libc::c_int = 1;
        let ret = unsafe { libc::ioctl(fd, vhost::VSOCK_SET_RUNNING, &running as *const libc::c_int) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            tracing::error!("VHOST_VSOCK_SET_RUNNING failed: {err}");
            return Err(anyhow::anyhow!("VHOST_VSOCK_SET_RUNNING failed: {err}"));
        }
        tracing::info!("vhost-vsock: SET_RUNNING succeeded");

        tracing::info!(
            "vhost-vsock: backend configured (guest_cid={}, vhost_fd={})",
            self.guest_cid,
            self.vhost_fd
        );

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn setup_vhost(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Signal the kick eventfd for the given queue.
    fn kick_queue(&self, queue_index: u16) {
        let qi = queue_index as usize;
        if qi < NUM_QUEUES && self.kick_fds[qi] >= 0 {
            tracing::trace!("vhost-vsock: kick queue {qi} (fd={})", self.kick_fds[qi]);
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
        let end = std::cmp::min(start + data.len(), config.len());
        if start < end {
            let len = end - start;
            data[..len].copy_from_slice(&config[start..end]);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        tracing::debug!(
            "virtio-vsock: write_config offset={offset} len={} (ignored)",
            data.len()
        );
    }

    fn prepare_activate(&mut self, queues: &[QueueInfo], guest_mem: *mut u8, mem_size: u64) {
        self.queue_configs = queues.to_vec();
        self.guest_mem = guest_mem;
        self.guest_mem_size = mem_size;
    }

    fn set_memory_hole(&mut self, hole_start: u64, hole_end: u64) {
        self.hole_start = hole_start;
        self.hole_end = hole_end;
    }

    fn activate(&mut self) -> anyhow::Result<()> {
        self.activated = true;

        if self.vhost_fd >= 0 {
            self.setup_vhost()?;
        }

        tracing::info!(
            "virtio-vsock: activated (guest_cid={}, vhost={})",
            self.guest_cid,
            self.vhost_fd >= 0
        );
        Ok(())
    }

    fn process_queue(&mut self, queue_index: u16) -> anyhow::Result<()> {
        if self.vhost_fd >= 0 {
            // vhost handles the data path — just signal the kick eventfd
            self.kick_queue(queue_index);
            return Ok(());
        }
        Ok(())
    }

    fn transport_processes_queue(&self, _queue_index: u16) -> bool {
        // vhost-vsock handles all queues in kernel
        self.vhost_fd < 0
    }

    fn reset(&mut self) {
        self.acked_features_low = 0;
        self.acked_features_high = 0;
        self.activated = false;
        tracing::info!("virtio-vsock: reset");
    }

    fn snapshot_state(&self) -> Vec<u8> {
        let state = serde_json::json!({
            "guest_cid": self.guest_cid,
            "acked_features_low": self.acked_features_low,
            "acked_features_high": self.acked_features_high,
        });
        serde_json::to_vec(&state).unwrap_or_default()
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
        // Close eventfds
        for &fd in self.kick_fds.iter().chain(self.call_fds.iter()) {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
        // Close vhost-vsock fd (releases the CID)
        if self.vhost_fd >= 0 {
            unsafe {
                libc::close(self.vhost_fd);
            }
            tracing::info!("vhost-vsock: closed fd={}", self.vhost_fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Each test gets a unique CID to avoid EADDRINUSE when tests run in parallel.
    static NEXT_CID: AtomicU64 = AtomicU64::new(100);
    fn unique_cid() -> u64 {
        NEXT_CID.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn test_cid_validation() {
        assert!(VirtioVsock::new(0).is_err());
        assert!(VirtioVsock::new(1).is_err());
        assert!(VirtioVsock::new(2).is_err());
        // CID 3+ should succeed.
        let cid = unique_cid();
        let dev = VirtioVsock::new(cid).unwrap();
        assert_eq!(dev.guest_cid(), cid);
    }

    #[test]
    fn test_config_space_cid() {
        let cid = unique_cid();
        let dev = VirtioVsock::new(cid).unwrap();
        let mut buf = [0u8; 8];
        dev.read_config(0, &mut buf);
        let read_cid = u64::from_le_bytes(buf);
        assert_eq!(read_cid, cid);
    }

    #[test]
    fn test_device_type() {
        let dev = VirtioVsock::new(unique_cid()).unwrap();
        assert_eq!(dev.device_type(), DeviceType::Vsock);
    }

    #[test]
    fn test_queue_count() {
        let dev = VirtioVsock::new(unique_cid()).unwrap();
        assert_eq!(dev.queue_max_sizes().len(), 3);
    }
}
