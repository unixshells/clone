//! Virtio MMIO transport layer.
//!
//! Implements the virtio MMIO register interface (virtio spec 4.2.2).
//! The guest reads/writes to MMIO offsets and this module translates
//! them into calls on the underlying VirtioDevice trait.

use serde::{Serialize, Deserialize};

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use crate::virtio::queue::Virtqueue;
use crate::virtio::{status, VirtioDevice, MMIO_BASE, MMIO_STRIDE};

// Virtio MMIO register offsets (virtio spec 4.2.2, Table 4.1).
mod reg {
    pub const MAGIC_VALUE: u64 = 0x000;
    pub const VERSION: u64 = 0x004;
    pub const DEVICE_ID: u64 = 0x008;
    pub const VENDOR_ID: u64 = 0x00c;
    pub const DEVICE_FEATURES: u64 = 0x010;
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const DRIVER_FEATURES: u64 = 0x020;
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const INTERRUPT_STATUS: u64 = 0x060;
    pub const INTERRUPT_ACK: u64 = 0x064;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    pub const QUEUE_AVAIL_LOW: u64 = 0x090;
    pub const QUEUE_AVAIL_HIGH: u64 = 0x094;
    pub const QUEUE_USED_LOW: u64 = 0x0a0;
    pub const QUEUE_USED_HIGH: u64 = 0x0a4;
    pub const CONFIG_GENERATION: u64 = 0x0fc;
    /// Device-specific config space starts at offset 0x100.
    pub const CONFIG_SPACE: u64 = 0x100;
}

/// The magic value that identifies a virtio MMIO device ("virt").
const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
/// We implement virtio MMIO version 2 (virtio 1.0+).
const VIRTIO_MMIO_VERSION: u32 = 2;
/// Our vendor ID (arbitrary, using 0x4E564D = "NVM").
const VENDOR_ID: u32 = 0x004E_564D;

/// Per-queue configuration state, tracked by the transport.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct QueueState {
    /// Maximum queue size (from device).
    max_size: u16,
    /// Configured queue size (from driver).
    size: u16,
    /// Whether the queue has been marked ready.
    ready: bool,
    /// Descriptor table physical address.
    desc_addr: u64,
    /// Available ring physical address.
    avail_addr: u64,
    /// Used ring physical address.
    used_addr: u64,
}

/// Serializable snapshot of an MMIO transport's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmioTransportState {
    pub device_status: u32,
    pub interrupt_status: u32,
    pub driver_features: [u32; 2],
    pub queue_sel: u32,
    pub queues: Vec<QueueState>,
    pub activated: bool,
    pub config_generation: u32,
    pub device_state: Vec<u8>,
}

/// MMIO transport for a single virtio device.
///
/// Wraps a `Box<dyn VirtioDevice>` and handles the MMIO register
/// interface, translating guest reads/writes into device trait calls.
pub struct MmioTransport {
    device: Box<dyn VirtioDevice>,
    /// IRQ number assigned to this device.
    irq: u32,
    /// Current device status register.
    device_status: u32,
    /// Interrupt status bits (bit 0 = used ring update, bit 1 = config change).
    interrupt_status: u32,
    /// Currently selected feature page (0 or 1).
    device_features_sel: u32,
    /// Currently selected driver feature page (0 or 1).
    driver_features_sel: u32,
    /// Driver-acknowledged feature bits, indexed by page.
    driver_features: [u32; 2],
    /// Currently selected queue index.
    queue_sel: u32,
    /// Per-queue state (MMIO register tracking).
    queues: Vec<QueueState>,
    /// Virtqueues for descriptor chain processing.
    virtqueues: Vec<Virtqueue>,
    /// Whether the device has been activated.
    activated: bool,
    /// Config generation counter (incremented on config change).
    config_generation: u32,
    /// Guest memory base pointer (for virtqueue access).
    guest_mem: *mut u8,
    /// Guest memory size in bytes.
    guest_mem_size: u64,
    /// External interrupt status from vhost call_fd poll thread.
    /// Set atomically by the poll thread, read and cleared by the transport.
    vhost_interrupt: Arc<AtomicU32>,
}

// SAFETY: The raw pointer is managed exclusively by the VMM.
unsafe impl Send for MmioTransport {}

impl MmioTransport {
    /// Create a new MMIO transport wrapping the given device.
    ///
    /// This creates a transport without guest memory access. Virtqueue
    /// descriptor chain processing will be unavailable until
    /// `set_guest_memory` is called.
    pub fn new(device: Box<dyn VirtioDevice>, irq: u32) -> Self {
        Self::new_with_mem(device, irq, std::ptr::null_mut(), 0)
    }

    /// Create a new MMIO transport with guest memory access.
    ///
    /// The guest memory pointer and size are passed to the virtqueues so
    /// they can read/write descriptor chains in guest memory.
    pub fn new_with_mem(
        device: Box<dyn VirtioDevice>,
        irq: u32,
        guest_mem: *mut u8,
        guest_mem_size: u64,
    ) -> Self {
        let queue_max_sizes = device.queue_max_sizes().to_vec();
        let queues: Vec<QueueState> = queue_max_sizes
            .iter()
            .map(|&max_size| QueueState {
                max_size,
                size: max_size, // default to max until driver configures
                ..Default::default()
            })
            .collect();

        let virtqueues = queue_max_sizes
            .iter()
            .map(|&max_size| Virtqueue::new(max_size, guest_mem, guest_mem_size))
            .collect();

        Self {
            device,
            irq,
            device_status: 0,
            interrupt_status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            queue_sel: 0,
            queues,
            virtqueues,
            activated: false,
            config_generation: 0,
            guest_mem,
            guest_mem_size,
            vhost_interrupt: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Set the guest memory pointer and size, and update all virtqueues.
    pub fn set_guest_memory(&mut self, guest_mem: *mut u8, guest_mem_size: u64) {
        self.guest_mem = guest_mem;
        self.guest_mem_size = guest_mem_size;
        // Recreate virtqueues with the new memory pointer
        let queue_max_sizes = self.device.queue_max_sizes().to_vec();
        self.virtqueues = queue_max_sizes
            .iter()
            .map(|&max_size| Virtqueue::new(max_size, guest_mem, guest_mem_size))
            .collect();
    }

    /// Returns the IRQ number for this device.
    pub fn irq(&self) -> u32 {
        self.irq
    }

    /// Returns a reference to the underlying device.
    pub fn device(&self) -> &dyn VirtioDevice {
        self.device.as_ref()
    }

    /// Returns the current interrupt status (for interrupt injection).
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    /// Raise a used-ring interrupt (bit 0 of interrupt status).
    pub fn raise_used_ring_interrupt(&mut self) {
        self.interrupt_status |= 1;
    }

    /// Get the vhost interrupt atomic for external poll threads.
    pub fn vhost_interrupt(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.vhost_interrupt)
    }

    /// Raise a config-change interrupt (bit 1 of interrupt status).
    pub fn raise_config_change_interrupt(&mut self) {
        self.interrupt_status |= 2;
        self.config_generation = self.config_generation.wrapping_add(1);
    }

    /// Returns the queue state for the given index, if valid.
    pub fn queue_state(&self, index: usize) -> Option<&QueueState> {
        self.queues.get(index)
    }

    fn current_queue(&self) -> Option<&QueueState> {
        self.queues.get(self.queue_sel as usize)
    }

    fn current_queue_mut(&mut self) -> Option<&mut QueueState> {
        self.queues.get_mut(self.queue_sel as usize)
    }

    /// Handle an MMIO read from the guest at the given offset within
    /// this device's MMIO region. Returns the value to provide to the guest.
    pub fn read(&self, offset: u64, data: &mut [u8]) {
        // All standard registers are 32-bit aligned reads.
        // Config space can be byte-granularity.
        if offset >= reg::CONFIG_SPACE {
            self.device
                .read_config(offset - reg::CONFIG_SPACE, data);
            return;
        }

        // Standard registers — 4-byte reads only.
        if data.len() != 4 {
            tracing::warn!("MMIO read with non-4-byte size at offset {offset:#x}");
            data.fill(0);
            return;
        }

        let val: u32 = match offset {
            reg::MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            reg::VERSION => VIRTIO_MMIO_VERSION,
            reg::DEVICE_ID => self.device.device_type() as u32,
            reg::VENDOR_ID => VENDOR_ID,
            reg::DEVICE_FEATURES => self.device.features(self.device_features_sel),
            reg::QUEUE_NUM_MAX => {
                self.current_queue()
                    .map(|q| q.max_size as u32)
                    .unwrap_or(0)
            }
            reg::QUEUE_READY => {
                self.current_queue()
                    .map(|q| u32::from(q.ready))
                    .unwrap_or(0)
            }
            reg::INTERRUPT_STATUS => {
                // Merge transport interrupt_status with vhost interrupt bits.
                //
                // For vhost devices that use irqfd (vsock), the kernel injects IRQs
                // directly when call_fd fires. The guest ISR then reads INTERRUPT_STATUS
                // to decide what to process. The vhost_interrupt atomic is set by:
                //   1. The userspace poll thread (for vhost-vsock call_fds)
                //   2. The vhost-net poll thread (via raise_used_ring_interrupt)
                //
                // If vhost_interrupt has bit 0 set, the ISR sees "used buffer notification"
                // and processes the vring. The atomic is cleared by INTERRUPT_ACK.
                let vhost_bits = self.vhost_interrupt.load(std::sync::atomic::Ordering::Acquire);
                self.interrupt_status | vhost_bits
            }
            reg::STATUS => self.device_status,
            reg::CONFIG_GENERATION => self.config_generation,
            _ => {
                tracing::trace!("MMIO read from unknown offset {offset:#x}");
                0
            }
        };

        data.copy_from_slice(&val.to_le_bytes());
    }

    /// Handle an MMIO write from the guest at the given offset.
    pub fn write(&mut self, offset: u64, data: &[u8]) {
        // Config space writes can be byte-granularity.
        if offset >= reg::CONFIG_SPACE {
            self.device
                .write_config(offset - reg::CONFIG_SPACE, data);
            return;
        }

        // Standard registers — 4-byte writes only.
        if data.len() != 4 {
            tracing::warn!("MMIO write with non-4-byte size at offset {offset:#x}");
            return;
        }

        let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        match offset {
            reg::DEVICE_FEATURES_SEL => {
                self.device_features_sel = val;
            }
            reg::DRIVER_FEATURES => {
                if self.device_status & status::FEATURES_OK == 0
                    && self.device_status & status::DRIVER != 0
                {
                    // Driver is setting features before FEATURES_OK
                    self.driver_features[self.driver_features_sel as usize & 1] = val;
                    self.device
                        .ack_features(self.driver_features_sel, val);
                }
            }
            reg::DRIVER_FEATURES_SEL => {
                self.driver_features_sel = val;
            }
            reg::QUEUE_SEL => {
                self.queue_sel = val;
            }
            reg::QUEUE_NUM => {
                if let Some(q) = self.current_queue_mut() {
                    if val <= q.max_size as u32 {
                        q.size = val as u16;
                    }
                }
            }
            reg::QUEUE_READY => {
                let sel = self.queue_sel as usize;
                if let Some(q) = self.current_queue_mut() {
                    q.ready = val == 1;
                }
                // Sync the virtqueue state
                if let (Some(qs), Some(vq)) =
                    (self.queues.get(sel), self.virtqueues.get_mut(sel))
                {
                    if val == 1 {
                        vq.configure(qs.desc_addr, qs.avail_addr, qs.used_addr);
                        vq.set_ready(true);
                    } else {
                        vq.set_ready(false);
                    }
                }
            }
            reg::QUEUE_NOTIFY => {
                let queue_idx = val as u16;
                // First, let the device handle its own notification
                if let Err(e) = self.device.process_queue(queue_idx) {
                    tracing::error!("Error processing queue {val}: {e}");
                }
                // Process descriptor chains unless the device manages this queue externally
                if self.device.transport_processes_queue(queue_idx) {
                    self.process_queue_descriptors(queue_idx);
                }
            }
            reg::INTERRUPT_ACK => {
                self.interrupt_status &= !val;
                // Also clear the bits in the vhost interrupt atomic
                self.vhost_interrupt.fetch_and(!val, std::sync::atomic::Ordering::Release);
            }
            reg::STATUS => {
                self.handle_status_write(val);
            }
            reg::QUEUE_DESC_LOW => {
                if let Some(q) = self.current_queue_mut() {
                    q.desc_addr = (q.desc_addr & 0xFFFF_FFFF_0000_0000) | val as u64;
                }
            }
            reg::QUEUE_DESC_HIGH => {
                if let Some(q) = self.current_queue_mut() {
                    q.desc_addr = (q.desc_addr & 0x0000_0000_FFFF_FFFF) | ((val as u64) << 32);
                }
            }
            reg::QUEUE_AVAIL_LOW => {
                if let Some(q) = self.current_queue_mut() {
                    q.avail_addr = (q.avail_addr & 0xFFFF_FFFF_0000_0000) | val as u64;
                }
            }
            reg::QUEUE_AVAIL_HIGH => {
                if let Some(q) = self.current_queue_mut() {
                    q.avail_addr = (q.avail_addr & 0x0000_0000_FFFF_FFFF) | ((val as u64) << 32);
                }
            }
            reg::QUEUE_USED_LOW => {
                if let Some(q) = self.current_queue_mut() {
                    q.used_addr = (q.used_addr & 0xFFFF_FFFF_0000_0000) | val as u64;
                }
            }
            reg::QUEUE_USED_HIGH => {
                if let Some(q) = self.current_queue_mut() {
                    q.used_addr = (q.used_addr & 0x0000_0000_FFFF_FFFF) | ((val as u64) << 32);
                }
            }
            _ => {
                tracing::trace!("MMIO write to unknown offset {offset:#x} = {val:#x}");
            }
        }
    }

    /// Process all available descriptor chains on the given queue.
    ///
    /// For each chain, separates readable and writable descriptors,
    /// then delegates to the device for actual I/O processing.
    /// After processing, pushes used entries and optionally raises
    /// an interrupt.
    fn process_queue_descriptors(&mut self, queue_idx: u16) {
        let qi = queue_idx as usize;

        // We need to work around the borrow checker: we can't borrow
        // self.virtqueues[qi] and self.device simultaneously. So we
        // temporarily take the virtqueue out, process, and put it back.
        if qi >= self.virtqueues.len() {
            return;
        }

        // Take the virtqueue out temporarily
        let mut vq = std::mem::replace(
            &mut self.virtqueues[qi],
            Virtqueue::new(0, std::ptr::null_mut(), 0),
        );

        if !vq.is_ready() {
            self.virtqueues[qi] = vq;
            return;
        }

        let mut raised_interrupt = false;

        while let Some(chain) = vq.pop_avail() {
            let bytes_written = self.device.process_descriptor_chain(queue_idx, &chain, &vq);

            vq.push_used(chain.index, bytes_written);

            if vq.needs_notification() {
                raised_interrupt = true;
            }
        }

        // Put the virtqueue back
        self.virtqueues[qi] = vq;

        if raised_interrupt {
            self.raise_used_ring_interrupt();
        }
    }

    /// Get a reference to a virtqueue by index.
    pub fn virtqueue(&self, index: usize) -> Option<&Virtqueue> {
        self.virtqueues.get(index)
    }

    /// Get a mutable reference to a virtqueue by index.
    pub fn virtqueue_mut(&mut self, index: usize) -> Option<&mut Virtqueue> {
        self.virtqueues.get_mut(index)
    }

    /// Inject a received frame into the RX virtqueue (queue 0).
    ///
    /// Pops an available descriptor, writes a zeroed virtio_net_hdr followed
    /// by the frame data into the writable descriptors, pushes to used ring,
    /// and raises the interrupt. Returns true if the frame was delivered.
    pub fn inject_rx_frame(&mut self, frame: &[u8]) -> bool {
        let qi = 0usize; // RX queue index
        if qi >= self.virtqueues.len() {
            return false;
        }

        let vq = &mut self.virtqueues[qi];
        if !vq.is_ready() || !vq.has_available() {
            return false;
        }

        let chain = match vq.pop_avail() {
            Some(c) => c,
            None => return false,
        };

        // virtio_net_hdr_v1 (12 bytes, all zeros = no offload)
        let hdr = [0u8; 12];
        let total_len = hdr.len() + frame.len();
        let mut written = 0usize;
        let mut src_offset = 0usize;

        // Combine header + frame into a logical source buffer
        let combined: Vec<u8> = [&hdr[..], frame].concat();

        for desc in &chain.descriptors {
            use crate::virtio::queue::VRING_DESC_F_WRITE;
            if desc.flags & VRING_DESC_F_WRITE == 0 {
                continue; // skip readable descriptors
            }
            if src_offset >= combined.len() {
                break;
            }
            if let Some(buf) = vq.write_descriptor_data(desc) {
                let copy_len = std::cmp::min(buf.len(), combined.len() - src_offset);
                buf[..copy_len].copy_from_slice(&combined[src_offset..src_offset + copy_len]);
                src_offset += copy_len;
                written += copy_len;
            }
        }

        vq.push_used(chain.index, written as u32);

        if vq.needs_notification() {
            self.raise_used_ring_interrupt();
        }

        true
    }

    /// Snapshot the full transport + device state.
    pub fn snapshot_state(&self) -> MmioTransportState {
        MmioTransportState {
            device_status: self.device_status,
            interrupt_status: self.interrupt_status,
            driver_features: self.driver_features,
            queue_sel: self.queue_sel,
            queues: self.queues.clone(),
            activated: self.activated,
            config_generation: self.config_generation,
            device_state: self.device.snapshot_state(),
        }
    }

    /// Restore transport + device state from a snapshot.
    pub fn restore_state(&mut self, state: &MmioTransportState) -> anyhow::Result<()> {
        self.device_status = state.device_status;
        self.interrupt_status = state.interrupt_status;
        self.driver_features = state.driver_features;
        self.queue_sel = state.queue_sel;
        self.queues = state.queues.clone();
        self.activated = state.activated;
        self.config_generation = state.config_generation;
        self.device.restore_state(&state.device_state)?;
        Ok(())
    }

    /// Handle a write to the device STATUS register.
    /// This drives the device state machine per virtio spec 3.1.1.
    fn handle_status_write(&mut self, val: u32) {
        // Writing 0 resets the device.
        if val == 0 {
            tracing::debug!("Virtio device reset");
            self.device_status = 0;
            self.interrupt_status = 0;
            self.activated = false;
            self.device_features_sel = 0;
            self.driver_features_sel = 0;
            self.driver_features = [0; 2];
            self.queue_sel = 0;
            for q in &mut self.queues {
                q.size = q.max_size;
                q.ready = false;
                q.desc_addr = 0;
                q.avail_addr = 0;
                q.used_addr = 0;
            }
            for vq in &mut self.virtqueues {
                vq.reset();
            }
            self.device.reset();
            return;
        }

        // Track transitions.
        let new_bits = val & !self.device_status;

        // If driver sets DRIVER_OK and we haven't activated yet, do so.
        if new_bits & status::DRIVER_OK != 0 && !self.activated {
            // Pass queue configuration and guest memory info to the device
            let queue_infos: Vec<crate::virtio::QueueInfo> = self.queues.iter().map(|q| {
                crate::virtio::QueueInfo {
                    size: q.size,
                    desc_addr: q.desc_addr,
                    avail_addr: q.avail_addr,
                    used_addr: q.used_addr,
                }
            }).collect();
            self.device.prepare_activate(&queue_infos, self.guest_mem, self.guest_mem_size);

            match self.device.activate() {
                Ok(()) => {
                    self.activated = true;
                    tracing::debug!("Virtio device activated");
                }
                Err(e) => {
                    tracing::error!("Failed to activate virtio device: {e}");
                    self.device_status |= status::DEVICE_NEEDS_RESET;
                    return;
                }
            }
        }

        self.device_status = val;
    }
}

/// The MMIO device bus — holds all virtio MMIO transports and routes
/// guest MMIO accesses to the correct device.
pub struct MmioBus {
    devices: Vec<MmioTransport>,
    /// Guest memory pointer (shared with all transports).
    guest_mem: *mut u8,
    /// Guest memory size.
    guest_mem_size: u64,
}

// SAFETY: The raw pointer is managed exclusively by the VMM.
unsafe impl Send for MmioBus {}

impl MmioBus {
    /// Create a new empty MMIO bus.
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            guest_mem: std::ptr::null_mut(),
            guest_mem_size: 0,
        }
    }

    /// Set the guest memory pointer and size for all current and future devices.
    pub fn set_guest_memory(&mut self, guest_mem: *mut u8, guest_mem_size: u64) {
        self.guest_mem = guest_mem;
        self.guest_mem_size = guest_mem_size;
        for transport in &mut self.devices {
            transport.set_guest_memory(guest_mem, guest_mem_size);
        }
    }

    /// Register a virtio device on the bus. Returns the MMIO base address
    /// and IRQ number assigned to it.
    pub fn register(&mut self, device: Box<dyn VirtioDevice>) -> (u64, u32) {
        let index = self.devices.len();
        let base = MMIO_BASE + (index as u64) * MMIO_STRIDE;
        let irq = crate::virtio::IRQ_BASE + index as u32;
        let transport = MmioTransport::new_with_mem(
            device, irq, self.guest_mem, self.guest_mem_size,
        );
        self.devices.push(transport);
        tracing::info!(
            "Registered virtio {:?} at MMIO {base:#x}, IRQ {irq}",
            self.devices.last().unwrap().device().device_type()
        );
        (base, irq)
    }

    /// Handle an MMIO read at the given guest physical address.
    /// Returns true if the address was handled (i.e., falls within a device region).
    pub fn handle_read(&self, addr: u64, data: &mut [u8]) -> bool {
        if let Some((transport, offset)) = self.find_device(addr) {
            transport.read(offset, data);
            true
        } else {
            false
        }
    }

    /// Handle an MMIO write at the given guest physical address.
    /// Returns `(handled, Option<irq>)` — the IRQ to inject if the write
    /// triggered a new interrupt.
    pub fn handle_write(&mut self, addr: u64, data: &[u8]) -> (bool, Option<u32>) {
        if let Some((transport, offset)) = self.find_device_mut(addr) {
            let irq = transport.irq();
            let had_interrupt = transport.interrupt_status() != 0;
            transport.write(offset, data);
            let has_interrupt = transport.interrupt_status() != 0;
            let inject = if has_interrupt && !had_interrupt {
                Some(irq)
            } else {
                None
            };
            (true, inject)
        } else {
            (false, None)
        }
    }

    /// Get a reference to a transport by index.
    pub fn transport(&self, index: usize) -> Option<&MmioTransport> {
        self.devices.get(index)
    }

    /// Get a mutable reference to a transport by index.
    pub fn transport_mut(&mut self, index: usize) -> Option<&mut MmioTransport> {
        self.devices.get_mut(index)
    }

    /// Number of registered devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Snapshot the state of all registered transports.
    pub fn snapshot_all(&self) -> Vec<MmioTransportState> {
        self.devices.iter().map(|t| t.snapshot_state()).collect()
    }

    /// Restore all transport states from a snapshot.
    pub fn restore_all(&mut self, states: &[MmioTransportState]) -> anyhow::Result<()> {
        for (transport, state) in self.devices.iter_mut().zip(states.iter()) {
            transport.restore_state(state)?;
        }
        Ok(())
    }

    /// Restore transport states from JSON-serialized snapshots.
    pub fn restore_all_from_json(&mut self, json_states: &[Vec<u8>]) -> anyhow::Result<()> {
        for (transport, json) in self.devices.iter_mut().zip(json_states.iter()) {
            if !json.is_empty() {
                let state: MmioTransportState = serde_json::from_slice(json)?;
                transport.restore_state(&state)?;
            }
        }
        Ok(())
    }

    fn find_device(&self, addr: u64) -> Option<(&MmioTransport, u64)> {
        if addr < MMIO_BASE {
            return None;
        }
        let offset_from_base = addr - MMIO_BASE;
        let index = (offset_from_base / MMIO_STRIDE) as usize;
        let offset_within = offset_from_base % MMIO_STRIDE;
        self.devices.get(index).map(|t| (t, offset_within))
    }

    fn find_device_mut(&mut self, addr: u64) -> Option<(&mut MmioTransport, u64)> {
        if addr < MMIO_BASE {
            return None;
        }
        let offset_from_base = addr - MMIO_BASE;
        let index = (offset_from_base / MMIO_STRIDE) as usize;
        let offset_within = offset_from_base % MMIO_STRIDE;
        self.devices.get_mut(index).map(|t| (t, offset_within))
    }
}

impl Default for MmioBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::{DeviceType, VirtioDevice};

    /// A simple mock device for testing the MMIO transport in isolation.
    struct MockDevice {
        device_type: DeviceType,
        queue_sizes: Vec<u16>,
        features_low: u32,
        features_high: u32,
        config_data: Vec<u8>,
        activated: bool,
        reset_count: u32,
        process_queue_count: u32,
    }

    impl MockDevice {
        fn new(device_type: DeviceType) -> Self {
            Self {
                device_type,
                queue_sizes: vec![128, 64],
                features_low: 0xABCD_0001,
                features_high: 0x0000_0001,
                config_data: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                activated: false,
                reset_count: 0,
                process_queue_count: 0,
            }
        }
    }

    impl VirtioDevice for MockDevice {
        fn device_type(&self) -> DeviceType {
            self.device_type
        }

        fn queue_max_sizes(&self) -> &[u16] {
            &self.queue_sizes
        }

        fn features(&self, page: u32) -> u32 {
            match page {
                0 => self.features_low,
                1 => self.features_high,
                _ => 0,
            }
        }

        fn ack_features(&mut self, _page: u32, _value: u32) {}

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let start = offset as usize;
            let end = std::cmp::min(start + data.len(), self.config_data.len());
            if start < end {
                let len = end - start;
                data[..len].copy_from_slice(&self.config_data[start..end]);
            }
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let start = offset as usize;
            let end = std::cmp::min(start + data.len(), self.config_data.len());
            if start < end {
                let len = end - start;
                self.config_data[start..end].copy_from_slice(&data[..len]);
            }
        }

        fn activate(&mut self) -> anyhow::Result<()> {
            self.activated = true;
            Ok(())
        }

        fn process_queue(&mut self, _queue_index: u16) -> anyhow::Result<()> {
            self.process_queue_count += 1;
            Ok(())
        }

        fn reset(&mut self) {
            self.reset_count += 1;
            self.activated = false;
        }
    }

    fn make_transport() -> MmioTransport {
        MmioTransport::new(Box::new(MockDevice::new(DeviceType::Block)), 5)
    }

    fn read_u32(transport: &MmioTransport, offset: u64) -> u32 {
        let mut buf = [0u8; 4];
        transport.read(offset, &mut buf);
        u32::from_le_bytes(buf)
    }

    fn write_u32(transport: &mut MmioTransport, offset: u64, val: u32) {
        transport.write(offset, &val.to_le_bytes());
    }

    // --- Magic, version, device ID ---

    #[test]
    fn test_magic_number() {
        let transport = make_transport();
        assert_eq!(read_u32(&transport, reg::MAGIC_VALUE), 0x7472_6976);
    }

    #[test]
    fn test_version() {
        let transport = make_transport();
        assert_eq!(read_u32(&transport, reg::VERSION), 2);
    }

    #[test]
    fn test_device_id_matches() {
        let transport = make_transport();
        assert_eq!(read_u32(&transport, reg::DEVICE_ID), DeviceType::Block as u32);
    }

    #[test]
    fn test_device_id_net() {
        let t = MmioTransport::new(Box::new(MockDevice::new(DeviceType::Net)), 6);
        assert_eq!(read_u32(&t, reg::DEVICE_ID), DeviceType::Net as u32);
    }

    #[test]
    fn test_vendor_id() {
        let transport = make_transport();
        assert_eq!(read_u32(&transport, reg::VENDOR_ID), VENDOR_ID);
    }

    // --- Status register transitions ---

    #[test]
    fn test_status_transitions() {
        let mut transport = make_transport();

        // Initial status is 0
        assert_eq!(read_u32(&transport, reg::STATUS), 0);

        // ACKNOWLEDGE
        write_u32(&mut transport, reg::STATUS, status::ACKNOWLEDGE);
        assert_eq!(read_u32(&transport, reg::STATUS), status::ACKNOWLEDGE);

        // ACKNOWLEDGE | DRIVER
        write_u32(&mut transport, reg::STATUS, status::ACKNOWLEDGE | status::DRIVER);
        assert_eq!(
            read_u32(&transport, reg::STATUS),
            status::ACKNOWLEDGE | status::DRIVER
        );

        // ACKNOWLEDGE | DRIVER | FEATURES_OK
        write_u32(
            &mut transport,
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
        );
        assert_eq!(
            read_u32(&transport, reg::STATUS),
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK
        );

        // DRIVER_OK triggers activation
        write_u32(
            &mut transport,
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );
        assert_eq!(
            read_u32(&transport, reg::STATUS),
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK
        );
        assert!(transport.activated);
    }

    // --- Device reset ---

    #[test]
    fn test_device_reset() {
        let mut transport = make_transport();

        // Set up device
        write_u32(
            &mut transport,
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::DRIVER_OK,
        );
        assert!(transport.activated);

        // Set some queue state
        write_u32(&mut transport, reg::QUEUE_SEL, 0);
        write_u32(&mut transport, reg::QUEUE_NUM, 64);
        write_u32(&mut transport, reg::QUEUE_READY, 1);

        // Raise an interrupt
        transport.raise_used_ring_interrupt();
        assert_ne!(transport.interrupt_status(), 0);

        // Reset by writing 0 to status
        write_u32(&mut transport, reg::STATUS, 0);

        assert_eq!(read_u32(&transport, reg::STATUS), 0);
        assert!(!transport.activated);
        assert_eq!(transport.interrupt_status(), 0);

        // Queue should be reset
        let q = transport.queue_state(0).unwrap();
        assert!(!q.ready);
        assert_eq!(q.desc_addr, 0);
    }

    // --- Queue configuration ---

    #[test]
    fn test_queue_select_and_max_size() {
        let transport = make_transport();

        // Queue 0 max size should be 128 (from MockDevice)
        assert_eq!(read_u32(&transport, reg::QUEUE_NUM_MAX), 128);
    }

    #[test]
    fn test_queue_select_second_queue() {
        let mut transport = make_transport();
        write_u32(&mut transport, reg::QUEUE_SEL, 1);
        // Queue 1 max size should be 64 (from MockDevice)
        assert_eq!(read_u32(&transport, reg::QUEUE_NUM_MAX), 64);
    }

    #[test]
    fn test_queue_set_size() {
        let mut transport = make_transport();
        write_u32(&mut transport, reg::QUEUE_SEL, 0);
        write_u32(&mut transport, reg::QUEUE_NUM, 64);

        let q = transport.queue_state(0).unwrap();
        assert_eq!(q.size, 64);
    }

    #[test]
    fn test_queue_size_capped_at_max() {
        let mut transport = make_transport();
        write_u32(&mut transport, reg::QUEUE_SEL, 0);
        // Try to set size > max (128) — should be ignored
        write_u32(&mut transport, reg::QUEUE_NUM, 256);

        let q = transport.queue_state(0).unwrap();
        assert_eq!(q.size, 128); // unchanged from default max
    }

    #[test]
    fn test_queue_set_addresses() {
        let mut transport = make_transport();
        write_u32(&mut transport, reg::QUEUE_SEL, 0);

        // Set descriptor table address (64-bit via low + high)
        write_u32(&mut transport, reg::QUEUE_DESC_LOW, 0x1000_0000);
        write_u32(&mut transport, reg::QUEUE_DESC_HIGH, 0x0000_0001);

        // Set avail ring address
        write_u32(&mut transport, reg::QUEUE_AVAIL_LOW, 0x2000_0000);
        write_u32(&mut transport, reg::QUEUE_AVAIL_HIGH, 0x0000_0002);

        // Set used ring address
        write_u32(&mut transport, reg::QUEUE_USED_LOW, 0x3000_0000);
        write_u32(&mut transport, reg::QUEUE_USED_HIGH, 0x0000_0003);

        let q = transport.queue_state(0).unwrap();
        assert_eq!(q.desc_addr, 0x0000_0001_1000_0000);
        assert_eq!(q.avail_addr, 0x0000_0002_2000_0000);
        assert_eq!(q.used_addr, 0x0000_0003_3000_0000);
    }

    #[test]
    fn test_queue_ready() {
        let mut transport = make_transport();
        write_u32(&mut transport, reg::QUEUE_SEL, 0);

        assert_eq!(read_u32(&transport, reg::QUEUE_READY), 0);

        write_u32(&mut transport, reg::QUEUE_READY, 1);
        assert_eq!(read_u32(&transport, reg::QUEUE_READY), 1);
    }

    // --- Interrupt status ---

    #[test]
    fn test_interrupt_status_used_ring() {
        let mut transport = make_transport();
        assert_eq!(read_u32(&transport, reg::INTERRUPT_STATUS), 0);

        transport.raise_used_ring_interrupt();
        assert_eq!(read_u32(&transport, reg::INTERRUPT_STATUS), 1);
    }

    #[test]
    fn test_interrupt_status_config_change() {
        let mut transport = make_transport();
        transport.raise_config_change_interrupt();
        assert_eq!(read_u32(&transport, reg::INTERRUPT_STATUS), 2);
    }

    #[test]
    fn test_interrupt_ack_clears_bits() {
        let mut transport = make_transport();
        transport.raise_used_ring_interrupt();
        transport.raise_config_change_interrupt();
        assert_eq!(read_u32(&transport, reg::INTERRUPT_STATUS), 3);

        // Ack bit 0 only
        write_u32(&mut transport, reg::INTERRUPT_ACK, 1);
        assert_eq!(read_u32(&transport, reg::INTERRUPT_STATUS), 2);

        // Ack bit 1
        write_u32(&mut transport, reg::INTERRUPT_ACK, 2);
        assert_eq!(read_u32(&transport, reg::INTERRUPT_STATUS), 0);
    }

    // --- Config space read-through ---

    #[test]
    fn test_config_space_read_through() {
        let transport = make_transport();
        let mut buf = [0u8; 4];
        transport.read(reg::CONFIG_SPACE, &mut buf);
        assert_eq!(buf, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_config_space_read_offset() {
        let transport = make_transport();
        let mut buf = [0u8; 4];
        transport.read(reg::CONFIG_SPACE + 4, &mut buf);
        assert_eq!(buf, [0x55, 0x66, 0x77, 0x88]);
    }

    #[test]
    fn test_config_space_write_through() {
        let mut transport = make_transport();
        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        transport.write(reg::CONFIG_SPACE, &data);

        let mut buf = [0u8; 4];
        transport.read(reg::CONFIG_SPACE, &mut buf);
        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    // --- Config generation ---

    #[test]
    fn test_config_generation_increments() {
        let mut transport = make_transport();
        assert_eq!(read_u32(&transport, reg::CONFIG_GENERATION), 0);

        transport.raise_config_change_interrupt();
        assert_eq!(read_u32(&transport, reg::CONFIG_GENERATION), 1);

        transport.raise_config_change_interrupt();
        assert_eq!(read_u32(&transport, reg::CONFIG_GENERATION), 2);
    }

    // --- Device features ---

    #[test]
    fn test_device_features_page0() {
        let mut transport = make_transport();
        write_u32(&mut transport, reg::DEVICE_FEATURES_SEL, 0);
        let features = read_u32(&transport, reg::DEVICE_FEATURES);
        assert_eq!(features, 0xABCD_0001);
    }

    #[test]
    fn test_device_features_page1() {
        let mut transport = make_transport();
        write_u32(&mut transport, reg::DEVICE_FEATURES_SEL, 1);
        let features = read_u32(&transport, reg::DEVICE_FEATURES);
        assert_eq!(features, 0x0000_0001);
    }

    // --- Non-4-byte reads/writes ---

    #[test]
    fn test_non_4byte_read_returns_zeros() {
        let transport = make_transport();
        let mut buf = [0xFF; 2];
        transport.read(reg::MAGIC_VALUE, &mut buf);
        assert_eq!(buf, [0, 0]);
    }

    #[test]
    fn test_non_4byte_write_ignored() {
        let mut transport = make_transport();
        let data = [0xFF; 2];
        transport.write(reg::STATUS, &data);
        // Status should remain 0
        assert_eq!(read_u32(&transport, reg::STATUS), 0);
    }

    // --- MmioBus tests ---

    #[test]
    fn test_mmio_bus_register_device() {
        let mut bus = MmioBus::new();
        let (base, irq) = bus.register(Box::new(MockDevice::new(DeviceType::Block)));
        assert_eq!(base, MMIO_BASE);
        assert_eq!(irq, crate::virtio::IRQ_BASE);
        assert_eq!(bus.device_count(), 1);
    }

    #[test]
    fn test_mmio_bus_multiple_devices() {
        let mut bus = MmioBus::new();
        let (base0, irq0) = bus.register(Box::new(MockDevice::new(DeviceType::Block)));
        let (base1, irq1) = bus.register(Box::new(MockDevice::new(DeviceType::Net)));

        assert_eq!(base0, MMIO_BASE);
        assert_eq!(base1, MMIO_BASE + MMIO_STRIDE);
        assert_eq!(irq0, crate::virtio::IRQ_BASE);
        assert_eq!(irq1, crate::virtio::IRQ_BASE + 1);
        assert_eq!(bus.device_count(), 2);
    }

    #[test]
    fn test_mmio_bus_route_reads() {
        let mut bus = MmioBus::new();
        bus.register(Box::new(MockDevice::new(DeviceType::Block)));
        bus.register(Box::new(MockDevice::new(DeviceType::Net)));

        // Read magic from device 0
        let mut buf = [0u8; 4];
        assert!(bus.handle_read(MMIO_BASE + reg::MAGIC_VALUE, &mut buf));
        assert_eq!(u32::from_le_bytes(buf), 0x7472_6976);

        // Read device_id from device 0
        let mut buf = [0u8; 4];
        assert!(bus.handle_read(MMIO_BASE + reg::DEVICE_ID, &mut buf));
        assert_eq!(u32::from_le_bytes(buf), DeviceType::Block as u32);

        // Read device_id from device 1
        let mut buf = [0u8; 4];
        assert!(bus.handle_read(MMIO_BASE + MMIO_STRIDE + reg::DEVICE_ID, &mut buf));
        assert_eq!(u32::from_le_bytes(buf), DeviceType::Net as u32);
    }

    #[test]
    fn test_mmio_bus_route_writes() {
        let mut bus = MmioBus::new();
        bus.register(Box::new(MockDevice::new(DeviceType::Block)));

        // Write status to device 0
        let val = (status::ACKNOWLEDGE | status::DRIVER).to_le_bytes();
        assert!(bus.handle_write(MMIO_BASE + reg::STATUS, &val).0);

        // Verify via read
        let mut buf = [0u8; 4];
        bus.handle_read(MMIO_BASE + reg::STATUS, &mut buf);
        assert_eq!(
            u32::from_le_bytes(buf),
            status::ACKNOWLEDGE | status::DRIVER
        );
    }

    #[test]
    fn test_mmio_bus_unhandled_address() {
        let bus = MmioBus::new();
        let mut buf = [0u8; 4];
        // No devices registered, address below MMIO_BASE
        assert!(!bus.handle_read(0x1000, &mut buf));
    }

    #[test]
    fn test_mmio_bus_address_below_base() {
        let mut bus = MmioBus::new();
        bus.register(Box::new(MockDevice::new(DeviceType::Block)));

        let mut buf = [0u8; 4];
        assert!(!bus.handle_read(MMIO_BASE - 1, &mut buf));
    }

    #[test]
    fn test_mmio_bus_default() {
        let bus = MmioBus::default();
        assert_eq!(bus.device_count(), 0);
    }

    #[test]
    fn test_irq_accessor() {
        let transport = make_transport();
        assert_eq!(transport.irq(), 5);
    }

    #[test]
    fn test_queue_select_invalid_returns_zero() {
        let mut transport = make_transport();
        // MockDevice has 2 queues (indices 0 and 1). Select index 99.
        write_u32(&mut transport, reg::QUEUE_SEL, 99);
        assert_eq!(read_u32(&transport, reg::QUEUE_NUM_MAX), 0);
        assert_eq!(read_u32(&transport, reg::QUEUE_READY), 0);
    }
}
