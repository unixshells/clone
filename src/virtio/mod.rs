pub mod balloon;
pub mod block;
pub mod fs;
pub mod mmio;
pub mod net;
pub mod queue;
pub mod vsock;

/// MMIO base address for virtio devices. Each device occupies 0x200 bytes.
pub const MMIO_BASE: u64 = 0xd000_0000;
/// Stride between virtio MMIO device regions.
pub const MMIO_STRIDE: u64 = 0x200;
/// First IRQ number for virtio devices.
pub const IRQ_BASE: u32 = 5;
/// Maximum number of virtio devices we support.
pub const MAX_DEVICES: usize = 8;

/// Virtio device status bits (virtio spec 2.1).
pub mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
    pub const DEVICE_NEEDS_RESET: u32 = 64;
    pub const FAILED: u32 = 128;
}

/// Virtio device type IDs (virtio spec 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceType {
    Net = 1,
    Block = 2,
    Console = 3,
    Balloon = 5,
    Vsock = 19,
    Fs = 26,
}

/// Queue configuration info passed to devices before activation.
///
/// Contains the virtqueue addresses and size as configured by the guest
/// driver. Used by vhost devices to set up kernel-side virtqueue access.
#[derive(Debug, Clone, Default)]
pub struct QueueInfo {
    pub size: u16,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
}

/// Trait that all virtio devices must implement.
///
/// The MMIO transport calls into this trait to handle device-specific
/// configuration and I/O. Each device provides its own config space,
/// feature bits, and queue processing logic.
pub trait VirtioDevice: Send {
    /// Returns the virtio device type ID.
    fn device_type(&self) -> DeviceType;

    /// Returns the maximum size for each virtqueue.
    /// The length of the returned slice determines the number of queues.
    fn queue_max_sizes(&self) -> &[u16];

    /// Returns the device feature bits (both low and high 32-bit selects).
    /// `page` is 0 for bits 0-31, 1 for bits 32-63.
    fn features(&self, page: u32) -> u32;

    /// Called when the driver acknowledges features.
    /// `page` is 0 for bits 0-31, 1 for bits 32-63.
    fn ack_features(&mut self, page: u32, value: u32);

    /// Read from the device-specific configuration space.
    /// `offset` is relative to the start of the config space.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Write to the device-specific configuration space.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Activate the device after the driver has finished setup.
    /// Called when device status transitions to DRIVER_OK.
    fn activate(&mut self) -> anyhow::Result<()>;

    /// Process a notification on the given queue index.
    fn process_queue(&mut self, queue_index: u16) -> anyhow::Result<()>;

    /// Process a single descriptor chain from the virtqueue.
    ///
    /// Called by the MMIO transport for each available descriptor chain.
    /// `queue_index` identifies which virtqueue the chain came from.
    /// The device reads data from readable descriptors and writes results
    /// to writable descriptors using the virtqueue's guest memory access
    /// methods. Returns the total number of bytes written to writable
    /// descriptors.
    ///
    /// The default implementation does nothing (suitable for devices that
    /// handle I/O entirely in `process_queue`).
    fn process_descriptor_chain(
        &mut self,
        _queue_index: u16,
        _chain: &crate::virtio::queue::DescriptorChain,
        _vq: &crate::virtio::queue::Virtqueue,
    ) -> u32 {
        0
    }

    /// Whether the transport should process descriptor chains for this queue.
    /// Return false for queues that are managed externally (e.g., net RX queue
    /// is filled by a TAP reader thread, not by the transport).
    fn transport_processes_queue(&self, _queue_index: u16) -> bool {
        true
    }

    /// Called by the transport before activate() with queue configuration
    /// and guest memory info. Devices that need queue addresses (e.g., for
    /// vhost setup) should store this information for use in activate().
    fn prepare_activate(&mut self, _queues: &[QueueInfo], _guest_mem: *mut u8, _mem_size: u64) {}

    /// Set MMIO hole info for GPA-to-HVA translation on large VMs.
    /// Called before activate() for VMs with >3GB RAM.
    fn set_memory_hole(&mut self, _hole_start: u64, _hole_end: u64) {}

    /// Reset the device to initial state.
    fn reset(&mut self);

    /// Snapshot the device-specific state as an opaque byte vector.
    ///
    /// The default implementation returns an empty vector (no state to save).
    fn snapshot_state(&self) -> Vec<u8> { Vec::new() }

    /// Restore device-specific state from a previously-snapshotted byte vector.
    ///
    /// The default implementation accepts any input and does nothing.
    fn restore_state(&mut self, _data: &[u8]) -> anyhow::Result<()> { Ok(()) }
}
