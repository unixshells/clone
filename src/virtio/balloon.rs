//! Virtio-balloon device (VIRTIO_ID_BALLOON = 5).
//!
//! Cooperatively reclaims guest memory via the inflate/deflate model:
//! - **Inflate queue (0)**: guest returns page frame numbers (PFNs). The VMM
//!   calls `madvise(MADV_DONTNEED)` on the corresponding host virtual
//!   addresses, releasing physical pages back to the host.
//! - **Deflate queue (1)**: guest requests pages back. No action needed — the
//!   pages will fault back in on access.
//!
//! The `BalloonController` ties the device to the `BalloonPolicy` state
//! machine, translating policy actions into config-space updates that the guest
//! driver observes.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use super::queue::{DescriptorChain, Virtqueue, VRING_DESC_F_WRITE};
use super::{DeviceType, VirtioDevice};

/// Feature bit: guest can deflate balloon on OOM.
pub const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u64 = 1 << 2;

/// Page size used by the balloon protocol (always 4 KiB).
const BALLOON_PAGE_SIZE: usize = 4096;

/// Maximum virtqueue size for balloon queues.
const QUEUE_MAX_SIZE: u16 = 128;

/// Queue indices.
const INFLATE_QUEUE: u16 = 0;
const DEFLATE_QUEUE: u16 = 1;

// ---------------------------------------------------------------------------
// Balloon config space
// ---------------------------------------------------------------------------

/// Virtio balloon config space (virtio spec §5.5.6).
///
/// ```text
/// offset  field
/// 0       num_pages  (r/w) — desired balloon size in 4 KiB pages
/// 4       actual     (r/w) — current balloon size reported by guest
/// ```
#[derive(Debug)]
pub struct BalloonConfig {
    /// Desired number of balloon pages (set by VMM).
    pub num_pages: Arc<AtomicU32>,
    /// Actual number of inflated pages (set by guest driver).
    pub actual: Arc<AtomicU32>,
}

impl BalloonConfig {
    pub fn new() -> Self {
        Self {
            num_pages: Arc::new(AtomicU32::new(0)),
            actual: Arc::new(AtomicU32::new(0)),
        }
    }
}

impl Default for BalloonConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// VirtioBalloon device
// ---------------------------------------------------------------------------

/// State for the virtio-balloon device.
pub struct VirtioBalloon {
    config: BalloonConfig,
    avail_features: u64,
    acked_features: u64,

    /// Base host virtual address of guest memory. Used to translate guest PFNs
    /// to host pointers for `madvise`.
    guest_mem_base: *mut u8,
    guest_mem_size: u64,

    /// Whether the device has been activated by the driver.
    activated: bool,

    /// Set to `true` when config space changes and the guest should be notified
    /// via a config-change interrupt.
    pub config_interrupt_pending: bool,
}

// SAFETY: The raw pointer is a guest-memory base managed exclusively by the VMM.
unsafe impl Send for VirtioBalloon {}

impl VirtioBalloon {
    /// Create a new balloon device.
    ///
    /// # Arguments
    /// * `guest_mem_base` — host virtual address where guest physical address 0
    ///   is mapped.
    /// * `guest_mem_size` — total size of the guest memory mapping in bytes.
    pub fn new(guest_mem_base: *mut u8, guest_mem_size: u64) -> Self {
        Self {
            config: BalloonConfig::new(),
            avail_features: VIRTIO_BALLOON_F_DEFLATE_ON_OOM | (1u64 << 32), // + VIRTIO_F_VERSION_1
            acked_features: 0,
            guest_mem_base,
            guest_mem_size,
            activated: false,
            config_interrupt_pending: false,
        }
    }

    /// Called by the policy / controller to set the desired balloon size.
    /// Updates the config space and flags a config-change interrupt.
    pub fn update_target(&mut self, num_pages: u32) {
        let old = self.config.num_pages.load(Ordering::Relaxed);
        if old != num_pages {
            self.config.num_pages.store(num_pages, Ordering::Release);
            self.config_interrupt_pending = true;
            tracing::info!(
                old_pages = old,
                new_pages = num_pages,
                "balloon target updated"
            );
        }
    }

    /// Process the inflate queue — guest is returning pages to the host.
    ///
    /// Each entry in the queue is a buffer of `u32` PFNs. For each PFN we
    /// advise the kernel that the corresponding host page is no longer needed.
    pub fn process_inflate(&mut self, pfns: &[u32]) {
        let mut inflated = 0u32;
        for &pfn in pfns {
            let guest_addr = pfn as u64 * BALLOON_PAGE_SIZE as u64;
            if guest_addr + BALLOON_PAGE_SIZE as u64 > self.guest_mem_size {
                tracing::warn!(pfn, "inflate: PFN out of range, skipping");
                continue;
            }

            #[cfg(target_os = "linux")]
            {
                // SAFETY: guest_mem_base + guest_addr is within the mmap region
                // and MADV_DONTNEED is safe on anonymous mappings.
                let ret = unsafe {
                    libc::madvise(
                        self.guest_mem_base.add(guest_addr as usize) as *mut libc::c_void,
                        BALLOON_PAGE_SIZE,
                        libc::MADV_DONTNEED,
                    )
                };
                if ret != 0 {
                    tracing::warn!(pfn, "madvise(MADV_DONTNEED) failed");
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                // madvise(MADV_DONTNEED) semantics differ on macOS; just log.
                let _ = guest_addr;
                tracing::debug!(pfn, "inflate: no-op on non-Linux");
            }

            inflated += 1;
        }

        // Update the actual count — only count pages that were in range.
        let current = self.config.actual.load(Ordering::Relaxed);
        let new_actual = current.saturating_add(inflated);
        self.config.actual.store(new_actual, Ordering::Release);

        tracing::debug!(inflated, actual = new_actual, "inflate: processed");
    }

    /// Process the deflate queue — guest is reclaiming pages.
    ///
    /// No host-side action is required; the pages will be demand-faulted when
    /// the guest accesses them. We just update the actual counter.
    pub fn process_deflate(&mut self, pfns: &[u32]) {
        let current = self.config.actual.load(Ordering::Relaxed);
        let new_actual = current.saturating_sub(pfns.len() as u32);
        self.config.actual.store(new_actual, Ordering::Release);

        tracing::debug!(pfn_count = pfns.len(), actual = new_actual, "deflate: processed");
    }

    /// Get a reference to the config for external inspection.
    pub fn config(&self) -> &BalloonConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// VirtioDevice trait implementation
// ---------------------------------------------------------------------------

impl VirtioDevice for VirtioBalloon {
    fn device_type(&self) -> DeviceType {
        DeviceType::Balloon
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &[QUEUE_MAX_SIZE; 2] // inflate + deflate
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            0 => self.avail_features as u32,
            1 => (self.avail_features >> 32) as u32,
            _ => 0,
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mask = match page {
            0 => value as u64,
            1 => (value as u64) << 32,
            _ => return,
        };
        self.acked_features |= self.avail_features & mask;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config layout: [num_pages: le32, actual: le32]
        let num_pages = self.config.num_pages.load(Ordering::Relaxed);
        let actual = self.config.actual.load(Ordering::Relaxed);

        let config_bytes = {
            let mut buf = [0u8; 8];
            buf[0..4].copy_from_slice(&num_pages.to_le_bytes());
            buf[4..8].copy_from_slice(&actual.to_le_bytes());
            buf
        };

        let offset = offset as usize;
        if offset < config_bytes.len() {
            let end = std::cmp::min(offset + data.len(), config_bytes.len());
            let len = end - offset;
            data[..len].copy_from_slice(&config_bytes[offset..end]);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let offset = offset as usize;
        if offset >= 8 {
            return;
        }

        // Read current config, overlay the write, store back.
        let mut config_bytes = [0u8; 8];
        config_bytes[0..4].copy_from_slice(
            &self.config.num_pages.load(Ordering::Relaxed).to_le_bytes(),
        );
        config_bytes[4..8].copy_from_slice(
            &self.config.actual.load(Ordering::Relaxed).to_le_bytes(),
        );

        let end = std::cmp::min(offset + data.len(), 8);
        config_bytes[offset..end].copy_from_slice(&data[..end - offset]);

        let num_pages = u32::from_le_bytes(config_bytes[0..4].try_into().unwrap());
        let actual = u32::from_le_bytes(config_bytes[4..8].try_into().unwrap());

        self.config.num_pages.store(num_pages, Ordering::Release);
        self.config.actual.store(actual, Ordering::Release);
    }

    fn activate(&mut self) -> anyhow::Result<()> {
        self.activated = true;
        tracing::info!("virtio-balloon activated");
        Ok(())
    }

    fn process_queue(&mut self, queue_index: u16) -> anyhow::Result<()> {
        match queue_index {
            INFLATE_QUEUE => {
                // Descriptor chain processing is handled by process_descriptor_chain.
                tracing::debug!("inflate queue notified");
            }
            DEFLATE_QUEUE => {
                tracing::debug!("deflate queue notified");
            }
            _ => {
                tracing::warn!(queue_index, "balloon: unexpected queue index");
            }
        }
        Ok(())
    }

    fn process_descriptor_chain(
        &mut self,
        queue_index: u16,
        chain: &DescriptorChain,
        vq: &Virtqueue,
    ) -> u32 {
        // Balloon descriptors contain arrays of u32 PFNs.
        // All descriptors in the chain are readable (guest provides PFN data).
        let mut pfns = Vec::new();

        for desc in &chain.descriptors {
            if desc.flags & VRING_DESC_F_WRITE != 0 {
                continue; // Skip writable descriptors
            }

            if let Some(data) = vq.read_descriptor_data(desc) {
                // Each PFN is a u32 (4 bytes)
                let count = data.len() / 4;
                for i in 0..count {
                    let off = i * 4;
                    let pfn = u32::from_le_bytes([
                        data[off], data[off + 1], data[off + 2], data[off + 3],
                    ]);
                    pfns.push(pfn);
                }
            }
        }

        if !pfns.is_empty() {
            match queue_index {
                INFLATE_QUEUE => self.process_inflate(&pfns),
                DEFLATE_QUEUE => self.process_deflate(&pfns),
                _ => {
                    tracing::warn!(queue_index, "balloon: unexpected queue in descriptor chain");
                }
            }
        }

        0 // Balloon doesn't write data back to descriptors
    }

    fn reset(&mut self) {
        self.config.num_pages.store(0, Ordering::Release);
        self.config.actual.store(0, Ordering::Release);
        self.acked_features = 0;
        self.activated = false;
        self.config_interrupt_pending = false;
        tracing::info!("virtio-balloon reset");
    }

    fn snapshot_state(&self) -> Vec<u8> {
        let state = serde_json::json!({
            "num_pages": self.config.num_pages.load(std::sync::atomic::Ordering::Relaxed),
            "actual": self.config.actual.load(std::sync::atomic::Ordering::Relaxed),
            "acked_features": self.acked_features,
        });
        serde_json::to_vec(&state).unwrap_or_default()
    }

    fn restore_state(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() { return Ok(()); }
        let state: serde_json::Value = serde_json::from_slice(data)?;
        if let Some(v) = state.get("num_pages").and_then(|v| v.as_u64()) {
            self.config.num_pages.store(v as u32, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(v) = state.get("actual").and_then(|v| v.as_u64()) {
            self.config.actual.store(v as u32, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(v) = state.get("acked_features").and_then(|v| v.as_u64()) {
            self.acked_features = v;
        }
        Ok(())
    }
}

// NOTE: BalloonController was previously here as a wrapper that owned the device.
// The VMM instead uses BalloonPolicy directly in the balloon-tick thread
// (vmm/mod.rs) because the device is owned by the MMIO bus, not the controller.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn make_device() -> VirtioBalloon {
        // Null pointer is fine — we won't call madvise in tests (non-Linux).
        VirtioBalloon::new(ptr::null_mut(), 512 * 1024 * 1024)
    }

    #[test]
    fn device_type_is_balloon() {
        let dev = make_device();
        assert_eq!(dev.device_type(), DeviceType::Balloon);
    }

    #[test]
    fn two_queues() {
        let dev = make_device();
        assert_eq!(dev.queue_max_sizes().len(), 2);
    }

    #[test]
    fn features_include_deflate_on_oom() {
        let dev = make_device();
        let low = dev.features(0);
        assert_ne!(low & (VIRTIO_BALLOON_F_DEFLATE_ON_OOM as u32), 0);
    }

    #[test]
    fn config_read_write_roundtrip() {
        let mut dev = make_device();

        // Set target to 1000 pages.
        dev.update_target(1000);

        let mut buf = [0u8; 4];
        dev.read_config(0, &mut buf);
        assert_eq!(u32::from_le_bytes(buf), 1000);

        // Guest writes actual = 500 at offset 4.
        dev.write_config(4, &500u32.to_le_bytes());
        let mut buf2 = [0u8; 4];
        dev.read_config(4, &mut buf2);
        assert_eq!(u32::from_le_bytes(buf2), 500);
    }

    #[test]
    fn inflate_updates_actual() {
        let mut dev = make_device();
        assert_eq!(dev.config.actual.load(Ordering::Relaxed), 0);

        dev.process_inflate(&[10, 20, 30]);
        assert_eq!(dev.config.actual.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn deflate_updates_actual() {
        let mut dev = make_device();
        dev.config.actual.store(10, Ordering::Relaxed);

        dev.process_deflate(&[1, 2, 3]);
        assert_eq!(dev.config.actual.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn inflate_skips_out_of_range_pfn() {
        let mut dev = make_device();
        // 512 MiB = 131072 pages, PFN 200000 is out of range.
        dev.process_inflate(&[200000]);
        assert_eq!(dev.config.actual.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn update_target_sets_interrupt() {
        let mut dev = make_device();
        assert!(!dev.config_interrupt_pending);

        dev.update_target(42);
        assert!(dev.config_interrupt_pending);
    }

    #[test]
    fn update_target_no_interrupt_if_unchanged() {
        let mut dev = make_device();
        dev.update_target(42);
        dev.config_interrupt_pending = false;

        dev.update_target(42); // same value
        assert!(!dev.config_interrupt_pending);
    }

    #[test]
    fn reset_clears_state() {
        let mut dev = make_device();
        dev.update_target(100);
        dev.config.actual.store(50, Ordering::Relaxed);
        dev.acked_features = 0xFF;

        dev.reset();

        assert_eq!(dev.config.num_pages.load(Ordering::Relaxed), 0);
        assert_eq!(dev.config.actual.load(Ordering::Relaxed), 0);
        assert_eq!(dev.acked_features, 0);
        assert!(!dev.config_interrupt_pending);
    }

    #[test]
    fn process_queue_handles_unknown_index() {
        let mut dev = make_device();
        // Should not panic, just log a warning.
        assert!(dev.process_queue(99).is_ok());
    }

    #[test]
    fn ack_features_masks_correctly() {
        let mut dev = make_device();
        // Ack a feature we offer.
        dev.ack_features(0, VIRTIO_BALLOON_F_DEFLATE_ON_OOM as u32);
        assert_eq!(dev.acked_features, VIRTIO_BALLOON_F_DEFLATE_ON_OOM);

        // Ack a feature we don't offer — should be masked out.
        dev.acked_features = 0;
        dev.ack_features(0, 0xFFFF_FFFF);
        assert_eq!(dev.acked_features, VIRTIO_BALLOON_F_DEFLATE_ON_OOM);
    }
}
