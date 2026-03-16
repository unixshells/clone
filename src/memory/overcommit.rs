/// Overcommit tracking for guest memory.
///
/// Tracks which pages have been touched (diverged from zero/template).
/// Used for:
/// - Billing: charge only for private pages
/// - Monitoring: overcommit ratio per host
/// - Dirty page tracking for incremental snapshots

pub struct OvercommitTracker {
    /// Total guest pages
    total_pages: u64,
    /// Estimated private (touched) pages — updated periodically
    private_pages: u64,
}

impl OvercommitTracker {
    pub fn new(total_pages: u64) -> Self {
        Self {
            total_pages,
            private_pages: 0,
        }
    }

    /// Update private page count from /proc/self/smaps or mincore.
    pub fn refresh(&mut self, mem_ptr: *const u8, mem_size: u64) {
        // Use mincore() to check which pages are resident in physical memory
        let page_count = (mem_size / 4096) as usize;
        let mut vec = vec![0u8; page_count];

        let resident = unsafe {
            let ret = libc::mincore(
                mem_ptr as *mut libc::c_void,
                mem_size as usize,
                vec.as_mut_ptr(),
            );
            if ret != 0 {
                tracing::warn!("mincore failed: {}", std::io::Error::last_os_error());
                return;
            }
            vec.iter().filter(|&&v| v & 1 != 0).count() as u64
        };

        self.private_pages = resident;
    }

    pub fn private_pages(&self) -> u64 {
        self.private_pages
    }

    pub fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Effective memory usage in bytes (for billing).
    pub fn effective_bytes(&self) -> u64 {
        self.private_pages * 4096
    }

    pub fn overcommit_ratio(&self) -> f64 {
        if self.private_pages == 0 {
            return self.total_pages as f64;
        }
        self.total_pages as f64 / self.private_pages as f64
    }
}

/// Tracks dirty pages via KVM's dirty page logging.
///
/// Used for incremental snapshots: only changed pages are dumped,
/// reducing snapshot size and time by 10-100x for warm VMs.
#[cfg(target_os = "linux")]
pub struct DirtyPageTracker {
    /// Total guest pages.
    total_pages: u64,
    /// Total guest memory size in bytes.
    mem_size: u64,
}

#[cfg(target_os = "linux")]
impl DirtyPageTracker {
    pub fn new(mem_size: u64) -> Self {
        Self {
            total_pages: mem_size / 4096,
            mem_size,
        }
    }

    /// Get the dirty page bitmap from KVM.
    ///
    /// The bitmap has one bit per page. A set bit means the page was written
    /// since the last call to get_dirty_bitmap (or since dirty logging was enabled).
    pub fn get_dirty_bitmap(&self, vm_fd: &kvm_ioctls::VmFd) -> anyhow::Result<Vec<u8>> {
        let bitmap = vm_fd.get_dirty_log(0, self.mem_size as usize)
            .map_err(|e| anyhow::anyhow!("get_dirty_log failed: {e}"))?;

        // Convert the kvm dirty log bitmap to a byte vec
        // KVM returns a bitmap where each bit represents a page
        let bitmap_size = ((self.total_pages + 63) / 64 * 8) as usize;
        let mut result = vec![0u8; bitmap_size];

        // The dirty log is returned as a Vec<u64> of atomic bitmap words
        for (i, &word) in bitmap.iter().enumerate() {
            let offset = i * 8;
            if offset + 8 <= result.len() {
                result[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
            }
        }

        let dirty_count = result.iter().map(|b| b.count_ones() as u64).sum::<u64>();
        tracing::info!(
            dirty_pages = dirty_count,
            total_pages = self.total_pages,
            "Dirty page bitmap collected"
        );

        Ok(result)
    }

    /// Extract only the dirty pages from guest memory.
    ///
    /// `usable_mem_size` limits page collection to only the usable guest memory
    /// (excluding guard regions). The full bitmap is still fetched from KVM.
    pub fn collect_dirty_pages(
        &self,
        vm_fd: &kvm_ioctls::VmFd,
        guest_mem: *const u8,
        usable_mem_size: u64,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let bitmap = self.get_dirty_bitmap(vm_fd)?;

        // Only collect pages within usable memory (not guard region)
        let usable_pages = usable_mem_size / 4096;
        let collect_pages = std::cmp::min(self.total_pages, usable_pages);

        // Count dirty pages first to pre-allocate
        let mut dirty_count: u64 = 0;
        for page_idx in 0..collect_pages {
            let byte_idx = (page_idx / 8) as usize;
            let bit_idx = (page_idx % 8) as u8;
            if byte_idx < bitmap.len() && (bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                dirty_count += 1;
            }
        }
        let mut dirty_data = Vec::with_capacity((dirty_count as usize) * 4096);
        for page_idx in 0..collect_pages {
            let byte_idx = (page_idx / 8) as usize;
            let bit_idx = (page_idx % 8) as u8;

            if byte_idx < bitmap.len() && (bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                let offset = page_idx * 4096;
                let page_data = unsafe {
                    std::slice::from_raw_parts(guest_mem.add(offset as usize), 4096)
                };
                dirty_data.extend_from_slice(page_data);
            }
        }

        tracing::info!(
            dirty_data_size = dirty_data.len(),
            "Collected dirty page data"
        );

        Ok((bitmap, dirty_data))
    }
}
