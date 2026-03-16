//! Virtqueue implementation for virtio devices.
//!
//! Reads/writes guest memory to process descriptor chains from the
//! available ring and post completions to the used ring, per the
//! virtio specification (sections 2.6 and 2.7).

/// Descriptor flag: buffer continues via the `next` field.
pub const VRING_DESC_F_NEXT: u16 = 1;
/// Descriptor flag: buffer is device-writable (guest reads after device writes).
pub const VRING_DESC_F_WRITE: u16 = 2;

/// Size of a single descriptor table entry in bytes.
const DESC_SIZE: u64 = 16;
/// Offset of `flags` field within the avail ring (past the flags+idx header).
const AVAIL_RING_HEADER: u64 = 4; // flags(u16) + idx(u16)
/// Size of a used ring element: id(u32) + len(u32).
const USED_ELEM_SIZE: u64 = 8;
/// Offset of the ring array within the used ring (past flags+idx header).
const USED_RING_HEADER: u64 = 4; // flags(u16) + idx(u16)

/// A single virtio descriptor from the descriptor table.
#[derive(Debug, Clone)]
pub struct Descriptor {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (VRING_DESC_F_NEXT, VRING_DESC_F_WRITE).
    pub flags: u16,
    /// Index of the next descriptor if VRING_DESC_F_NEXT is set.
    pub next: u16,
}

/// A chain of descriptors starting from a head index in the available ring.
#[derive(Debug)]
pub struct DescriptorChain {
    /// Head descriptor index (used when pushing to the used ring).
    pub index: u16,
    /// All descriptors in the chain, walked via the `next` field.
    pub descriptors: Vec<Descriptor>,
}

/// Virtqueue state — reads/writes guest memory to process I/O.
///
/// The queue itself lives in guest memory; this struct tracks the guest
/// physical addresses and a host pointer to the guest memory region so
/// we can read the avail ring, walk descriptor chains, and write the
/// used ring.
pub struct Virtqueue {
    /// Queue size (number of descriptors).
    size: u16,
    /// Whether the queue has been marked ready by the driver.
    ready: bool,
    /// Guest physical address of the descriptor table.
    desc_table: u64,
    /// Guest physical address of the available ring.
    avail_ring: u64,
    /// Guest physical address of the used ring.
    used_ring: u64,
    /// Last index we consumed from the available ring.
    last_avail_idx: u16,
    /// Host pointer to guest physical address 0.
    guest_mem: *mut u8,
    /// Total size of the guest memory region.
    guest_mem_size: u64,
}

// SAFETY: The raw pointer is managed exclusively by the VMM.
unsafe impl Send for Virtqueue {}

impl Virtqueue {
    /// Create a new virtqueue with the given size and guest memory region.
    ///
    /// The queue starts unconfigured (addresses zeroed) and not ready.
    pub fn new(size: u16, guest_mem: *mut u8, guest_mem_size: u64) -> Self {
        Self {
            size,
            ready: false,
            desc_table: 0,
            avail_ring: 0,
            used_ring: 0,
            last_avail_idx: 0,
            guest_mem,
            guest_mem_size,
        }
    }

    /// Configure the three ring area addresses.
    pub fn configure(&mut self, desc_table: u64, avail_ring: u64, used_ring: u64) {
        self.desc_table = desc_table;
        self.avail_ring = avail_ring;
        self.used_ring = used_ring;
    }

    /// Mark the queue as ready (or not).
    pub fn set_ready(&mut self, ready: bool) {
        self.ready = ready;
    }

    /// Returns whether the queue is ready.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// Reset the queue to its initial state (called on device reset).
    pub fn reset(&mut self) {
        self.ready = false;
        self.desc_table = 0;
        self.avail_ring = 0;
        self.used_ring = 0;
        self.last_avail_idx = 0;
    }

    // --- Guest memory helpers ---

    /// Read bytes from guest memory at the given guest physical address.
    /// Returns `None` if the access is out of bounds.
    fn guest_read(&self, gpa: u64, len: u64) -> Option<&[u8]> {
        if gpa.checked_add(len)? > self.guest_mem_size {
            return None;
        }
        if self.guest_mem.is_null() {
            return None;
        }
        unsafe {
            Some(std::slice::from_raw_parts(
                self.guest_mem.add(gpa as usize),
                len as usize,
            ))
        }
    }

    /// Get a mutable slice of guest memory at the given GPA.
    fn guest_write(&self, gpa: u64, len: u64) -> Option<&mut [u8]> {
        if gpa.checked_add(len)? > self.guest_mem_size {
            return None;
        }
        if self.guest_mem.is_null() {
            return None;
        }
        unsafe {
            Some(std::slice::from_raw_parts_mut(
                self.guest_mem.add(gpa as usize),
                len as usize,
            ))
        }
    }

    fn read_u16(&self, gpa: u64) -> Option<u16> {
        let bytes = self.guest_read(gpa, 2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&self, gpa: u64) -> Option<u32> {
        let bytes = self.guest_read(gpa, 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&self, gpa: u64) -> Option<u64> {
        let bytes = self.guest_read(gpa, 8)?;
        Some(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn write_u16(&self, gpa: u64, val: u16) -> Option<()> {
        let slice = self.guest_write(gpa, 2)?;
        slice.copy_from_slice(&val.to_le_bytes());
        Some(())
    }

    fn write_u32(&self, gpa: u64, val: u32) -> Option<()> {
        let slice = self.guest_write(gpa, 4)?;
        slice.copy_from_slice(&val.to_le_bytes());
        Some(())
    }

    // --- Avail ring operations ---

    /// Check if the guest has placed new buffers in the available ring.
    pub fn has_available(&self) -> bool {
        if !self.ready || self.guest_mem.is_null() {
            return false;
        }
        // avail.idx is at avail_ring + 2 (after the flags field)
        let avail_idx = match self.read_u16(self.avail_ring + 2) {
            Some(v) => v,
            None => return false,
        };
        avail_idx != self.last_avail_idx
    }

    /// Pop the next available descriptor chain from the avail ring.
    ///
    /// Returns `None` if no new entries are available or if a bounds check fails.
    pub fn pop_avail(&mut self) -> Option<DescriptorChain> {
        if !self.ready || self.guest_mem.is_null() {
            return None;
        }

        // Read avail.idx
        let avail_idx = self.read_u16(self.avail_ring + 2)?;
        if avail_idx == self.last_avail_idx {
            return None;
        }

        // Read the head descriptor index from avail.ring[last_avail_idx % size]
        let ring_entry_offset = (self.last_avail_idx % self.size) as u64;
        let head_idx = self.read_u16(
            self.avail_ring + AVAIL_RING_HEADER + ring_entry_offset * 2,
        )?;

        // Walk the descriptor chain
        let mut descriptors = Vec::new();
        let mut idx = head_idx;
        let mut seen = 0u32;

        loop {
            if idx >= self.size {
                tracing::warn!("Descriptor index {idx} out of range (size={})", self.size);
                return None;
            }
            if seen >= self.size as u32 {
                tracing::warn!("Descriptor chain loop detected");
                return None;
            }

            let desc_gpa = self.desc_table + (idx as u64) * DESC_SIZE;
            let addr = self.read_u64(desc_gpa)?;
            let len = self.read_u32(desc_gpa + 8)?;
            let flags = self.read_u16(desc_gpa + 12)?;
            let next = self.read_u16(desc_gpa + 14)?;

            descriptors.push(Descriptor { addr, len, flags, next });
            seen += 1;

            if flags & VRING_DESC_F_NEXT != 0 {
                idx = next;
            } else {
                break;
            }
        }

        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);

        Some(DescriptorChain {
            index: head_idx,
            descriptors,
        })
    }

    /// Push a completion entry to the used ring.
    ///
    /// `desc_index` is the head descriptor index (from `DescriptorChain::index`).
    /// `bytes_written` is the total number of bytes the device wrote into
    /// writable descriptors.
    pub fn push_used(&mut self, desc_index: u16, bytes_written: u32) -> Option<()> {
        if !self.ready || self.guest_mem.is_null() {
            return None;
        }

        // Read current used.idx
        let used_idx = self.read_u16(self.used_ring + 2)?;
        let ring_entry = (used_idx % self.size) as u64;

        // Write used.ring[used_idx % size] = { id: desc_index, len: bytes_written }
        let elem_gpa = self.used_ring + USED_RING_HEADER + ring_entry * USED_ELEM_SIZE;
        self.write_u32(elem_gpa, desc_index as u32)?;
        self.write_u32(elem_gpa + 4, bytes_written)?;

        // Increment used.idx
        // Use a memory fence to ensure the ring entry is visible before idx update
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        self.write_u16(self.used_ring + 2, used_idx.wrapping_add(1))?;

        Some(())
    }

    /// Check whether the guest wants to be notified (interrupt) when we
    /// add entries to the used ring.
    ///
    /// The guest sets VRING_AVAIL_F_NO_INTERRUPT (bit 0 of avail.flags) to
    /// suppress notifications. If that bit is clear, we should notify.
    pub fn needs_notification(&self) -> bool {
        if !self.ready || self.guest_mem.is_null() {
            return false;
        }
        // avail.flags is at avail_ring + 0
        let flags = match self.read_u16(self.avail_ring) {
            Some(v) => v,
            None => return true, // If we can't read, err on the side of notifying
        };
        // Bit 0 = VRING_AVAIL_F_NO_INTERRUPT
        flags & 1 == 0
    }

    /// Read from a guest buffer described by a descriptor.
    ///
    /// Returns a slice of the guest memory at the descriptor's address.
    pub fn read_descriptor_data(&self, desc: &Descriptor) -> Option<&[u8]> {
        self.guest_read(desc.addr, desc.len as u64)
    }

    /// Get a mutable slice for a writable descriptor's guest buffer.
    pub fn write_descriptor_data(&self, desc: &Descriptor) -> Option<&mut [u8]> {
        self.guest_write(desc.addr, desc.len as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a fake guest memory region with rings set up.
    ///
    /// Layout in the buffer:
    ///   0x0000 - descriptor table (16 bytes per entry)
    ///   0x1000 - avail ring
    ///   0x2000 - used ring
    ///   0x3000 - data buffers
    struct FakeGuest {
        mem: Vec<u8>,
        queue_size: u16,
    }

    const DESC_BASE: u64 = 0x0000;
    const AVAIL_BASE: u64 = 0x1000;
    const USED_BASE: u64 = 0x2000;
    const DATA_BASE: u64 = 0x3000;
    const MEM_SIZE: usize = 0x8000;

    impl FakeGuest {
        fn new(queue_size: u16) -> Self {
            Self {
                mem: vec![0u8; MEM_SIZE],
                queue_size,
            }
        }

        fn ptr(&mut self) -> *mut u8 {
            self.mem.as_mut_ptr()
        }

        fn write_u16(&mut self, offset: u64, val: u16) {
            let off = offset as usize;
            self.mem[off..off + 2].copy_from_slice(&val.to_le_bytes());
        }

        fn write_u32(&mut self, offset: u64, val: u32) {
            let off = offset as usize;
            self.mem[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }

        fn write_u64(&mut self, offset: u64, val: u64) {
            let off = offset as usize;
            self.mem[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }

        fn read_u16(&self, offset: u64) -> u16 {
            let off = offset as usize;
            u16::from_le_bytes([self.mem[off], self.mem[off + 1]])
        }

        fn read_u32(&self, offset: u64) -> u32 {
            let off = offset as usize;
            u32::from_le_bytes([
                self.mem[off], self.mem[off + 1],
                self.mem[off + 2], self.mem[off + 3],
            ])
        }

        /// Write a descriptor at the given index in the descriptor table.
        fn write_desc(&mut self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
            let base = DESC_BASE + (idx as u64) * DESC_SIZE;
            self.write_u64(base, addr);
            self.write_u32(base + 8, len);
            self.write_u16(base + 12, flags);
            self.write_u16(base + 14, next);
        }

        /// Add an entry to the avail ring. `avail_idx` should be the current
        /// avail.idx before incrementing.
        fn push_avail(&mut self, avail_idx: u16, desc_idx: u16) {
            let ring_off = AVAIL_BASE + AVAIL_RING_HEADER + (avail_idx % self.queue_size) as u64 * 2;
            self.write_u16(ring_off, desc_idx);
            // Update avail.idx
            self.write_u16(AVAIL_BASE + 2, avail_idx.wrapping_add(1));
        }

        /// Create a virtqueue pointing at our fake memory.
        fn make_queue(&mut self) -> Virtqueue {
            let ptr = self.ptr();
            let mut q = Virtqueue::new(self.queue_size, ptr, MEM_SIZE as u64);
            q.configure(DESC_BASE, AVAIL_BASE, USED_BASE);
            q.set_ready(true);
            q
        }
    }

    #[test]
    fn test_new_queue_not_ready() {
        let q = Virtqueue::new(128, std::ptr::null_mut(), 0);
        assert!(!q.is_ready());
        assert!(!q.has_available());
    }

    #[test]
    fn test_set_ready() {
        let mut q = Virtqueue::new(128, std::ptr::null_mut(), 0);
        q.set_ready(true);
        assert!(q.is_ready());
        q.set_ready(false);
        assert!(!q.is_ready());
    }

    #[test]
    fn test_has_available_empty() {
        let mut guest = FakeGuest::new(16);
        let q = guest.make_queue();
        assert!(!q.has_available());
    }

    #[test]
    fn test_pop_avail_empty() {
        let mut guest = FakeGuest::new(16);
        let mut q = guest.make_queue();
        assert!(q.pop_avail().is_none());
    }

    #[test]
    fn test_single_descriptor_chain() {
        let mut guest = FakeGuest::new(16);

        // Set up a single descriptor at index 0 pointing to DATA_BASE
        guest.write_desc(0, DATA_BASE, 512, 0, 0);
        // Put it in the avail ring
        guest.push_avail(0, 0);

        let mut q = guest.make_queue();

        assert!(q.has_available());
        let chain = q.pop_avail().unwrap();
        assert_eq!(chain.index, 0);
        assert_eq!(chain.descriptors.len(), 1);
        assert_eq!(chain.descriptors[0].addr, DATA_BASE);
        assert_eq!(chain.descriptors[0].len, 512);
        assert_eq!(chain.descriptors[0].flags, 0);

        // Should be empty now
        assert!(!q.has_available());
        assert!(q.pop_avail().is_none());
    }

    #[test]
    fn test_chained_descriptors() {
        let mut guest = FakeGuest::new(16);

        // Descriptor 0 -> Descriptor 1 -> Descriptor 2
        guest.write_desc(0, DATA_BASE, 16, VRING_DESC_F_NEXT, 1);
        guest.write_desc(1, DATA_BASE + 16, 512, VRING_DESC_F_NEXT | VRING_DESC_F_WRITE, 2);
        guest.write_desc(2, DATA_BASE + 528, 1, VRING_DESC_F_WRITE, 0);

        guest.push_avail(0, 0);

        let mut q = guest.make_queue();
        let chain = q.pop_avail().unwrap();

        assert_eq!(chain.index, 0);
        assert_eq!(chain.descriptors.len(), 3);

        // First: readable header
        assert_eq!(chain.descriptors[0].addr, DATA_BASE);
        assert_eq!(chain.descriptors[0].len, 16);
        assert_eq!(chain.descriptors[0].flags & VRING_DESC_F_WRITE, 0);

        // Second: writable data buffer
        assert_eq!(chain.descriptors[1].addr, DATA_BASE + 16);
        assert_eq!(chain.descriptors[1].len, 512);
        assert_ne!(chain.descriptors[1].flags & VRING_DESC_F_WRITE, 0);

        // Third: writable status byte
        assert_eq!(chain.descriptors[2].addr, DATA_BASE + 528);
        assert_eq!(chain.descriptors[2].len, 1);
        assert_ne!(chain.descriptors[2].flags & VRING_DESC_F_WRITE, 0);
    }

    #[test]
    fn test_push_used() {
        let mut guest = FakeGuest::new(16);

        guest.write_desc(0, DATA_BASE, 100, 0, 0);
        guest.push_avail(0, 0);

        let mut q = guest.make_queue();
        let chain = q.pop_avail().unwrap();

        // Push the used entry
        q.push_used(chain.index, 42).unwrap();

        // Verify used ring: used.idx should be 1
        let used_idx = guest.read_u16(USED_BASE + 2);
        assert_eq!(used_idx, 1);

        // used.ring[0].id should be 0 (the head descriptor index)
        let used_id = guest.read_u32(USED_BASE + USED_RING_HEADER);
        assert_eq!(used_id, 0);

        // used.ring[0].len should be 42
        let used_len = guest.read_u32(USED_BASE + USED_RING_HEADER + 4);
        assert_eq!(used_len, 42);
    }

    #[test]
    fn test_multiple_avail_entries() {
        let mut guest = FakeGuest::new(16);

        // Two separate single-descriptor chains
        guest.write_desc(0, DATA_BASE, 100, 0, 0);
        guest.write_desc(1, DATA_BASE + 100, 200, 0, 0);

        guest.push_avail(0, 0);
        guest.push_avail(1, 1);

        let mut q = guest.make_queue();

        let chain0 = q.pop_avail().unwrap();
        assert_eq!(chain0.index, 0);
        assert_eq!(chain0.descriptors[0].len, 100);

        let chain1 = q.pop_avail().unwrap();
        assert_eq!(chain1.index, 1);
        assert_eq!(chain1.descriptors[0].len, 200);

        assert!(q.pop_avail().is_none());
    }

    #[test]
    fn test_needs_notification_default() {
        let mut guest = FakeGuest::new(16);
        let q = guest.make_queue();
        // avail.flags = 0 by default, so notifications are desired
        assert!(q.needs_notification());
    }

    #[test]
    fn test_needs_notification_suppressed() {
        let mut guest = FakeGuest::new(16);
        // Set avail.flags = 1 (VRING_AVAIL_F_NO_INTERRUPT)
        guest.write_u16(AVAIL_BASE, 1);
        let q = guest.make_queue();
        assert!(!q.needs_notification());
    }

    #[test]
    fn test_read_descriptor_data() {
        let mut guest = FakeGuest::new(16);

        // Write some data at DATA_BASE
        let test_data = b"Hello, virtqueue!";
        let off = DATA_BASE as usize;
        guest.mem[off..off + test_data.len()].copy_from_slice(test_data);

        guest.write_desc(0, DATA_BASE, test_data.len() as u32, 0, 0);
        guest.push_avail(0, 0);

        let mut q = guest.make_queue();
        let chain = q.pop_avail().unwrap();

        let data = q.read_descriptor_data(&chain.descriptors[0]).unwrap();
        assert_eq!(data, test_data);
    }

    #[test]
    fn test_write_descriptor_data() {
        let mut guest = FakeGuest::new(16);

        guest.write_desc(0, DATA_BASE, 4, VRING_DESC_F_WRITE, 0);
        guest.push_avail(0, 0);

        let mut q = guest.make_queue();
        let chain = q.pop_avail().unwrap();

        let buf = q.write_descriptor_data(&chain.descriptors[0]).unwrap();
        buf.copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // Verify the data was written to guest memory
        let off = DATA_BASE as usize;
        assert_eq!(&guest.mem[off..off + 4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_wrapping_indices() {
        let mut guest = FakeGuest::new(4); // small queue

        // Fill up descriptors
        for i in 0..4u16 {
            guest.write_desc(i, DATA_BASE + (i as u64) * 64, 64, 0, 0);
        }

        // Push 4 entries and pop them all, then push 2 more (wrapping)
        for i in 0..4u16 {
            guest.push_avail(i, i);
        }

        let mut q = guest.make_queue();
        for _ in 0..4 {
            q.pop_avail().unwrap();
        }
        assert!(q.pop_avail().is_none());

        // Now push 2 more (avail_idx wraps around in the ring array)
        guest.push_avail(4, 0);
        guest.push_avail(5, 1);

        let chain = q.pop_avail().unwrap();
        assert_eq!(chain.index, 0);
        let chain = q.pop_avail().unwrap();
        assert_eq!(chain.index, 1);
    }

    #[test]
    fn test_reset() {
        let mut guest = FakeGuest::new(16);
        let mut q = guest.make_queue();

        q.reset();
        assert!(!q.is_ready());
        assert!(!q.has_available());
    }

    #[test]
    fn test_out_of_bounds_descriptor_index() {
        let mut guest = FakeGuest::new(4);

        // Push avail entry with descriptor index >= size
        guest.push_avail(0, 99);

        let mut q = guest.make_queue();
        // Should return None due to bounds check
        assert!(q.pop_avail().is_none());
    }

    #[test]
    fn test_push_used_multiple() {
        let mut guest = FakeGuest::new(16);

        guest.write_desc(0, DATA_BASE, 100, 0, 0);
        guest.write_desc(1, DATA_BASE + 100, 200, 0, 0);
        guest.push_avail(0, 0);
        guest.push_avail(1, 1);

        let mut q = guest.make_queue();

        let c0 = q.pop_avail().unwrap();
        q.push_used(c0.index, 10).unwrap();

        let c1 = q.pop_avail().unwrap();
        q.push_used(c1.index, 20).unwrap();

        // used.idx should be 2
        let used_idx = guest.read_u16(USED_BASE + 2);
        assert_eq!(used_idx, 2);

        // Check both entries
        assert_eq!(guest.read_u32(USED_BASE + USED_RING_HEADER), 0);
        assert_eq!(guest.read_u32(USED_BASE + USED_RING_HEADER + 4), 10);
        assert_eq!(guest.read_u32(USED_BASE + USED_RING_HEADER + USED_ELEM_SIZE), 1);
        assert_eq!(guest.read_u32(USED_BASE + USED_RING_HEADER + USED_ELEM_SIZE + 4), 20);
    }
}
