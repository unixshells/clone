pub mod balloon;
pub mod overcommit;

use anyhow::{Context, Result};
use vm_memory::{GuestAddress, GuestMemoryMmap, MmapRegion};

/// Guest physical memory layout:
///
/// 0x0000_0000 - 0x0000_7000  Reserved (real mode IVT, BDA, etc.)
/// 0x0000_7000 - 0x0000_8000  boot_params struct
/// 0x0000_9000 - 0x0000_A000  PML4 page table
/// 0x0000_A000 - 0x0000_B000  PDPT page table
/// 0x0001_0000 - 0x0002_0000  PD page tables (one 4KB PD per GB, up to 64)
/// 0x0010_0000 - (kernel end) Kernel image (loaded at 1MB)
/// (kernel end) - mem_size    Free memory for guest use

const GUEST_MEM_START: u64 = 0;

/// Create guest memory backed by anonymous mmap with MAP_NORESERVE.
///
/// MAP_NORESERVE enables overcommit — physical pages are only allocated
/// on first write. This is Layer 2 of the memory stack.
pub struct GuestMem {
    ptr: *mut u8,
    size: u64, // total mmap'd size (contiguous userspace allocation)
    /// For VMs > 3GB, the MMIO hole splits guest physical address space:
    /// GPA [0, hole_start) maps to userspace [ptr, ptr+hole_start)
    /// GPA [hole_end, ...) maps to userspace [ptr+hole_start, ...)
    /// If hole_start == 0, there is no hole (small VM).
    hole_start: u64, // 0 = no hole
    hole_end: u64,
}

impl GuestMem {
    /// Create a GuestMem from a raw pointer and size (no MMIO hole).
    pub fn from_raw(ptr: *mut u8, size: u64) -> Self {
        Self { ptr, size, hole_start: 0, hole_end: 0 }
    }

    /// Create a GuestMem with an MMIO hole for large VMs.
    /// The hole splits the guest physical address space:
    /// - GPA [0, hole_start) → userspace [ptr, ptr+hole_start)
    /// - GPA [hole_end, ...) → userspace [ptr+hole_start, ...)
    pub fn from_raw_with_hole(ptr: *mut u8, size: u64, hole_start: u64, hole_end: u64) -> Self {
        Self { ptr, size, hole_start, hole_end }
    }

    /// Create a temporary borrow of existing guest memory.
    pub unsafe fn borrow_raw(ptr: *mut u8, size: u64) -> BorrowedGuestMem {
        BorrowedGuestMem { inner: GuestMem { ptr, size, hole_start: 0, hole_end: 0 } }
    }

    /// Create a temporary borrow with MMIO hole info.
    pub unsafe fn borrow_raw_with_hole(ptr: *mut u8, size: u64, hole_start: u64, hole_end: u64) -> BorrowedGuestMem {
        BorrowedGuestMem { inner: GuestMem { ptr, size, hole_start, hole_end } }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn hole_start(&self) -> u64 {
        self.hole_start
    }

    pub fn hole_end(&self) -> u64 {
        self.hole_end
    }

    pub fn has_hole(&self) -> bool {
        self.hole_start > 0
    }

    /// Translate a guest physical address (GPA) to a userspace pointer offset.
    /// Accounts for the MMIO hole if present.
    fn gpa_to_offset(&self, gpa: u64) -> Result<usize> {
        if self.hole_start == 0 {
            // No hole — direct mapping
            if gpa >= self.size {
                anyhow::bail!("GPA {gpa:#x} exceeds memory size {:#x}", self.size);
            }
            return Ok(gpa as usize);
        }

        if gpa < self.hole_start {
            // Below the hole — direct mapping
            Ok(gpa as usize)
        } else if gpa >= self.hole_end {
            // Above the hole — subtract the hole size
            let offset = self.hole_start + (gpa - self.hole_end);
            if offset >= self.size {
                anyhow::bail!("GPA {gpa:#x} (offset {offset:#x}) exceeds memory size {:#x}", self.size);
            }
            Ok(offset as usize)
        } else {
            anyhow::bail!("GPA {gpa:#x} is in the MMIO hole ({:#x}..{:#x})", self.hole_start, self.hole_end);
        }
    }

    /// Translate a GPA to a raw host virtual address pointer.
    /// Used by virtio devices for DMA.
    pub fn gpa_to_hva(&self, gpa: u64) -> Result<*mut u8> {
        let offset = self.gpa_to_offset(gpa)?;
        Ok(unsafe { self.ptr.add(offset) })
    }

    /// Write bytes to a guest physical address.
    pub fn write_at(&self, gpa: u64, data: &[u8]) -> Result<()> {
        let offset = self.gpa_to_offset(gpa)?;
        if offset + data.len() > self.size as usize {
            anyhow::bail!("Write at GPA {gpa:#x} + {} exceeds memory", data.len());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len());
        }
        Ok(())
    }

    /// Read bytes from a guest physical address.
    pub fn read_at(&self, gpa: u64, len: usize) -> Result<Vec<u8>> {
        let offset = self.gpa_to_offset(gpa)?;
        if offset + len > self.size as usize {
            anyhow::bail!("Read at GPA {gpa:#x} + {len} exceeds memory");
        }
        let mut buf = vec![0u8; len];
        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), len);
        }
        Ok(buf)
    }

    /// Get the guest physical memory size (including the hole gap for large VMs).
    /// This is the total GPA space, not the userspace allocation size.
    pub fn guest_phys_size(&self) -> u64 {
        if self.hole_start == 0 {
            self.size
        } else {
            // Total GPA = below hole + hole gap + above hole
            self.hole_end + (self.size - self.hole_start)
        }
    }
}

impl Drop for GuestMem {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.size > 0 {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.size as usize);
            }
        }
    }
}

// SAFETY: Guest memory is a raw allocation we manage exclusively.
unsafe impl Send for GuestMem {}
unsafe impl Sync for GuestMem {}

/// A borrowed reference to guest memory that does NOT unmap on drop.
///
/// Used by the snapshot handler to access the VM's memory without
/// taking ownership.
pub struct BorrowedGuestMem {
    inner: GuestMem,
}

impl std::ops::Deref for BorrowedGuestMem {
    type Target = GuestMem;
    fn deref(&self) -> &GuestMem {
        &self.inner
    }
}

impl Drop for BorrowedGuestMem {
    fn drop(&mut self) {
        // Override the ptr so GuestMem::drop doesn't munmap
        self.inner.ptr = std::ptr::null_mut();
        self.inner.size = 0;
    }
}

/// Allocate guest memory with overcommit (MAP_NORESERVE).
/// Physical pages only allocated on first write — kernel handles faults natively.
/// For VMs > 3GB, pass hole_start/hole_end to create split memory regions.
pub fn create_guest_memory(size: u64) -> Result<GuestMem> {
    create_guest_memory_with_hole(size, 0, 0)
}

pub fn create_guest_memory_with_hole(size: u64, hole_start: u64, hole_end: u64) -> Result<GuestMem> {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        anyhow::bail!("mmap failed for guest memory ({size} bytes)");
    }

    // Advise kernel this is mergeable (KSM — Layer 1 of memory stack)
    unsafe {
        libc::madvise(ptr, size as usize, libc::MADV_MERGEABLE);
    }

    tracing::info!("Guest memory: {size} bytes at {ptr:?} (overcommit, KSM-enabled)");

    Ok(GuestMem {
        ptr: ptr as *mut u8,
        size,
        hole_start,
        hole_end,
    })
}

/// Write identity-mapped page tables into guest memory.
/// PML4 at 0x9000, PDPT at 0xA000, PDs at 0x10000+ (64KB, one per GB).
///
/// Maps the full VM memory as 2MB pages (identity mapped). Previously only
/// mapped the first 1GB, causing TLB misses and kernel init slowdowns for
/// VMs larger than 1GB.
///
/// PD tables are placed at 0x10000 (64KB), each 4KB, well below the kernel
/// at 0x100000 (1MB). Supports up to 64GB of guest memory.
pub fn setup_page_tables(mem: &GuestMem, mem_size: u64) -> Result<()> {
    let pml4_addr: u64 = 0x9000;
    let pdpt_addr: u64 = 0xA000;
    let pd_base: u64 = 0x10000; // 64KB — PD tables start here

    // How many GB to map (at least 1, capped at 64 to fit below kernel at 0x100000)
    let num_gb = ((mem_size + (1 << 30) - 1) >> 30).max(1).min(64) as u64;

    // PML4[0] -> PDPT (present, writable)
    let pml4_entry: u64 = pdpt_addr | 0x3;
    mem.write_at(pml4_addr, &pml4_entry.to_le_bytes())?;

    for gb in 0..num_gb {
        let pd_addr = pd_base + gb * 0x1000; // each PD is 4KB

        // PDPT[gb] -> PD (present, writable)
        let pdpt_entry: u64 = pd_addr | 0x3;
        mem.write_at(pdpt_addr + gb * 8, &pdpt_entry.to_le_bytes())?;

        // PD: 512 entries, each mapping a 2MB page (PS bit set)
        for i in 0u64..512 {
            let phys_addr = (gb << 30) | (i << 21);
            let pd_entry: u64 = phys_addr | 0x83; // present + writable + PS (2MB page)
            mem.write_at(pd_addr + i * 8, &pd_entry.to_le_bytes())?;
        }
    }

    Ok(())
}

/// Write a minimal GDT to guest memory at 0x500.
/// Matches the segment selectors set in vcpu.rs setup_long_mode():
///   Entry 0 (0x00): null descriptor
///   Entry 1 (0x08): unused (reserved)
///   Entry 2 (0x10): 64-bit code segment (CS)
///   Entry 3 (0x18): data segment (DS/ES/FS/GS/SS)
pub fn setup_gdt(mem: &GuestMem) -> Result<()> {
    const GDT_ADDR: u64 = 0x500;

    let mut gdt = [0u64; 4];

    // Entry 0: null descriptor
    gdt[0] = 0;

    // Entry 1: unused
    gdt[1] = 0;

    // Entry 2 (selector 0x10): 64-bit code segment
    // Base=0, Limit=0xFFFFF, Type=0xB (exec/read/accessed), S=1, DPL=0,
    // P=1, L=1 (64-bit), D=0, G=1
    gdt[2] = 0x00AF_9B00_0000_FFFF;

    // Entry 3 (selector 0x18): data segment
    // Base=0, Limit=0xFFFFF, Type=0x3 (read/write/accessed), S=1, DPL=0,
    // P=1, L=0, D=1 (32-bit operand size), G=1
    gdt[3] = 0x00CF_9300_0000_FFFF;

    for (i, &entry) in gdt.iter().enumerate() {
        mem.write_at(GDT_ADDR + (i as u64) * 8, &entry.to_le_bytes())?;
    }

    Ok(())
}
