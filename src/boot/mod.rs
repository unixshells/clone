pub mod acpi;
pub mod identity;
pub mod measured;
pub mod template;

use anyhow::{Context, Result};
use vm_memory::GuestAddress;

use crate::memory::GuestMem;

/// Kernel is loaded at the 1MB mark (standard for x86_64 Linux).
const KERNEL_LOAD_ADDR: u64 = 0x10_0000;

/// boot_params struct placed at 0x7000.
const BOOT_PARAMS_ADDR: u64 = 0x7000;

/// Kernel command line placed at 0x20000.
const CMDLINE_ADDR: u64 = 0x2_0000;

/// Load a Linux kernel (bzImage or ELF) into guest memory.
/// Returns the entry point address.
pub fn load_kernel(
    mem: &GuestMem,
    kernel_path: &str,
    initrd_path: Option<&str>,
    cmdline: &str,
    num_cpus: u32,
    ram_size: u64,
) -> Result<GuestAddress> {
    load_kernel_with_pci(mem, kernel_path, initrd_path, cmdline, num_cpus, ram_size, false)
}

/// Load kernel with optional PCI ECAM support.
pub fn load_kernel_with_pci(
    mem: &GuestMem,
    kernel_path: &str,
    initrd_path: Option<&str>,
    cmdline: &str,
    num_cpus: u32,
    ram_size: u64,
    pci_enabled: bool,
) -> Result<GuestAddress> {
    // Load kernel via mmap + MADV_SEQUENTIAL|WILLNEED for async readahead.
    // Pages fault in while we set up ACPI/page tables in parallel, saving ~50ms
    // vs synchronous read() for a ~14MB kernel.
    let kernel_data = mmap_kernel(kernel_path)
        .with_context(|| format!("Failed to mmap kernel: {kernel_path}"))?;

    tracing::info!(
        "Loading kernel: {} ({} bytes)",
        kernel_path,
        kernel_data.len()
    );

    // Write kernel command line to guest memory
    let cmdline_bytes = cmdline.as_bytes();
    mem.write_at(CMDLINE_ADDR, cmdline_bytes)?;
    mem.write_at(CMDLINE_ADDR + cmdline_bytes.len() as u64, &[0])?; // null terminator

    // Set up ACPI tables (RSDP → XSDT → MADT, optionally MCFG for PCI)
    acpi::setup_acpi_tables_with_pci(mem, num_cpus, pci_enabled)?;

    // Set up page tables (identity-mapped, covers full VM memory)
    crate::memory::setup_page_tables(mem, ram_size)?;

    // Set up GDT in guest memory
    crate::memory::setup_gdt(mem)?;

    // Detect kernel format and load
    let entry = if is_bzimage(&kernel_data) {
        load_bzimage(mem, &kernel_data, cmdline, ram_size)?
    } else {
        load_elf(mem, &kernel_data)?
    };

    // Load initrd if provided
    if let Some(initrd_path) = initrd_path {
        load_initrd(mem, initrd_path)?;
    }

    Ok(entry)
}

/// Check if kernel is a bzImage (Linux boot protocol magic).
fn is_bzimage(data: &[u8]) -> bool {
    // bzImage has magic "HdrS" at offset 0x202 in the setup header
    if data.len() > 0x206 {
        &data[0x202..0x206] == b"HdrS"
    } else {
        false
    }
}

/// E820 memory map entry (20 bytes, matching Linux struct e820_entry).
#[repr(C, packed)]
struct E820Entry {
    addr: u64,
    size: u64,
    type_: u32,
}

const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

/// Boot params offsets (struct boot_params from Linux arch/x86/include/uapi/asm/bootparam.h).
const BP_E820_ENTRIES: u64 = 0x1E8; // offset of e820_entries count (u8)
const BP_E820_TABLE: u64 = 0x2D0;   // offset of e820_table array
const BP_HEAP_END_PTR: u64 = 0x224; // heap_end_ptr
const BP_CMD_LINE_PTR: u64 = 0x228; // cmd_line_ptr

/// Load a bzImage kernel following the Linux x86 boot protocol.
fn load_bzimage(mem: &GuestMem, data: &[u8], _cmdline: &str, ram_size: u64) -> Result<GuestAddress> {
    // Parse setup header
    let setup_sects = if data[0x1F1] == 0 { 4 } else { data[0x1F1] as u32 };
    let setup_size = (setup_sects + 1) as usize * 512;
    let kernel_offset = setup_size;

    if kernel_offset >= data.len() {
        anyhow::bail!("Invalid bzImage: setup_size ({setup_size}) >= file size ({})", data.len());
    }

    // Zero the boot_params area first, then copy setup header into it.
    // boot_params is 4096 bytes at BOOT_PARAMS_ADDR.
    let zeros = vec![0u8; 4096];
    mem.write_at(BOOT_PARAMS_ADDR, &zeros)?;

    // Copy the setup header (starts at offset 0x1F1 in the boot sector)
    // into boot_params at the same offset. The setup header sits within
    // the first sector(s) of the bzImage.
    let header_start = 0x1F1usize;
    let header_end = setup_size.min(data.len()).min(4096);
    if header_end > header_start {
        mem.write_at(
            BOOT_PARAMS_ADDR + header_start as u64,
            &data[header_start..header_end],
        )?;
    }

    // Patch boot_params with our cmdline pointer
    let cmdline_ptr = CMDLINE_ADDR as u32;
    mem.write_at(BOOT_PARAMS_ADDR + BP_CMD_LINE_PTR, &cmdline_ptr.to_le_bytes())?;

    // Set type_of_loader (0xFF = undefined bootloader)
    mem.write_at(BOOT_PARAMS_ADDR + 0x210, &[0xFF])?;

    // Set loadflags: LOADED_HIGH (bit 0) | CAN_USE_HEAP (bit 7)
    // Note: do NOT set KEEP_SEGMENTS (bit 6) — let the kernel reload its own segments
    mem.write_at(BOOT_PARAMS_ADDR + 0x211, &[0x81])?;

    // Set heap_end_ptr (relative to setup header base)
    let heap_end: u16 = 0xFE00;
    mem.write_at(BOOT_PARAMS_ADDR + BP_HEAP_END_PTR, &heap_end.to_le_bytes())?;

    // Set up e820 memory map — the kernel needs this to know available RAM.
    //
    // IMPORTANT: The kernel text area (phys 0x100000+) MUST be in E820_RAM.
    //
    // For VMs > 3GB, the MMIO hole (3GB-4GB) splits RAM into two regions:
    //   Region 1: 1MB to 3GB (below hole)
    //   Region 2: 4GB to 4GB + overflow (above hole)
    let mmio_hole_start: u64 = 0xC000_0000; // 3 GB
    let mmio_hole_end: u64 = 0x1_0000_0000; // 4 GB

    let mut e820: Vec<E820Entry> = Vec::with_capacity(9);

    // Usable RAM below 640K
    e820.push(E820Entry { addr: 0, size: 0x9FC00, type_: E820_RAM });
    // Reserved: EBDA
    e820.push(E820Entry { addr: 0x9FC00, size: 0x400, type_: E820_RESERVED });
    // Reserved: BIOS ROM
    e820.push(E820Entry { addr: 0xF0000, size: 0x10000, type_: E820_RESERVED });

    if ram_size <= mmio_hole_start {
        // Small VM: single RAM region
        let reserved_top: u64 = 0x20000;
        let ram_end = ram_size - reserved_top;
        e820.push(E820Entry { addr: 0x100000, size: ram_end - 0x100000, type_: E820_RAM });
        e820.push(E820Entry { addr: ram_end, size: reserved_top, type_: E820_RESERVED });
    } else {
        // Large VM: split RAM around the MMIO hole
        // Region below hole: 1MB to 3GB
        e820.push(E820Entry { addr: 0x100000, size: mmio_hole_start - 0x100000, type_: E820_RAM });
        // Region above hole: 4GB to 4GB + overflow
        let above_hole = ram_size - mmio_hole_start;
        e820.push(E820Entry { addr: mmio_hole_end, size: above_hole, type_: E820_RAM });
    }

    // Reserved: IOAPIC/LAPIC MMIO
    e820.push(E820Entry { addr: 0xFEFFC000, size: 0x4000, type_: E820_RESERVED });
    // Reserved: High BIOS ROM
    e820.push(E820Entry { addr: 0xFFFC0000, size: 0x40000, type_: E820_RESERVED });

    let e820_entries = &e820;

    // Write e820 entry count
    mem.write_at(BOOT_PARAMS_ADDR + BP_E820_ENTRIES, &[e820_entries.len() as u8])?;

    // Write e820 table entries (each 20 bytes)
    for (i, entry) in e820_entries.iter().enumerate() {
        let offset = BP_E820_TABLE + (i as u64) * 20;
        mem.write_at(BOOT_PARAMS_ADDR + offset, &entry.addr.to_le_bytes())?;
        mem.write_at(BOOT_PARAMS_ADDR + offset + 8, &entry.size.to_le_bytes())?;
        mem.write_at(BOOT_PARAMS_ADDR + offset + 16, &entry.type_.to_le_bytes())?;
    }

    // Write protected-mode kernel to 1MB
    let kernel_code = &data[kernel_offset..];
    mem.write_at(KERNEL_LOAD_ADDR, kernel_code)?;

    tracing::info!(
        "bzImage loaded: setup={setup_size} bytes, kernel={} bytes at {KERNEL_LOAD_ADDR:#x}, e820={} entries, mem={}MB",
        kernel_code.len(),
        e820_entries.len(),
        ram_size >> 20,
    );

    // 64-bit entry point for bzImage is at load_addr + 0x200 (startup_64).
    // This is per the Linux boot protocol: the protected-mode code at offset 0
    // is the 32-bit entry, and 0x200 is the 64-bit entry.
    Ok(GuestAddress(KERNEL_LOAD_ADDR + 0x200))
}

/// Load an ELF kernel.
fn load_elf(mem: &GuestMem, data: &[u8]) -> Result<GuestAddress> {
    // Minimal ELF64 parsing — load segments into guest memory
    if data.len() < 64 || &data[..4] != b"\x7fELF" {
        anyhow::bail!("Not a valid ELF file");
    }

    let entry = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as usize;

    for i in 0..phnum {
        let ph = &data[phoff + i * phentsize..];
        let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());

        if p_type != 1 {
            continue; // PT_LOAD = 1
        }

        let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap()) as usize;
        let p_paddr = u64::from_le_bytes(ph[24..32].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize;

        if p_filesz > 0 && p_offset + p_filesz <= data.len() {
            mem.write_at(p_paddr, &data[p_offset..p_offset + p_filesz])?;
            tracing::info!("ELF LOAD: {p_filesz} bytes at {p_paddr:#x}");
        }
    }

    Ok(GuestAddress(entry))
}

/// mmap a kernel file with readahead hints for parallel I/O.
///
/// Uses MAP_PRIVATE + MADV_SEQUENTIAL + MADV_WILLNEED so the kernel starts
/// paging in the file asynchronously. The actual data is accessed later when
/// we copy it into guest memory, by which time most pages are already resident.
fn mmap_kernel(path: &str) -> Result<Vec<u8>> {
    use std::os::unix::io::AsRawFd;

    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open kernel: {path}"))?;
    let len = file.metadata()?.len() as usize;
    if len == 0 {
        anyhow::bail!("Kernel file is empty: {path}");
    }

    let fd = file.as_raw_fd();
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        // Fall back to regular read
        return std::fs::read(path)
            .with_context(|| format!("Failed to read kernel: {path}"));
    }

    // Advise sequential access + willneed — triggers async readahead
    unsafe {
        libc::madvise(ptr, len, libc::MADV_SEQUENTIAL);
        libc::madvise(ptr, len, libc::MADV_WILLNEED);
    }

    // Copy into owned Vec (triggers page faults, but pages are being read ahead)
    let data = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec();

    unsafe {
        libc::munmap(ptr, len);
    }

    Ok(data)
}

/// Load initrd into guest memory at a high address.
fn load_initrd(mem: &GuestMem, path: &str) -> Result<()> {
    let initrd_data = std::fs::read(path)
        .with_context(|| format!("Failed to read initrd: {path}"))?;

    // Place initrd at a high address below the MMIO hole (or below memory top for small VMs).
    // For large VMs with a hole, place it below 3GB to keep it in the first memory slot.
    let initrd_top = if mem.has_hole() {
        mem.hole_start()
    } else {
        mem.size()
    };
    let initrd_addr = initrd_top - initrd_data.len() as u64;
    let initrd_addr = initrd_addr & !0xFFF; // page-align down

    mem.write_at(initrd_addr, &initrd_data)?;

    // Update boot_params with initrd location.
    // ramdisk_image (0x218) is the low 32 bits.
    // ext_ramdisk_image (0x0C0) is the high 32 bits (for initrd above 4GB).
    let initrd_lo = initrd_addr as u32;
    let initrd_hi = (initrd_addr >> 32) as u32;
    let initrd_size_u32 = initrd_data.len() as u32;
    mem.write_at(BOOT_PARAMS_ADDR + 0x218, &initrd_lo.to_le_bytes())?;
    mem.write_at(BOOT_PARAMS_ADDR + 0x21C, &initrd_size_u32.to_le_bytes())?;
    if initrd_hi > 0 {
        mem.write_at(BOOT_PARAMS_ADDR + 0x0C0, &initrd_hi.to_le_bytes())?;
    }

    tracing::info!("initrd loaded: {} bytes at {initrd_addr:#x}", initrd_data.len());

    Ok(())
}
