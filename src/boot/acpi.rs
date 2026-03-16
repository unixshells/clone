//! Minimal ACPI tables for guest boot.
//!
//! Provides RSDP → XSDT → MADT so the Linux kernel discovers the LAPIC
//! and IOAPIC. Without these, the kernel falls back to "virtual wire mode"
//! and timer interrupts don't route properly, stalling the boot.

use anyhow::Result;
use crate::memory::GuestMem;

/// RSDP is placed at 0xE0000 (in the EBDA/ROM region the kernel scans).
const RSDP_ADDR: u64 = 0x000E_0000;
/// XSDT immediately after RSDP.
const XSDT_ADDR: u64 = RSDP_ADDR + 36; // RSDP v2 is 36 bytes
/// FADT follows XSDT. XSDT header(36) + 2 pointers(16) = 52 bytes, round up.
const FADT_ADDR: u64 = XSDT_ADDR + 64; // Aligned for safety
/// DSDT follows FADT (276 bytes for FADT rev 6).
const DSDT_ADDR: u64 = FADT_ADDR + 276;
/// MADT follows DSDT. DSDT size = 36-byte header + 7-byte AML body = 43 bytes.
/// Rounded up to 48 for alignment safety.
const MADT_ADDR: u64 = DSDT_ADDR + 48;

/// LAPIC address (standard x86).
const LAPIC_DEFAULT_ADDR: u32 = 0xFEE0_0000;
/// IOAPIC address (standard x86).
const IOAPIC_DEFAULT_ADDR: u32 = 0xFEC0_0000;

/// Write minimal ACPI tables into guest memory.
///
/// Layout:
/// - RSDP v2 at 0xE0000 (kernel scans 0xE0000-0xFFFFF for RSDP)
/// - XSDT at RSDP + 36
/// - MADT at XSDT + 52 (contains LAPIC + IOAPIC entries)
pub fn setup_acpi_tables(mem: &GuestMem, num_cpus: u32) -> Result<()> {
    setup_acpi_tables_with_pci(mem, num_cpus, false)
}

/// Write ACPI tables with optional PCI ECAM support (MCFG table).
pub fn setup_acpi_tables_with_pci(mem: &GuestMem, num_cpus: u32, pci_enabled: bool) -> Result<()> {
    let madt = build_madt(num_cpus);

    if pci_enabled {
        // XSDT points to both MADT and MCFG
        let mcfg = build_mcfg();
        // XSDT header(36) + 2 pointers(16) = 52
        let madt_addr = XSDT_ADDR + 56;
        let mcfg_addr = madt_addr + madt.len() as u64 + 8; // pad for alignment
        let xsdt = build_xsdt(&[madt_addr, mcfg_addr]);
        let rsdp = build_rsdp(XSDT_ADDR, xsdt.len() as u32);

        mem.write_at(RSDP_ADDR, &rsdp)?;
        mem.write_at(XSDT_ADDR, &xsdt)?;
        mem.write_at(madt_addr, &madt)?;
        mem.write_at(mcfg_addr, &mcfg)?;

        tracing::info!(
            "ACPI tables: RSDP@{RSDP_ADDR:#x}, XSDT@{XSDT_ADDR:#x}, MADT@{madt_addr:#x}, MCFG@{mcfg_addr:#x} ({num_cpus} CPU(s), PCI)"
        );
    } else {
        let madt_addr = XSDT_ADDR + 52;
        let xsdt = build_xsdt(&[madt_addr]);
        let rsdp = build_rsdp(XSDT_ADDR, xsdt.len() as u32);

        mem.write_at(RSDP_ADDR, &rsdp)?;
        mem.write_at(XSDT_ADDR, &xsdt)?;
        mem.write_at(madt_addr, &madt)?;

        tracing::info!(
            "ACPI tables: RSDP@{RSDP_ADDR:#x}, XSDT@{XSDT_ADDR:#x}, MADT@{madt_addr:#x} ({num_cpus} CPU(s))"
        );
    }

    Ok(())
}

/// Build MCFG (Memory Mapped Configuration) table for PCI ECAM discovery.
///
/// Tells the OS where to find the ECAM region for PCI config space access.
fn build_mcfg() -> Vec<u8> {
    // MCFG: 36-byte header + 8 bytes reserved + 16-byte allocation entry = 60 bytes
    let total_len: u32 = 60;
    let mut mcfg = vec![0u8; total_len as usize];

    // Standard ACPI header
    mcfg[0..4].copy_from_slice(b"MCFG");
    mcfg[4..8].copy_from_slice(&total_len.to_le_bytes());
    mcfg[8] = 1; // Revision
    mcfg[10..16].copy_from_slice(b"CLONE ");
    mcfg[16..24].copy_from_slice(b"CLONE   ");
    mcfg[24..28].copy_from_slice(&1u32.to_le_bytes());
    mcfg[28..32].copy_from_slice(b"NVM ");
    mcfg[32..36].copy_from_slice(&1u32.to_le_bytes());

    // 8 bytes reserved (bytes 36-43)
    // Already zero

    // Allocation entry (16 bytes, starting at offset 44)
    let ecam_base: u64 = crate::pci::ECAM_BASE;
    mcfg[44..52].copy_from_slice(&ecam_base.to_le_bytes()); // Base address
    mcfg[52..54].copy_from_slice(&0u16.to_le_bytes());       // PCI Segment Group
    mcfg[54] = 0;  // Start Bus Number
    mcfg[55] = 0;  // End Bus Number (only bus 0)
    // 4 bytes reserved (56-59) — already zero

    // Checksum (byte 9)
    let cksum: u8 = mcfg.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    mcfg[9] = 0u8.wrapping_sub(cksum);

    mcfg
}

/// Build RSDP v2 (Root System Description Pointer).
fn build_rsdp(xsdt_addr: u64, xsdt_len: u32) -> Vec<u8> {
    let mut rsdp = vec![0u8; 36]; // RSDP v2 = 36 bytes

    // Signature: "RSD PTR " (8 bytes)
    rsdp[0..8].copy_from_slice(b"RSD PTR ");
    // Revision: 2 (ACPI 2.0+)
    rsdp[15] = 2;
    // OEMID: "CLONE " (6 bytes)
    rsdp[9..15].copy_from_slice(b"CLONE ");
    // RSDT Address: 0 (we use XSDT)
    // Length (bytes 20-23): 36
    rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
    // XSDT Address (bytes 24-31)
    rsdp[24..32].copy_from_slice(&xsdt_addr.to_le_bytes());
    // Extended checksum (byte 32): computed below

    // Checksum (byte 8): sum of bytes 0-19 must be 0 mod 256
    let cksum: u8 = rsdp[0..20].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    rsdp[8] = 0u8.wrapping_sub(cksum);

    // Extended checksum (byte 32): sum of all 36 bytes must be 0 mod 256
    let ext_cksum: u8 = rsdp.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    rsdp[32] = 0u8.wrapping_sub(ext_cksum);

    rsdp
}

/// Build XSDT (Extended System Description Table) with pointers to sub-tables.
fn build_xsdt(table_addrs: &[u64]) -> Vec<u8> {
    let total_len: u32 = 36 + (table_addrs.len() as u32) * 8;
    let mut xsdt = vec![0u8; total_len as usize];

    // Header
    xsdt[0..4].copy_from_slice(b"XSDT");                       // Signature
    xsdt[4..8].copy_from_slice(&total_len.to_le_bytes());       // Length
    xsdt[8] = 1;                                                 // Revision
    xsdt[10..16].copy_from_slice(b"CLONE ");                    // OEM ID
    xsdt[16..24].copy_from_slice(b"CLONE   ");                  // OEM Table ID
    xsdt[24..28].copy_from_slice(&1u32.to_le_bytes());          // OEM Revision
    xsdt[28..32].copy_from_slice(b"NVM ");                      // Creator ID
    xsdt[32..36].copy_from_slice(&1u32.to_le_bytes());          // Creator Revision

    // Table pointers
    for (i, &addr) in table_addrs.iter().enumerate() {
        let off = 36 + i * 8;
        xsdt[off..off + 8].copy_from_slice(&addr.to_le_bytes());
    }

    // Checksum (byte 9)
    let cksum: u8 = xsdt.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    xsdt[9] = 0u8.wrapping_sub(cksum);

    xsdt
}

/// Build FADT (Fixed ACPI Description Table) revision 6.
///
/// Uses the HW_REDUCED_ACPI flag (bit 20) to tell the OS there are no legacy
/// ACPI hardware registers (PM1a, PM1b, GPE, etc.). This avoids the kernel
/// trying to read/write PM registers at address 0, which causes a null deref.
fn build_fadt(dsdt_addr: u64) -> Vec<u8> {
    // FADT revision 6 is 276 bytes
    let total_len: u32 = 276;
    let mut fadt = vec![0u8; total_len as usize];

    // Standard ACPI header (36 bytes)
    fadt[0..4].copy_from_slice(b"FACP");                          // Signature
    fadt[4..8].copy_from_slice(&total_len.to_le_bytes());          // Length
    fadt[8] = 6;                                                    // Revision (ACPI 6.0)
    fadt[10..16].copy_from_slice(b"CLONE ");                       // OEM ID
    fadt[16..24].copy_from_slice(b"CLONE   ");                     // OEM Table ID
    fadt[24..28].copy_from_slice(&1u32.to_le_bytes());             // OEM Revision
    fadt[28..32].copy_from_slice(b"NVM ");                         // Creator ID
    fadt[32..36].copy_from_slice(&1u32.to_le_bytes());             // Creator Revision

    // DSDT address (legacy 32-bit field at offset 40)
    fadt[40..44].copy_from_slice(&(dsdt_addr as u32).to_le_bytes());

    // Preferred PM Profile (offset 45): 0 = Unspecified
    fadt[45] = 0;

    // SCI Interrupt (offset 46): 0 — no SCI interrupt (we don't deliver ACPI events)
    // Leaving as 0 prevents the kernel from trying to install a SCI handler.

    // PM1a Event Block (offset 56): I/O port 0x600, 4 bytes (status + enable)
    fadt[56..60].copy_from_slice(&0x600u32.to_le_bytes());
    // PM1a Control Block (offset 64): I/O port 0x604, 2 bytes
    fadt[64..68].copy_from_slice(&0x604u32.to_le_bytes());

    // PM1 Event Length (offset 88): 4 bytes
    fadt[88] = 4;
    // PM1 Control Length (offset 89): 2 bytes
    fadt[89] = 2;

    // Flags (offset 112): WBINVD (bit 0) + WBINVD_FLUSH (bit 1) +
    //                       SLP_BUTTON (bit 5, headless) + RESET_REG_SUP (bit 10)
    //
    // Bit 4: PWR_BUTTON — power button is control-method (not fixed feature)
    // Bit 5: SLP_BUTTON — sleep button is control-method (not fixed feature)
    // Setting both prevents the kernel from trying to enable fixed
    // PowerButton/SleepButton ACPI events (which need SCI delivery).
    //
    // Note: HW_REDUCED_ACPI (bit 20) MUST NOT be set — it causes the
    // kernel to skip IOAPIC interrupt routing, breaking legacy IRQs.
    let flags: u32 = (1 << 0) | (1 << 1) | (1 << 4) | (1 << 5) | (1 << 10);
    fadt[112..116].copy_from_slice(&flags.to_le_bytes());

    // FADT Minor Version (offset 131): 1 (ACPI 6.1)
    fadt[131] = 1;

    // X_DSDT (64-bit DSDT address, offset 140)
    fadt[140..148].copy_from_slice(&dsdt_addr.to_le_bytes());

    // Checksum (byte 9)
    let cksum: u8 = fadt.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    fadt[9] = 0u8.wrapping_sub(cksum);

    fadt
}

/// Build a minimal DSDT with AML defining an empty \_SB scope.
///
/// Provides a valid DSDT that the kernel can parse without errors.
/// No devices are declared — PWRB and RTC0 were removed because they cause
/// the kernel to try enabling fixed ACPI events (PowerButton, RealTimeClock)
/// which require SCI interrupt delivery we don't implement.
fn build_dsdt() -> Vec<u8> {
    // Hand-assembled AML bytecode for:
    //   Scope (\_SB) { }
    //
    // AML encoding:
    //   0x10 = ScopeOp
    //   PkgLength encodes total scope length (including PkgLength itself)
    //   Body: RootChar(1) + "_SB_"(4) = 5 bytes
    //   PkgLength = 5 + 1 (1-byte PkgLength self) = 6
    //   Total AML = 1(ScopeOp) + 1(PkgLen) + 5(body) = 7 bytes
    let aml: &[u8] = &[
        // Scope (\_SB)
        0x10,                           // ScopeOp
        0x06,                           // PkgLength = 6 (1-byte encoding)
        0x5C,                           // RootChar '\'
        0x5F, 0x53, 0x42, 0x5F,        // "_SB_"
    ];

    let header_len = 36;
    let total_len = (header_len + aml.len()) as u32;
    let mut dsdt = vec![0u8; total_len as usize];

    dsdt[0..4].copy_from_slice(b"DSDT");                          // Signature
    dsdt[4..8].copy_from_slice(&total_len.to_le_bytes());          // Length
    dsdt[8] = 2;                                                    // Revision
    dsdt[10..16].copy_from_slice(b"CLONE ");                       // OEM ID
    dsdt[16..24].copy_from_slice(b"CLONE   ");                     // OEM Table ID
    dsdt[24..28].copy_from_slice(&1u32.to_le_bytes());             // OEM Revision
    dsdt[28..32].copy_from_slice(b"NVM ");                         // Creator ID
    dsdt[32..36].copy_from_slice(&1u32.to_le_bytes());             // Creator Revision

    // Copy AML body after header
    dsdt[header_len..].copy_from_slice(aml);

    // Checksum (byte 9)
    let cksum: u8 = dsdt.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    dsdt[9] = 0u8.wrapping_sub(cksum);

    dsdt
}

/// Build MADT (Multiple APIC Description Table).
///
/// Contains:
/// - MADT header with LAPIC address
/// - One Local APIC entry per vCPU
/// - One I/O APIC entry
/// - Interrupt Source Override entries (matching QEMU/SeaBIOS)
///
/// The INT_SRC_OVR entries tell the kernel how ISA IRQs map to GSIs.
/// Without them, the kernel logs "preallocated irqs: 0" instead of 16
/// and may misconfigure interrupt routing.
fn build_madt(num_cpus: u32) -> Vec<u8> {
    // MADT header: 44 bytes (36 standard + 4 LAPIC addr + 4 flags)
    // Local APIC entry: 8 bytes each
    // I/O APIC entry: 12 bytes
    // INT_SRC_OVR entry: 10 bytes each (5 entries matching QEMU)
    // Local APIC NMI: 6 bytes
    let lapic_entries_len = num_cpus as usize * 8;
    let ioapic_entry_len = 12;
    let iso_entries_len = 5 * 10; // 5 interrupt source overrides
    let lapic_nmi_len = 6;
    let total_len = 44 + lapic_entries_len + ioapic_entry_len + iso_entries_len + lapic_nmi_len;

    let mut madt = vec![0u8; total_len];

    // Standard ACPI header
    madt[0..4].copy_from_slice(b"APIC");                          // Signature
    madt[4..8].copy_from_slice(&(total_len as u32).to_le_bytes()); // Length
    madt[8] = 4;                                                    // Revision (ACPI 6.0)
    madt[10..16].copy_from_slice(b"CLONE ");                       // OEM ID
    madt[16..24].copy_from_slice(b"CLONE   ");                     // OEM Table ID
    madt[24..28].copy_from_slice(&1u32.to_le_bytes());             // OEM Revision
    madt[28..32].copy_from_slice(b"NVM ");                         // Creator ID
    madt[32..36].copy_from_slice(&1u32.to_le_bytes());             // Creator Revision

    // Local Interrupt Controller Address (offset 36)
    madt[36..40].copy_from_slice(&LAPIC_DEFAULT_ADDR.to_le_bytes());
    // Flags (offset 40): bit 0 = PCAT_COMPAT (dual 8259 present)
    madt[40..44].copy_from_slice(&1u32.to_le_bytes());

    let mut offset = 44;

    // Local APIC entries (type 0, length 8)
    for i in 0..num_cpus {
        madt[offset] = 0;          // Type: Processor Local APIC
        madt[offset + 1] = 8;      // Length
        madt[offset + 2] = i as u8; // ACPI Processor UID
        madt[offset + 3] = i as u8; // APIC ID
        // Flags: bit 0 = Enabled
        madt[offset + 4..offset + 8].copy_from_slice(&1u32.to_le_bytes());
        offset += 8;
    }

    // I/O APIC entry (type 1, length 12)
    madt[offset] = 1;              // Type: I/O APIC
    madt[offset + 1] = 12;         // Length
    madt[offset + 2] = 0;          // I/O APIC ID
    madt[offset + 3] = 0;          // Reserved
    // I/O APIC Address
    madt[offset + 4..offset + 8].copy_from_slice(&IOAPIC_DEFAULT_ADDR.to_le_bytes());
    // Global System Interrupt Base
    madt[offset + 8..offset + 12].copy_from_slice(&0u32.to_le_bytes());
    offset += 12;

    // Interrupt Source Override entries (type 2, length 10)
    // These match QEMU/SeaBIOS MADT exactly.

    // ISO 1: IRQ 0 (PIT) → GSI 2 (standard PC remap)
    // Flags: 0 = conforms to bus specifications (edge, active high)
    write_iso(&mut madt, offset, 0, 0, 2, 0);
    offset += 10;

    // ISO 2: IRQ 5 → GSI 5 (level, active low)
    write_iso(&mut madt, offset, 0, 5, 5, 0x000d);
    offset += 10;

    // ISO 3: IRQ 9 → GSI 9 (ACPI SCI, level, active low)
    write_iso(&mut madt, offset, 0, 9, 9, 0x000d);
    offset += 10;

    // ISO 4: IRQ 10 → GSI 10 (level, active low)
    write_iso(&mut madt, offset, 0, 10, 10, 0x000d);
    offset += 10;

    // ISO 5: IRQ 11 → GSI 11 (level, active low)
    write_iso(&mut madt, offset, 0, 11, 11, 0x000d);
    offset += 10;

    // Local APIC NMI entry (type 4, length 6)
    // All processors, LINT1 = NMI, flags = 0 (conforms)
    madt[offset] = 4;       // Type: Local APIC NMI
    madt[offset + 1] = 6;   // Length
    madt[offset + 2] = 0xFF; // ACPI Processor UID (0xFF = all processors)
    madt[offset + 3..offset + 5].copy_from_slice(&0u16.to_le_bytes()); // Flags
    madt[offset + 5] = 1;   // Local APIC LINT# (1 = LINT1 for NMI)

    // Checksum (byte 9)
    let cksum: u8 = madt.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    madt[9] = 0u8.wrapping_sub(cksum);

    madt
}

/// Write an Interrupt Source Override entry at the given offset.
fn write_iso(madt: &mut [u8], offset: usize, bus: u8, source: u8, gsi: u32, flags: u16) {
    madt[offset] = 2;              // Type: Interrupt Source Override
    madt[offset + 1] = 10;         // Length
    madt[offset + 2] = bus;        // Bus (0 = ISA)
    madt[offset + 3] = source;     // Source (ISA IRQ)
    madt[offset + 4..offset + 8].copy_from_slice(&gsi.to_le_bytes()); // Global System Interrupt
    madt[offset + 8..offset + 10].copy_from_slice(&flags.to_le_bytes()); // Flags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsdp_checksum() {
        let rsdp = build_rsdp(0x1000, 44);
        // First 20 bytes checksum
        let sum: u8 = rsdp[0..20].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);
        // Full 36 bytes checksum
        let sum: u8 = rsdp.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_rsdp_signature() {
        let rsdp = build_rsdp(0x1000, 44);
        assert_eq!(&rsdp[0..8], b"RSD PTR ");
    }

    #[test]
    fn test_rsdp_revision() {
        let rsdp = build_rsdp(0x1000, 44);
        assert_eq!(rsdp[15], 2);
    }

    #[test]
    fn test_xsdt_checksum() {
        let xsdt = build_xsdt(&[0x2000]);
        let sum: u8 = xsdt.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_xsdt_signature() {
        let xsdt = build_xsdt(&[0x2000]);
        assert_eq!(&xsdt[0..4], b"XSDT");
    }

    #[test]
    fn test_xsdt_contains_table_pointers() {
        let xsdt = build_xsdt(&[0x2000, 0x3000]);
        let ptr0 = u64::from_le_bytes(xsdt[36..44].try_into().unwrap());
        let ptr1 = u64::from_le_bytes(xsdt[44..52].try_into().unwrap());
        assert_eq!(ptr0, 0x2000);
        assert_eq!(ptr1, 0x3000);
    }

    #[test]
    fn test_madt_checksum() {
        let madt = build_madt(1);
        let sum: u8 = madt.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_madt_signature() {
        let madt = build_madt(1);
        assert_eq!(&madt[0..4], b"APIC");
    }

    #[test]
    fn test_madt_lapic_address() {
        let madt = build_madt(1);
        let addr = u32::from_le_bytes(madt[36..40].try_into().unwrap());
        assert_eq!(addr, LAPIC_DEFAULT_ADDR);
    }

    #[test]
    fn test_madt_single_cpu() {
        let madt = build_madt(1);
        // Header: 44, LAPIC: 8, IOAPIC: 12, ISO: 5*10=50, LAPIC NMI: 6 = 120
        assert_eq!(madt.len(), 120);
        // LAPIC entry at offset 44
        assert_eq!(madt[44], 0); // type = Local APIC
        assert_eq!(madt[45], 8); // length
        assert_eq!(madt[46], 0); // processor UID
        assert_eq!(madt[47], 0); // APIC ID
    }

    #[test]
    fn test_madt_multi_cpu() {
        let madt = build_madt(4);
        // 44 + 4*8 + 12 + 50 + 6 = 144
        assert_eq!(madt.len(), 144);
        // Check CPU 3's LAPIC entry (at offset 44 + 3*8 = 68)
        assert_eq!(madt[68], 0);     // type
        assert_eq!(madt[70], 3);     // processor UID
        assert_eq!(madt[71], 3);     // APIC ID
    }

    #[test]
    fn test_madt_ioapic_entry() {
        let madt = build_madt(1);
        // IOAPIC at offset 44 + 8 = 52
        assert_eq!(madt[52], 1); // type = I/O APIC
        assert_eq!(madt[53], 12); // length
        let addr = u32::from_le_bytes(madt[56..60].try_into().unwrap());
        assert_eq!(addr, IOAPIC_DEFAULT_ADDR);
    }

    #[test]
    fn test_madt_iso_entries() {
        let madt = build_madt(1);
        // First ISO at offset 44 + 8 + 12 = 64
        assert_eq!(madt[64], 2); // type = INT_SRC_OVR
        assert_eq!(madt[65], 10); // length
        assert_eq!(madt[66], 0); // bus = ISA
        assert_eq!(madt[67], 0); // source = IRQ 0
        let gsi = u32::from_le_bytes(madt[68..72].try_into().unwrap());
        assert_eq!(gsi, 2); // GSI 2 (PIT remap)
    }

    #[test]
    fn test_madt_lapic_nmi() {
        let madt = build_madt(1);
        // LAPIC NMI at end: offset = 44 + 8 + 12 + 50 = 114
        assert_eq!(madt[114], 4); // type = Local APIC NMI
        assert_eq!(madt[115], 6); // length
        assert_eq!(madt[116], 0xFF); // all processors
        assert_eq!(madt[119], 1); // LINT1
    }

    #[test]
    fn test_dsdt_checksum() {
        let dsdt = build_dsdt();
        let sum: u8 = dsdt.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_dsdt_has_aml() {
        let dsdt = build_dsdt();
        assert_eq!(&dsdt[0..4], b"DSDT");
        // Should be larger than just the 36-byte header (has AML body)
        assert!(dsdt.len() > 36, "DSDT should contain AML body");
        // First AML byte after header should be ScopeOp (0x10)
        assert_eq!(dsdt[36], 0x10, "AML should start with ScopeOp");
    }

    #[test]
    fn test_dsdt_contains_sb_scope() {
        let dsdt = build_dsdt();
        let body = &dsdt[36..];
        // Should contain "_SB_" scope name
        let has_sb = body.windows(4).any(|w| w == b"_SB_");
        assert!(has_sb, "DSDT AML should contain \\_SB scope");
    }

    #[test]
    fn test_fadt_no_hw_reduced_flag() {
        let fadt = build_fadt(0x1000);
        let flags = u32::from_le_bytes(fadt[112..116].try_into().unwrap());
        assert_eq!(flags & (1 << 20), 0, "HW_REDUCED_ACPI flag must NOT be set (breaks IOAPIC)");
    }

    #[test]
    fn test_fadt_pm_registers() {
        let fadt = build_fadt(0x1000);
        let pm1a_evt = u32::from_le_bytes(fadt[56..60].try_into().unwrap());
        assert_eq!(pm1a_evt, 0x600, "PM1a Event Block should be at I/O 0x600");
        let pm1a_cnt = u32::from_le_bytes(fadt[64..68].try_into().unwrap());
        assert_eq!(pm1a_cnt, 0x604, "PM1a Control Block should be at I/O 0x604");
        assert_eq!(fadt[88], 4, "PM1 Event Length should be 4");
        assert_eq!(fadt[89], 2, "PM1 Control Length should be 2");
    }

    #[test]
    fn test_madt_pcat_compat_flag() {
        let madt = build_madt(1);
        let flags = u32::from_le_bytes(madt[40..44].try_into().unwrap());
        assert_eq!(flags & 1, 1); // PCAT_COMPAT
    }
}
