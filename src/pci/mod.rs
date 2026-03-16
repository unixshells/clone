//! Minimal PCI bus with ECAM (Enhanced Configuration Access Mechanism).
//!
//! Provides a PCI bus that the guest discovers via the MCFG ACPI table.
//! ECAM maps PCI config space to MMIO: each device gets a 4KB page at
//! `ecam_base + (bus << 20 | dev << 15 | func << 12)`.
//!
//! This is the minimum needed for VFIO device passthrough.

pub mod vfio;

use std::collections::HashMap;

/// ECAM base address — below our virtio MMIO region at 0xD000_0000.
pub const ECAM_BASE: u64 = 0xB000_0000;

/// PCI MMIO BAR window for device BARs.
pub const PCI_MMIO_BASE: u64 = 0xC000_0000;
pub const PCI_MMIO_END: u64 = 0xCFFF_FFFF;

/// ECAM region size: 1 bus × 32 devices × 8 functions × 4KB = 1MB.
pub const ECAM_SIZE: u64 = 1 << 20;

const PAGE_SIZE: u64 = 4096;

/// BDF (Bus/Device/Function) address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PciBdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciBdf {
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        Self { bus, device, function }
    }

    /// ECAM offset for this BDF within the ECAM region.
    pub fn ecam_offset(&self) -> u64 {
        ((self.bus as u64) << 20) | ((self.device as u64) << 15) | ((self.function as u64) << 12)
    }
}

impl std::fmt::Display for PciBdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

/// A PCI BAR (Base Address Register).
#[derive(Debug, Clone)]
pub struct PciBar {
    /// BAR index (0-5).
    pub index: u8,
    /// Guest physical address where this BAR is mapped.
    pub guest_addr: u64,
    /// Size of this BAR region.
    pub size: u64,
    /// Is this a 64-bit BAR? (consumes two BAR slots)
    pub is_64bit: bool,
    /// Is this a prefetchable memory BAR?
    pub prefetchable: bool,
}

/// MSI-X table entry.
#[derive(Debug, Clone, Default)]
pub struct MsixEntry {
    pub msg_addr: u64,
    pub msg_data: u32,
    pub vector_control: u32,
}

/// MSI-X state for a device.
#[derive(Debug, Clone)]
pub struct MsixState {
    pub entries: Vec<MsixEntry>,
    pub enabled: bool,
    pub function_mask: bool,
}

/// A PCI device on the bus.
pub struct PciDevice {
    /// BDF address.
    pub bdf: PciBdf,
    /// PCIe extended config space (4096 bytes).
    pub config: [u8; 4096],
    /// BAR allocations.
    pub bars: Vec<PciBar>,
    /// MSI-X state (if supported).
    pub msix: Option<MsixState>,
    /// VFIO device handle (if passthrough).
    pub vfio: Option<vfio::VfioDevice>,
}

impl PciDevice {
    /// Read from PCI config space.
    pub fn config_read(&self, offset: u64, len: usize) -> u32 {
        let off = offset as usize;
        if off + len > 4096 {
            return 0xFFFF_FFFF;
        }
        match len {
            1 => self.config[off] as u32,
            2 => u16::from_le_bytes([self.config[off], self.config[off + 1]]) as u32,
            4 => u32::from_le_bytes([
                self.config[off],
                self.config[off + 1],
                self.config[off + 2],
                self.config[off + 3],
            ]),
            _ => 0xFFFF_FFFF,
        }
    }

    /// Write to PCI config space.
    pub fn config_write(&mut self, offset: u64, data: &[u8]) {
        let off = offset as usize;
        let len = data.len();
        if off + len > 4096 {
            return;
        }

        // For VFIO devices, proxy config writes to the real device
        if let Some(ref vfio) = self.vfio {
            let _ = vfio.config_write(off, data);
        }

        // BAR writes need special handling — mask to BAR size alignment
        if off >= 0x10 && off < 0x28 {
            let bar_index = (off - 0x10) / 4;
            if bar_index < self.bars.len() {
                // Guest is probing BAR size: write all 1s, read back aligned size
                // We store the written value but enforce alignment
                let bar = &self.bars[bar_index];
                let mask = !(bar.size - 1) as u32;
                let written = match data.len() {
                    4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
                    _ => return,
                };

                // If guest writes all 1s, return size mask. Otherwise store the BAR address.
                let val = if written == 0xFFFF_FFFF {
                    // Size mask: lower bits forced to 0 per BAR size, bit 0 = memory type
                    mask | (self.config[off] as u32 & 0xF) // preserve type bits
                } else {
                    // Guest is programming the BAR address
                    (written & mask) | (self.config[off] as u32 & 0xF)
                };

                let bytes = val.to_le_bytes();
                self.config[off..off + 4].copy_from_slice(&bytes);
                return;
            }
        }

        // Command register (offset 0x04) — allow bus master, memory space, etc.
        self.config[off..off + len].copy_from_slice(data);
    }
}

/// The PCI bus.
pub struct PciBus {
    /// Registered devices, keyed by BDF.
    pub devices: Vec<PciDevice>,
    /// ECAM base address in guest physical space.
    pub ecam_base: u64,
    /// Next available MMIO address for BAR allocation.
    mmio_next: u64,
}

impl PciBus {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            ecam_base: ECAM_BASE,
            mmio_next: PCI_MMIO_BASE,
        }
    }

    /// Add a VFIO passthrough device.
    ///
    /// Assigns a BDF, allocates BARs in the MMIO window, and populates
    /// config space from the real device.
    pub fn add_vfio_device(&mut self, mut vfio_dev: vfio::VfioDevice) -> anyhow::Result<PciBdf> {
        let dev_index = self.devices.len() as u8;
        let bdf = PciBdf::new(0, dev_index, 0);

        // Read config space from real device
        let mut config = [0u8; 4096];
        if let Ok(data) = vfio_dev.config_read(0, 256) {
            config[..data.len().min(256)].copy_from_slice(&data[..data.len().min(256)]);
        }

        // Discover BARs from the real device
        let mut bars = Vec::new();
        let regions = vfio_dev.get_regions()?;

        for (i, region) in regions.iter().enumerate() {
            if i >= 6 || region.size == 0 {
                continue;
            }

            // Align BAR size to power of 2
            let size = region.size.next_power_of_two();

            // Align mmio_next to BAR size
            self.mmio_next = (self.mmio_next + size - 1) & !(size - 1);

            if self.mmio_next + size > PCI_MMIO_END {
                tracing::warn!("PCI MMIO space exhausted, cannot allocate BAR {i}");
                continue;
            }

            let guest_addr = self.mmio_next;
            self.mmio_next += size;

            let is_64bit = region.flags & 0x4 != 0;
            let prefetchable = region.flags & 0x8 != 0;

            // Write BAR value into config space
            let bar_offset = 0x10 + i * 4;
            let bar_val = (guest_addr as u32) | if is_64bit { 0x4 } else { 0x0 }
                | if prefetchable { 0x8 } else { 0x0 };
            config[bar_offset..bar_offset + 4].copy_from_slice(&bar_val.to_le_bytes());

            // For 64-bit BARs, write upper 32 bits in next BAR slot
            if is_64bit && i + 1 < 6 {
                let upper = ((guest_addr >> 32) as u32).to_le_bytes();
                let next_offset = bar_offset + 4;
                config[next_offset..next_offset + 4].copy_from_slice(&upper);
            }

            bars.push(PciBar {
                index: i as u8,
                guest_addr,
                size,
                is_64bit,
                prefetchable,
            });

            tracing::info!(
                "PCI {bdf} BAR{i}: {guest_addr:#x}-{:#x} ({} KB, {}bit{})",
                guest_addr + size - 1,
                size / 1024,
                if is_64bit { 64 } else { 32 },
                if prefetchable { ", prefetchable" } else { "" },
            );
        }

        // Set up MSI-X if supported
        let msix = vfio_dev.setup_msix()?;

        // Map device BARs for MMIO access
        for bar in &bars {
            vfio_dev.map_bar(bar.index as usize, bar.guest_addr, bar.size)?;
        }

        let device = PciDevice {
            bdf,
            config,
            bars,
            msix,
            vfio: Some(vfio_dev),
        };

        self.devices.push(device);
        tracing::info!("Added VFIO device at PCI {bdf}");

        Ok(bdf)
    }

    /// Handle ECAM MMIO read.
    ///
    /// Returns true if the address was in the ECAM range.
    pub fn handle_ecam_read(&self, addr: u64, data: &mut [u8]) -> bool {
        if addr < self.ecam_base || addr >= self.ecam_base + ECAM_SIZE {
            return false;
        }

        let offset = addr - self.ecam_base;
        let bdf = ecam_decode_bdf(offset);
        let reg_offset = offset & 0xFFF;

        // Find the device
        if let Some(dev) = self.find_device(&bdf) {
            let val = dev.config_read(reg_offset, data.len());
            match data.len() {
                1 => data[0] = val as u8,
                2 => data[..2].copy_from_slice(&(val as u16).to_le_bytes()),
                4 => data[..4].copy_from_slice(&val.to_le_bytes()),
                _ => data.fill(0xFF),
            }
        } else {
            // Empty slot: return all 1s (standard PCI enumeration response)
            data.fill(0xFF);
        }

        true
    }

    /// Handle ECAM MMIO write.
    ///
    /// Returns true if the address was in the ECAM range.
    pub fn handle_ecam_write(&mut self, addr: u64, data: &[u8]) -> bool {
        if addr < self.ecam_base || addr >= self.ecam_base + ECAM_SIZE {
            return false;
        }

        let offset = addr - self.ecam_base;
        let bdf = ecam_decode_bdf(offset);
        let reg_offset = offset & 0xFFF;

        if let Some(dev) = self.find_device_mut(&bdf) {
            dev.config_write(reg_offset, data);
        }

        true
    }

    /// Handle BAR MMIO read (for passthrough device regions).
    ///
    /// Returns true if the address was in a device BAR.
    pub fn handle_bar_read(&self, addr: u64, data: &mut [u8]) -> bool {
        for dev in &self.devices {
            for bar in &dev.bars {
                if addr >= bar.guest_addr && addr < bar.guest_addr + bar.size {
                    if let Some(ref vfio) = dev.vfio {
                        let bar_offset = addr - bar.guest_addr;
                        if let Ok(read_data) = vfio.bar_read(bar.index as usize, bar_offset, data.len()) {
                            let copy_len = data.len().min(read_data.len());
                            data[..copy_len].copy_from_slice(&read_data[..copy_len]);
                        } else {
                            data.fill(0xFF);
                        }
                    }
                    return true;
                }
            }
        }
        false
    }

    /// Handle BAR MMIO write (for passthrough device regions).
    ///
    /// Returns true if the address was in a device BAR.
    pub fn handle_bar_write(&mut self, addr: u64, data: &[u8]) -> bool {
        for dev in &mut self.devices {
            for bar in &dev.bars {
                if addr >= bar.guest_addr && addr < bar.guest_addr + bar.size {
                    if let Some(ref vfio) = dev.vfio {
                        let bar_offset = addr - bar.guest_addr;
                        let _ = vfio.bar_write(bar.index as usize, bar_offset, data);
                    }
                    return true;
                }
            }
        }
        false
    }

    /// Check if an address falls within the ECAM or BAR ranges.
    pub fn handles_address(&self, addr: u64) -> bool {
        // ECAM range
        if addr >= self.ecam_base && addr < self.ecam_base + ECAM_SIZE {
            return true;
        }
        // BAR ranges
        for dev in &self.devices {
            for bar in &dev.bars {
                if addr >= bar.guest_addr && addr < bar.guest_addr + bar.size {
                    return true;
                }
            }
        }
        false
    }

    fn find_device(&self, bdf: &PciBdf) -> Option<&PciDevice> {
        self.devices.iter().find(|d| d.bdf == *bdf)
    }

    fn find_device_mut(&mut self, bdf: &PciBdf) -> Option<&mut PciDevice> {
        self.devices.iter_mut().find(|d| d.bdf == *bdf)
    }

    /// Get all device BDFs.
    pub fn device_bdfs(&self) -> Vec<PciBdf> {
        self.devices.iter().map(|d| d.bdf).collect()
    }

    /// Check if the bus has any devices.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

/// Decode BDF from an ECAM offset.
fn ecam_decode_bdf(offset: u64) -> PciBdf {
    PciBdf {
        bus: ((offset >> 20) & 0xFF) as u8,
        device: ((offset >> 15) & 0x1F) as u8,
        function: ((offset >> 12) & 0x7) as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecam_decode_bdf() {
        // Device 0, function 0 on bus 0
        let bdf = ecam_decode_bdf(0);
        assert_eq!(bdf.bus, 0);
        assert_eq!(bdf.device, 0);
        assert_eq!(bdf.function, 0);

        // Device 1, function 0 on bus 0
        let bdf = ecam_decode_bdf(1 << 15);
        assert_eq!(bdf.bus, 0);
        assert_eq!(bdf.device, 1);
        assert_eq!(bdf.function, 0);

        // Device 0, function 2 on bus 0
        let bdf = ecam_decode_bdf(2 << 12);
        assert_eq!(bdf.bus, 0);
        assert_eq!(bdf.device, 0);
        assert_eq!(bdf.function, 2);
    }

    #[test]
    fn test_pci_bus_empty_read() {
        let bus = PciBus::new();
        let mut data = [0u8; 4];
        assert!(bus.handle_ecam_read(ECAM_BASE, &mut data));
        // Empty slot returns all 1s
        assert_eq!(data, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_bdf_display() {
        let bdf = PciBdf::new(0, 1, 0);
        assert_eq!(format!("{bdf}"), "00:01.0");
    }

    #[test]
    fn test_ecam_range() {
        let bus = PciBus::new();
        assert!(bus.handles_address(ECAM_BASE));
        assert!(bus.handles_address(ECAM_BASE + ECAM_SIZE - 1));
        assert!(!bus.handles_address(ECAM_BASE + ECAM_SIZE));
        assert!(!bus.handles_address(ECAM_BASE - 1));
    }
}
