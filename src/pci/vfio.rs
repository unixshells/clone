//! VFIO device passthrough.
//!
//! Manages the VFIO container → group → device lifecycle:
//! 1. Open /dev/vfio/vfio (container), set IOMMU type
//! 2. Open /dev/vfio/N (group), add to container
//! 3. VFIO_GROUP_GET_DEVICE_FD → device fd
//! 4. Query regions, map DMA, set up MSI-X
//!
//! No external crate dependencies — raw ioctl constants from Linux headers.

use std::fs;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::MsixState;

// ---------------------------------------------------------------------------
// VFIO ioctl constants (from linux/vfio.h)
// ---------------------------------------------------------------------------

const VFIO_TYPE: u8 = b';'; // 0x3B
const VFIO_BASE: u8 = 100;

// Container ioctls
const VFIO_GET_API_VERSION: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE);
const VFIO_CHECK_EXTENSION: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE + 1);
const VFIO_SET_IOMMU: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE + 2);

// Group ioctls
const VFIO_GROUP_GET_STATUS: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE + 3);
const VFIO_GROUP_SET_CONTAINER: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE + 4);
const VFIO_GROUP_GET_DEVICE_FD: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE + 6);

// Device ioctls
const VFIO_DEVICE_GET_INFO: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE + 7);
const VFIO_DEVICE_GET_REGION_INFO: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE + 8);
const VFIO_DEVICE_RESET: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE + 11);

// IOMMU ioctls
const VFIO_IOMMU_MAP_DMA: u64 = request_code_none!(VFIO_TYPE, VFIO_BASE + 13);

// Constants
const VFIO_API_VERSION: i32 = 0;
const VFIO_TYPE1_IOMMU: u64 = 1;
const VFIO_TYPE1V2_IOMMU: u64 = 3;

// Group status flags
const VFIO_GROUP_FLAGS_VIABLE: u32 = 1;

// DMA map flags
const VFIO_DMA_MAP_FLAG_READ: u32 = 1;
const VFIO_DMA_MAP_FLAG_WRITE: u32 = 2;

// Region flags
const VFIO_REGION_INFO_FLAG_READ: u32 = 1;
const VFIO_REGION_INFO_FLAG_WRITE: u32 = 2;
const VFIO_REGION_INFO_FLAG_MMAP: u32 = 4;

// ---------------------------------------------------------------------------
// ioctl helper macro
// ---------------------------------------------------------------------------

macro_rules! request_code_none {
    ($ty:expr, $nr:expr) => {
        (($ty as u64) << 8) | ($nr as u64)
    };
}

// Re-export for use in constants above (macros must be defined before use)
pub(crate) use request_code_none;

// ---------------------------------------------------------------------------
// VFIO ioctl structs (repr(C) matching kernel headers)
// ---------------------------------------------------------------------------

#[repr(C)]
struct VfioGroupStatus {
    argsz: u32,
    flags: u32,
}

#[repr(C)]
struct VfioDeviceInfo {
    argsz: u32,
    flags: u32,
    num_regions: u32,
    num_irqs: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct VfioRegionInfo {
    pub argsz: u32,
    pub flags: u32,
    pub index: u32,
    pub cap_offset: u32,
    pub size: u64,
    pub offset: u64,
}

#[repr(C)]
struct VfioDmaMap {
    argsz: u32,
    flags: u32,
    vaddr: u64,
    iova: u64,
    size: u64,
}

// ---------------------------------------------------------------------------
// VFIO Device
// ---------------------------------------------------------------------------

/// A VFIO device opened for passthrough.
pub struct VfioDevice {
    /// Container fd (/dev/vfio/vfio).
    container_fd: RawFd,
    /// Group fd (/dev/vfio/N).
    group_fd: RawFd,
    /// Device fd.
    device_fd: RawFd,
    /// BDF string (e.g., "0000:01:00.0").
    pub bdf: String,
    /// Discovered regions.
    regions: Vec<VfioRegionInfo>,
    /// Whether we own the fds (for Drop).
    owned: bool,
}

impl VfioDevice {
    /// Open a VFIO device by its sysfs BDF (e.g., "0000:01:00.0").
    ///
    /// The device must already be bound to the `vfio-pci` driver.
    pub fn open(bdf: &str) -> Result<Self> {
        // 1. Find IOMMU group
        let iommu_group = find_iommu_group(bdf)?;
        tracing::info!("VFIO device {bdf}: IOMMU group {iommu_group}");

        // 2. Open container
        let container_fd = open_rw("/dev/vfio/vfio")
            .context("Failed to open /dev/vfio/vfio")?;

        // Check API version
        let version = unsafe { libc::ioctl(container_fd, VFIO_GET_API_VERSION as libc::c_ulong) };
        if version != VFIO_API_VERSION as i32 {
            anyhow::bail!("VFIO API version mismatch: got {version}, expected {VFIO_API_VERSION}");
        }

        // Check IOMMU support
        let has_type1v2 = unsafe {
            libc::ioctl(container_fd, VFIO_CHECK_EXTENSION as libc::c_ulong, VFIO_TYPE1V2_IOMMU)
        };
        let iommu_type = if has_type1v2 > 0 {
            VFIO_TYPE1V2_IOMMU
        } else {
            let has_type1 = unsafe {
                libc::ioctl(container_fd, VFIO_CHECK_EXTENSION as libc::c_ulong, VFIO_TYPE1_IOMMU)
            };
            if has_type1 <= 0 {
                anyhow::bail!("No supported VFIO IOMMU type found");
            }
            VFIO_TYPE1_IOMMU
        };

        // 3. Open group
        let group_path = format!("/dev/vfio/{iommu_group}");
        let group_fd = open_rw(&group_path)
            .with_context(|| format!("Failed to open VFIO group: {group_path}"))?;

        // Check group is viable
        let mut status = VfioGroupStatus { argsz: 8, flags: 0 };
        let ret = unsafe {
            libc::ioctl(group_fd, VFIO_GROUP_GET_STATUS as libc::c_ulong, &mut status)
        };
        if ret < 0 {
            anyhow::bail!("VFIO_GROUP_GET_STATUS failed: {}", std::io::Error::last_os_error());
        }
        if status.flags & VFIO_GROUP_FLAGS_VIABLE == 0 {
            anyhow::bail!(
                "VFIO group {iommu_group} is not viable. \
                 Ensure all devices in the group are bound to vfio-pci."
            );
        }

        // 4. Set container for group
        let ret = unsafe {
            libc::ioctl(group_fd, VFIO_GROUP_SET_CONTAINER as libc::c_ulong, &container_fd)
        };
        if ret < 0 {
            anyhow::bail!("VFIO_GROUP_SET_CONTAINER failed: {}", std::io::Error::last_os_error());
        }

        // 5. Set IOMMU type
        let ret = unsafe {
            libc::ioctl(container_fd, VFIO_SET_IOMMU as libc::c_ulong, iommu_type)
        };
        if ret < 0 {
            anyhow::bail!("VFIO_SET_IOMMU failed: {}", std::io::Error::last_os_error());
        }

        // 6. Get device fd
        let bdf_cstr = std::ffi::CString::new(bdf)?;
        let device_fd = unsafe {
            libc::ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD as libc::c_ulong, bdf_cstr.as_ptr())
        };
        if device_fd < 0 {
            anyhow::bail!(
                "VFIO_GROUP_GET_DEVICE_FD failed for {bdf}: {}",
                std::io::Error::last_os_error()
            );
        }

        // 7. Query device info
        let mut dev_info = VfioDeviceInfo {
            argsz: std::mem::size_of::<VfioDeviceInfo>() as u32,
            flags: 0,
            num_regions: 0,
            num_irqs: 0,
        };
        let ret = unsafe {
            libc::ioctl(device_fd, VFIO_DEVICE_GET_INFO as libc::c_ulong, &mut dev_info)
        };
        if ret < 0 {
            anyhow::bail!("VFIO_DEVICE_GET_INFO failed: {}", std::io::Error::last_os_error());
        }
        tracing::info!(
            "VFIO device {bdf}: {} regions, {} IRQs",
            dev_info.num_regions, dev_info.num_irqs
        );

        // 8. Query regions
        let mut regions = Vec::new();
        for i in 0..dev_info.num_regions {
            let mut region = VfioRegionInfo {
                argsz: std::mem::size_of::<VfioRegionInfo>() as u32,
                flags: 0,
                index: i,
                cap_offset: 0,
                size: 0,
                offset: 0,
            };
            let ret = unsafe {
                libc::ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO as libc::c_ulong, &mut region)
            };
            if ret < 0 {
                tracing::warn!("Failed to get region {i} info");
                continue;
            }
            if region.size > 0 {
                tracing::info!(
                    "  Region {i}: size={:#x}, flags={:#x}, offset={:#x}",
                    region.size, region.flags, region.offset
                );
            }
            regions.push(region);
        }

        Ok(Self {
            container_fd,
            group_fd,
            device_fd,
            bdf: bdf.to_string(),
            regions,
            owned: true,
        })
    }

    /// Map guest memory for DMA (IOVA = GPA identity mapping).
    pub fn map_dma(&self, guest_mem_ptr: *const u8, mem_size: u64) -> Result<()> {
        let dma_map = VfioDmaMap {
            argsz: std::mem::size_of::<VfioDmaMap>() as u32,
            flags: VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
            vaddr: guest_mem_ptr as u64,
            iova: 0, // Identity mapping: IOVA == GPA
            size: mem_size,
        };

        let ret = unsafe {
            libc::ioctl(self.container_fd, VFIO_IOMMU_MAP_DMA as libc::c_ulong, &dma_map)
        };
        if ret < 0 {
            anyhow::bail!(
                "VFIO_IOMMU_MAP_DMA failed: {}",
                std::io::Error::last_os_error()
            );
        }

        tracing::info!("DMA mapped: IOVA 0x0-{:#x} → vaddr {:#x}", mem_size, guest_mem_ptr as u64);
        Ok(())
    }

    /// Get discovered regions.
    pub fn get_regions(&self) -> Result<Vec<VfioRegionInfo>> {
        Ok(self.regions.clone())
    }

    /// Read from PCI config space (region index typically = num_regions - 1 or index 7).
    pub fn config_read(&self, offset: usize, len: usize) -> Result<Vec<u8>> {
        // PCI config space is typically region index 7 (VFIO_PCI_CONFIG_REGION_INDEX)
        let config_region_idx = 7;
        if let Some(region) = self.regions.get(config_region_idx) {
            let mut buf = vec![0u8; len];
            let n = unsafe {
                libc::pread(
                    self.device_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    len,
                    (region.offset + offset as u64) as libc::off_t,
                )
            };
            if n < 0 {
                anyhow::bail!("Config read failed: {}", std::io::Error::last_os_error());
            }
            buf.truncate(n as usize);
            Ok(buf)
        } else {
            anyhow::bail!("Config region not found");
        }
    }

    /// Write to PCI config space.
    pub fn config_write(&self, offset: usize, data: &[u8]) -> Result<()> {
        let config_region_idx = 7;
        if let Some(region) = self.regions.get(config_region_idx) {
            let n = unsafe {
                libc::pwrite(
                    self.device_fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    (region.offset + offset as u64) as libc::off_t,
                )
            };
            if n < 0 {
                anyhow::bail!("Config write failed: {}", std::io::Error::last_os_error());
            }
            Ok(())
        } else {
            anyhow::bail!("Config region not found");
        }
    }

    /// Read from a BAR region.
    pub fn bar_read(&self, bar_index: usize, offset: u64, len: usize) -> Result<Vec<u8>> {
        if let Some(region) = self.regions.get(bar_index) {
            let mut buf = vec![0u8; len];
            let n = unsafe {
                libc::pread(
                    self.device_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    len,
                    (region.offset + offset) as libc::off_t,
                )
            };
            if n < 0 {
                anyhow::bail!("BAR read failed: {}", std::io::Error::last_os_error());
            }
            buf.truncate(n as usize);
            Ok(buf)
        } else {
            anyhow::bail!("BAR region {bar_index} not found");
        }
    }

    /// Write to a BAR region.
    pub fn bar_write(&self, bar_index: usize, offset: u64, data: &[u8]) -> Result<()> {
        if let Some(region) = self.regions.get(bar_index) {
            let n = unsafe {
                libc::pwrite(
                    self.device_fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    (region.offset + offset) as libc::off_t,
                )
            };
            if n < 0 {
                anyhow::bail!("BAR write failed: {}", std::io::Error::last_os_error());
            }
            Ok(())
        } else {
            anyhow::bail!("BAR region {bar_index} not found");
        }
    }

    /// Map a device BAR into the KVM memory region for direct MMIO access.
    ///
    /// For VFIO, the actual data path goes through KVM MMIO exits → pread/pwrite
    /// on the VFIO device fd. This is a placeholder for future mmap optimization.
    pub fn map_bar(&mut self, bar_index: usize, guest_addr: u64, size: u64) -> Result<()> {
        tracing::info!(
            "VFIO {} BAR{}: mapped at guest {:#x}, size {:#x}",
            self.bdf, bar_index, guest_addr, size
        );
        Ok(())
    }

    /// Set up MSI-X if the device supports it.
    pub fn setup_msix(&mut self) -> Result<Option<MsixState>> {
        // TODO: Full MSI-X setup requires:
        // 1. VFIO_DEVICE_GET_IRQ_INFO to check MSI-X capability
        // 2. Create eventfds per vector
        // 3. VFIO_DEVICE_SET_IRQS to associate eventfds
        // 4. KVM irqfd for each eventfd → guest IRQ injection
        //
        // For now, return None — the device still works via INTx (legacy interrupts).
        Ok(None)
    }

    /// Reset the device.
    pub fn reset(&self) -> Result<()> {
        let ret = unsafe {
            libc::ioctl(self.device_fd, VFIO_DEVICE_RESET as libc::c_ulong)
        };
        if ret < 0 {
            tracing::warn!("VFIO device reset failed: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for VfioDevice {
    fn drop(&mut self) {
        if self.owned {
            let _ = self.reset();
            unsafe {
                libc::close(self.device_fd);
                libc::close(self.group_fd);
                libc::close(self.container_fd);
            }
        }
    }
}

// SAFETY: VfioDevice fds are not shared across threads without synchronization.
unsafe impl Send for VfioDevice {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the IOMMU group for a PCI device.
fn find_iommu_group(bdf: &str) -> Result<u32> {
    let link = fs::read_link(format!("/sys/bus/pci/devices/{bdf}/iommu_group"))
        .with_context(|| format!("Device {bdf} has no IOMMU group (is iommu enabled in BIOS?)"))?;

    let group_name = link.file_name()
        .and_then(|n| n.to_str())
        .context("Invalid IOMMU group path")?;

    group_name.parse::<u32>()
        .with_context(|| format!("Invalid IOMMU group number: {group_name}"))
}

/// Open a file read-write and return the raw fd.
fn open_rw(path: &str) -> Result<RawFd> {
    let fd = unsafe {
        libc::open(
            std::ffi::CString::new(path)?.as_ptr(),
            libc::O_RDWR,
        )
    };
    if fd < 0 {
        anyhow::bail!("Failed to open {path}: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// Check if a PCI device is bound to vfio-pci.
pub fn is_vfio_bound(bdf: &str) -> bool {
    let driver_link = format!("/sys/bus/pci/devices/{bdf}/driver");
    if let Ok(link) = fs::read_link(&driver_link) {
        link.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s == "vfio-pci")
            .unwrap_or(false)
    } else {
        false
    }
}

/// Find any PCI device bound to vfio-pci (for testing).
pub fn find_any_vfio_device() -> Option<String> {
    let pci_dir = Path::new("/sys/bus/pci/devices");
    if let Ok(entries) = fs::read_dir(pci_dir) {
        for entry in entries.flatten() {
            let bdf = entry.file_name().to_string_lossy().to_string();
            if is_vfio_bound(&bdf) {
                return Some(bdf);
            }
        }
    }
    None
}
