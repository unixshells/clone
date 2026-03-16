// Virtio-block device.
//
// Provides block storage to the guest via a backing file (raw or qcow2).
// Single request queue. Supports read, write, and flush operations.
// Thin provisioning via sparse files on the host.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::storage::qcow2::Qcow2File;

use super::queue::{DescriptorChain, Virtqueue, VRING_DESC_F_WRITE};
use super::{DeviceType, VirtioDevice};

// --- Feature bits (virtio spec 5.2.3) ---

/// Maximum size of any single segment is in `size_max`.
const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
/// Maximum number of segments in a request is in `seg_max`.
const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
/// Disk-style geometry specified in `geometry`.
const VIRTIO_BLK_F_GEOMETRY: u64 = 1 << 4;
/// Block size of disk is in `blk_size`.
const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
/// Cache flush command support.
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
/// Virtio 1.0+ requirement.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// --- Request types (virtio spec 5.2.6) ---

/// Read from device.
pub const VIRTIO_BLK_T_IN: u32 = 0;
/// Write to device.
pub const VIRTIO_BLK_T_OUT: u32 = 1;
/// Flush volatile write cache.
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
/// Get device ID.
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;
/// Discard (TRIM).
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;

// --- Status bytes ---

/// Request completed successfully.
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// Request failed (I/O error).
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
/// Request unsupported.
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

// --- Config space layout (virtio spec 5.2.4) ---
// Bytes 0-7:   capacity (u64, le, in 512-byte sectors)
// Bytes 8-11:  size_max (u32)
// Bytes 12-15: seg_max (u32)
// Bytes 16-19: geometry (cylinders u16 + heads u8 + sectors u8)
// Bytes 20-23: blk_size (u32)
const CONFIG_CAPACITY_OFFSET: u64 = 0;
const CONFIG_BLK_SIZE_OFFSET: u64 = 20;
const CONFIG_SPACE_SIZE: usize = 24;

/// Sector size in bytes.
const SECTOR_SIZE: u64 = 512;

/// Maximum queue size.
const QUEUE_MAX_SIZE: u16 = 128;

/// Request queue index.
const REQUEST_QUEUE: u16 = 0;

/// Re-export DiskFormat from the storage layer.
pub use crate::storage::DiskFormat;

/// The backing store for a virtio-block device — either raw file I/O or QCOW2.
enum BlockBackend {
    /// Raw disk image — direct seek/read/write.
    Raw(File),
    /// QCOW2 disk image — translated through L1/L2 tables.
    Qcow2(Qcow2File),
}

/// A virtio-block device backed by a disk image file.
pub struct VirtioBlock {
    /// Backing store (raw or qcow2).
    backend: BlockBackend,

    /// Path to the disk image.
    path: PathBuf,

    /// Disk format.
    format: DiskFormat,

    /// Whether the disk is read-only.
    readonly: bool,

    /// Capacity in 512-byte sectors.
    capacity_sectors: u64,

    /// Block size (typically 512).
    block_size: u32,

    /// Acknowledged feature bits (low 32 bits).
    acked_features_low: u32,
    /// Acknowledged feature bits (high 32 bits).
    acked_features_high: u32,

    /// Whether the device has been activated.
    activated: bool,
}

impl VirtioBlock {
    /// Create a new virtio-block device from an already-opened raw file.
    ///
    /// `capacity_sectors` is the disk size in 512-byte sectors.
    pub fn new(
        file: File,
        path: PathBuf,
        format: DiskFormat,
        readonly: bool,
        capacity_sectors: u64,
    ) -> Self {
        Self {
            backend: BlockBackend::Raw(file),
            path,
            format,
            readonly,
            capacity_sectors,
            block_size: SECTOR_SIZE as u32,
            acked_features_low: 0,
            acked_features_high: 0,
            activated: false,
        }
    }

    /// Open a disk image file and create a VirtioBlock device.
    ///
    /// Automatically detects QCOW2 vs raw format and uses the appropriate
    /// I/O backend.
    pub fn open<P: AsRef<Path>>(path: P, readonly: bool) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Use the storage layer for format detection and file opening
        let disk = crate::storage::open_disk(&path, readonly)?;

        match disk.format {
            DiskFormat::Qcow2 => {
                let qcow2 = Qcow2File::open(&path)?;
                let virtual_size = qcow2.virtual_size();
                let capacity_sectors = virtual_size / SECTOR_SIZE;

                tracing::info!(
                    "virtio-block: opened QCOW2 {} ({} sectors, {})",
                    path.display(),
                    capacity_sectors,
                    if readonly { "ro" } else { "rw" }
                );

                Ok(Self {
                    backend: BlockBackend::Qcow2(qcow2),
                    path,
                    format: disk.format,
                    readonly,
                    capacity_sectors,
                    block_size: SECTOR_SIZE as u32,
                    acked_features_low: 0,
                    acked_features_high: 0,
                    activated: false,
                })
            }
            DiskFormat::Raw => {
                let capacity_sectors = disk.virtual_size / SECTOR_SIZE;
                Ok(Self::new(disk.file, path, disk.format, readonly, capacity_sectors))
            }
        }
    }

    /// Get the capacity in sectors.
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    /// Get the disk format.
    pub fn format(&self) -> DiskFormat {
        self.format
    }

    /// Process a block request.
    ///
    /// In the full MMIO wiring, the transport layer parses the virtio_blk_req
    /// header from the descriptor chain and calls these methods. We expose
    /// them publicly so the transport can drive I/O.
    pub fn process_request(
        &mut self,
        request_type: u32,
        sector: u64,
        data: &mut [u8],
    ) -> u8 {
        match request_type {
            VIRTIO_BLK_T_IN => self.do_read(sector, data),
            VIRTIO_BLK_T_OUT => self.do_write(sector, data),
            VIRTIO_BLK_T_FLUSH => self.do_flush(),
            VIRTIO_BLK_T_GET_ID => {
                // Write disk ID (path basename, truncated to 20 bytes).
                let id = self
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let id_bytes = id.as_bytes();
                let len = std::cmp::min(id_bytes.len(), data.len());
                data[..len].copy_from_slice(&id_bytes[..len]);
                if len < data.len() {
                    // Zero-fill remainder.
                    data[len..].fill(0);
                }
                VIRTIO_BLK_S_OK
            }
            VIRTIO_BLK_T_DISCARD => self.do_discard(sector, data.len() as u64),
            _ => {
                tracing::warn!("virtio-block: unsupported request type {request_type}");
                VIRTIO_BLK_S_UNSUPP
            }
        }
    }

    fn do_read(&mut self, sector: u64, buf: &mut [u8]) -> u8 {
        let offset = sector * SECTOR_SIZE;
        if offset + buf.len() as u64 > self.capacity_sectors * SECTOR_SIZE {
            tracing::error!("virtio-block: read past end of disk");
            return VIRTIO_BLK_S_IOERR;
        }

        match &mut self.backend {
            BlockBackend::Raw(file) => {
                if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                    tracing::error!("virtio-block: seek failed: {e}");
                    return VIRTIO_BLK_S_IOERR;
                }
                if let Err(e) = file.read_exact(buf) {
                    tracing::error!("virtio-block: read failed: {e}");
                    return VIRTIO_BLK_S_IOERR;
                }
            }
            BlockBackend::Qcow2(qcow2) => {
                if let Err(e) = qcow2.read_at(offset, buf) {
                    tracing::error!("virtio-block: qcow2 read failed: {e}");
                    return VIRTIO_BLK_S_IOERR;
                }
            }
        }

        VIRTIO_BLK_S_OK
    }

    fn do_write(&mut self, sector: u64, data: &[u8]) -> u8 {
        if self.readonly {
            tracing::warn!("virtio-block: write to read-only disk");
            return VIRTIO_BLK_S_IOERR;
        }

        let offset = sector * SECTOR_SIZE;
        if offset + data.len() as u64 > self.capacity_sectors * SECTOR_SIZE {
            tracing::error!("virtio-block: write past end of disk");
            return VIRTIO_BLK_S_IOERR;
        }

        match &mut self.backend {
            BlockBackend::Raw(file) => {
                if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                    tracing::error!("virtio-block: seek failed: {e}");
                    return VIRTIO_BLK_S_IOERR;
                }
                if let Err(e) = file.write_all(data) {
                    tracing::error!("virtio-block: write failed: {e}");
                    return VIRTIO_BLK_S_IOERR;
                }
            }
            BlockBackend::Qcow2(qcow2) => {
                if let Err(e) = qcow2.write_at(offset, data) {
                    tracing::error!("virtio-block: qcow2 write failed: {e}");
                    return VIRTIO_BLK_S_IOERR;
                }
            }
        }

        VIRTIO_BLK_S_OK
    }

    fn do_flush(&mut self) -> u8 {
        match &mut self.backend {
            BlockBackend::Raw(file) => {
                if let Err(e) = file.sync_all() {
                    tracing::error!("virtio-block: flush failed: {e}");
                    return VIRTIO_BLK_S_IOERR;
                }
            }
            BlockBackend::Qcow2(qcow2) => {
                if let Err(e) = qcow2.flush() {
                    tracing::error!("virtio-block: qcow2 flush failed: {e}");
                    return VIRTIO_BLK_S_IOERR;
                }
            }
        }
        VIRTIO_BLK_S_OK
    }

    /// Discard (TRIM) sectors using fallocate PUNCH_HOLE on Linux for raw images.
    /// For QCOW2, discard is a no-op (clusters remain allocated).
    fn do_discard(&mut self, sector: u64, byte_len: u64) -> u8 {
        if self.readonly {
            return VIRTIO_BLK_S_IOERR;
        }

        match &self.backend {
            BlockBackend::Qcow2(_) => {
                // QCOW2 doesn't support discard — just report success.
                VIRTIO_BLK_S_OK
            }
            BlockBackend::Raw(_file) => {
                let offset = sector * SECTOR_SIZE;

                #[cfg(target_os = "linux")]
                {
                    let ret = unsafe {
                        libc::fallocate(
                            _file.as_raw_fd(),
                            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                            offset as i64,
                            byte_len as i64,
                        )
                    };
                    if ret < 0 {
                        tracing::error!(
                            "virtio-block: fallocate punch_hole failed: {}",
                            std::io::Error::last_os_error()
                        );
                        return VIRTIO_BLK_S_IOERR;
                    }
                    VIRTIO_BLK_S_OK
                }

                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (offset, byte_len);
                    tracing::debug!("virtio-block: discard not supported on this platform (stub)");
                    VIRTIO_BLK_S_OK
                }
            }
        }
    }
}

impl VirtioDevice for VirtioBlock {
    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &[QUEUE_MAX_SIZE]
    }

    fn features(&self, page: u32) -> u32 {
        let all = VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_FLUSH | VIRTIO_F_VERSION_1;
        match page {
            0 => (all & 0xFFFF_FFFF) as u32,
            1 => ((all >> 32) & 0xFFFF_FFFF) as u32,
            _ => 0,
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        match page {
            0 => self.acked_features_low = value,
            1 => self.acked_features_high = value,
            _ => {}
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config = [0u8; CONFIG_SPACE_SIZE];

        // capacity (u64 LE at offset 0)
        config[0..8].copy_from_slice(&self.capacity_sectors.to_le_bytes());

        // blk_size (u32 LE at offset 20)
        config[20..24].copy_from_slice(&self.block_size.to_le_bytes());

        let start = offset as usize;
        let end = std::cmp::min(start + data.len(), config.len());
        if start < end {
            let len = end - start;
            data[..len].copy_from_slice(&config[start..end]);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        tracing::debug!(
            "virtio-block: write_config offset={offset} len={} (ignored)",
            data.len()
        );
    }

    fn activate(&mut self) -> anyhow::Result<()> {
        self.activated = true;
        tracing::info!(
            "virtio-block: activated ({}, {} sectors, {:?})",
            self.path.display(),
            self.capacity_sectors,
            self.format
        );
        Ok(())
    }

    fn process_queue(&mut self, queue_index: u16) -> anyhow::Result<()> {
        match queue_index {
            REQUEST_QUEUE => {
                // The actual descriptor chain processing is done by
                // process_descriptor_chain, called by the MMIO transport.
                tracing::trace!("virtio-block: process_queue notification");
                Ok(())
            }
            _ => {
                tracing::warn!("virtio-block: unknown queue index {queue_index}");
                Ok(())
            }
        }
    }

    fn process_descriptor_chain(
        &mut self,
        _queue_index: u16,
        chain: &DescriptorChain,
        vq: &Virtqueue,
    ) -> u32 {
        // A virtio-block request is:
        //   Descriptor 0: readable — virtio_blk_req header (type: u32, reserved: u32, sector: u64)
        //   Descriptor 1..N-1: data buffer(s) — readable for writes, writable for reads
        //   Descriptor N: writable — status byte (u8)
        if chain.descriptors.len() < 2 {
            tracing::error!("virtio-block: descriptor chain too short ({})", chain.descriptors.len());
            return 0;
        }

        // Parse the header from the first readable descriptor
        let header_desc = &chain.descriptors[0];
        if header_desc.len < 16 {
            tracing::error!("virtio-block: header descriptor too small ({})", header_desc.len);
            return 0;
        }

        let header_data = match vq.read_descriptor_data(header_desc) {
            Some(d) => d,
            None => {
                tracing::error!("virtio-block: failed to read header from guest memory");
                return 0;
            }
        };

        let request_type = u32::from_le_bytes([
            header_data[0], header_data[1], header_data[2], header_data[3],
        ]);
        // bytes 4-7: reserved
        let sector = u64::from_le_bytes([
            header_data[8], header_data[9], header_data[10], header_data[11],
            header_data[12], header_data[13], header_data[14], header_data[15],
        ]);

        let mut total_written: u32 = 0;

        // Process data descriptors (between header and status)
        let last_idx = chain.descriptors.len() - 1;
        let status_desc = &chain.descriptors[last_idx];

        match request_type {
            VIRTIO_BLK_T_IN => {
                // Read from device into writable data descriptors
                let mut cur_sector = sector;
                for desc in &chain.descriptors[1..last_idx] {
                    if desc.flags & VRING_DESC_F_WRITE == 0 {
                        continue; // skip non-writable descriptors
                    }
                    if let Some(buf) = vq.write_descriptor_data(desc) {
                        let status = self.process_request(VIRTIO_BLK_T_IN, cur_sector, buf);
                        if status != VIRTIO_BLK_S_OK {
                            // Write error status and return
                            if let Some(status_buf) = vq.write_descriptor_data(status_desc) {
                                if !status_buf.is_empty() {
                                    status_buf[0] = status;
                                    total_written += 1;
                                }
                            }
                            return total_written;
                        }
                        total_written += desc.len;
                        cur_sector += desc.len as u64 / SECTOR_SIZE;
                    }
                }
            }
            VIRTIO_BLK_T_OUT => {
                // Write to device from readable data descriptors
                let mut cur_sector = sector;
                for desc in &chain.descriptors[1..last_idx] {
                    if desc.flags & VRING_DESC_F_WRITE != 0 {
                        continue; // skip writable descriptors for OUT
                    }
                    if let Some(data) = vq.read_descriptor_data(desc) {
                        // process_request needs &mut [u8] for the OUT path, but
                        // the data is read-only from guest perspective. We copy.
                        let mut data_copy = data.to_vec();
                        let status = self.process_request(VIRTIO_BLK_T_OUT, cur_sector, &mut data_copy);
                        if status != VIRTIO_BLK_S_OK {
                            if let Some(status_buf) = vq.write_descriptor_data(status_desc) {
                                if !status_buf.is_empty() {
                                    status_buf[0] = status;
                                    total_written += 1;
                                }
                            }
                            return total_written;
                        }
                        cur_sector += desc.len as u64 / SECTOR_SIZE;
                    }
                }
            }
            VIRTIO_BLK_T_FLUSH => {
                let status = self.process_request(VIRTIO_BLK_T_FLUSH, 0, &mut []);
                if let Some(status_buf) = vq.write_descriptor_data(status_desc) {
                    if !status_buf.is_empty() {
                        status_buf[0] = status;
                        total_written += 1;
                    }
                }
                return total_written;
            }
            VIRTIO_BLK_T_GET_ID => {
                for desc in &chain.descriptors[1..last_idx] {
                    if desc.flags & VRING_DESC_F_WRITE != 0 {
                        if let Some(buf) = vq.write_descriptor_data(desc) {
                            let status = self.process_request(VIRTIO_BLK_T_GET_ID, 0, buf);
                            total_written += desc.len;
                            if status != VIRTIO_BLK_S_OK {
                                if let Some(status_buf) = vq.write_descriptor_data(status_desc) {
                                    if !status_buf.is_empty() {
                                        status_buf[0] = status;
                                        total_written += 1;
                                    }
                                }
                                return total_written;
                            }
                        }
                    }
                }
            }
            _ => {
                // Unsupported request type
                if let Some(status_buf) = vq.write_descriptor_data(status_desc) {
                    if !status_buf.is_empty() {
                        status_buf[0] = VIRTIO_BLK_S_UNSUPP;
                        total_written += 1;
                    }
                }
                return total_written;
            }
        }

        // Write success status byte
        if let Some(status_buf) = vq.write_descriptor_data(status_desc) {
            if !status_buf.is_empty() {
                status_buf[0] = VIRTIO_BLK_S_OK;
                total_written += 1;
            }
        }

        total_written
    }

    fn reset(&mut self) {
        self.acked_features_low = 0;
        self.acked_features_high = 0;
        self.activated = false;
        tracing::info!("virtio-block: reset");
    }

    fn snapshot_state(&self) -> Vec<u8> {
        let state = serde_json::json!({
            "capacity_sectors": self.capacity_sectors,
            "acked_features_low": self.acked_features_low,
            "acked_features_high": self.acked_features_high,
            "readonly": self.readonly,
        });
        serde_json::to_vec(&state).unwrap_or_default()
    }

    fn restore_state(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() { return Ok(()); }
        let state: serde_json::Value = serde_json::from_slice(data)?;
        if let Some(v) = state.get("acked_features_low").and_then(|v| v.as_u64()) {
            self.acked_features_low = v as u32;
        }
        if let Some(v) = state.get("acked_features_high").and_then(|v| v.as_u64()) {
            self.acked_features_high = v as u32;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn make_temp_disk(size: u64) -> (tempfile::NamedTempFile, PathBuf) {
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(size).unwrap();
        let path = f.path().to_path_buf();
        (f, path)
    }

    #[test]
    fn test_read_write() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 100);
        let mut dev = VirtioBlock::open(&path, false).unwrap();

        // Write data.
        let data = b"Hello, block device!";
        let mut buf = [0u8; 512];
        buf[..data.len()].copy_from_slice(data);
        let status = dev.process_request(VIRTIO_BLK_T_OUT, 0, &mut buf);
        assert_eq!(status, VIRTIO_BLK_S_OK);

        // Read it back.
        let mut read_buf = [0u8; 512];
        let status = dev.process_request(VIRTIO_BLK_T_IN, 0, &mut read_buf);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        assert_eq!(&read_buf[..data.len()], data);

        drop(tmp); // ensure temp file lives long enough
    }

    #[test]
    fn test_readonly_write_fails() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, true).unwrap();
        let mut buf = [0u8; 512];
        let status = dev.process_request(VIRTIO_BLK_T_OUT, 0, &mut buf);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        drop(tmp);
    }

    #[test]
    fn test_config_capacity() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 42);
        let dev = VirtioBlock::open(&path, true).unwrap();

        let mut buf = [0u8; 8];
        dev.read_config(CONFIG_CAPACITY_OFFSET, &mut buf);
        let capacity = u64::from_le_bytes(buf);
        assert_eq!(capacity, 42);
        drop(tmp);
    }

    #[test]
    fn test_device_type() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE);
        let dev = VirtioBlock::open(&path, true).unwrap();
        assert_eq!(dev.device_type(), DeviceType::Block);
        drop(tmp);
    }

    #[test]
    fn test_detect_raw() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        assert_eq!(detect_format(&path).unwrap(), DiskFormat::Raw);
        drop(tmp);
    }

    #[test]
    fn test_flush_operation() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, false).unwrap();

        // Write some data first
        let mut buf = [0x42u8; 512];
        dev.process_request(VIRTIO_BLK_T_OUT, 0, &mut buf);

        // Flush should succeed
        let status = dev.process_request(VIRTIO_BLK_T_FLUSH, 0, &mut []);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        drop(tmp);
    }

    #[test]
    fn test_get_id_returns_device_path() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, false).unwrap();

        let mut id_buf = [0u8; 64];
        let status = dev.process_request(VIRTIO_BLK_T_GET_ID, 0, &mut id_buf);
        assert_eq!(status, VIRTIO_BLK_S_OK);

        // The ID should contain the file name
        let file_name = path.file_name().unwrap().to_string_lossy();
        let id_str = String::from_utf8_lossy(&id_buf);
        assert!(id_str.starts_with(&*file_name));
        drop(tmp);
    }

    #[test]
    fn test_get_id_truncates_long_name() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, false).unwrap();

        // Request ID with a small buffer
        let mut id_buf = [0u8; 4];
        let status = dev.process_request(VIRTIO_BLK_T_GET_ID, 0, &mut id_buf);
        assert_eq!(status, VIRTIO_BLK_S_OK);
        // Should not panic even with small buffer
        drop(tmp);
    }

    #[test]
    fn test_config_space_capacity_calculation() {
        // 100 sectors = 51200 bytes
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 100);
        let dev = VirtioBlock::open(&path, true).unwrap();
        assert_eq!(dev.capacity_sectors(), 100);

        let mut buf = [0u8; 8];
        dev.read_config(CONFIG_CAPACITY_OFFSET, &mut buf);
        let capacity = u64::from_le_bytes(buf);
        assert_eq!(capacity, 100);
        drop(tmp);
    }

    #[test]
    fn test_config_space_blk_size() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let dev = VirtioBlock::open(&path, true).unwrap();

        let mut buf = [0u8; 4];
        dev.read_config(CONFIG_BLK_SIZE_OFFSET, &mut buf);
        let blk_size = u32::from_le_bytes(buf);
        assert_eq!(blk_size, 512);
        drop(tmp);
    }

    #[test]
    fn test_device_reset_clears_state() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, false).unwrap();

        // Activate and set features
        dev.ack_features(0, 0xFF);
        dev.ack_features(1, 0x01);
        dev.activate().unwrap();

        // Reset
        dev.reset();
        assert_eq!(dev.acked_features_low, 0);
        assert_eq!(dev.acked_features_high, 0);
        assert!(!dev.activated);
        drop(tmp);
    }

    #[test]
    fn test_read_past_end_of_disk() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, false).unwrap();

        // Try to read at sector 20 (past the 10-sector disk)
        let mut buf = [0u8; 512];
        let status = dev.process_request(VIRTIO_BLK_T_IN, 20, &mut buf);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        drop(tmp);
    }

    #[test]
    fn test_write_past_end_of_disk() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, false).unwrap();

        let mut buf = [0u8; 512];
        let status = dev.process_request(VIRTIO_BLK_T_OUT, 20, &mut buf);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        drop(tmp);
    }

    #[test]
    fn test_unsupported_request_type() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, false).unwrap();

        let mut buf = [0u8; 512];
        let status = dev.process_request(255, 0, &mut buf);
        assert_eq!(status, VIRTIO_BLK_S_UNSUPP);
        drop(tmp);
    }

    #[test]
    fn test_features_page0_and_page1() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE);
        let dev = VirtioBlock::open(&path, true).unwrap();

        let f0 = dev.features(0);
        // Should include BLK_SIZE and FLUSH
        assert_ne!(f0 & (VIRTIO_BLK_F_BLK_SIZE as u32), 0);
        assert_ne!(f0 & (VIRTIO_BLK_F_FLUSH as u32), 0);

        let f1 = dev.features(1);
        // Should include VERSION_1 (bit 0 of page 1 = bit 32 overall)
        assert_ne!(f1 & 1, 0);

        // Page 2+ should be 0
        assert_eq!(dev.features(2), 0);
        drop(tmp);
    }

    #[test]
    fn test_queue_max_sizes() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE);
        let dev = VirtioBlock::open(&path, true).unwrap();
        assert_eq!(dev.queue_max_sizes(), &[128]);
        drop(tmp);
    }

    #[test]
    fn test_discard_on_readonly_fails() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, true).unwrap();

        let mut buf = [0u8; 512];
        let status = dev.process_request(VIRTIO_BLK_T_DISCARD, 0, &mut buf);
        assert_eq!(status, VIRTIO_BLK_S_IOERR);
        drop(tmp);
    }

    #[test]
    fn test_activate_and_process_queue() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let mut dev = VirtioBlock::open(&path, false).unwrap();

        assert!(dev.activate().is_ok());
        assert!(dev.process_queue(0).is_ok()); // request queue
        assert!(dev.process_queue(99).is_ok()); // unknown queue, should not error
        drop(tmp);
    }

    #[test]
    fn test_format_detection() {
        let (tmp, path) = make_temp_disk(SECTOR_SIZE * 10);
        let dev = VirtioBlock::open(&path, false).unwrap();
        assert_eq!(dev.format(), DiskFormat::Raw);
        drop(tmp);
    }
}
