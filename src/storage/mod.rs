// Storage subsystem.
//
// Phase 1: basic virtio-block for root disk
// Phase 2: virtiofs + DAX for shared rootfs
// Phase 4: persistent home dirs with thin provisioning
//
// Architecture:
// - Shared rootfs: virtiofs with DAX (read-only base image)
// - Per-user overlay: CoW writable layer in tmpfs
// - Persistent home: virtio-block, thin-provisioned, qcow2 format

pub mod qcow2;

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Disk image format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskFormat {
    /// Raw disk image — direct mapping, sparse file for thin provisioning.
    Raw,
    /// QCOW2 format — placeholder, not fully implemented yet.
    Qcow2,
}

/// Represents an opened disk image.
pub struct DiskImage {
    /// Path to the disk image file.
    pub path: PathBuf,
    /// Detected or specified format.
    pub format: DiskFormat,
    /// Whether the image is opened read-only.
    pub readonly: bool,
    /// The opened file handle.
    pub file: File,
    /// Virtual size in bytes (may be larger than actual allocation for sparse files).
    pub virtual_size: u64,
}

impl DiskImage {
    /// Get the actual (allocated) size on disk.
    pub fn actual_size(&self) -> anyhow::Result<u64> {
        let metadata = self.file.metadata()?;
        // On Linux, st_blocks * 512 gives the actually allocated bytes.
        // On macOS, we use the same approach via std metadata (which gives
        // logical size, not allocated — but it's the best we can do portably).
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(metadata.blocks() * 512)
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Fallback: report logical size.
            Ok(metadata.len())
        }
    }
}

/// Create a thin-provisioned (sparse) disk image.
///
/// The file is created with `virtual_size` as its logical length, but no
/// actual disk blocks are allocated until data is written. This is the
/// standard Linux sparse file mechanism.
///
/// Returns the path to the created file.
pub fn create_thin_disk(path: &Path, virtual_size: u64) -> anyhow::Result<PathBuf> {
    let file = File::create(path)?;

    // set_len creates a sparse file — no blocks allocated.
    file.set_len(virtual_size)?;

    tracing::info!(
        "Created thin-provisioned disk: {} ({} bytes virtual)",
        path.display(),
        virtual_size
    );

    Ok(path.to_path_buf())
}

/// Open a disk image, auto-detecting its format.
///
/// Format detection:
/// - Reads the first 4 bytes for the QCOW2 magic number (QFI\xfb).
/// - Falls back to Raw if not recognized.
pub fn open_disk(path: &Path, readonly: bool) -> anyhow::Result<DiskImage> {
    // Detect format first (need a separate read-only open for this).
    let format = detect_format(path)?;

    let file = if readonly {
        File::open(path)?
    } else {
        OpenOptions::new().read(true).write(true).open(path)?
    };

    let metadata = file.metadata()?;
    let virtual_size = metadata.len();

    tracing::info!(
        "Opened disk image: {} ({:?}, {} bytes, {})",
        path.display(),
        format,
        virtual_size,
        if readonly { "ro" } else { "rw" }
    );

    Ok(DiskImage {
        path: path.to_path_buf(),
        format,
        readonly,
        file,
        virtual_size,
    })
}

/// Detect disk image format by reading magic bytes.
fn detect_format(path: &Path) -> anyhow::Result<DiskFormat> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    match f.read_exact(&mut magic) {
        Ok(()) => {
            if &magic == b"QFI\xfb" {
                Ok(DiskFormat::Qcow2)
            } else {
                Ok(DiskFormat::Raw)
            }
        }
        Err(_) => Ok(DiskFormat::Raw),
    }
}

/// Punch a hole in a disk image file (TRIM / discard).
///
/// On Linux, uses fallocate with FALLOC_FL_PUNCH_HOLE to deallocate blocks
/// while keeping the file's logical size unchanged. This is the mechanism
/// behind thin provisioning reclaim.
///
/// On non-Linux platforms, this is a no-op stub.
#[cfg(target_os = "linux")]
pub fn punch_hole(file: &File, offset: u64, length: u64) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;

    let ret = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset as i64,
            length as i64,
        )
    };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "fallocate PUNCH_HOLE failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn punch_hole(_file: &File, _offset: u64, _length: u64) -> anyhow::Result<()> {
    tracing::debug!("punch_hole not supported on this platform (stub)");
    Ok(())
}

/// Pre-allocate blocks for a region of a disk image.
///
/// On Linux, uses fallocate to ensure blocks are allocated, avoiding
/// later write-time allocation latency. Useful for performance-critical
/// regions (e.g., filesystem metadata area).
#[cfg(target_os = "linux")]
pub fn preallocate(file: &File, offset: u64, length: u64) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;

    let ret = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            0, // default mode = allocate
            offset as i64,
            length as i64,
        )
    };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "fallocate (preallocate) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn preallocate(_file: &File, _offset: u64, _length: u64) -> anyhow::Result<()> {
    tracing::debug!("preallocate not supported on this platform (stub)");
    Ok(())
}

// ---------------------------------------------------------------------------
// io_uring block I/O (optional, Linux 5.1+)
// ---------------------------------------------------------------------------

/// Asynchronous block I/O engine using io_uring.
///
/// Provides high-performance disk I/O by submitting read/write operations
/// to the kernel's io_uring interface, avoiding syscall overhead for
/// each individual I/O operation.
///
/// Falls back to synchronous pread/pwrite when io_uring is unavailable
/// (kernel <5.1 or feature not enabled).
#[cfg(all(target_os = "linux", feature = "io_uring"))]
pub struct IoUringBlockIo {
    ring: io_uring::IoUring,
    fd: std::os::unix::io::RawFd,
}

#[cfg(all(target_os = "linux", feature = "io_uring"))]
impl IoUringBlockIo {
    /// Create a new io_uring I/O engine for the given file.
    ///
    /// `queue_depth` controls the submission queue size (typically 32-256).
    pub fn new(file: &File, queue_depth: u32) -> anyhow::Result<Self> {
        use std::os::unix::io::AsRawFd;

        let ring = io_uring::IoUring::new(queue_depth)
            .map_err(|e| anyhow::anyhow!("Failed to create io_uring: {e}"))?;
        let fd = file.as_raw_fd();

        tracing::info!(fd, queue_depth, "io_uring block I/O engine initialized");

        Ok(Self { ring, fd })
    }

    /// Submit a read operation and wait for completion.
    ///
    /// Reads `len` bytes at `offset` into `buf`.
    pub fn read_at(&mut self, buf: &mut [u8], offset: u64) -> anyhow::Result<usize> {
        let read_e = io_uring::opcode::Read::new(
            io_uring::types::Fd(self.fd),
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
        .offset(offset)
        .build()
        .user_data(0x01);

        unsafe {
            self.ring
                .submission()
                .push(&read_e)
                .map_err(|e| anyhow::anyhow!("io_uring submit failed: {e}"))?;
        }

        self.ring.submit_and_wait(1)?;

        let cqe = self.ring.completion().next()
            .ok_or_else(|| anyhow::anyhow!("io_uring: no completion entry"))?;

        let result = cqe.result();
        if result < 0 {
            return Err(anyhow::anyhow!(
                "io_uring read failed: {}",
                std::io::Error::from_raw_os_error(-result)
            ));
        }

        Ok(result as usize)
    }

    /// Submit a write operation and wait for completion.
    ///
    /// Writes `buf` at `offset`.
    pub fn write_at(&mut self, buf: &[u8], offset: u64) -> anyhow::Result<usize> {
        let write_e = io_uring::opcode::Write::new(
            io_uring::types::Fd(self.fd),
            buf.as_ptr(),
            buf.len() as u32,
        )
        .offset(offset)
        .build()
        .user_data(0x02);

        unsafe {
            self.ring
                .submission()
                .push(&write_e)
                .map_err(|e| anyhow::anyhow!("io_uring submit failed: {e}"))?;
        }

        self.ring.submit_and_wait(1)?;

        let cqe = self.ring.completion().next()
            .ok_or_else(|| anyhow::anyhow!("io_uring: no completion entry"))?;

        let result = cqe.result();
        if result < 0 {
            return Err(anyhow::anyhow!(
                "io_uring write failed: {}",
                std::io::Error::from_raw_os_error(-result)
            ));
        }

        Ok(result as usize)
    }

    /// Submit a fsync operation and wait for completion.
    pub fn fsync(&mut self) -> anyhow::Result<()> {
        let fsync_e = io_uring::opcode::Fsync::new(
            io_uring::types::Fd(self.fd),
        )
        .build()
        .user_data(0x03);

        unsafe {
            self.ring
                .submission()
                .push(&fsync_e)
                .map_err(|e| anyhow::anyhow!("io_uring submit failed: {e}"))?;
        }

        self.ring.submit_and_wait(1)?;

        let cqe = self.ring.completion().next()
            .ok_or_else(|| anyhow::anyhow!("io_uring: no completion entry"))?;

        let result = cqe.result();
        if result < 0 {
            return Err(anyhow::anyhow!(
                "io_uring fsync failed: {}",
                std::io::Error::from_raw_os_error(-result)
            ));
        }

        Ok(())
    }
}

/// Check if io_uring is available on this system.
///
/// Returns true if the io_uring feature is enabled and the kernel supports it.
#[cfg(all(target_os = "linux", feature = "io_uring"))]
pub fn io_uring_available() -> bool {
    match io_uring::IoUring::new(1) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[cfg(not(all(target_os = "linux", feature = "io_uring")))]
pub fn io_uring_available() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_create_thin_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.img");

        let virtual_size = 1024 * 1024 * 100; // 100 MB virtual
        create_thin_disk(&path, virtual_size).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), virtual_size);

        // On most filesystems, sparse file uses near-zero actual blocks.
        // We don't assert on actual_size because it varies by filesystem.
    }

    #[test]
    fn test_open_disk_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.raw");
        create_thin_disk(&path, 4096).unwrap();

        let img = open_disk(&path, false).unwrap();
        assert_eq!(img.format, DiskFormat::Raw);
        assert_eq!(img.virtual_size, 4096);
        assert!(!img.readonly);
    }

    #[test]
    fn test_open_disk_readonly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.raw");
        create_thin_disk(&path, 4096).unwrap();

        let img = open_disk(&path, true).unwrap();
        assert!(img.readonly);
    }

    #[test]
    fn test_detect_format_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.raw");
        create_thin_disk(&path, 4096).unwrap();

        assert_eq!(detect_format(&path).unwrap(), DiskFormat::Raw);
    }

    #[test]
    fn test_detect_format_qcow2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut f = File::create(&path).unwrap();
        // Write QCOW2 magic.
        f.write_all(b"QFI\xfb").unwrap();
        f.write_all(&[0u8; 508]).unwrap(); // pad to 512 bytes
        drop(f);

        assert_eq!(detect_format(&path).unwrap(), DiskFormat::Qcow2);
    }

    #[test]
    fn test_punch_hole_is_noop_or_works() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hole.img");
        let file = File::create(&path).unwrap();
        file.set_len(4096 * 10).unwrap();

        // On non-Linux this is a no-op stub, on Linux it punches a hole.
        // Either way, it should succeed.
        let result = punch_hole(&file, 0, 4096);
        assert!(result.is_ok());
    }

    #[test]
    fn test_preallocate_is_noop_or_works() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prealloc.img");
        let file = File::create(&path).unwrap();
        file.set_len(4096 * 10).unwrap();

        let result = preallocate(&file, 0, 4096);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_thin_disk_zero_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero.img");
        create_thin_disk(&path, 0).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_create_thin_disk_one_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tiny.img");
        create_thin_disk(&path, 1).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 1);
    }

    #[test]
    fn test_create_thin_disk_1gb() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.img");
        let one_gb = 1024 * 1024 * 1024;
        create_thin_disk(&path, one_gb).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), one_gb);
    }

    #[test]
    fn test_open_disk_actual_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("actual.img");
        create_thin_disk(&path, 4096 * 100).unwrap();

        let img = open_disk(&path, false).unwrap();
        let actual = img.actual_size().unwrap();
        // Actual size should be <= virtual size (sparse file)
        assert!(actual <= img.virtual_size);
    }

    #[test]
    fn test_detect_format_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.img");
        File::create(&path).unwrap(); // 0 bytes

        // Should detect as Raw (fallback)
        assert_eq!(detect_format(&path).unwrap(), DiskFormat::Raw);
    }

    #[test]
    fn test_detect_format_small_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.img");
        let mut f = File::create(&path).unwrap();
        f.write_all(&[0x01, 0x02]).unwrap(); // only 2 bytes, can't read 4

        assert_eq!(detect_format(&path).unwrap(), DiskFormat::Raw);
    }

    #[test]
    fn test_create_thin_disk_returns_correct_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("returned.img");
        let returned = create_thin_disk(&path, 4096).unwrap();
        assert_eq!(returned, path);
    }
}
