// QCOW2 disk image format implementation.
//
// Supports version 2 and 3 of the QCOW2 format with:
// - Two-level (L1 → L2) address translation
// - Copy-on-write cluster allocation
// - Reference counting for cluster management
// - Backing file chains (raw or qcow2)
// - L2 table caching
//
// Used by the virtio-block device for guest disk I/O when the disk image
// is in QCOW2 format rather than raw.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// QCOW2 magic number: "QFI\xfb"
const QCOW2_MAGIC: u32 = 0x514649fb;

/// Minimum header size for version 2.
const QCOW2_V2_HEADER_SIZE: u64 = 72;

/// Minimum header size for version 3.
const QCOW2_V3_HEADER_SIZE: u64 = 104;

/// Default cluster bits (16 → 64 KB clusters).
const DEFAULT_CLUSTER_BITS: u32 = 16;

/// Default refcount order (4 → 16-bit refcounts).
const DEFAULT_REFCOUNT_ORDER: u32 = 4;

/// L2 entry flag: cluster data has been copied (CoW complete).
const L2_FLAG_COPIED: u64 = 1 << 63;

/// L2 entry flag: cluster is compressed (not supported).
const L2_FLAG_COMPRESSED: u64 = 1 << 62;

/// Mask to extract the host cluster offset from an L2 entry.
/// Bits 0..61 contain the offset, but it must be cluster-aligned,
/// so effectively bits 9..61 carry the address (bit 0 is the standard
/// cluster descriptor flag in some docs, but for our purposes we mask
/// off the top two flag bits).
const L2_OFFSET_MASK: u64 = 0x3FFF_FFFF_FFFF_FE00;

/// Mask for L1 entries: bits 9..55 give the L2 table offset.
const L1_OFFSET_MASK: u64 = 0x00FF_FFFF_FFFF_FE00;

/// Maximum number of cached L2 tables.
const L2_CACHE_MAX_TABLES: usize = 256;

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// Parsed QCOW2 header (all fields in native byte order).
#[derive(Debug, Clone)]
pub struct Qcow2Header {
    pub magic: u32,
    pub version: u32,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,
    pub l1_size: u32,
    pub l1_table_offset: u64,
    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,
    pub nb_snapshots: u32,
    pub snapshots_offset: u64,
    // v3 extensions
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub autoclear_features: u64,
    pub refcount_order: u32,
    pub header_length: u32,
}

impl Qcow2Header {
    /// Read and parse a QCOW2 header from the beginning of `file`.
    pub fn read_from(file: &mut File) -> Result<Self> {
        file.seek(SeekFrom::Start(0))
            .context("seeking to start of QCOW2 file")?;

        let mut buf = [0u8; 104]; // v3 header size
        // Read at least v2 header bytes.
        file.read_exact(&mut buf[..72])
            .context("reading QCOW2 header (first 72 bytes)")?;

        let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        ensure!(magic == QCOW2_MAGIC, "not a QCOW2 file: bad magic 0x{magic:08x}");

        let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        ensure!(
            version == 2 || version == 3,
            "unsupported QCOW2 version {version} (expected 2 or 3)"
        );

        let backing_file_offset = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        let backing_file_size = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        let cluster_bits = u32::from_be_bytes(buf[20..24].try_into().unwrap());
        let size = u64::from_be_bytes(buf[24..32].try_into().unwrap());
        let crypt_method = u32::from_be_bytes(buf[32..36].try_into().unwrap());
        let l1_size = u32::from_be_bytes(buf[36..40].try_into().unwrap());
        let l1_table_offset = u64::from_be_bytes(buf[40..48].try_into().unwrap());
        let refcount_table_offset = u64::from_be_bytes(buf[48..56].try_into().unwrap());
        let refcount_table_clusters = u32::from_be_bytes(buf[56..60].try_into().unwrap());
        let nb_snapshots = u32::from_be_bytes(buf[60..64].try_into().unwrap());
        let snapshots_offset = u64::from_be_bytes(buf[64..72].try_into().unwrap());

        // Validate cluster_bits.
        ensure!(
            (9..=21).contains(&cluster_bits),
            "cluster_bits {cluster_bits} out of valid range 9..21"
        );
        ensure!(
            crypt_method == 0,
            "encrypted QCOW2 images are not supported (crypt_method={crypt_method})"
        );

        // v3 extensions.
        let (incompatible_features, compatible_features, autoclear_features, refcount_order, header_length) =
            if version == 3 {
                file.seek(SeekFrom::Start(72))?;
                file.read_exact(&mut buf[72..104])
                    .context("reading QCOW2 v3 header extension fields")?;
                (
                    u64::from_be_bytes(buf[68..76].try_into().unwrap()),
                    u64::from_be_bytes(buf[76..84].try_into().unwrap()),
                    u64::from_be_bytes(buf[84..92].try_into().unwrap()),
                    u32::from_be_bytes(buf[92..96].try_into().unwrap()),
                    u32::from_be_bytes(buf[96..100].try_into().unwrap()),
                )
            } else {
                (0, 0, 0, DEFAULT_REFCOUNT_ORDER, 72)
            };

        Ok(Qcow2Header {
            magic,
            version,
            backing_file_offset,
            backing_file_size,
            cluster_bits,
            size,
            crypt_method,
            l1_size,
            l1_table_offset,
            refcount_table_offset,
            refcount_table_clusters,
            nb_snapshots,
            snapshots_offset,
            incompatible_features,
            compatible_features,
            autoclear_features,
            refcount_order,
            header_length,
        })
    }

    /// Write this header to the beginning of `file` in big-endian format.
    pub fn write_to(&self, file: &mut File) -> Result<()> {
        file.seek(SeekFrom::Start(0))?;
        let mut buf = [0u8; 104];

        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4..8].copy_from_slice(&self.version.to_be_bytes());
        buf[8..16].copy_from_slice(&self.backing_file_offset.to_be_bytes());
        buf[16..20].copy_from_slice(&self.backing_file_size.to_be_bytes());
        buf[20..24].copy_from_slice(&self.cluster_bits.to_be_bytes());
        buf[24..32].copy_from_slice(&self.size.to_be_bytes());
        buf[32..36].copy_from_slice(&self.crypt_method.to_be_bytes());
        buf[36..40].copy_from_slice(&self.l1_size.to_be_bytes());
        buf[40..48].copy_from_slice(&self.l1_table_offset.to_be_bytes());
        buf[48..56].copy_from_slice(&self.refcount_table_offset.to_be_bytes());
        buf[56..60].copy_from_slice(&self.refcount_table_clusters.to_be_bytes());
        buf[60..64].copy_from_slice(&self.nb_snapshots.to_be_bytes());
        buf[64..72].copy_from_slice(&self.snapshots_offset.to_be_bytes());

        if self.version == 3 {
            buf[68..76].copy_from_slice(&self.incompatible_features.to_be_bytes());
            buf[76..84].copy_from_slice(&self.compatible_features.to_be_bytes());
            buf[84..92].copy_from_slice(&self.autoclear_features.to_be_bytes());
            buf[92..96].copy_from_slice(&self.refcount_order.to_be_bytes());
            buf[96..100].copy_from_slice(&self.header_length.to_be_bytes());
            file.write_all(&buf[..104])?;
        } else {
            file.write_all(&buf[..72])?;
        }

        Ok(())
    }

    /// Cluster size in bytes.
    pub fn cluster_size(&self) -> u64 {
        1u64 << self.cluster_bits
    }

    /// Number of L2 entries per table (cluster_size / 8).
    pub fn l2_entries_per_table(&self) -> u64 {
        self.cluster_size() / 8
    }

    /// Refcount bits per entry (1 << refcount_order).
    pub fn refcount_bits(&self) -> u32 {
        1 << self.refcount_order
    }
}

// ---------------------------------------------------------------------------
// L2 cache entry
// ---------------------------------------------------------------------------

/// A cached L2 table.
struct L2CacheEntry {
    /// The L2 table entries (native byte order).
    entries: Vec<u64>,
    /// Whether the table has been modified since last flush.
    dirty: bool,
    /// Host file offset where this L2 table lives.
    host_offset: u64,
    /// Access counter for simple LRU eviction.
    last_access: u64,
}

// ---------------------------------------------------------------------------
// Backing file abstraction
// ---------------------------------------------------------------------------

/// A backing file that provides data for unallocated clusters.
enum BackingFile {
    /// Backing file is itself a QCOW2 image.
    Qcow2(Box<Qcow2File>),
    /// Backing file is a raw disk image.
    Raw(File, u64), // file + size
}

impl BackingFile {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        match self {
            BackingFile::Qcow2(q) => q.read_at(offset, buf),
            BackingFile::Raw(file, size) => {
                if offset >= *size {
                    buf.fill(0);
                    return Ok(());
                }
                file.seek(SeekFrom::Start(offset))?;
                let readable = std::cmp::min(buf.len() as u64, *size - offset) as usize;
                file.read_exact(&mut buf[..readable])?;
                buf[readable..].fill(0);
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Qcow2File
// ---------------------------------------------------------------------------

/// An opened QCOW2 disk image with read/write access.
pub struct Qcow2File {
    /// The underlying file handle.
    file: File,
    /// Path to this QCOW2 file (for error messages).
    path: PathBuf,
    /// Parsed header.
    header: Qcow2Header,
    /// L1 table (native byte order).
    l1_table: Vec<u64>,
    /// Refcount table (native byte order): each entry is the host offset of a
    /// refcount block, or 0 if not yet allocated.
    refcount_table: Vec<u64>,
    /// Cache of L2 tables, keyed by L1 index.
    l2_cache: HashMap<u32, L2CacheEntry>,
    /// Monotonic access counter for LRU eviction.
    access_counter: u64,
    /// Next allocation offset (always cluster-aligned, at end of file).
    next_alloc_offset: u64,
    /// Optional backing file for unallocated clusters.
    backing: Option<BackingFile>,
}

impl Qcow2File {
    // -------------------------------------------------------------------
    // Open an existing QCOW2 image
    // -------------------------------------------------------------------

    /// Open an existing QCOW2 image file.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening QCOW2 file {}", path.display()))?;

        let header = Qcow2Header::read_from(&mut file)
            .with_context(|| format!("parsing QCOW2 header in {}", path.display()))?;

        tracing::info!(
            path = %path.display(),
            version = header.version,
            virtual_size = header.size,
            cluster_bits = header.cluster_bits,
            l1_size = header.l1_size,
            "opened QCOW2 image"
        );

        // Read L1 table.
        let l1_table = Self::read_table(&mut file, header.l1_table_offset, header.l1_size as usize)
            .context("reading L1 table")?;

        // Read refcount table.
        let rc_entries = (header.refcount_table_clusters as u64 * header.cluster_size()) / 8;
        let refcount_table =
            Self::read_table(&mut file, header.refcount_table_offset, rc_entries as usize)
                .context("reading refcount table")?;

        // Determine next allocation offset: end of the file, rounded up to cluster boundary.
        let file_len = file.seek(SeekFrom::End(0))?;
        let cluster_size = header.cluster_size();
        let next_alloc_offset = align_up(file_len, cluster_size);

        // Open backing file if present.
        let backing = if header.backing_file_offset != 0 && header.backing_file_size > 0 {
            let backing_path = Self::read_backing_file_path(&mut file, &header)?;
            let resolved = resolve_backing_path(path, &backing_path)?;
            tracing::info!(backing = %resolved.display(), "opening backing file");
            Some(open_backing_file(&resolved)?)
        } else {
            None
        };

        Ok(Qcow2File {
            file,
            path: path.to_path_buf(),
            header,
            l1_table,
            refcount_table,
            l2_cache: HashMap::new(),
            access_counter: 0,
            next_alloc_offset,
            backing,
        })
    }

    // -------------------------------------------------------------------
    // Create a new QCOW2 image
    // -------------------------------------------------------------------

    /// Create a new QCOW2 image file.
    ///
    /// - `path`: destination file (will be created/overwritten).
    /// - `virtual_size`: virtual disk size in bytes.
    /// - `cluster_bits`: log2 of cluster size (typically 16 for 64 KB).
    /// - `backing_file`: optional path to a backing file.
    pub fn create(
        path: &Path,
        virtual_size: u64,
        cluster_bits: u32,
        backing_file: Option<&Path>,
    ) -> Result<Self> {
        ensure!(
            (9..=21).contains(&cluster_bits),
            "cluster_bits {cluster_bits} out of valid range 9..21"
        );

        let cluster_size = 1u64 << cluster_bits;
        let l2_entries = cluster_size / 8;

        // How many L1 entries do we need?
        let total_clusters = div_round_up(virtual_size, cluster_size);
        let l1_size = div_round_up(total_clusters, l2_entries) as u32;
        // L1 table size in bytes, rounded up to cluster boundary.
        let l1_bytes = (l1_size as u64) * 8;
        let l1_clusters = div_round_up(l1_bytes, cluster_size);

        // Layout:
        // Cluster 0: header (+ optional backing file name)
        // Cluster 1..1+rc_clusters: refcount table
        // After refcount table: first refcount block
        // After refcount block: L1 table
        //
        // We need to figure out how many clusters total so we can size the
        // refcount table. We'll be conservative and iterate.

        // Minimum clusters: header(1) + refcount_table(1) + refcount_block(1) + L1(l1_clusters)
        let mut total_meta_clusters = 1 + 1 + 1 + l1_clusters;

        // Refcount table needs to cover at least total_meta_clusters.
        // Each refcount block covers cluster_size / 2 clusters (16-bit refcounts).
        let refcounts_per_block = cluster_size / 2; // 16-bit refcounts
        let rc_blocks_needed = div_round_up(total_meta_clusters, refcounts_per_block);
        // Each refcount table entry is 8 bytes, pointing to one block.
        let rc_table_entries = rc_blocks_needed;
        let rc_table_bytes = rc_table_entries * 8;
        let rc_table_clusters = div_round_up(rc_table_bytes, cluster_size).max(1);

        // Recalculate with the actual rc_table_clusters.
        total_meta_clusters = 1 + rc_table_clusters + rc_blocks_needed + l1_clusters;

        let refcount_table_offset = cluster_size; // cluster 1
        let first_rc_block_offset = refcount_table_offset + rc_table_clusters * cluster_size;
        let l1_table_offset = first_rc_block_offset + rc_blocks_needed * cluster_size;
        let file_end = l1_table_offset + l1_clusters * cluster_size;

        // Build the header.
        let mut header = Qcow2Header {
            magic: QCOW2_MAGIC,
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits,
            size: virtual_size,
            crypt_method: 0,
            l1_size,
            l1_table_offset,
            refcount_table_offset,
            refcount_table_clusters: rc_table_clusters as u32,
            nb_snapshots: 0,
            snapshots_offset: 0,
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: DEFAULT_REFCOUNT_ORDER,
            header_length: QCOW2_V3_HEADER_SIZE as u32,
        };

        // Create the file.
        let mut file = File::create(path)
            .with_context(|| format!("creating QCOW2 file {}", path.display()))?;

        // Write backing file path into cluster 0 if specified.
        if let Some(backing_path) = backing_file {
            let bs = backing_path.to_string_lossy();
            let bs_bytes = bs.as_bytes();
            ensure!(
                (QCOW2_V3_HEADER_SIZE as usize) + bs_bytes.len() <= cluster_size as usize,
                "backing file path too long to fit in header cluster"
            );
            header.backing_file_offset = QCOW2_V3_HEADER_SIZE;
            header.backing_file_size = bs_bytes.len() as u32;
        }

        // Write header.
        header.write_to(&mut file)?;

        // Write backing file path.
        if let Some(backing_path) = backing_file {
            let bs = backing_path.to_string_lossy();
            file.seek(SeekFrom::Start(header.backing_file_offset))?;
            file.write_all(bs.as_bytes())?;
        }

        // Extend file to full metadata size.
        file.set_len(file_end)?;

        // Write refcount table: first entry points to the first refcount block.
        file.seek(SeekFrom::Start(refcount_table_offset))?;
        // Write entries for each refcount block.
        for i in 0..rc_blocks_needed {
            let block_offset = first_rc_block_offset + i * cluster_size;
            file.write_all(&block_offset.to_be_bytes())?;
        }

        // Write refcount block: set refcount=1 for each metadata cluster.
        for cluster_idx in 0..total_meta_clusters {
            let block_idx = cluster_idx / refcounts_per_block;
            let entry_idx = cluster_idx % refcounts_per_block;
            let offset = first_rc_block_offset + block_idx * cluster_size + entry_idx * 2;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&1u16.to_be_bytes())?;
        }

        // L1 table is already zeroed (file.set_len fills with zeros).

        file.flush()?;

        tracing::info!(
            path = %path.display(),
            virtual_size,
            cluster_bits,
            l1_size,
            "created new QCOW2 image"
        );

        // Reopen for read-write.
        drop(file);
        Self::open(path)
    }

    // -------------------------------------------------------------------
    // Public I/O interface
    // -------------------------------------------------------------------

    /// Read `buf.len()` bytes starting at guest `offset`.
    ///
    /// Unallocated regions return zeros (or data from the backing file if present).
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .context("read offset overflow")?;
        ensure!(
            end <= self.header.size,
            "read past end of virtual disk: offset={offset} len={} size={}",
            buf.len(),
            self.header.size
        );

        let cluster_size = self.header.cluster_size();
        let mut pos = offset;
        let mut buf_offset = 0usize;

        while buf_offset < buf.len() {
            let in_cluster_offset = pos % cluster_size;
            let remaining_in_cluster = cluster_size - in_cluster_offset;
            let remaining_in_buf = (buf.len() - buf_offset) as u64;
            let chunk_len = std::cmp::min(remaining_in_cluster, remaining_in_buf) as usize;

            let host_offset = self.translate_cluster(pos)?;

            match host_offset {
                Some(host_off) => {
                    let read_off = host_off + in_cluster_offset;
                    self.file.seek(SeekFrom::Start(read_off))?;
                    self.file
                        .read_exact(&mut buf[buf_offset..buf_offset + chunk_len])
                        .with_context(|| {
                            format!(
                                "reading {chunk_len} bytes at host offset {read_off} in {}",
                                self.path.display()
                            )
                        })?;
                }
                None => {
                    // Unallocated cluster.
                    if let Some(ref mut backing) = self.backing {
                        backing.read_at(pos, &mut buf[buf_offset..buf_offset + chunk_len])?;
                    } else {
                        buf[buf_offset..buf_offset + chunk_len].fill(0);
                    }
                }
            }

            pos += chunk_len as u64;
            buf_offset += chunk_len;
        }

        Ok(())
    }

    /// Write `data.len()` bytes starting at guest `offset`.
    ///
    /// Allocates new clusters as needed (copy-on-write).
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(data.len() as u64)
            .context("write offset overflow")?;
        ensure!(
            end <= self.header.size,
            "write past end of virtual disk: offset={offset} len={} size={}",
            data.len(),
            self.header.size
        );

        let cluster_size = self.header.cluster_size();
        let mut pos = offset;
        let mut data_offset = 0usize;

        while data_offset < data.len() {
            let in_cluster_offset = pos % cluster_size;
            let remaining_in_cluster = cluster_size - in_cluster_offset;
            let remaining_in_data = (data.len() - data_offset) as u64;
            let chunk_len = std::cmp::min(remaining_in_cluster, remaining_in_data) as usize;

            let host_offset = self.translate_cluster(pos)?;

            let cluster_host_offset = match host_offset {
                Some(off) => off,
                None => {
                    // Need to allocate a new cluster.
                    let new_offset = self.alloc_cluster()?;

                    // If partial write, we need read-modify-write.
                    if chunk_len < cluster_size as usize {
                        // Read existing data for the full cluster.
                        let mut cluster_buf = vec![0u8; cluster_size as usize];
                        if let Some(ref mut backing) = self.backing {
                            let cluster_start = pos - in_cluster_offset;
                            backing.read_at(cluster_start, &mut cluster_buf)?;
                        }
                        // Write the full cluster first.
                        self.file.seek(SeekFrom::Start(new_offset))?;
                        self.file.write_all(&cluster_buf)?;
                    }

                    // Update L2 entry.
                    self.set_l2_entry(pos, new_offset | L2_FLAG_COPIED)?;

                    new_offset
                }
            };

            // Write the actual data.
            let write_off = cluster_host_offset + in_cluster_offset;
            self.file.seek(SeekFrom::Start(write_off))?;
            self.file
                .write_all(&data[data_offset..data_offset + chunk_len])
                .with_context(|| {
                    format!(
                        "writing {chunk_len} bytes at host offset {write_off} in {}",
                        self.path.display()
                    )
                })?;

            pos += chunk_len as u64;
            data_offset += chunk_len;
        }

        Ok(())
    }

    /// Flush all dirty metadata (L2 tables, refcounts) and data to disk.
    pub fn flush(&mut self) -> Result<()> {
        // Write dirty L2 tables.
        let dirty_indices: Vec<u32> = self
            .l2_cache
            .iter()
            .filter(|(_, e)| e.dirty)
            .map(|(idx, _)| *idx)
            .collect();

        for l1_idx in dirty_indices {
            self.flush_l2_table(l1_idx)?;
        }

        // Write L1 table.
        self.write_l1_table()?;

        // Write refcount table.
        self.write_refcount_table()?;

        self.file.flush()?;

        tracing::debug!(path = %self.path.display(), "flushed QCOW2 metadata");
        Ok(())
    }

    /// Return the virtual disk size in bytes.
    pub fn virtual_size(&self) -> u64 {
        self.header.size
    }

    /// Return a reference to the parsed header.
    pub fn header(&self) -> &Qcow2Header {
        &self.header
    }

    // -------------------------------------------------------------------
    // Cluster allocation
    // -------------------------------------------------------------------

    /// Allocate a new cluster at the end of the file.
    ///
    /// Returns the host file offset of the newly allocated cluster.
    pub fn alloc_cluster(&mut self) -> Result<u64> {
        let offset = self.next_alloc_offset;
        let cluster_size = self.header.cluster_size();
        self.next_alloc_offset += cluster_size;

        // Extend the file.
        let new_len = self.next_alloc_offset;
        self.file.set_len(new_len).with_context(|| {
            format!(
                "extending {} to {new_len} bytes for cluster allocation",
                self.path.display()
            )
        })?;

        // Set refcount to 1.
        self.set_refcount(offset, 1)?;

        tracing::debug!(offset, cluster_size, "allocated new cluster");
        Ok(offset)
    }

    // -------------------------------------------------------------------
    // Address translation
    // -------------------------------------------------------------------

    /// Translate a guest byte offset to a host cluster offset.
    ///
    /// Returns `None` if the cluster is unallocated.
    fn translate_cluster(&mut self, guest_offset: u64) -> Result<Option<u64>> {
        let cluster_size = self.header.cluster_size();
        let l2_entries = self.header.l2_entries_per_table();

        let l1_index = (guest_offset / cluster_size) / l2_entries;
        let l2_index = ((guest_offset / cluster_size) % l2_entries) as usize;

        ensure!(
            (l1_index as u32) < self.header.l1_size,
            "L1 index {l1_index} out of bounds (l1_size={})",
            self.header.l1_size
        );

        // Check L1 entry.
        let l1_entry = self.l1_table[l1_index as usize];
        let l2_table_offset = l1_entry & L1_OFFSET_MASK;
        if l2_table_offset == 0 {
            return Ok(None);
        }

        // Load L2 table (from cache or disk).
        let l2_entry = self.get_l2_entry(l1_index as u32, l2_table_offset, l2_index)?;

        if l2_entry == 0 {
            return Ok(None);
        }

        // Check for compressed cluster (unsupported).
        ensure!(
            l2_entry & L2_FLAG_COMPRESSED == 0,
            "compressed clusters are not supported (L2 entry 0x{l2_entry:016x} at L1={l1_index} L2={l2_index})"
        );

        let host_offset = l2_entry & L2_OFFSET_MASK;
        if host_offset == 0 {
            Ok(None)
        } else {
            Ok(Some(host_offset))
        }
    }

    /// Get an L2 entry, loading the L2 table into the cache if necessary.
    fn get_l2_entry(
        &mut self,
        l1_index: u32,
        l2_table_offset: u64,
        l2_index: usize,
    ) -> Result<u64> {
        self.ensure_l2_cached(l1_index, l2_table_offset)?;
        let entry = self.l2_cache.get(&l1_index).unwrap();
        Ok(entry.entries[l2_index])
    }

    /// Set an L2 entry. Allocates a new L2 table if the L1 entry is empty.
    fn set_l2_entry(&mut self, guest_offset: u64, value: u64) -> Result<()> {
        let cluster_size = self.header.cluster_size();
        let l2_entries = self.header.l2_entries_per_table();

        let l1_index = (guest_offset / cluster_size) / l2_entries;
        let l2_index = ((guest_offset / cluster_size) % l2_entries) as usize;

        let l1_idx = l1_index as u32;

        // If L1 entry is empty, allocate a new L2 table.
        let l1_entry = self.l1_table[l1_index as usize];
        let l2_table_offset = l1_entry & L1_OFFSET_MASK;

        if l2_table_offset == 0 {
            let new_l2_offset = self.alloc_cluster()?;
            // Zero-initialize the L2 table on disk (already done by set_len in alloc_cluster).
            self.l1_table[l1_index as usize] = new_l2_offset | L2_FLAG_COPIED;

            // Insert an empty L2 table into cache.
            let entries = vec![0u64; l2_entries as usize];
            self.access_counter += 1;
            self.l2_cache.insert(
                l1_idx,
                L2CacheEntry {
                    entries,
                    dirty: true,
                    host_offset: new_l2_offset,
                    last_access: self.access_counter,
                },
            );
        } else {
            self.ensure_l2_cached(l1_idx, l2_table_offset)?;
        }

        // Update the entry.
        let cache_entry = self.l2_cache.get_mut(&l1_idx).unwrap();
        cache_entry.entries[l2_index] = value;
        cache_entry.dirty = true;

        Ok(())
    }

    /// Ensure the L2 table for `l1_index` is in the cache.
    fn ensure_l2_cached(&mut self, l1_index: u32, l2_table_offset: u64) -> Result<()> {
        if self.l2_cache.contains_key(&l1_index) {
            self.access_counter += 1;
            self.l2_cache.get_mut(&l1_index).unwrap().last_access = self.access_counter;
            return Ok(());
        }

        // Evict if cache is full.
        if self.l2_cache.len() >= L2_CACHE_MAX_TABLES {
            self.evict_l2_entry()?;
        }

        // Read L2 table from disk.
        let n_entries = self.header.l2_entries_per_table() as usize;
        let entries = Self::read_table(&mut self.file, l2_table_offset, n_entries)
            .with_context(|| {
                format!("reading L2 table at offset {l2_table_offset} (L1 index {l1_index})")
            })?;

        self.access_counter += 1;
        self.l2_cache.insert(
            l1_index,
            L2CacheEntry {
                entries,
                dirty: false,
                host_offset: l2_table_offset,
                last_access: self.access_counter,
            },
        );

        Ok(())
    }

    /// Evict the least-recently-used L2 cache entry.
    fn evict_l2_entry(&mut self) -> Result<()> {
        let victim = self
            .l2_cache
            .iter()
            .min_by_key(|(_, e)| e.last_access)
            .map(|(k, _)| *k);

        if let Some(idx) = victim {
            // Flush if dirty.
            if self.l2_cache.get(&idx).unwrap().dirty {
                self.flush_l2_table(idx)?;
            }
            self.l2_cache.remove(&idx);
        }

        Ok(())
    }

    /// Write a dirty L2 table back to disk.
    fn flush_l2_table(&mut self, l1_index: u32) -> Result<()> {
        let entry = self.l2_cache.get_mut(&l1_index).unwrap();
        if !entry.dirty {
            return Ok(());
        }

        self.file.seek(SeekFrom::Start(entry.host_offset))?;
        for &val in &entry.entries {
            self.file.write_all(&val.to_be_bytes())?;
        }
        entry.dirty = false;

        Ok(())
    }

    // -------------------------------------------------------------------
    // Refcount management
    // -------------------------------------------------------------------

    /// Get the refcount for the cluster at `cluster_offset`.
    fn get_refcount(&mut self, cluster_offset: u64) -> Result<u16> {
        let cluster_size = self.header.cluster_size();
        let cluster_index = cluster_offset / cluster_size;
        let refcounts_per_block = cluster_size / 2; // 16-bit refcounts

        let rc_table_index = cluster_index / refcounts_per_block;
        let rc_block_index = cluster_index % refcounts_per_block;

        if rc_table_index as usize >= self.refcount_table.len() {
            return Ok(0);
        }

        let block_offset = self.refcount_table[rc_table_index as usize];
        if block_offset == 0 {
            return Ok(0);
        }

        let entry_offset = block_offset + rc_block_index * 2;
        self.file.seek(SeekFrom::Start(entry_offset))?;
        let mut buf = [0u8; 2];
        self.file.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    /// Set the refcount for the cluster at `cluster_offset`.
    fn set_refcount(&mut self, cluster_offset: u64, refcount: u16) -> Result<()> {
        let cluster_size = self.header.cluster_size();
        let cluster_index = cluster_offset / cluster_size;
        let refcounts_per_block = cluster_size / 2; // 16-bit refcounts

        let rc_table_index = (cluster_index / refcounts_per_block) as usize;
        let rc_block_index = cluster_index % refcounts_per_block;

        // Grow refcount table if needed.
        while rc_table_index >= self.refcount_table.len() {
            self.refcount_table.push(0);
        }

        // Allocate a refcount block if needed.
        if self.refcount_table[rc_table_index] == 0 {
            // Allocate a new refcount block. We do this carefully to avoid
            // infinite recursion: we directly extend the file and assign.
            let block_offset = self.next_alloc_offset;
            self.next_alloc_offset += cluster_size;
            self.file.set_len(self.next_alloc_offset)?;

            self.refcount_table[rc_table_index] = block_offset;

            // Set refcount for the refcount block itself to 1.
            let self_cluster_index = block_offset / cluster_size;
            let self_rc_table_index = (self_cluster_index / refcounts_per_block) as usize;
            let self_rc_block_index = self_cluster_index % refcounts_per_block;

            if self_rc_table_index == rc_table_index {
                // The refcount block covers itself.
                let entry_offset = block_offset + self_rc_block_index * 2;
                self.file.seek(SeekFrom::Start(entry_offset))?;
                self.file.write_all(&1u16.to_be_bytes())?;
            }
            // else: the new block is covered by a different refcount block,
            // which would need its own allocation. For simplicity, we only
            // handle the common case where the block covers itself.
        }

        let block_offset = self.refcount_table[rc_table_index];
        let entry_offset = block_offset + rc_block_index * 2;
        self.file.seek(SeekFrom::Start(entry_offset))?;
        self.file.write_all(&refcount.to_be_bytes())?;

        Ok(())
    }

    /// Increment the refcount for the cluster at `cluster_offset`.
    #[allow(dead_code)]
    pub fn refcount_increment(&mut self, cluster_offset: u64) -> Result<u16> {
        let current = self.get_refcount(cluster_offset)?;
        let new_rc = current
            .checked_add(1)
            .context("refcount overflow")?;
        self.set_refcount(cluster_offset, new_rc)?;
        Ok(new_rc)
    }

    /// Decrement the refcount for the cluster at `cluster_offset`.
    #[allow(dead_code)]
    pub fn refcount_decrement(&mut self, cluster_offset: u64) -> Result<u16> {
        let current = self.get_refcount(cluster_offset)?;
        ensure!(current > 0, "cannot decrement refcount below 0 for cluster at offset {cluster_offset}");
        let new_rc = current - 1;
        self.set_refcount(cluster_offset, new_rc)?;
        Ok(new_rc)
    }

    // -------------------------------------------------------------------
    // Table I/O helpers
    // -------------------------------------------------------------------

    /// Read a table of big-endian u64 entries from the file.
    fn read_table(file: &mut File, offset: u64, count: usize) -> Result<Vec<u64>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; count * 8];
        file.read_exact(&mut buf)?;
        let entries: Vec<u64> = buf
            .chunks_exact(8)
            .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
            .collect();
        Ok(entries)
    }

    /// Write the L1 table to disk.
    fn write_l1_table(&mut self) -> Result<()> {
        self.file
            .seek(SeekFrom::Start(self.header.l1_table_offset))?;
        for &entry in &self.l1_table {
            self.file.write_all(&entry.to_be_bytes())?;
        }
        Ok(())
    }

    /// Write the refcount table to disk.
    fn write_refcount_table(&mut self) -> Result<()> {
        // The refcount table may have grown beyond the originally allocated clusters.
        // Compute how many clusters we need now.
        let cluster_size = self.header.cluster_size();
        let rc_table_bytes = (self.refcount_table.len() as u64) * 8;
        let rc_table_clusters_needed = div_round_up(rc_table_bytes, cluster_size) as u32;

        if rc_table_clusters_needed > self.header.refcount_table_clusters {
            // Need to relocate the refcount table. Allocate new space.
            let new_rc_table_offset = self.next_alloc_offset;
            let alloc_size = rc_table_clusters_needed as u64 * cluster_size;
            self.next_alloc_offset += alloc_size;
            self.file.set_len(self.next_alloc_offset)?;

            // Update refcounts for the new clusters.
            for i in 0..rc_table_clusters_needed as u64 {
                let off = new_rc_table_offset + i * cluster_size;
                self.set_refcount(off, 1)?;
            }

            self.header.refcount_table_offset = new_rc_table_offset;
            self.header.refcount_table_clusters = rc_table_clusters_needed;
            self.header.write_to(&mut self.file)?;
        }

        self.file
            .seek(SeekFrom::Start(self.header.refcount_table_offset))?;
        for &entry in &self.refcount_table {
            self.file.write_all(&entry.to_be_bytes())?;
        }
        Ok(())
    }

    /// Read the backing file path from the header cluster.
    fn read_backing_file_path(file: &mut File, header: &Qcow2Header) -> Result<String> {
        file.seek(SeekFrom::Start(header.backing_file_offset))?;
        let mut buf = vec![0u8; header.backing_file_size as usize];
        file.read_exact(&mut buf)?;
        String::from_utf8(buf).context("backing file path is not valid UTF-8")
    }
}

impl Drop for Qcow2File {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            tracing::error!(error = %e, path = %self.path.display(), "failed to flush QCOW2 on drop");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Round `value` up to the next multiple of `align` (which must be a power of 2).
fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

/// Integer division, rounding up.
fn div_round_up(a: u64, b: u64) -> u64 {
    (a + b - 1) / b
}

/// Resolve a backing file path relative to the directory containing the overlay image.
fn resolve_backing_path(overlay_path: &Path, backing_name: &str) -> Result<PathBuf> {
    let backing_path = Path::new(backing_name);
    if backing_path.is_absolute() {
        Ok(backing_path.to_path_buf())
    } else {
        let parent = overlay_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        Ok(parent.join(backing_path))
    }
}

/// Open a backing file, auto-detecting format (QCOW2 or raw).
fn open_backing_file(path: &Path) -> Result<BackingFile> {
    // Try to detect format by reading magic.
    let mut f = File::open(path)
        .with_context(|| format!("opening backing file {}", path.display()))?;
    let mut magic = [0u8; 4];
    let is_qcow2 = f.read_exact(&mut magic).is_ok() && magic == *b"QFI\xfb";
    drop(f);

    if is_qcow2 {
        let qcow2 = Qcow2File::open(path)?;
        Ok(BackingFile::Qcow2(Box::new(qcow2)))
    } else {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(BackingFile::Raw(file, size))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a QCOW2 image in a temp directory and return (Qcow2File, tempdir).
    fn create_test_image(
        virtual_size: u64,
        cluster_bits: u32,
    ) -> (Qcow2File, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let q = Qcow2File::create(&path, virtual_size, cluster_bits, None).unwrap();
        (q, dir)
    }

    #[test]
    fn test_create_and_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let virtual_size = 1024 * 1024; // 1 MB

        let q = Qcow2File::create(&path, virtual_size, DEFAULT_CLUSTER_BITS, None).unwrap();
        assert_eq!(q.virtual_size(), virtual_size);
        assert_eq!(q.header().magic, QCOW2_MAGIC);
        assert_eq!(q.header().version, 3);
        assert_eq!(q.header().cluster_bits, DEFAULT_CLUSTER_BITS);
        drop(q);

        // Reopen.
        let q2 = Qcow2File::open(&path).unwrap();
        assert_eq!(q2.virtual_size(), virtual_size);
        assert_eq!(q2.header().cluster_bits, DEFAULT_CLUSTER_BITS);
    }

    #[test]
    fn test_read_unallocated_returns_zeros() {
        let (mut q, _dir) = create_test_image(1024 * 1024, DEFAULT_CLUSTER_BITS);
        let mut buf = vec![0xffu8; 4096];
        q.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "unallocated region should read as zeros");
    }

    #[test]
    fn test_write_and_read_back() {
        let (mut q, _dir) = create_test_image(1024 * 1024, DEFAULT_CLUSTER_BITS);

        let data = b"Hello, QCOW2 world!";
        q.write_at(0, data).unwrap();

        let mut buf = vec![0u8; data.len()];
        q.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_write_at_offset() {
        let (mut q, _dir) = create_test_image(1024 * 1024, DEFAULT_CLUSTER_BITS);

        let offset = 4096u64;
        let data = b"offset data";
        q.write_at(offset, data).unwrap();

        let mut buf = vec![0u8; data.len()];
        q.read_at(offset, &mut buf).unwrap();
        assert_eq!(&buf, data);

        // Area before should still be zeros.
        let mut before = vec![0xffu8; 16];
        q.read_at(0, &mut before).unwrap();
        assert!(before.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_write_spanning_clusters() {
        let cluster_bits = 12u32; // 4 KB clusters for faster tests
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = cluster_size * 64;
        let (mut q, _dir) = create_test_image(virtual_size, cluster_bits);

        // Write across a cluster boundary.
        let offset = cluster_size - 10;
        let data = vec![0xAB; 20]; // 10 bytes in cluster 0, 10 in cluster 1
        q.write_at(offset, &data).unwrap();

        let mut buf = vec![0u8; 20];
        q.read_at(offset, &mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_partial_cluster_write_preserves_zeros() {
        let cluster_bits = 12u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = cluster_size * 16;
        let (mut q, _dir) = create_test_image(virtual_size, cluster_bits);

        // Write 10 bytes at the beginning of a cluster.
        let data = vec![0xCD; 10];
        q.write_at(0, &data).unwrap();

        // The rest of the cluster should be zeros.
        let mut rest = vec![0xffu8; (cluster_size - 10) as usize];
        q.read_at(10, &mut rest).unwrap();
        assert!(rest.iter().all(|&b| b == 0), "rest of cluster should be zeros");

        // And the written part should be correct.
        let mut readback = vec![0u8; 10];
        q.read_at(0, &mut readback).unwrap();
        assert_eq!(readback, data);
    }

    #[test]
    fn test_large_write_and_read() {
        let cluster_bits = 12u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = cluster_size * 256;
        let (mut q, _dir) = create_test_image(virtual_size, cluster_bits);

        // Write a large block spanning many clusters.
        let data: Vec<u8> = (0..cluster_size as usize * 10)
            .map(|i| (i % 256) as u8)
            .collect();
        q.write_at(0, &data).unwrap();

        let mut buf = vec![0u8; data.len()];
        q.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_flush_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flush.qcow2");
        let cluster_bits = 12u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = cluster_size * 64;

        {
            let mut q = Qcow2File::create(&path, virtual_size, cluster_bits, None).unwrap();
            let data = b"persistent data";
            q.write_at(100, data).unwrap();
            q.flush().unwrap();
        }

        // Reopen and verify.
        let mut q = Qcow2File::open(&path).unwrap();
        let mut buf = vec![0u8; 15];
        q.read_at(100, &mut buf).unwrap();
        assert_eq!(&buf, b"persistent data");
    }

    #[test]
    fn test_cluster_allocation_increments() {
        let cluster_bits = 12u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = cluster_size * 64;
        let (mut q, _dir) = create_test_image(virtual_size, cluster_bits);

        let c1 = q.alloc_cluster().unwrap();
        let c2 = q.alloc_cluster().unwrap();
        let c3 = q.alloc_cluster().unwrap();

        // Each allocation should be one cluster apart.
        assert_eq!(c2 - c1, cluster_size);
        assert_eq!(c3 - c2, cluster_size);
    }

    #[test]
    fn test_refcount_increment_decrement() {
        let cluster_bits = 12u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = cluster_size * 64;
        let (mut q, _dir) = create_test_image(virtual_size, cluster_bits);

        let offset = q.alloc_cluster().unwrap();
        // After alloc, refcount should be 1.
        let rc = q.get_refcount(offset).unwrap();
        assert_eq!(rc, 1);

        // Increment.
        let rc = q.refcount_increment(offset).unwrap();
        assert_eq!(rc, 2);

        // Decrement.
        let rc = q.refcount_decrement(offset).unwrap();
        assert_eq!(rc, 1);

        let rc = q.refcount_decrement(offset).unwrap();
        assert_eq!(rc, 0);
    }

    #[test]
    fn test_read_past_end_fails() {
        let (mut q, _dir) = create_test_image(4096, 12);
        let mut buf = [0u8; 1];
        let result = q.read_at(4096, &mut buf);
        assert!(result.is_err(), "reading past virtual size should fail");
    }

    #[test]
    fn test_write_past_end_fails() {
        let (mut q, _dir) = create_test_image(4096, 12);
        let result = q.write_at(4096, &[0u8; 1]);
        assert!(result.is_err(), "writing past virtual size should fail");
    }

    #[test]
    fn test_backing_file_raw() {
        let dir = tempfile::tempdir().unwrap();

        // Create a raw backing file with known data.
        let backing_path = dir.path().join("base.raw");
        {
            let mut f = File::create(&backing_path).unwrap();
            let data = vec![0xBBu8; 8192];
            f.write_all(&data).unwrap();
        }

        // Create a QCOW2 overlay.
        let overlay_path = dir.path().join("overlay.qcow2");
        let cluster_bits = 12u32;
        let virtual_size = 8192u64;
        let mut q = Qcow2File::create(
            &overlay_path,
            virtual_size,
            cluster_bits,
            Some(&backing_path),
        )
        .unwrap();

        // Reading unallocated clusters should return backing file data.
        let mut buf = vec![0u8; 100];
        q.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB), "should read from backing file");

        // Write to overlay.
        let overlay_data = vec![0xCC; 50];
        q.write_at(0, &overlay_data).unwrap();

        // Read back: first 50 bytes should be overlay, rest of cluster should
        // have backing data (from read-modify-write).
        let mut buf2 = vec![0u8; 100];
        q.read_at(0, &mut buf2).unwrap();
        assert!(buf2[..50].iter().all(|&b| b == 0xCC));
        assert!(buf2[50..100].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn test_backing_file_qcow2_chain() {
        let dir = tempfile::tempdir().unwrap();
        let cluster_bits = 12u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = cluster_size * 8;

        // Create base QCOW2 image.
        let base_path = dir.path().join("base.qcow2");
        {
            let mut base = Qcow2File::create(&base_path, virtual_size, cluster_bits, None).unwrap();
            let data = vec![0xAA; cluster_size as usize];
            base.write_at(0, &data).unwrap();
            base.flush().unwrap();
        }

        // Create overlay referencing base.
        let overlay_path = dir.path().join("overlay.qcow2");
        let mut overlay = Qcow2File::create(
            &overlay_path,
            virtual_size,
            cluster_bits,
            Some(&base_path),
        )
        .unwrap();

        // Read unallocated from overlay → should get base data.
        let mut buf = vec![0u8; 16];
        overlay.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));

        // Write to overlay.
        overlay.write_at(0, &[0xDD; 16]).unwrap();
        let mut buf2 = vec![0u8; 16];
        overlay.read_at(0, &mut buf2).unwrap();
        assert!(buf2.iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn test_virtual_size() {
        let sizes = [0u64, 512, 4096, 1 << 20, 1 << 30];
        for &sz in &sizes {
            let (q, _dir) = create_test_image(sz, 12);
            assert_eq!(q.virtual_size(), sz, "virtual_size mismatch for {sz}");
        }
    }

    #[test]
    fn test_header_magic_and_version() {
        let (q, _dir) = create_test_image(1 << 20, DEFAULT_CLUSTER_BITS);
        assert_eq!(q.header().magic, QCOW2_MAGIC);
        assert_eq!(q.header().version, 3);
    }

    #[test]
    fn test_multiple_writes_same_cluster() {
        let cluster_bits = 12u32;
        let cluster_size = 1u64 << cluster_bits;
        let (mut q, _dir) = create_test_image(cluster_size * 16, cluster_bits);

        // Write different data to the same cluster multiple times.
        q.write_at(0, &[1u8; 100]).unwrap();
        q.write_at(50, &[2u8; 100]).unwrap();

        let mut buf = vec![0u8; 150];
        q.read_at(0, &mut buf).unwrap();
        assert!(buf[..50].iter().all(|&b| b == 1));
        assert!(buf[50..100].iter().all(|&b| b == 2)); // overwritten
        assert!(buf[100..150].iter().all(|&b| b == 2)); // second write
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.qcow2");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(&[0u8; 512]).unwrap();
        }
        let result = Qcow2File::open(&path);
        assert!(result.is_err());
        let err = result.err().unwrap();
        let err_chain = format!("{err:#}");
        assert!(
            err_chain.contains("bad magic"),
            "error should mention bad magic: {err_chain}"
        );
    }

    #[test]
    fn test_different_cluster_sizes() {
        for cluster_bits in [9u32, 12, 16, 18] {
            let cluster_size = 1u64 << cluster_bits;
            let virtual_size = cluster_size * 8;
            let (mut q, _dir) = create_test_image(virtual_size, cluster_bits);

            let data = vec![0xFE; cluster_size as usize];
            q.write_at(0, &data).unwrap();

            let mut buf = vec![0u8; cluster_size as usize];
            q.read_at(0, &mut buf).unwrap();
            assert_eq!(buf, data, "mismatch with cluster_bits={cluster_bits}");
        }
    }

    #[test]
    fn test_write_exact_cluster_boundary() {
        let cluster_bits = 12u32;
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = cluster_size * 16;
        let (mut q, _dir) = create_test_image(virtual_size, cluster_bits);

        // Write exactly one full cluster.
        let data = vec![0xAB; cluster_size as usize];
        q.write_at(0, &data).unwrap();

        // Write exactly the next full cluster.
        let data2 = vec![0xCD; cluster_size as usize];
        q.write_at(cluster_size, &data2).unwrap();

        let mut buf1 = vec![0u8; cluster_size as usize];
        q.read_at(0, &mut buf1).unwrap();
        assert_eq!(buf1, data);

        let mut buf2 = vec![0u8; cluster_size as usize];
        q.read_at(cluster_size, &mut buf2).unwrap();
        assert_eq!(buf2, data2);
    }

    #[test]
    fn test_zero_length_read_write() {
        let (mut q, _dir) = create_test_image(4096, 12);
        // Zero-length operations should succeed as no-ops.
        q.read_at(0, &mut []).unwrap();
        q.write_at(0, &[]).unwrap();
    }
}
