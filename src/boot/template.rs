//! Template snapshot and CoW fork system.
//!
//! This module implements the core fast-boot mechanism:
//! 1. Boot a "template" VM to idle state for a given runtime
//! 2. Snapshot its full memory + register state to disk
//! 3. Fork new VMs by mmap-ing the snapshot with MAP_PRIVATE (CoW)
//! 4. Inject per-VM identity, then start — pages fault in on demand
//!
//! This is the primary source of <20ms cold starts.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Serialized vCPU register state.
///
/// We store registers as raw bytes so this module compiles on all platforms.
/// On Linux, these are serialized from `kvm_regs` and `kvm_sregs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuState {
    /// General-purpose registers (serialized kvm_regs).
    pub regs: Vec<u8>,
    /// Special registers — segment, control, etc. (serialized kvm_sregs).
    pub sregs: Vec<u8>,
}

/// Serialized device state for template restoration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStates {
    /// Serial port state (if any).
    pub serial: Option<Vec<u8>>,
    /// Virtio device configs, keyed by device name.
    pub virtio_configs: HashMap<String, Vec<u8>>,
    /// Serialized MmioTransportState per device.
    #[serde(default)]
    pub transports: Vec<Vec<u8>>,
}

impl Default for DeviceStates {
    fn default() -> Self {
        Self {
            serial: None,
            virtio_configs: HashMap::new(),
            transports: Vec::new(),
        }
    }
}

/// A template snapshot capturing a VM's full state for CoW forking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSnapshot {
    /// Path to the raw memory dump file on disk.
    pub memory_file: PathBuf,
    /// vCPU register states (one per vCPU).
    pub vcpu_states: Vec<VcpuState>,
    /// Device configuration states.
    pub device_states: DeviceStates,
    /// Original guest memory size in bytes.
    pub memory_size: u64,
    /// Runtime type this template was created for (e.g., "node20", "python312", "bare").
    pub runtime_type: String,
    /// SHA-256 hash of the memory file for integrity verification.
    pub memory_hash: String,
}

/// Metadata file name stored alongside the memory dump.
const TEMPLATE_METADATA_FILE: &str = "template.json";

impl TemplateSnapshot {
    /// Load a template snapshot from a directory.
    ///
    /// Expects `template.json` (metadata) and a memory dump file in the directory.
    pub fn load(template_dir: &str, verify: bool) -> Result<Self> {
        let meta_path = Path::new(template_dir).join(TEMPLATE_METADATA_FILE);
        let meta_data = std::fs::read_to_string(&meta_path)
            .with_context(|| format!("Failed to read template metadata: {}", meta_path.display()))?;
        let snapshot: TemplateSnapshot =
            serde_json::from_str(&meta_data).context("Failed to parse template metadata")?;

        // Verify the memory file exists
        if !snapshot.memory_file.exists() {
            anyhow::bail!(
                "Template memory file not found: {}",
                snapshot.memory_file.display()
            );
        }

        // Verify memory file integrity
        if verify {
            let mem_data = std::fs::read(&snapshot.memory_file)
                .with_context(|| format!("Failed to read template memory for verification: {}", snapshot.memory_file.display()))?;
            let actual_hash = crate::boot::measured::compute_sha256(&mem_data);
            let actual_hex: String = actual_hash.iter().map(|b| format!("{b:02x}")).collect();
            if actual_hex != snapshot.memory_hash {
                anyhow::bail!(
                    "Template integrity check failed: expected {}, got {}",
                    snapshot.memory_hash, actual_hex
                );
            }
            tracing::info!("Template integrity verified (SHA-256 matches)");
        }

        tracing::info!(
            "Loaded template: runtime={}, memory_size={}MB, vcpus={}",
            snapshot.runtime_type,
            snapshot.memory_size >> 20,
            snapshot.vcpu_states.len(),
        );

        Ok(snapshot)
    }

    /// Save this template's metadata to a directory.
    pub fn save_metadata(&self, template_dir: &str) -> Result<()> {
        std::fs::create_dir_all(template_dir)
            .with_context(|| format!("Failed to create template dir: {template_dir}"))?;

        let meta_path = Path::new(template_dir).join(TEMPLATE_METADATA_FILE);
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize template metadata")?;
        std::fs::write(&meta_path, json)
            .with_context(|| format!("Failed to write template metadata: {}", meta_path.display()))?;

        tracing::info!("Saved template metadata to {}", meta_path.display());
        Ok(())
    }
}

/// Save a VM's state as a template snapshot.
///
/// This dumps the full guest memory to a file and saves register + device state
/// as JSON metadata alongside it.
///
/// On Linux, this reads directly from the guest memory mapping.
/// On other platforms, this is a stub.
#[cfg(target_os = "linux")]
pub fn save_template(
    guest_mem: &crate::memory::GuestMem,
    vcpu_states: Vec<VcpuState>,
    device_states: DeviceStates,
    runtime_type: &str,
    output_dir: &str,
) -> Result<TemplateSnapshot> {
    use crate::boot::measured::compute_sha256;

    let memory_size = guest_mem.size();
    let mem_file_path = Path::new(output_dir).join("memory.raw");

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir: {output_dir}"))?;

    // Dump raw guest memory to file
    let mem_data = guest_mem.read_at(0, memory_size as usize)?;
    std::fs::write(&mem_file_path, &mem_data)
        .with_context(|| format!("Failed to write memory dump: {}", mem_file_path.display()))?;

    // Compute integrity hash
    let hash = compute_sha256(&mem_data);
    let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

    let snapshot = TemplateSnapshot {
        memory_file: mem_file_path,
        vcpu_states,
        device_states,
        memory_size,
        runtime_type: runtime_type.to_string(),
        memory_hash: hash_hex,
    };

    snapshot.save_metadata(output_dir)?;

    tracing::info!(
        "Template saved: runtime={runtime_type}, memory={}MB, file={}",
        memory_size >> 20,
        output_dir,
    );

    Ok(snapshot)
}

/// Fork a new VM from a template snapshot using CoW memory mapping.
///
/// The template memory file is mmap-ed with MAP_PRIVATE (no MAP_POPULATE),
/// so pages are copy-on-write references that only fault in on demand.
/// This is the core mechanism for <20ms cold starts.
///
/// After this call, the caller must:
/// 1. Call `inject_identity()` to write per-VM state
/// 2. Restore vCPU registers from `template.vcpu_states`
/// 3. Start vCPU execution
#[cfg(target_os = "linux")]
pub fn fork_from_template(template: &TemplateSnapshot) -> Result<crate::memory::GuestMem> {
    use std::os::unix::io::AsRawFd;

    let mem_file = std::fs::File::open(&template.memory_file).with_context(|| {
        format!(
            "Failed to open template memory: {}",
            template.memory_file.display()
        )
    })?;

    let fd = mem_file.as_raw_fd();
    let size = template.memory_size as usize;

    // mmap with MAP_PRIVATE — CoW semantics, pages shared until written.
    // NO MAP_POPULATE — pages fault in on demand for minimal startup latency.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE, // CoW: shared read, private write
            fd,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        anyhow::bail!(
            "mmap failed for template memory ({size} bytes): {}",
            std::io::Error::last_os_error()
        );
    }

    // Enable KSM on the forked mapping — identical pages across VMs get merged
    unsafe {
        libc::madvise(ptr, size, libc::MADV_MERGEABLE);
    }

    tracing::info!(
        "Forked VM from template: {}MB CoW-mapped at {ptr:?} (runtime={})",
        size >> 20,
        template.runtime_type,
    );

    // Wrap in GuestMem. Note: GuestMem::drop calls munmap, which is correct here.
    Ok(crate::memory::GuestMem::from_raw(ptr as *mut u8, template.memory_size))
}

/// An incremental snapshot capturing only modified pages since the base.
///
/// Combined with a base template, this provides fast warm snapshots:
/// only dirty pages are dumped (typically 10-100x smaller than full).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalSnapshot {
    /// Path to the base template directory.
    pub base_template: String,
    /// Dirty page bitmap (one bit per 4KiB page).
    pub dirty_bitmap: Vec<u8>,
    /// Only the modified page data (concatenated dirty pages).
    pub dirty_pages_file: PathBuf,
    /// vCPU register states at snapshot time.
    pub vcpu_states: Vec<VcpuState>,
    /// Device states at snapshot time.
    pub device_states: DeviceStates,
    /// Total guest memory size in bytes.
    pub memory_size: u64,
}

const INCREMENTAL_METADATA_FILE: &str = "incremental.json";

impl IncrementalSnapshot {
    /// Save incremental snapshot metadata.
    pub fn save_metadata(&self, output_dir: &str) -> Result<()> {
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output dir: {output_dir}"))?;

        let meta_path = Path::new(output_dir).join(INCREMENTAL_METADATA_FILE);
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize incremental snapshot metadata")?;
        std::fs::write(&meta_path, json)
            .with_context(|| format!("Failed to write metadata: {}", meta_path.display()))?;

        tracing::info!("Saved incremental snapshot metadata to {}", meta_path.display());
        Ok(())
    }

    /// Load incremental snapshot metadata.
    pub fn load(snapshot_dir: &str) -> Result<Self> {
        let meta_path = Path::new(snapshot_dir).join(INCREMENTAL_METADATA_FILE);
        let meta_data = std::fs::read_to_string(&meta_path)
            .with_context(|| format!("Failed to read incremental metadata: {}", meta_path.display()))?;
        let snapshot: IncrementalSnapshot = serde_json::from_str(&meta_data)
            .context("Failed to parse incremental snapshot metadata")?;
        Ok(snapshot)
    }
}

/// Save an incremental snapshot (only dirty pages since base).
///
/// `kvm_slot_size` is the actual KVM memory slot size (may include guard region)
/// and must be used for `get_dirty_log` to match the registered slot size.
/// Only pages within `guest_mem.size()` are actually collected.
#[cfg(target_os = "linux")]
pub fn save_incremental(
    guest_mem: &crate::memory::GuestMem,
    vm_fd: &kvm_ioctls::VmFd,
    vcpu_states: Vec<VcpuState>,
    device_states: DeviceStates,
    base_template: &str,
    output_dir: &str,
    kvm_slot_size: u64,
) -> Result<IncrementalSnapshot> {
    let mem_size = guest_mem.size();
    // Use kvm_slot_size for get_dirty_log (must match registered KVM slot),
    // but only collect pages within mem_size (actual guest memory).
    let tracker = crate::memory::overcommit::DirtyPageTracker::new(kvm_slot_size);

    let (bitmap, dirty_data) = tracker.collect_dirty_pages(vm_fd, guest_mem.as_ptr() as *const u8, mem_size)?;

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir: {output_dir}"))?;

    let dirty_file = Path::new(output_dir).join("dirty_pages.raw");
    std::fs::write(&dirty_file, &dirty_data)
        .with_context(|| format!("Failed to write dirty pages: {}", dirty_file.display()))?;

    let snapshot = IncrementalSnapshot {
        base_template: base_template.to_string(),
        dirty_bitmap: bitmap,
        dirty_pages_file: dirty_file,
        vcpu_states,
        device_states,
        memory_size: mem_size,
    };

    snapshot.save_metadata(output_dir)?;

    tracing::info!(
        "Incremental snapshot saved: dirty_data={}KB, base={}",
        dirty_data.len() / 1024,
        base_template,
    );

    Ok(snapshot)
}

/// Manages a pool of pre-created template snapshots, one per runtime type.
///
/// Templates are created lazily on first request and cached. The pool can be
/// refreshed when base images are updated.
pub struct TemplatePool {
    /// Base directory where templates are stored on disk.
    base_dir: PathBuf,
    /// Cached template snapshots, keyed by runtime type.
    templates: HashMap<String, TemplateSnapshot>,
}

impl TemplatePool {
    /// Create a new template pool rooted at the given directory.
    pub fn new(base_dir: &str) -> Self {
        Self {
            base_dir: PathBuf::from(base_dir),
            templates: HashMap::new(),
        }
    }

    /// Get an existing template for a runtime type, or return None if not cached.
    pub fn get(&self, runtime_type: &str) -> Option<&TemplateSnapshot> {
        self.templates.get(runtime_type)
    }

    /// Get a template, loading from disk if not already cached.
    pub fn get_or_load(&mut self, runtime_type: &str) -> Result<&TemplateSnapshot> {
        if !self.templates.contains_key(runtime_type) {
            let template_dir = self.base_dir.join(runtime_type);
            let template = TemplateSnapshot::load(
                template_dir
                    .to_str()
                    .context("Invalid template directory path")?,
                true,
            )?;
            self.templates.insert(runtime_type.to_string(), template);
        }
        Ok(self.templates.get(runtime_type).unwrap())
    }

    /// Register a freshly-created template in the pool.
    pub fn register(&mut self, runtime_type: &str, template: TemplateSnapshot) {
        tracing::info!("Registered template in pool: {runtime_type}");
        self.templates.insert(runtime_type.to_string(), template);
    }

    /// Refresh a template by removing the cached version.
    ///
    /// The next call to `get_or_load` will reload from disk, picking up
    /// any updates to the template files.
    pub fn refresh(&mut self, runtime_type: &str) {
        if self.templates.remove(runtime_type).is_some() {
            tracing::info!("Refreshed template: {runtime_type} (removed from cache)");
        } else {
            tracing::info!("Template not cached, nothing to refresh: {runtime_type}");
        }
    }

    /// List all cached runtime types.
    pub fn cached_runtime_types(&self) -> Vec<&str> {
        self.templates.keys().map(|s| s.as_str()).collect()
    }
}
