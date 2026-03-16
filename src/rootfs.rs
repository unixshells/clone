// Rootfs boot support — generates a minimal initrd for mounting a
// virtio-block device as the root filesystem.
//
// When --rootfs is specified, Clone:
// 1. Finds the clone-init binary (next to clone binary or CLONE_INIT env)
// 2. Packs it into a CPIO "newc" archive as /init
// 3. Loads that archive as the initrd
// 4. Appends clone.rootfs= and clone.overlay= to the kernel cmdline

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Options for rootfs boot mode.
#[derive(Debug, Clone)]
pub struct RootfsConfig {
    /// Path to the rootfs disk image.
    pub image: String,
    /// Whether the rootfs is read-only (requires overlay).
    pub readonly: bool,
    /// Overlay mode: "none", "tmpfs", or a path to a qcow2.
    pub overlay: String,
    /// Filesystem type override (default: "auto").
    pub fstype: String,
}

/// Find the clone-init binary.
///
/// Search order:
/// 1. CLONE_INIT environment variable
/// 2. Next to the clone binary (../crates/clone-init target path)
/// 3. Same directory as the clone binary
/// 4. In PATH
pub fn find_init_binary() -> Result<PathBuf> {
    // 1. Environment variable
    if let Ok(path) = std::env::var("CLONE_INIT") {
        let p = PathBuf::from(&path);
        if p.is_file() {
            return Ok(p);
        }
        anyhow::bail!("CLONE_INIT={path} does not exist");
    }

    // 2. Same directory as clone binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("clone-init");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // 3. In PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("clone-init")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    anyhow::bail!(
        "Could not find clone-init binary. Build it with:\n  \
         cargo build --release -p clone-init\n\
         Or set CLONE_INIT=/path/to/clone-init"
    )
}

/// Find the clone-agent binary (guest agent).
///
/// Search order: CLONE_AGENT env, same dir as clone binary, PATH.
/// Returns None if not found (agent is optional).
pub fn find_agent_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CLONE_AGENT") {
        let p = PathBuf::from(&path);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("clone-agent");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    if let Ok(output) = std::process::Command::new("which")
        .arg("clone-agent")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

/// Embed kernel modules needed by clone-init into the CPIO initrd.
///
/// Searches `/lib/modules/<running-kernel>/` for vsock and overlay modules.
/// These are placed at `/lib/modules/` (flat) in the initrd so clone-init
/// can load them before switching root into the real rootfs.
fn embed_kernel_modules(cpio: &mut Vec<u8>) {
    let uname = match std::process::Command::new("uname").arg("-r").output() {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        _ => return,
    };

    let mod_root = PathBuf::from(format!("/lib/modules/{uname}"));
    if !mod_root.is_dir() {
        tracing::debug!("kernel module dir not found: {}", mod_root.display());
        return;
    }

    // Modules to embed: (subdir, filename) — loaded in order by clone-init
    let modules: &[(&str, &str)] = &[
        // vsock transport (needed for guest agent)
        ("kernel/net/vmw_vsock", "vsock.ko"),
        ("kernel/net/vmw_vsock", "vmw_vsock_virtio_transport_common.ko"),
        ("kernel/net/vmw_vsock", "vmw_vsock_virtio_transport.ko"),
        // overlayfs (needed for --overlay mode)
        ("kernel/fs/overlayfs", "overlay.ko"),
    ];

    // Create /lib/modules directory in initrd
    cpio_write_entry(cpio, "/lib", 0o040755, &[]);
    cpio_write_entry(cpio, "/lib/modules", 0o040755, &[]);

    let mut count = 0;
    for (subdir, name) in modules {
        let path = mod_root.join(subdir).join(name);
        match fs::read(&path) {
            Ok(data) => {
                let cpio_path = format!("/lib/modules/{name}");
                cpio_write_entry(cpio, &cpio_path, 0o100644, &data);
                count += 1;
            }
            Err(e) => {
                tracing::debug!("kernel module {name} not found: {e}");
            }
        }
    }

    if count > 0 {
        tracing::info!("Embedded {count} kernel modules in initrd");
    }
}

/// Generate a minimal CPIO initrd containing the clone-init binary as /init
/// and optionally the clone-agent binary.
///
/// Returns the initrd contents as a byte vector.
pub fn generate_initrd(init_binary: &Path) -> Result<Vec<u8>> {
    let init_data =
        fs::read(init_binary).with_context(|| format!("Failed to read {}", init_binary.display()))?;

    let mut cpio = Vec::new();

    // Create directory entries: /dev, /proc, /sys, /mnt
    for dir in &["/dev", "/proc", "/sys", "/mnt", "/mnt/root", "/mnt/merged", "/mnt/overlay"] {
        cpio_write_entry(&mut cpio, dir, 0o040755, &[]);
    }

    // Create device nodes — the kernel needs /dev/console to set up fd 0/1/2
    // for PID 1. Without it, init's stdout is disconnected and println! is lost.
    // Format: mode=chardev, data=[major:u32 LE, minor:u32 LE]
    fn dev_data(major: u32, minor: u32) -> Vec<u8> {
        let mut d = Vec::with_capacity(8);
        d.extend_from_slice(&major.to_le_bytes());
        d.extend_from_slice(&minor.to_le_bytes());
        d
    }
    // /dev/console: char major 5, minor 1
    cpio_write_entry(&mut cpio, "/dev/console", 0o020666, &dev_data(5, 1));
    // /dev/null: char major 1, minor 3
    cpio_write_entry(&mut cpio, "/dev/null", 0o020666, &dev_data(1, 3));
    // /dev/ttyS0: char major 4, minor 64
    cpio_write_entry(&mut cpio, "/dev/ttyS0", 0o020666, &dev_data(4, 64));

    // Write /init (the clone-init binary, executable)
    cpio_write_entry(&mut cpio, "/init", 0o100755, &init_data);

    // Include clone-agent if available — clone-init will copy it to rootfs and start it
    if let Some(agent_path) = find_agent_binary() {
        match fs::read(&agent_path) {
            Ok(agent_data) => {
                cpio_write_entry(&mut cpio, "/clone-agent", 0o100755, &agent_data);
                tracing::info!(
                    "Embedded clone-agent in initrd ({} bytes)",
                    agent_data.len()
                );
            }
            Err(e) => {
                tracing::warn!("Failed to read clone-agent at {}: {e}", agent_path.display());
            }
        }
    }

    // Include vsock kernel modules so clone-init can load them before switching root.
    // These are required for the guest agent to connect back to the host VMM.
    // The kernel may have CONFIG_VIRTIO_VSOCKETS=m, so modules must be loaded explicitly.
    embed_kernel_modules(&mut cpio);

    // Write trailer
    cpio_write_trailer(&mut cpio);

    tracing::info!(
        "Generated initrd: {} bytes (init binary: {} bytes)",
        cpio.len(),
        init_data.len()
    );

    Ok(cpio)
}

/// Build the extra kernel cmdline parameters for rootfs boot.
pub fn rootfs_cmdline_params(config: &RootfsConfig) -> Vec<String> {
    let mut params = Vec::new();

    if config.readonly {
        params.push("clone.rootfs=ro".to_string());
    } else {
        params.push("clone.rootfs=rw".to_string());
    }

    if config.overlay != "none" {
        params.push(format!("clone.overlay={}", config.overlay));
    }

    if config.fstype != "auto" {
        params.push(format!("clone.fstype={}", config.fstype));
    }

    params
}

// --- CPIO newc format ---
//
// Each entry:
//   110-byte ASCII header
//   filename (padded to 4-byte boundary)
//   file data (padded to 4-byte boundary)
//
// Header fields (all 8-digit lowercase hex):
//   magic: "070701"
//   ino, mode, uid, gid, nlink, mtime
//   filesize
//   devmajor, devminor, rdevmajor, rdevminor
//   namesize (including trailing NUL)
//   check (always 0)

fn cpio_write_entry(buf: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
    // Strip leading / for cpio (names are relative)
    let name = name.strip_prefix('/').unwrap_or(name);
    let namesize = name.len() + 1; // include NUL terminator

    let is_dir = (mode & 0o170000) == 0o040000;
    let is_dev = (mode & 0o170000) == 0o020000 || (mode & 0o170000) == 0o060000;
    let nlink: u32 = if is_dir { 2 } else { 1 };
    let filesize = if is_dir || is_dev { 0 } else { data.len() };

    // Use sequential inode numbers (doesn't matter, kernel ignores them for initramfs)
    static INODE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let ino = INODE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // Write header (with optional rdev for device nodes)
    let (rdevmajor, rdevminor) = if is_dev && data.len() >= 8 {
        // Device nodes: encode major/minor in data as [major:u32, minor:u32]
        let major = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let minor = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        (major, minor)
    } else {
        (0, 0)
    };

    write!(
        buf,
        "070701\
         {ino:08x}\
         {mode:08x}\
         00000000\
         00000000\
         {nlink:08x}\
         00000000\
         {filesize:08x}\
         00000000\
         00000000\
         {rdevmajor:08x}\
         {rdevminor:08x}\
         {namesize:08x}\
         00000000"
    )
    .unwrap();

    // Write filename + NUL
    buf.extend_from_slice(name.as_bytes());
    buf.push(0);

    // Pad to 4-byte boundary
    pad4(buf);

    // Write file data (skip for dirs and device nodes — their info is in the header)
    if filesize > 0 {
        buf.extend_from_slice(data);
        pad4(buf);
    }
}

fn cpio_write_trailer(buf: &mut Vec<u8>) {
    cpio_write_entry(buf, "TRAILER!!!", 0, &[]);
}

fn pad4(buf: &mut Vec<u8>) {
    let padding = (4 - (buf.len() % 4)) % 4;
    for _ in 0..padding {
        buf.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpio_basic_structure() {
        let mut buf = Vec::new();
        cpio_write_entry(&mut buf, "/init", 0o100755, b"#!/bin/sh\necho hello\n");
        cpio_write_trailer(&mut buf);

        // Should start with cpio magic
        let header = std::str::from_utf8(&buf[..6]).unwrap();
        assert_eq!(header, "070701");

        // Should be 4-byte aligned throughout
        assert_eq!(buf.len() % 4, 0);
    }

    #[test]
    fn test_cpio_directory_entry() {
        let mut buf = Vec::new();
        cpio_write_entry(&mut buf, "/proc", 0o040755, &[]);

        let header = std::str::from_utf8(&buf[..6]).unwrap();
        assert_eq!(header, "070701");

        // Directory should have filesize 0
        // filesize is at offset 54 (6+8+8+8+8+8+8 = 54), 8 chars
        let filesize_str = std::str::from_utf8(&buf[54..62]).unwrap();
        assert_eq!(filesize_str, "00000000");
    }

    #[test]
    fn test_rootfs_cmdline_rw() {
        let config = RootfsConfig {
            image: "test.img".into(),
            readonly: false,
            overlay: "none".into(),
            fstype: "auto".into(),
        };
        let params = rootfs_cmdline_params(&config);
        assert_eq!(params, vec!["clone.rootfs=rw"]);
    }

    #[test]
    fn test_rootfs_cmdline_overlay() {
        let config = RootfsConfig {
            image: "test.img".into(),
            readonly: true,
            overlay: "tmpfs".into(),
            fstype: "ext4".into(),
        };
        let params = rootfs_cmdline_params(&config);
        assert!(params.contains(&"clone.rootfs=ro".to_string()));
        assert!(params.contains(&"clone.overlay=tmpfs".to_string()));
        assert!(params.contains(&"clone.fstype=ext4".to_string()));
    }
}
