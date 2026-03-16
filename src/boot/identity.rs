//! Per-VM identity injection.
//!
//! After forking from a CoW template, each VM must be personalized with unique
//! state before the first vCPU enters guest mode. This module defines the
//! identity page layout and writes it to a fixed guest physical address that
//! the guest agent reads on resume.

use anyhow::{Context, Result};
use std::io::Read;

/// Fixed guest physical address where the identity page is written.
/// This must not collide with boot_params (0x7000), page tables (0x9000-0xBFFF),
/// or the command line (0x20000). We use 0x6000, which sits in reserved low memory.
pub const IDENTITY_PAGE_ADDR: u64 = 0x6000;

/// Magic value at the start of the identity page so the guest agent can validate it.
pub const IDENTITY_MAGIC: u32 = 0x4E564D49; // "NVMI" (Clone Identity) in little-endian

/// Version of the identity page layout. Bump when the struct changes.
pub const IDENTITY_VERSION: u32 = 1;

/// Per-VM identity information.
///
/// This struct is written to guest memory at `IDENTITY_PAGE_ADDR` and must have
/// a well-defined C-compatible layout that the guest agent can read directly.
///
/// Memory layout (total: 344 bytes, fits well within a single 4K page):
///
/// ```text
/// Offset  Size  Field
/// 0x000   4     magic (0x4E564D49)
/// 0x004   4     version
/// 0x008   16    vm_id (UUID, big-endian bytes)
/// 0x018   64    hostname (null-terminated UTF-8)
/// 0x058   8     vsock_cid (u64 LE)
/// 0x060   6     mac_address
/// 0x066   2     (padding)
/// 0x068   4     ip_address (IPv4 in network byte order)
/// 0x06C   4     (padding)
/// 0x070   32    entropy_seed (256-bit)
/// 0x090   4     entropy_seed_len (should be 32)
/// 0x094   ...   (reserved, zero-filled to end of page)
/// ```
#[derive(Debug, Clone)]
pub struct VmIdentity {
    /// Unique VM identifier (UUID v4).
    pub vm_id: [u8; 16],
    /// Hostname for this VM (up to 63 bytes + null terminator).
    pub hostname: String,
    /// Vsock context ID — unique per VM on the host.
    pub vsock_cid: u64,
    /// MAC address (6 bytes). Locally administered: first byte has bit 1 set (02:xx:xx:xx:xx:xx).
    pub mac_address: [u8; 6],
    /// IPv4 address in network byte order.
    pub ip_address: [u8; 4],
    /// Fresh 256-bit entropy seed from /dev/urandom.
    pub entropy_seed: [u8; 32],
}

impl VmIdentity {
    /// Format the VM ID as a UUID string.
    pub fn vm_id_string(&self) -> String {
        let b = &self.vm_id;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
        )
    }

    /// Format the MAC address as a colon-separated hex string.
    pub fn mac_address_string(&self) -> String {
        let m = &self.mac_address;
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5],
        )
    }

    /// Serialize the identity into a fixed-layout byte buffer for writing to guest memory.
    /// Returns exactly 4096 bytes (one page), zero-padded.
    pub fn to_page(&self) -> Vec<u8> {
        let mut page = vec![0u8; 4096];

        // Magic
        page[0x000..0x004].copy_from_slice(&IDENTITY_MAGIC.to_le_bytes());
        // Version
        page[0x004..0x008].copy_from_slice(&IDENTITY_VERSION.to_le_bytes());
        // VM ID (16 bytes)
        page[0x008..0x018].copy_from_slice(&self.vm_id);
        // Hostname (64 bytes, null-terminated)
        let hostname_bytes = self.hostname.as_bytes();
        let hostname_len = hostname_bytes.len().min(63);
        page[0x018..0x018 + hostname_len].copy_from_slice(&hostname_bytes[..hostname_len]);
        // null terminator already present (page is zero-initialized)
        // Vsock CID
        page[0x058..0x060].copy_from_slice(&self.vsock_cid.to_le_bytes());
        // MAC address (6 bytes)
        page[0x060..0x066].copy_from_slice(&self.mac_address);
        // IP address (4 bytes, network byte order)
        page[0x068..0x06C].copy_from_slice(&self.ip_address);
        // Entropy seed (32 bytes)
        page[0x070..0x090].copy_from_slice(&self.entropy_seed);
        // Entropy seed length
        page[0x090..0x094].copy_from_slice(&(32u32).to_le_bytes());

        page
    }
}

/// Generate a new random VmIdentity with unique values.
///
/// - UUID v4 for vm_id
/// - Random MAC with locally-administered bit (02:xx:xx:xx:xx:xx)
/// - Fresh 256-bit entropy seed from /dev/urandom
/// - Unique vsock CID (derived from UUID bytes to avoid collisions)
/// - Default hostname derived from VM ID
/// - IP address defaults to 0.0.0.0 (assigned later by the control plane)
pub fn generate_identity() -> Result<VmIdentity> {
    // Read random bytes for UUID, MAC, entropy seed, and CID
    // Total: 16 (uuid) + 5 (mac random bytes) + 32 (entropy) + 8 (cid randomness) = 61 bytes
    let mut random_bytes = [0u8; 61];
    let mut urandom = std::fs::File::open("/dev/urandom")
        .context("Failed to open /dev/urandom")?;
    urandom
        .read_exact(&mut random_bytes)
        .context("Failed to read from /dev/urandom")?;

    // UUID v4: set version (4) and variant (RFC 4122)
    let mut vm_id = [0u8; 16];
    vm_id.copy_from_slice(&random_bytes[0..16]);
    vm_id[6] = (vm_id[6] & 0x0F) | 0x40; // version 4
    vm_id[8] = (vm_id[8] & 0x3F) | 0x80; // variant RFC 4122

    // MAC address: locally administered (02:xx:xx:xx:xx:xx)
    let mut mac_address = [0u8; 6];
    mac_address[0] = 0x02; // locally administered, unicast
    mac_address[1..6].copy_from_slice(&random_bytes[16..21]);

    // Entropy seed
    let mut entropy_seed = [0u8; 32];
    entropy_seed.copy_from_slice(&random_bytes[21..53]);

    // Vsock CID: use random bytes, ensure > 2 (0=hypervisor, 1=reserved, 2=host)
    let mut cid_bytes = [0u8; 8];
    cid_bytes.copy_from_slice(&random_bytes[53..61]);
    let mut vsock_cid = u64::from_le_bytes(cid_bytes);
    // Ensure CID is in a valid range (3..u32::MAX to stay within vsock spec)
    vsock_cid = (vsock_cid % (u32::MAX as u64 - 3)) + 3;

    // Hostname derived from first 4 bytes of UUID
    let hostname = format!(
        "clone-{:02x}{:02x}{:02x}{:02x}",
        vm_id[0], vm_id[1], vm_id[2], vm_id[3],
    );

    let identity = VmIdentity {
        vm_id,
        hostname,
        vsock_cid,
        mac_address,
        ip_address: [0, 0, 0, 0], // assigned by control plane
        entropy_seed,
    };

    tracing::info!(
        "Generated VM identity: id={}, hostname={}, vsock_cid={}, mac={}",
        identity.vm_id_string(),
        identity.hostname,
        identity.vsock_cid,
        identity.mac_address_string(),
    );

    Ok(identity)
}

/// Write the identity struct to a fixed page in guest memory.
///
/// This must be called after forking from a template and before the first vCPU
/// enters guest mode. The guest agent reads this page on resume to pick up
/// its unique identity, entropy, and network configuration.
#[cfg(target_os = "linux")]
pub fn inject_identity(guest_mem: &crate::memory::GuestMem, identity: &VmIdentity) -> Result<()> {
    let page = identity.to_page();
    guest_mem
        .write_at(IDENTITY_PAGE_ADDR, &page)
        .context("Failed to write identity page to guest memory")?;

    tracing::info!(
        "Injected identity page at {IDENTITY_PAGE_ADDR:#x}: vm_id={}, hostname={}",
        identity.vm_id_string(),
        identity.hostname,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_page_layout() {
        let identity = VmIdentity {
            vm_id: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x47, 0x08, 0x89, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F, 0x10,
            ],
            hostname: "test-vm".to_string(),
            vsock_cid: 42,
            mac_address: [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            ip_address: [10, 0, 0, 1],
            entropy_seed: [0xFF; 32],
        };

        let page = identity.to_page();

        // Check size
        assert_eq!(page.len(), 4096);

        // Check magic
        let magic = u32::from_le_bytes(page[0..4].try_into().unwrap());
        assert_eq!(magic, IDENTITY_MAGIC);

        // Check version
        let version = u32::from_le_bytes(page[4..8].try_into().unwrap());
        assert_eq!(version, IDENTITY_VERSION);

        // Check VM ID
        assert_eq!(&page[0x008..0x018], &identity.vm_id);

        // Check hostname
        assert_eq!(&page[0x018..0x01F], b"test-vm");
        assert_eq!(page[0x01F], 0); // null terminated

        // Check vsock CID
        let cid = u64::from_le_bytes(page[0x058..0x060].try_into().unwrap());
        assert_eq!(cid, 42);

        // Check MAC
        assert_eq!(&page[0x060..0x066], &[0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

        // Check IP
        assert_eq!(&page[0x068..0x06C], &[10, 0, 0, 1]);

        // Check entropy
        assert_eq!(&page[0x070..0x090], &[0xFF; 32]);

        // Check entropy len
        let elen = u32::from_le_bytes(page[0x090..0x094].try_into().unwrap());
        assert_eq!(elen, 32);
    }

    #[test]
    fn test_generate_identity() {
        let id = generate_identity().unwrap();

        // UUID v4 checks
        assert_eq!(id.vm_id[6] >> 4, 4); // version 4
        assert_eq!(id.vm_id[8] >> 6, 2); // variant 10

        // MAC locally administered
        assert_eq!(id.mac_address[0], 0x02);

        // CID valid range
        assert!(id.vsock_cid >= 3);

        // Hostname starts with clone-
        assert!(id.hostname.starts_with("clone-"));
    }

    #[test]
    fn test_generate_identity_produces_unique_values() {
        let id1 = generate_identity().unwrap();
        let id2 = generate_identity().unwrap();

        // UUIDs should differ
        assert_ne!(id1.vm_id, id2.vm_id);

        // MAC addresses should differ (with overwhelming probability)
        assert_ne!(id1.mac_address, id2.mac_address);

        // Entropy seeds should differ
        assert_ne!(id1.entropy_seed, id2.entropy_seed);

        // CIDs should differ (with overwhelming probability)
        assert_ne!(id1.vsock_cid, id2.vsock_cid);
    }

    #[test]
    fn test_mac_address_locally_administered_bit() {
        let id = generate_identity().unwrap();
        // Bit 1 of first byte = locally administered
        assert_eq!(id.mac_address[0] & 0x02, 0x02);
        // Bit 0 of first byte = unicast (should be 0)
        assert_eq!(id.mac_address[0] & 0x01, 0x00);
    }

    #[test]
    fn test_vsock_cid_range() {
        // Generate multiple identities and check CID range
        for _ in 0..10 {
            let id = generate_identity().unwrap();
            assert!(id.vsock_cid >= 3, "CID {} is below 3", id.vsock_cid);
            assert!(
                id.vsock_cid < u32::MAX as u64,
                "CID {} exceeds u32::MAX",
                id.vsock_cid
            );
        }
    }

    #[test]
    fn test_entropy_seed_is_nonzero() {
        let id = generate_identity().unwrap();
        // The entropy seed should not be all zeros
        assert_ne!(id.entropy_seed, [0u8; 32]);
    }

    #[test]
    fn test_identity_page_size() {
        let id = generate_identity().unwrap();
        let page = id.to_page();
        assert_eq!(page.len(), 4096);
    }

    #[test]
    fn test_identity_page_magic_at_correct_offset() {
        let id = generate_identity().unwrap();
        let page = id.to_page();
        let magic = u32::from_le_bytes(page[0x000..0x004].try_into().unwrap());
        assert_eq!(magic, IDENTITY_MAGIC);
        assert_eq!(magic, 0x4E564D49);
    }

    #[test]
    fn test_identity_page_version_at_correct_offset() {
        let id = generate_identity().unwrap();
        let page = id.to_page();
        let version = u32::from_le_bytes(page[0x004..0x008].try_into().unwrap());
        assert_eq!(version, IDENTITY_VERSION);
        assert_eq!(version, 1);
    }

    #[test]
    fn test_identity_page_entropy_seed_len() {
        let id = generate_identity().unwrap();
        let page = id.to_page();
        let elen = u32::from_le_bytes(page[0x090..0x094].try_into().unwrap());
        assert_eq!(elen, 32);
    }

    #[test]
    fn test_identity_page_reserved_area_is_zero() {
        let id = generate_identity().unwrap();
        let page = id.to_page();
        // Area after entropy_seed_len (0x094) to end should be zero
        for &b in &page[0x094..] {
            assert_eq!(b, 0, "Reserved area should be zero-filled");
        }
    }

    #[test]
    fn test_vm_id_string_format() {
        let identity = VmIdentity {
            vm_id: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x47, 0x08,
                0x89, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            ],
            hostname: "test".to_string(),
            vsock_cid: 3,
            mac_address: [0x02, 0, 0, 0, 0, 0],
            ip_address: [0; 4],
            entropy_seed: [0; 32],
        };

        let uuid_str = identity.vm_id_string();
        assert_eq!(uuid_str, "01020304-0506-4708-890a-0b0c0d0e0f10");
    }

    #[test]
    fn test_mac_address_string_format() {
        let identity = VmIdentity {
            vm_id: [0; 16],
            hostname: "test".to_string(),
            vsock_cid: 3,
            mac_address: [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            ip_address: [0; 4],
            entropy_seed: [0; 32],
        };

        assert_eq!(identity.mac_address_string(), "02:aa:bb:cc:dd:ee");
    }

    #[test]
    fn test_hostname_truncation_at_63_bytes() {
        let long_hostname = "a".repeat(100);
        let identity = VmIdentity {
            vm_id: [0; 16],
            hostname: long_hostname,
            vsock_cid: 3,
            mac_address: [0x02, 0, 0, 0, 0, 0],
            ip_address: [0; 4],
            entropy_seed: [0; 32],
        };

        let page = identity.to_page();
        // Only 63 bytes should be written
        assert_eq!(page[0x018 + 62], b'a');
        assert_eq!(page[0x018 + 63], 0); // null terminator
    }
}
