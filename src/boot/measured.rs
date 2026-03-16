//! Measured boot — kernel hash verification before loading.
//!
//! The VMM verifies the kernel binary's SHA-256 hash against a signed manifest
//! before allowing it to be loaded into guest memory. This prevents kernel
//! substitution attacks and ensures all guests run an audited kernel.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// A kernel verifier that checks kernel binaries against expected SHA-256 hashes.
#[derive(Debug)]
pub struct KernelVerifier {
    /// Expected SHA-256 hash (32 bytes).
    expected_hash: [u8; 32],
}

impl KernelVerifier {
    /// Create a new verifier with the given expected SHA-256 hash.
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self { expected_hash }
    }

    /// Create a verifier from a hex-encoded hash string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex_decode(hex).context("Invalid hex string for kernel hash")?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "Expected 32-byte SHA-256 hash, got {} bytes",
                bytes.len()
            );
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Self::new(hash))
    }

    /// Read the kernel file, compute its SHA-256 hash, and verify it matches
    /// the expected hash. Returns the kernel bytes on success.
    pub fn verify_kernel(&self, path: &str) -> Result<Vec<u8>> {
        let kernel_data = std::fs::read(path)
            .with_context(|| format!("Failed to read kernel: {path}"))?;

        let actual_hash = compute_sha256(&kernel_data);

        if actual_hash != self.expected_hash {
            anyhow::bail!(
                "Kernel hash mismatch for {path}!\n  expected: {}\n  actual:   {}",
                hex_encode(&self.expected_hash),
                hex_encode(&actual_hash),
            );
        }

        tracing::info!(
            "Kernel verified: {} (SHA-256: {})",
            path,
            hex_encode(&actual_hash),
        );

        Ok(kernel_data)
    }

    /// Return the expected hash as a hex string.
    pub fn expected_hash_hex(&self) -> String {
        hex_encode(&self.expected_hash)
    }
}

/// A signed manifest containing trusted kernel hashes, keyed by kernel name or path.
///
/// Manifest file format (JSON):
/// ```json
/// {
///   "hashes": {
///     "vmlinux-6.1": "abcdef0123456789...",
///     "vmlinux-6.6": "fedcba9876543210..."
///   },
///   "signature": "base64-encoded-signature"
/// }
/// ```
#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct TrustedManifest {
    /// Map of kernel name -> hex-encoded SHA-256 hash.
    pub hashes: HashMap<String, String>,
    /// Base64-encoded signature over the hashes (verification is a future phase).
    #[serde(default)]
    pub signature: String,
}

/// Load trusted kernel hashes from a signed manifest file.
///
/// The manifest is a JSON file containing a map of kernel names to their
/// expected SHA-256 hashes, plus a signature field for future verification.
pub fn load_trusted_hashes(manifest_path: &str) -> Result<TrustedManifest> {
    let data = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read manifest: {manifest_path}"))?;

    let manifest: TrustedManifest =
        serde_json::from_str(&data).context("Failed to parse kernel manifest JSON")?;

    if manifest.hashes.is_empty() {
        anyhow::bail!("Kernel manifest contains no hashes");
    }

    // TODO (Phase 3): Verify the manifest signature against a trusted public key.
    // For now we log a warning if no signature is present.
    if manifest.signature.is_empty() {
        tracing::warn!("Kernel manifest has no signature — signature verification not yet implemented");
    }

    tracing::info!(
        "Loaded {} trusted kernel hash(es) from {manifest_path}",
        manifest.hashes.len(),
    );

    Ok(manifest)
}

/// Look up a verifier for a specific kernel name from a manifest.
pub fn verifier_for_kernel(manifest: &TrustedManifest, kernel_name: &str) -> Result<KernelVerifier> {
    let hash_hex = manifest
        .hashes
        .get(kernel_name)
        .with_context(|| format!("No trusted hash for kernel: {kernel_name}"))?;

    KernelVerifier::from_hex(hash_hex)
}

/// Compute the SHA-256 hash of a byte slice.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Encode bytes as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string into bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("Hex string has odd length");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .with_context(|| format!("Invalid hex at position {i}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256() {
        let hash = compute_sha256(b"hello world");
        let hex = hex_encode(&hash);
        assert_eq!(
            hex,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23];
        let encoded = hex_encode(&original);
        assert_eq!(encoded, "deadbeef0123");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_verifier_from_hex() {
        let hash = compute_sha256(b"test kernel data");
        let hex = hex_encode(&hash);
        let verifier = KernelVerifier::from_hex(&hex).unwrap();
        assert_eq!(verifier.expected_hash, hash);
    }

    #[test]
    fn test_correct_hash_passes_verification() {
        let kernel_data = b"this is a fake kernel binary for testing";
        let hash = compute_sha256(kernel_data);
        let verifier = KernelVerifier::new(hash);

        // Write kernel to a temp file and verify
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vmlinux");
        std::fs::write(&path, kernel_data).unwrap();

        let result = verifier.verify_kernel(path.to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), kernel_data);
    }

    #[test]
    fn test_wrong_hash_fails_verification() {
        let kernel_data = b"this is a fake kernel binary for testing";
        let wrong_hash = [0xAA; 32]; // wrong hash
        let verifier = KernelVerifier::new(wrong_hash);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vmlinux");
        std::fs::write(&path, kernel_data).unwrap();

        let result = verifier.verify_kernel(path.to_str().unwrap());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("hash mismatch"));
    }

    #[test]
    fn test_verify_nonexistent_kernel_fails() {
        let verifier = KernelVerifier::new([0; 32]);
        let result = verifier.verify_kernel("/nonexistent/path/vmlinux");
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_loading_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("manifest.json");

        let kernel_data = b"test kernel";
        let hash = compute_sha256(kernel_data);
        let hash_hex = hex_encode(&hash);

        let manifest_json = format!(
            r#"{{"hashes": {{"vmlinux-6.1": "{}"}}, "signature": "test-sig"}}"#,
            hash_hex
        );
        std::fs::write(&manifest_path, manifest_json).unwrap();

        let manifest = load_trusted_hashes(manifest_path.to_str().unwrap()).unwrap();
        assert_eq!(manifest.hashes.len(), 1);
        assert_eq!(manifest.signature, "test-sig");

        // Lookup existing kernel
        let verifier = verifier_for_kernel(&manifest, "vmlinux-6.1").unwrap();
        assert_eq!(verifier.expected_hash, hash);

        // Lookup non-existing kernel
        let result = verifier_for_kernel(&manifest, "vmlinux-99.9");
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_empty_hashes_fails() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("manifest.json");
        std::fs::write(&manifest_path, r#"{"hashes": {}, "signature": ""}"#).unwrap();

        let result = load_trusted_hashes(manifest_path.to_str().unwrap());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("no hashes"));
    }

    #[test]
    fn test_compute_sha256_determinism() {
        let data = b"determinism test data";
        let hash1 = compute_sha256(data);
        let hash2 = compute_sha256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_sha256_different_inputs() {
        let hash1 = compute_sha256(b"input A");
        let hash2 = compute_sha256(b"input B");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_sha256_empty_input() {
        let hash = compute_sha256(b"");
        let hex = hex_encode(&hash);
        // Known SHA-256 of empty string
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_verifier_from_hex_invalid_hex() {
        let result = KernelVerifier::from_hex("not_valid_hex_zz");
        assert!(result.is_err());
    }

    #[test]
    fn test_verifier_from_hex_wrong_length() {
        let result = KernelVerifier::from_hex("aabb");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("32-byte"));
    }

    #[test]
    fn test_hex_decode_odd_length() {
        let result = hex_decode("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_expected_hash_hex() {
        // Build a proper 32-byte array
        let mut h = [0u8; 32];
        h[0] = 0xDE;
        h[1] = 0xAD;
        let verifier = KernelVerifier::new(h);
        let hex = verifier.expected_hash_hex();
        assert!(hex.starts_with("dead"));
        assert_eq!(hex.len(), 64);
    }
}
