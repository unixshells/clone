//! Wire protocol for Clone control plane.
//!
//! Framing: 4-byte little-endian length prefix + JSON body.
//! All messages are either a Request or Response enum, serialized as JSON.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    CreateVm {
        kernel: String,
        initrd: Option<String>,
        cmdline: String,
        mem_mb: u32,
        vcpus: u32,
        #[serde(default)]
        rootfs: Option<String>,
        #[serde(default)]
        overlay: Option<String>,
        #[serde(default)]
        shared_dir: Option<String>,
        #[serde(default)]
        block: Option<String>,
        #[serde(default)]
        net: bool,
        #[serde(default)]
        tap: Option<String>,
        #[serde(default)]
        seccomp: bool,
        #[serde(default)]
        jail: Option<String>,
    },
    DestroyVm {
        vm_id: String,
    },
    VmStatus {
        vm_id: String,
    },
    ListVms,
    Snapshot {
        vm_id: String,
        output_path: String,
    },
    ForkVm {
        template_path: String,
        #[serde(default)]
        net: bool,
        #[serde(default)]
        shared_dir: Option<String>,
    },
    Metrics {
        vm_id: String,
    },
    /// Incremental snapshot (only dirty pages since last snapshot).
    IncrementalSnapshot {
        output_path: String,
        base_template: String,
    },
    /// Pause all vCPUs (used by control socket).
    Pause,
    /// Resume all vCPUs (used by control socket).
    Resume,
    /// Shutdown the VM.
    Shutdown,
    /// Live migrate the VM to a remote host.
    LiveMigrate {
        dest_host: String,
        dest_port: u16,
    },
    /// Execute a command inside the VM via the guest agent.
    Exec {
        command: String,
        args: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok {
        #[serde(flatten)]
        body: ResponseBody,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseBody {
    VmCreated {
        vm_id: String,
        pid: u32,
    },
    ExecResult {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    VmStatus {
        state: String,
        uptime_secs: f64,
        memory_usage_bytes: u64,
    },
    VmList {
        vms: Vec<VmSummary>,
    },
    Metrics {
        metrics: serde_json::Value,
    },
    SnapshotComplete {
        path: String,
    },
    Status {
        state: String,
        pid: u32,
        vcpus: u32,
    },
    MigrationComplete {
        total_pages_sent: u64,
        rounds: u32,
        downtime_ms: u64,
        total_time_ms: u64,
    },
    Ack {},
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSummary {
    pub vm_id: String,
    pub state: String,
    pub uptime_secs: f64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame too large: {0} bytes (max {MAX_FRAME_SIZE})")]
    FrameTooLarge(u32),
    #[error("connection closed")]
    ConnectionClosed,
}

/// Maximum size of a single JSON frame (1 MB).
pub const MAX_FRAME_SIZE: u32 = 1 << 20;

// ---------------------------------------------------------------------------
// Framing helpers — length-prefixed JSON
// ---------------------------------------------------------------------------

/// Write a length-prefixed JSON message to an async writer.
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), ProtocolError>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let json = serde_json::to_vec(msg)?;
    let len = json.len() as u32;
    if len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed JSON message from an async reader.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, ProtocolError>
where
    R: AsyncReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::ConnectionClosed);
        }
        Err(e) => return Err(ProtocolError::Io(e)),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    let msg = serde_json::from_slice(&buf)?;
    Ok(msg)
}

// ---------------------------------------------------------------------------
// Synchronous framing helpers (for the per-VM control socket)
// ---------------------------------------------------------------------------

/// Write a length-prefixed JSON message to a synchronous writer.
pub fn write_frame_sync<W, T>(writer: &mut W, msg: &T) -> Result<(), ProtocolError>
where
    W: std::io::Write,
    T: Serialize,
{
    let json = serde_json::to_vec(msg)?;
    let len = json.len() as u32;
    if len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&json)?;
    writer.flush()?;
    Ok(())
}

/// Read a length-prefixed JSON message from a synchronous reader.
pub fn read_frame_sync<R, T>(reader: &mut R) -> Result<T, ProtocolError>
where
    R: std::io::Read,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::ConnectionClosed);
        }
        Err(e) => return Err(ProtocolError::Io(e)),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    let msg = serde_json::from_slice(&buf)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Request serialization/deserialization ---

    #[test]
    fn test_create_vm_roundtrip() {
        let req = Request::CreateVm {
            kernel: "/boot/vmlinux".to_string(),
            initrd: Some("/boot/initrd".to_string()),
            cmdline: "console=ttyS0".to_string(),
            mem_mb: 512,
            vcpus: 2,
            rootfs: None,
            overlay: None,
            shared_dir: None,
            block: None,
            net: false,
            tap: None,
            seccomp: false,
            jail: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        match deserialized {
            Request::CreateVm {
                kernel,
                initrd,
                cmdline,
                mem_mb,
                vcpus,
                ..
            } => {
                assert_eq!(kernel, "/boot/vmlinux");
                assert_eq!(initrd, Some("/boot/initrd".to_string()));
                assert_eq!(cmdline, "console=ttyS0");
                assert_eq!(mem_mb, 512);
                assert_eq!(vcpus, 2);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_create_vm_no_initrd() {
        let req = Request::CreateVm {
            kernel: "/boot/vmlinux".to_string(),
            initrd: None,
            cmdline: "".to_string(),
            mem_mb: 256,
            vcpus: 1,
            rootfs: None,
            overlay: None,
            shared_dir: None,
            block: None,
            net: false,
            tap: None,
            seccomp: false,
            jail: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        match deserialized {
            Request::CreateVm { initrd, .. } => assert_eq!(initrd, None),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_destroy_vm_roundtrip() {
        let req = Request::DestroyVm {
            vm_id: "vm-0001".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        match deserialized {
            Request::DestroyVm { vm_id } => assert_eq!(vm_id, "vm-0001"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_vm_status_roundtrip() {
        let req = Request::VmStatus {
            vm_id: "vm-0042".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        match deserialized {
            Request::VmStatus { vm_id } => assert_eq!(vm_id, "vm-0042"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_list_vms_roundtrip() {
        let req = Request::ListVms;
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        match deserialized {
            Request::ListVms => {}
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_snapshot_roundtrip() {
        let req = Request::Snapshot {
            vm_id: "vm-0001".to_string(),
            output_path: "/tmp/snap".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        match deserialized {
            Request::Snapshot {
                vm_id,
                output_path,
            } => {
                assert_eq!(vm_id, "vm-0001");
                assert_eq!(output_path, "/tmp/snap");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_fork_vm_roundtrip() {
        let req = Request::ForkVm {
            template_path: "/templates/node20".to_string(),
            net: true,
            shared_dir: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        match deserialized {
            Request::ForkVm { template_path, net, .. } => {
                assert_eq!(template_path, "/templates/node20");
                assert!(net);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_metrics_request_roundtrip() {
        let req = Request::Metrics {
            vm_id: "vm-0007".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        match deserialized {
            Request::Metrics { vm_id } => assert_eq!(vm_id, "vm-0007"),
            _ => panic!("Wrong variant"),
        }
    }

    // --- Response serialization/deserialization ---

    #[test]
    fn test_response_ok_ack() {
        let resp = Response::Ok {
            body: ResponseBody::Ack {},
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        match deserialized {
            Response::Ok { body: ResponseBody::Ack {} } => {}
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_response_error() {
        let resp = Response::Error {
            message: "VM not found".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        match deserialized {
            Response::Error { message } => assert_eq!(message, "VM not found"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_response_vm_created() {
        let resp = Response::Ok {
            body: ResponseBody::VmCreated {
                vm_id: "vm-0099".to_string(),
                pid: 12345,
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: Response = serde_json::from_str(&json).unwrap();
        match deserialized {
            Response::Ok {
                body: ResponseBody::VmCreated { vm_id, pid },
            } => {
                assert_eq!(vm_id, "vm-0099");
                assert_eq!(pid, 12345);
            }
            _ => panic!("Wrong variant"),
        }
    }

    // --- Frame encoding ---

    #[tokio::test]
    async fn test_frame_encoding_4byte_le_length_plus_json() {
        let req = Request::ListVms;
        let mut buf = Vec::new();

        write_frame(&mut buf, &req).await.unwrap();

        // First 4 bytes should be LE length of JSON body
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(len as usize, buf.len() - 4);

        // Remaining bytes should be valid JSON
        let json_body = &buf[4..];
        let deserialized: Request = serde_json::from_slice(json_body).unwrap();
        match deserialized {
            Request::ListVms => {}
            _ => panic!("Wrong variant after frame decode"),
        }
    }

    #[tokio::test]
    async fn test_write_read_frame_roundtrip() {
        let req = Request::CreateVm {
            kernel: "/kernel".to_string(),
            initrd: None,
            cmdline: "quiet".to_string(),
            mem_mb: 128,
            vcpus: 1,
            rootfs: None,
            overlay: None,
            shared_dir: None,
            block: None,
            net: false,
            tap: None,
            seccomp: false,
            jail: None,
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &req).await.unwrap();

        let mut cursor = &buf[..];
        let deserialized: Request = read_frame(&mut cursor).await.unwrap();

        match deserialized {
            Request::CreateVm {
                kernel,
                mem_mb,
                vcpus,
                ..
            } => {
                assert_eq!(kernel, "/kernel");
                assert_eq!(mem_mb, 128);
                assert_eq!(vcpus, 1);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[tokio::test]
    async fn test_read_frame_empty_stream_returns_connection_closed() {
        let empty: &[u8] = &[];
        let result: Result<Request, _> = read_frame(&mut &*empty).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ProtocolError::ConnectionClosed => {}
            other => panic!("Expected ConnectionClosed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_frame_too_large_on_write() {
        // We can't easily construct a message > 1MB, but we can test the
        // frame-too-large path on read by crafting a raw frame
        let fake_len: u32 = MAX_FRAME_SIZE + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&fake_len.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]); // some payload

        let result: Result<Request, _> = read_frame(&mut &buf[..]).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ProtocolError::FrameTooLarge(size) => {
                assert_eq!(size, MAX_FRAME_SIZE + 1);
            }
            other => panic!("Expected FrameTooLarge, got {:?}", other),
        }
    }

    // --- Request JSON uses snake_case tag ---

    #[test]
    fn test_request_json_tag_format() {
        let req = Request::ListVms;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"cmd\":\"list_vms\""));
    }

    #[test]
    fn test_request_create_vm_tag() {
        let req = Request::CreateVm {
            kernel: "k".to_string(),
            initrd: None,
            cmdline: "c".to_string(),
            mem_mb: 1,
            vcpus: 1,
            rootfs: None,
            overlay: None,
            shared_dir: None,
            block: None,
            net: false,
            tap: None,
            seccomp: false,
            jail: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"cmd\":\"create_vm\""));
    }

    #[test]
    fn test_response_json_tag_format() {
        let resp = Response::Ok {
            body: ResponseBody::Ack {},
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_response_error_json_tag_format() {
        let resp = Response::Error {
            message: "err".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"error\""));
    }
}
