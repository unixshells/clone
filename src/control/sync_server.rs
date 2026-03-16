//! Synchronous per-VM control socket.
//!
//! Each running VM gets a Unix domain socket at `/tmp/clone-{pid}.sock`.
//! A single blocking listener thread accepts one connection at a time,
//! dispatches commands (snapshot, pause, resume, status, shutdown), and
//! responds with length-prefixed JSON — the same framing as the async
//! control protocol.

use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use kvm_ioctls::VmFd;

use super::protocol::{self, Request, Response, ResponseBody};
use crate::boot::template::{DeviceStates, VcpuState};
use crate::vmm::vcpu::VcpuPauseState;

/// Shared handle giving the control socket access to VM internals.
pub struct VmHandle {
    /// Pointer to guest memory (for save_template).
    pub guest_memory: *mut u8,
    /// Size of guest memory in bytes.
    pub mem_size: u64,
    /// Actual KVM memory slot size in bytes (may include guard region).
    /// Must be used for get_dirty_log to match the registered slot size.
    pub kvm_slot_size: u64,
    /// Shared vCPU pause coordination state.
    pub pause_state: Arc<VcpuPauseState>,
    /// pthread_t handles for each vCPU thread (used for SIGUSR1 kick).
    pub vcpu_threads: Vec<libc::pthread_t>,
    /// Number of vCPUs.
    pub num_vcpus: u32,
    /// Global shutdown flag (shared with the VM run loop).
    pub shutdown_flag: Arc<AtomicBool>,
    /// MMIO bus holding all virtio transports (for device state snapshots).
    pub mmio_bus: Arc<std::sync::Mutex<crate::virtio::mmio::MmioBus>>,
    /// KVM VM fd for dirty page tracking.
    pub vm_fd: Option<Arc<VmFd>>,
    /// Guest agent state (for exec commands via vsock).
    pub agent_state: Option<Arc<crate::vmm::agent_listener::AgentState>>,
}

// SAFETY: VmHandle contains a raw pointer to guest memory, which is
// valid for the lifetime of the VM. The control socket thread only
// reads from it during snapshots while vCPUs are paused.
unsafe impl Send for VmHandle {}
unsafe impl Sync for VmHandle {}

/// Socket path for a VM identified by PID.
pub fn socket_path(pid: u32) -> String {
    format!("/tmp/clone-{pid}.sock")
}

/// Start the control socket listener in a background thread.
///
/// Returns the socket path. The thread runs until the VM shuts down
/// (detected via `vm_handle.shutdown_flag`).
pub fn start_control_socket(vm_handle: Arc<VmHandle>) -> Result<String> {
    let pid = std::process::id();
    let path = socket_path(pid);

    // Remove stale socket
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)
        .with_context(|| format!("Failed to bind control socket: {path}"))?;

    // Set a timeout so the accept loop can check for shutdown
    listener.set_nonblocking(false)?;

    let path_clone = path.clone();
    let shutdown = Arc::clone(&vm_handle.shutdown_flag);

    std::thread::Builder::new()
        .name("control-socket".into())
        .spawn(move || {
            // Set accept timeout to 1s so we periodically check shutdown
            let _ = listener.set_nonblocking(false);

            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Use a short timeout via SO_RCVTIMEO for the accept
                unsafe {
                    let tv = libc::timeval {
                        tv_sec: 1,
                        tv_usec: 0,
                    };
                    libc::setsockopt(
                        std::os::unix::io::AsRawFd::as_raw_fd(&listener),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        &tv as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                    );
                }

                match listener.accept() {
                    Ok((stream, _addr)) => {
                        if let Err(e) = handle_connection(stream, &vm_handle) {
                            tracing::error!("Control socket connection error: {e}");
                        }
                    }
                    Err(e) => {
                        // Timeout or interrupted — just loop and check shutdown
                        if e.kind() != std::io::ErrorKind::WouldBlock
                            && e.kind() != std::io::ErrorKind::TimedOut
                        {
                            // On Linux, SO_RCVTIMEO on accept returns EAGAIN
                            if e.raw_os_error() != Some(libc::EAGAIN) {
                                tracing::error!("Control socket accept error: {e}");
                            }
                        }
                    }
                }
            }

            // Clean up socket file
            let _ = std::fs::remove_file(&path_clone);
            tracing::info!("Control socket shut down");
        })
        .context("Failed to spawn control socket thread")?;

    Ok(path)
}

fn handle_connection(
    stream: std::os::unix::net::UnixStream,
    vm_handle: &VmHandle,
) -> Result<()> {
    use std::io::{BufReader, BufWriter};

    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    loop {
        let request: Request = match protocol::read_frame_sync(&mut reader) {
            Ok(r) => r,
            Err(protocol::ProtocolError::ConnectionClosed) => return Ok(()),
            Err(e) => {
                let resp = Response::Error {
                    message: format!("Protocol error: {e}"),
                };
                let _ = protocol::write_frame_sync(&mut writer, &resp);
                return Err(e.into());
            }
        };

        let response = dispatch(request, vm_handle);
        protocol::write_frame_sync(&mut writer, &response)?;
    }
}

fn dispatch(req: Request, vm: &VmHandle) -> Response {
    match req {
        Request::Snapshot { output_path, .. } => handle_snapshot(vm, &output_path),
        Request::IncrementalSnapshot { output_path, base_template } => {
            handle_incremental_snapshot(vm, &output_path, &base_template)
        }
        Request::Pause => handle_pause(vm),
        Request::Resume => handle_resume(vm),
        Request::Shutdown => handle_shutdown(vm),
        Request::LiveMigrate { dest_host, dest_port } => handle_live_migrate(vm, &dest_host, dest_port),
        Request::VmStatus { .. } => Response::Ok {
            body: ResponseBody::Status {
                state: if vm.pause_state.pause_requested.load(Ordering::SeqCst) {
                    "paused".to_string()
                } else {
                    "running".to_string()
                },
                pid: std::process::id(),
                vcpus: vm.num_vcpus,
            },
        },
        Request::Exec { command, args } => {
            match &vm.agent_state {
                Some(agent_state) => {
                    match agent_state.send_exec(&command, &args) {
                        Ok((exit_code, stdout, stderr)) => Response::Ok {
                            body: ResponseBody::ExecResult { exit_code, stdout, stderr },
                        },
                        Err(msg) => Response::Error { message: msg },
                    }
                }
                None => Response::Error {
                    message: "Guest agent not available".to_string(),
                },
            }
        }
        _ => Response::Error {
            message: "Unsupported command on per-VM control socket".to_string(),
        },
    }
}

/// Public wrapper for pause_vcpus (used by migration sender).
pub fn pause_vcpus_pub(vm: &VmHandle) -> Result<(), String> {
    pause_vcpus(vm)
}

/// Public wrapper for resume_vcpus (used by migration sender).
pub fn resume_vcpus_pub(vm: &VmHandle) {
    resume_vcpus(vm);
}

/// Pause all vCPUs by setting the pause flag and sending SIGUSR1.
fn pause_vcpus(vm: &VmHandle) -> Result<(), String> {
    let ps = &vm.pause_state;

    // Reset state
    ps.paused_count.store(0, Ordering::SeqCst);
    {
        let mut states = ps.captured_states.lock().unwrap();
        for s in states.iter_mut() {
            *s = None;
        }
    }
    {
        let mut locked = ps.all_paused_lock.lock().unwrap();
        *locked = false;
    }

    // Request pause
    ps.pause_requested.store(true, Ordering::SeqCst);

    // Kick each vCPU out of KVM_RUN
    for &tid in &vm.vcpu_threads {
        unsafe {
            libc::pthread_kill(tid, libc::SIGUSR1);
        }
    }

    // Wait for all vCPUs to park
    let mut locked = ps.all_paused_lock.lock().unwrap();
    let timeout = std::time::Duration::from_secs(5);
    let start = std::time::Instant::now();
    while !*locked {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            // Abort — resume vCPUs and report failure
            ps.pause_requested.store(false, Ordering::SeqCst);
            ps.resume.notify_all();
            return Err(format!(
                "Timeout waiting for vCPUs to pause (got {}/{})",
                ps.paused_count.load(Ordering::SeqCst),
                ps.total_vcpus,
            ));
        }
        let remaining = timeout - elapsed;
        let result = ps.all_paused.wait_timeout(locked, remaining).unwrap();
        locked = result.0;
    }

    Ok(())
}

/// Resume all paused vCPUs.
fn resume_vcpus(vm: &VmHandle) {
    let ps = &vm.pause_state;
    ps.pause_requested.store(false, Ordering::SeqCst);
    ps.paused_count.store(0, Ordering::SeqCst);
    {
        let mut locked = ps.resume_lock.lock().unwrap();
        *locked = true;
    }
    ps.resume.notify_all();
}

fn handle_pause(vm: &VmHandle) -> Response {
    match pause_vcpus(vm) {
        Ok(()) => Response::Ok {
            body: ResponseBody::Ack {},
        },
        Err(msg) => Response::Error { message: msg },
    }
}

fn handle_resume(vm: &VmHandle) -> Response {
    resume_vcpus(vm);
    Response::Ok {
        body: ResponseBody::Ack {},
    }
}

fn handle_shutdown(vm: &VmHandle) -> Response {
    // Set the global shutdown flag — vCPU run loops will exit
    crate::vmm::vcpu::SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    vm.shutdown_flag.store(true, Ordering::SeqCst);

    // Kick vCPUs out of KVM_RUN so they notice the shutdown
    for &tid in &vm.vcpu_threads {
        unsafe {
            libc::pthread_kill(tid, libc::SIGUSR1);
        }
    }

    // If vCPUs are paused, resume them so they can exit
    if vm.pause_state.pause_requested.load(Ordering::SeqCst) {
        resume_vcpus(vm);
    }

    Response::Ok {
        body: ResponseBody::Ack {},
    }
}

fn handle_incremental_snapshot(vm: &VmHandle, output_path: &str, base_template: &str) -> Response {
    let vm_fd = match &vm.vm_fd {
        Some(fd) => fd,
        None => {
            return Response::Error {
                message: "VM fd not available for dirty page tracking".to_string(),
            };
        }
    };

    // 0. Clear stale dirty bitmap (from boot or previous snapshot) BEFORE pausing.
    //    get_dirty_log atomically returns and clears the bitmap.
    //    We discard this result — we only want pages dirtied AFTER this point.
    {
        let tracker = crate::memory::overcommit::DirtyPageTracker::new(vm.kvm_slot_size);
        match tracker.get_dirty_bitmap(vm_fd) {
            Ok(_) => tracing::info!("Cleared stale dirty bitmap"),
            Err(e) => tracing::warn!("Failed to clear dirty bitmap: {e}"),
        }
    }

    // Give the VM a tiny window to dirty only the pages it's actively using
    std::thread::sleep(std::time::Duration::from_millis(100));

    // 1. Pause all vCPUs
    if let Err(msg) = pause_vcpus(vm) {
        return Response::Error { message: msg };
    }

    // 2. Collect captured register states
    let vcpu_states: Vec<VcpuState> = {
        let states = vm.pause_state.captured_states.lock().unwrap();
        states
            .iter()
            .enumerate()
            .map(|(i, s)| {
                s.clone().unwrap_or_else(|| {
                    tracing::error!("vCPU {i} state not captured");
                    VcpuState {
                        regs: Vec::new(),
                        sregs: Vec::new(),
                    }
                })
            })
            .collect()
    };

    // 3. Capture device states from MMIO bus
    let device_states = {
        let bus = vm.mmio_bus.lock().unwrap();
        let transport_states = bus.snapshot_all();
        let transports: Vec<Vec<u8>> = transport_states.iter()
            .map(|s| serde_json::to_vec(s).unwrap_or_default())
            .collect();
        DeviceStates {
            serial: None,
            virtio_configs: std::collections::HashMap::new(),
            transports,
        }
    };

    // 4. Save incremental snapshot (only dirty pages)
    let result = {
        let guest_mem = unsafe {
            crate::memory::GuestMem::borrow_raw(vm.guest_memory, vm.mem_size)
        };
        crate::boot::template::save_incremental(
            &guest_mem,
            vm_fd,
            vcpu_states,
            device_states,
            base_template,
            output_path,
            vm.kvm_slot_size,
        )
    };

    // 5. Resume vCPUs
    resume_vcpus(vm);

    // 6. Return result
    match result {
        Ok(_snapshot) => Response::Ok {
            body: ResponseBody::SnapshotComplete {
                path: output_path.to_string(),
            },
        },
        Err(e) => Response::Error {
            message: format!("Incremental snapshot failed: {e}"),
        },
    }
}

fn handle_snapshot(vm: &VmHandle, output_path: &str) -> Response {
    // 1. Pause all vCPUs
    if let Err(msg) = pause_vcpus(vm) {
        return Response::Error { message: msg };
    }

    // 2. Collect captured register states
    let vcpu_states: Vec<VcpuState> = {
        let states = vm.pause_state.captured_states.lock().unwrap();
        states
            .iter()
            .enumerate()
            .map(|(i, s)| {
                s.clone().unwrap_or_else(|| {
                    tracing::error!("vCPU {i} state not captured");
                    VcpuState {
                        regs: Vec::new(),
                        sregs: Vec::new(),
                    }
                })
            })
            .collect()
    };

    // 2.5. Capture device states from MMIO bus
    let device_states = {
        let bus = vm.mmio_bus.lock().unwrap();
        let transport_states = bus.snapshot_all();
        let transports: Vec<Vec<u8>> = transport_states.iter()
            .map(|s| serde_json::to_vec(s).unwrap_or_default())
            .collect();
        DeviceStates {
            serial: None,
            virtio_configs: std::collections::HashMap::new(),
            transports,
        }
    };

    // 3. Save template
    let result = {
        let guest_mem = unsafe {
            crate::memory::GuestMem::borrow_raw(vm.guest_memory, vm.mem_size)
        };
        crate::boot::template::save_template(
            &guest_mem,
            vcpu_states,
            device_states,
            "snapshot",
            output_path,
        )
    };

    // 4. Resume vCPUs
    resume_vcpus(vm);

    // 5. Return result
    match result {
        Ok(_snapshot) => Response::Ok {
            body: ResponseBody::SnapshotComplete {
                path: output_path.to_string(),
            },
        },
        Err(e) => Response::Error {
            message: format!("Snapshot failed: {e}"),
        },
    }
}

fn handle_live_migrate(vm: &VmHandle, dest_host: &str, dest_port: u16) -> Response {
    let config = crate::migration::MigrationSenderConfig {
        dest_host: dest_host.to_string(),
        dest_port,
        ..Default::default()
    };

    match crate::migration::run_sender(vm, config) {
        Ok(stats) => Response::Ok {
            body: ResponseBody::MigrationComplete {
                total_pages_sent: stats.total_pages_sent,
                rounds: stats.rounds,
                downtime_ms: stats.downtime_ms,
                total_time_ms: stats.total_time_ms,
            },
        },
        Err(e) => Response::Error {
            message: format!("Live migration failed: {e}"),
        },
    }
}
