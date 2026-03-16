//! Daemon mode — multi-VM orchestration.
//!
//! The daemon process listens on a control socket and manages VM lifecycle:
//! - CreateVm spawns `clone run` as a child process
//! - DestroyVm sends Shutdown to the per-VM control socket
//! - Monitors child processes for unexpected exits

use std::sync::Arc;
use anyhow::Result;

/// Spawn a new VM as a child process.
///
/// Runs `clone run` with the given parameters and returns the child PID.
pub fn spawn_vm(
    kernel: &str,
    initrd: Option<&str>,
    cmdline: &str,
    mem_mb: u32,
    vcpus: u32,
    rootfs: Option<&str>,
    overlay: Option<&str>,
    shared_dir: Option<&str>,
    block: Option<&str>,
    net: bool,
    tap: Option<&str>,
    seccomp: bool,
    jail: Option<&str>,
    cid: Option<u64>,
) -> Result<u32> {
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("clone"));

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("run")
        .arg("--kernel").arg(kernel)
        .arg("--cmdline").arg(cmdline)
        .arg("--mem-mb").arg(mem_mb.to_string())
        .arg("--vcpus").arg(vcpus.to_string());

    if let Some(i) = initrd {
        cmd.arg("--initrd").arg(i);
    }
    if let Some(r) = rootfs {
        cmd.arg("--rootfs").arg(r);
    }
    if let Some(o) = overlay {
        cmd.arg("--overlay").arg(o);
    }
    if let Some(sd) = shared_dir {
        cmd.arg("--shared-dir").arg(sd);
    }
    if let Some(b) = block {
        cmd.arg("--block").arg(b);
    }
    if net {
        cmd.arg("--net");
    }
    if let Some(t) = tap {
        cmd.arg("--tap").arg(t);
    }
    if seccomp {
        cmd.arg("--seccomp");
    }
    if let Some(j) = jail {
        cmd.arg("--jail").arg(j);
    }
    if let Some(c) = cid {
        cmd.arg("--cid").arg(c.to_string());
    }

    // Detach stdin so the child doesn't compete for terminal input
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let child = cmd.spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn VM process: {e}"))?;

    let pid = child.id();
    tracing::info!(pid, "Spawned VM child process");

    // Detach — we don't want to wait on it here.
    // The monitor thread will handle waitpid.
    std::mem::forget(child);

    Ok(pid)
}

/// Spawn a forked VM from a template snapshot.
///
/// Runs `clone fork --template <path>` as a child process with optional
/// networking and CID assignment.
pub fn spawn_fork(
    template_path: &str,
    net: bool,
    shared_dir: Option<&str>,
    cid: Option<u64>,
) -> Result<u32> {
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("clone"));

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("fork")
        .arg("--template").arg(template_path);

    if net {
        cmd.arg("--net");
    }
    if let Some(sd) = shared_dir {
        cmd.arg("--shared-dir").arg(sd);
    }
    if let Some(c) = cid {
        cmd.arg("--cid").arg(c.to_string());
    }

    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let child = cmd.spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn fork process: {e}"))?;

    let pid = child.id();
    tracing::info!(pid, template = template_path, "Spawned forked VM");

    std::mem::forget(child);
    Ok(pid)
}

/// Forward a snapshot request to a VM's per-VM control socket.
pub fn snapshot_vm(control_socket: &str, output_path: &str) -> Result<crate::control::protocol::Response> {
    use std::io::{BufReader, BufWriter};

    let stream = std::os::unix::net::UnixStream::connect(control_socket)
        .map_err(|e| anyhow::anyhow!("Failed to connect to VM socket {control_socket}: {e}"))?;

    stream.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let mut writer = BufWriter::new(&stream);
    let mut reader = BufReader::new(&stream);

    let request = crate::control::protocol::Request::Snapshot {
        vm_id: String::new(), // per-VM socket ignores vm_id
        output_path: output_path.to_string(),
    };
    crate::control::protocol::write_frame_sync(&mut writer, &request)?;
    let response: crate::control::protocol::Response =
        crate::control::protocol::read_frame_sync(&mut reader)?;

    Ok(response)
}

/// Send a shutdown command to a VM's per-VM control socket.
pub fn shutdown_vm(control_socket: &str) -> Result<()> {
    use std::io::{BufReader, BufWriter};

    let stream = std::os::unix::net::UnixStream::connect(control_socket)
        .map_err(|e| anyhow::anyhow!("Failed to connect to VM socket {control_socket}: {e}"))?;

    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let mut writer = BufWriter::new(&stream);
    let mut reader = BufReader::new(&stream);

    let request = crate::control::protocol::Request::Shutdown;
    crate::control::protocol::write_frame_sync(&mut writer, &request)?;
    let _response: crate::control::protocol::Response =
        crate::control::protocol::read_frame_sync(&mut reader)?;

    Ok(())
}

/// Query status from a VM's per-VM control socket.
pub fn query_vm_status(control_socket: &str) -> Result<crate::control::protocol::Response> {
    use std::io::{BufReader, BufWriter};

    let stream = std::os::unix::net::UnixStream::connect(control_socket)
        .map_err(|e| anyhow::anyhow!("Failed to connect to VM socket {control_socket}: {e}"))?;

    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let mut writer = BufWriter::new(&stream);
    let mut reader = BufReader::new(&stream);

    let request = crate::control::protocol::Request::VmStatus {
        vm_id: String::new(),
    };
    crate::control::protocol::write_frame_sync(&mut writer, &request)?;
    let response: crate::control::protocol::Response =
        crate::control::protocol::read_frame_sync(&mut reader)?;

    Ok(response)
}


/// Run the daemon.
///
/// Starts the control server and child process monitor.
pub async fn run_daemon(socket_path: &str) -> Result<()> {
    eprintln!("Clone daemon listening on {socket_path}");
    tracing::info!(socket = socket_path, "Daemon starting");

    let server = crate::control::ControlServer::new(socket_path);

    // Start the child process monitor using the server's shared state.
    // The monitor checks if tracked VM processes are still alive and
    // marks dead ones as Stopped.
    start_server_monitor(server.state());

    server.run().await
}

/// Monitor child processes using the ControlServer's state.
///
/// Periodically checks if tracked VM child processes are still alive
/// and updates their state to Stopped if they've exited.
fn start_server_monitor(state: Arc<tokio::sync::Mutex<crate::control::ServerState>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let mut s = state.lock().await;
            let mut dead = Vec::new();

            for (vm_id, record) in &s.vms {
                if record.pid == 0 {
                    continue; // fork stub, no real process
                }
                let alive = unsafe { libc::kill(record.pid as i32, 0) } == 0;
                if !alive {
                    tracing::warn!(
                        vm_id = %vm_id,
                        pid = record.pid,
                        "VM child process exited"
                    );
                    dead.push(vm_id.clone());
                }
            }

            for vm_id in dead {
                if let Some(record) = s.vms.get_mut(&vm_id) {
                    record.state = crate::control::VmState::Stopped;
                }
            }
        }
    });
}
