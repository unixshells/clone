//! VMM-side vsock listener for guest agent communication.
//!
//! Listens on AF_VSOCK for connections from the guest agent, receives
//! heartbeat messages, and feeds activity state into the balloon controller.
//!
//! Uses an mpsc channel to decouple socket reads from message consumers.
//! The listener thread reads all messages from the socket and sends them
//! into the channel. Heartbeat processing and exec both read from the
//! channel receiver, eliminating the 2.5s sleep + drain race.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use serde::{Deserialize, Serialize};

/// Base vsock port the VMM listens on.
/// When multiple VMs run on the same host, each uses a unique port
/// derived from its CID: port = AGENT_VSOCK_PORT_BASE + (cid - 3).
/// The guest agent connects to the same port via kernel cmdline param.
pub const AGENT_VSOCK_PORT_BASE: u32 = 9999;

/// AF_VSOCK address family.
const AF_VSOCK: libc::c_int = 40;

/// VMADDR_CID_ANY — accept from any guest.
const VMADDR_CID_ANY: u32 = u32::MAX;

/// Messages from guest agent to VMM.
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum AgentMessage {
    Heartbeat {
        active: bool,
        load_avg_1m: f64,
        mem_pressure_pct: f64,
        process_count: u32,
        uptime_secs: u64,
    },
    Ready,
    ExecResult {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
}

/// Messages from VMM to guest agent.
#[derive(Serialize)]
#[serde(tag = "type")]
pub enum VmmMessage {
    Poll,
    Shutdown,
    Exec {
        command: String,
        args: Vec<String>,
    },
}

/// Shared state between the listener thread and the balloon tick thread.
pub struct AgentState {
    /// Whether the guest is currently active (from last heartbeat).
    pub active: AtomicBool,
    /// Whether the agent has connected at least once.
    pub connected: AtomicBool,
    /// The vsock client fd (for sending commands).
    pub client_fd: Mutex<Option<i32>>,
    /// Set to true to pause the listener's heartbeat processing (for exec).
    pub exec_in_progress: AtomicBool,
    /// Channel receiver for messages from the listener thread.
    msg_rx: Mutex<Option<mpsc::Receiver<AgentMessage>>>,
}

impl AgentState {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
            connected: AtomicBool::new(false),
            client_fd: Mutex::new(None),
            exec_in_progress: AtomicBool::new(false),
            msg_rx: Mutex::new(None),
        }
    }

    /// Send a shutdown command to the guest agent.
    pub fn send_shutdown(&self) {
        if let Some(fd) = *self.client_fd.lock().unwrap() {
            let _ = send_vmm_message(fd, &VmmMessage::Shutdown);
        }
    }

    /// Send an Exec command to the guest agent and wait for the result.
    ///
    /// Returns (exit_code, stdout, stderr) on success.
    pub fn send_exec(&self, command: &str, args: &[String]) -> Result<(i32, String, String), String> {
        let fd = self.client_fd.lock().unwrap()
            .ok_or_else(|| "Guest agent not connected".to_string())?;

        // Signal the listener to stop processing heartbeats
        self.exec_in_progress.store(true, Ordering::Release);

        // Drain any pending messages already in the channel (heartbeats)
        {
            let rx_guard = self.msg_rx.lock().unwrap();
            if let Some(ref rx) = *rx_guard {
                while rx.try_recv().is_ok() {
                    // discard queued heartbeats
                }
            }
        }

        // Send exec command
        send_vmm_message(fd, &VmmMessage::Exec {
            command: command.to_string(),
            args: args.to_vec(),
        }).map_err(|_| "Failed to send exec command to agent".to_string())?;

        // Read from channel until ExecResult arrives (timeout 30s)
        let rx_guard = self.msg_rx.lock().unwrap();
        let rx = rx_guard.as_ref().ok_or("Channel not available")?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let timeout = deadline.saturating_duration_since(std::time::Instant::now());
            if timeout.is_zero() {
                self.exec_in_progress.store(false, Ordering::Release);
                return Err("Exec timed out after 30s".to_string());
            }

            match rx.recv_timeout(timeout) {
                Ok(AgentMessage::ExecResult { exit_code, stdout, stderr }) => {
                    self.exec_in_progress.store(false, Ordering::Release);
                    return Ok((exit_code, stdout, stderr));
                }
                Ok(AgentMessage::Heartbeat { .. }) => {
                    // Skip heartbeats while waiting for exec result
                    continue;
                }
                Ok(_other) => {
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.exec_in_progress.store(false, Ordering::Release);
                    return Err("Exec timed out waiting for response".to_string());
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.exec_in_progress.store(false, Ordering::Release);
                    return Err("Agent disconnected during exec".to_string());
                }
            }
        }
    }
}

/// Start the vsock listener thread. Returns the shared AgentState.
///
/// `port` is the vsock port to listen on. Each VM should use a unique port
/// (derived from CID) to avoid bind conflicts when multiple VMs run on the same host.
pub fn start_listener(shutdown: Arc<AtomicBool>, port: u32) -> Arc<AgentState> {
    let state = Arc::new(AgentState::new());
    let state_clone = Arc::clone(&state);

    std::thread::Builder::new()
        .name("agent-listener".into())
        .spawn(move || {
            listener_thread(state_clone, shutdown, port);
        })
        .expect("Failed to spawn agent listener thread");

    state
}

fn listener_thread(state: Arc<AgentState>, shutdown: Arc<AtomicBool>, port: u32) {
    // Create vsock listener socket
    let listen_fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if listen_fd < 0 {
        tracing::warn!("agent-listener: socket(AF_VSOCK) failed, agent communication disabled");
        return;
    }

    // Allow address reuse
    let optval: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            listen_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Bind to VMADDR_CID_ANY, port AGENT_VSOCK_PORT
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = port;

    let ret = unsafe {
        libc::bind(
            listen_fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!("agent-listener: bind failed: {err}");
        unsafe { libc::close(listen_fd) };
        return;
    }

    let ret = unsafe { libc::listen(listen_fd, 1) };
    if ret != 0 {
        tracing::warn!("agent-listener: listen failed");
        unsafe { libc::close(listen_fd) };
        return;
    }

    tracing::info!("agent-listener: listening on vsock port {port}");

    // Set accept timeout so we can check shutdown flag
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            listen_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Accept loop — handle one connection at a time (one agent per VM)
    while !shutdown.load(Ordering::Relaxed) {
        let client_fd = unsafe {
            libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut())
        };
        if client_fd < 0 {
            continue; // timeout or error, retry
        }

        tracing::info!("agent-listener: guest agent connected");
        state.connected.store(true, Ordering::Release);
        *state.client_fd.lock().unwrap() = Some(client_fd);

        // Create bounded message channel for this connection.
        // Capacity of 16 is enough for exec (one ExecResult + a few heartbeats).
        // During normal operation, heartbeats that overflow are dropped
        // (the listener already updates state.active directly).
        let (tx, rx) = mpsc::sync_channel::<AgentMessage>(16);
        *state.msg_rx.lock().unwrap() = Some(rx);

        // Set read timeout on client socket
        let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
        unsafe {
            libc::setsockopt(
                client_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        // Read messages from this client until disconnected
        handle_client(&state, client_fd, &shutdown, &tx);

        // Client disconnected
        unsafe { libc::close(client_fd) };
        *state.client_fd.lock().unwrap() = None;
        *state.msg_rx.lock().unwrap() = None;
        state.connected.store(false, Ordering::Release);
        tracing::info!("agent-listener: guest agent disconnected");
    }

    unsafe { libc::close(listen_fd) };
}

fn handle_client(state: &AgentState, fd: i32, shutdown: &AtomicBool, tx: &mpsc::SyncSender<AgentMessage>) {
    while !shutdown.load(Ordering::Relaxed) {
        // Read 4-byte length header
        let mut len_buf = [0u8; 4];
        if !read_exact(fd, &mut len_buf) {
            return; // disconnected or timeout — check shutdown and retry
        }

        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 1_048_576 {
            tracing::warn!("agent-listener: message too large ({len} bytes)");
            return;
        }

        let mut body = vec![0u8; len];
        if !read_exact(fd, &mut body) {
            return;
        }

        match serde_json::from_slice::<AgentMessage>(&body) {
            Ok(msg) => {
                // Update activity state for heartbeats (always, even during exec)
                if let AgentMessage::Heartbeat { active, load_avg_1m, mem_pressure_pct, process_count, uptime_secs } = &msg {
                    state.active.store(*active, Ordering::Release);
                    tracing::debug!(
                        active,
                        load_avg_1m,
                        mem_pressure_pct,
                        process_count,
                        uptime_secs,
                        "agent heartbeat"
                    );
                }
                if let AgentMessage::Ready = &msg {
                    tracing::info!("agent-listener: guest agent ready");
                }
                // Send message into the channel — exec reads from here.
                // Use try_send: if channel is full, drop non-critical messages.
                match tx.try_send(msg) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Disconnected(_)) => return,
                    Err(mpsc::TrySendError::Full(_)) => {
                        // Channel full, drop message (heartbeat during normal operation)
                    }
                }
            }
            Err(e) => {
                tracing::warn!("agent-listener: failed to parse message: {e}");
            }
        }
    }
}

fn read_exact(fd: i32, buf: &mut [u8]) -> bool {
    let mut read = 0;
    while read < buf.len() {
        let n = unsafe {
            libc::recv(
                fd,
                buf[read..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - read,
                0,
            )
        };
        if n <= 0 {
            if n == 0 {
                return false; // EOF
            }
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                return false; // timeout
            }
            return false;
        }
        read += n as usize;
    }
    true
}

fn send_vmm_message(fd: i32, msg: &VmmMessage) -> Result<(), ()> {
    let json = serde_json::to_vec(msg).map_err(|_| ())?;
    let len = (json.len() as u32).to_le_bytes();

    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&json);

    let written = unsafe {
        libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
    };

    if written as usize == buf.len() {
        Ok(())
    } else {
        Err(())
    }
}
