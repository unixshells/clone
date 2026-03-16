//! Clone Guest Agent
//!
//! Runs inside the guest VM as a lightweight daemon (<1MB).
//! Communicates with the VMM over virtio-vsock.
//!
//! Responsibilities:
//! - Report activity state (active/idle) based on process activity
//! - Report memory pressure via PSI (Pressure Stall Information)
//! - Read VM identity page on boot (entropy, hostname, vsock CID)
//! - Respond to VMM commands (shutdown, balloon hints)

use serde::{Deserialize, Serialize};
use std::fs;
use std::time::Duration;

/// vsock port the agent connects to on the host.
pub const AGENT_VSOCK_PORT: u32 = 9999;

/// Host CID (always 2 per vsock spec).
const VMADDR_CID_HOST: u32 = 2;

/// Messages from guest agent to VMM.
#[derive(Serialize)]
#[serde(tag = "type")]
enum AgentMessage {
    /// Periodic heartbeat with guest metrics.
    Heartbeat {
        active: bool,
        load_avg_1m: f64,
        mem_pressure_pct: f64,
        process_count: u32,
        uptime_secs: u64,
    },
    /// Guest is ready (sent once after boot).
    Ready,
    /// Result of an exec command.
    ExecResult {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
}

/// Messages from VMM to guest agent.
#[derive(Deserialize)]
#[serde(tag = "type")]
enum VmmMessage {
    /// Request immediate metrics report.
    Poll,
    /// Graceful shutdown.
    Shutdown,
    /// Execute a command inside the guest.
    Exec {
        command: String,
        args: Vec<String>,
    },
}

fn main() {
    eprintln!("clone-agent: starting");

    // Configure guest networking from kernel cmdline if present
    configure_guest_network();

    // Read agent port from kernel cmdline (for concurrent VM support)
    let agent_port = {
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
        parse_cmdline_param(&cmdline, "clone.agent_port")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(AGENT_VSOCK_PORT)
    };

    // Try to connect to VMM over vsock, with retries
    let fd = match connect_vsock(VMADDR_CID_HOST, agent_port) {
        Some(fd) => fd,
        None => {
            eprintln!("clone-agent: failed to connect to VMM via vsock, exiting");
            return;
        }
    };

    eprintln!("clone-agent: connected to VMM via vsock");

    // Send ready message
    if send_message(fd, &AgentMessage::Ready).is_err() {
        eprintln!("clone-agent: failed to send Ready message");
        close_fd(fd);
        return;
    }

    let mut last_load = 0.0f64;

    loop {
        // Check for incoming VMM messages (non-blocking)
        if let Some(msg) = recv_message(fd) {
            match msg {
                VmmMessage::Poll => {
                    // Send immediate heartbeat
                    let metrics = collect_metrics();
                    let active = is_active(&metrics, last_load);
                    last_load = metrics.load_avg_1m;
                    let _ = send_message(fd, &AgentMessage::Heartbeat {
                        active,
                        load_avg_1m: metrics.load_avg_1m,
                        mem_pressure_pct: metrics.mem_pressure_pct,
                        process_count: metrics.process_count,
                        uptime_secs: metrics.uptime_secs,
                    });
                    continue;
                }
                VmmMessage::Shutdown => {
                    eprintln!("clone-agent: received shutdown command");
                    request_shutdown();
                    return;
                }
                VmmMessage::Exec { command, args } => {
                    eprintln!("clone-agent: exec: {} {:?}", command, args);
                    let result = std::process::Command::new(&command)
                        .args(&args)
                        .output();
                    let msg = match result {
                        Ok(output) => AgentMessage::ExecResult {
                            exit_code: output.status.code().unwrap_or(-1),
                            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                        },
                        Err(e) => AgentMessage::ExecResult {
                            exit_code: -1,
                            stdout: String::new(),
                            stderr: format!("Failed to execute command: {e}"),
                        },
                    };
                    let _ = send_message(fd, &msg);
                    continue;
                }
            }
        }

        // Collect and send periodic heartbeat
        let metrics = collect_metrics();
        let active = is_active(&metrics, last_load);
        last_load = metrics.load_avg_1m;

        let msg = AgentMessage::Heartbeat {
            active,
            load_avg_1m: metrics.load_avg_1m,
            mem_pressure_pct: metrics.mem_pressure_pct,
            process_count: metrics.process_count,
            uptime_secs: metrics.uptime_secs,
        };

        if send_message(fd, &msg).is_err() {
            eprintln!("clone-agent: lost connection to VMM, reconnecting...");
            close_fd(fd);
            // Try to reconnect
            match connect_vsock(VMADDR_CID_HOST, AGENT_VSOCK_PORT) {
                Some(new_fd) => {
                    // Recursion avoided — just restart main
                    eprintln!("clone-agent: reconnected");
                    // We can't reassign fd since it's immutable, so just exit
                    // and let the init system restart us.
                    close_fd(new_fd);
                }
                None => {}
            }
            return;
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Configure guest networking from kernel command line parameters.
///
/// Looks for clone.net_ip, clone.net_gw, clone.net_mask in /proc/cmdline.
/// If present, configures eth0 with the given IP/mask/gateway and sets up DNS.
fn configure_guest_network() {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let ip = parse_cmdline_param(&cmdline, "clone.net_ip");
    let gw = parse_cmdline_param(&cmdline, "clone.net_gw");
    let mask = parse_cmdline_param(&cmdline, "clone.net_mask");

    let (ip, gw, mask) = match (ip, gw, mask) {
        (Some(ip), Some(gw), Some(mask)) => (ip, gw, mask),
        _ => return, // No network params, skip
    };

    eprintln!("clone-agent: configuring eth0: {ip}/{mask} gw {gw}");

    // ip addr add {ip}/{mask} dev eth0
    let _ = std::process::Command::new("ip")
        .args(["addr", "add", &format!("{ip}/{mask}"), "dev", "eth0"])
        .status();

    // ip link set eth0 up
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "eth0", "up"])
        .status();

    // ip route add default via {gw}
    let _ = std::process::Command::new("ip")
        .args(["route", "add", "default", "via", &gw])
        .status();

    // Write /etc/resolv.conf
    let _ = fs::write("/etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 8.8.4.4\n");

    eprintln!("clone-agent: network configured");
}

fn parse_cmdline_param<'a>(cmdline: &'a str, key: &str) -> Option<String> {
    for part in cmdline.split_whitespace() {
        if let Some(val) = part.strip_prefix(&format!("{key}=")) {
            return Some(val.to_string());
        }
    }
    None
}

struct GuestMetrics {
    load_avg_1m: f64,
    mem_pressure_pct: f64,
    process_count: u32,
    uptime_secs: u64,
}

fn collect_metrics() -> GuestMetrics {
    GuestMetrics {
        load_avg_1m: read_load_avg(),
        mem_pressure_pct: read_psi_memory(),
        process_count: count_processes(),
        uptime_secs: read_uptime(),
    }
}

/// Determine if guest is "active" — any meaningful CPU activity.
fn is_active(metrics: &GuestMetrics, prev_load: f64) -> bool {
    // Active if load average is above threshold or increasing
    metrics.load_avg_1m > 0.05 || metrics.load_avg_1m > prev_load
}

fn read_load_avg() -> f64 {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0)
}

/// Read PSI (Pressure Stall Information) for memory.
/// Returns percentage of time tasks were stalled on memory in last 10s.
fn read_psi_memory() -> f64 {
    fs::read_to_string("/proc/pressure/memory")
        .ok()
        .and_then(|s| {
            // Parse "some avg10=X.XX avg60=X.XX avg300=X.XX total=N"
            for line in s.lines() {
                if line.starts_with("some") {
                    for part in line.split_whitespace() {
                        if let Some(val) = part.strip_prefix("avg10=") {
                            return val.parse().ok();
                        }
                    }
                }
            }
            None
        })
        .unwrap_or(0.0)
}

fn count_processes() -> u32 {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|s| s.chars().all(|c| c.is_ascii_digit()))
                })
                .count() as u32
        })
        .unwrap_or(0)
}

fn read_uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0)
}

/// Request system shutdown. Only works inside a Linux guest.
#[cfg(target_os = "linux")]
fn request_shutdown() {
    // sync + reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, POWER_OFF, NULL)
    unsafe {
        libc::sync();
        libc::syscall(
            libc::SYS_reboot,
            0xfee1dead_u32 as libc::c_long,  // LINUX_REBOOT_MAGIC1
            0x28121969_u32 as libc::c_long,  // LINUX_REBOOT_MAGIC2
            0x4321fedc_u32 as libc::c_long,  // LINUX_REBOOT_CMD_POWER_OFF
            0_i64,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn request_shutdown() {
    // Stub — agent only runs inside Linux guest
}

// ---------------------------------------------------------------------------
// Vsock I/O
// ---------------------------------------------------------------------------

/// AF_VSOCK address family (Linux).
const AF_VSOCK: libc::c_int = 40;

/// Connect to the host over vsock. Retries up to 30 times (1s apart).
fn connect_vsock(cid: u32, port: u32) -> Option<i32> {
    for attempt in 0..30 {
        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            if attempt == 0 {
                eprintln!("clone-agent: socket(AF_VSOCK) failed, vsock not available");
            }
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }

        // Build sockaddr_vm
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        addr.svm_family = AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;

        // Set a longer connect timeout (10 seconds)
        let tv = libc::timeval { tv_sec: 10, tv_usec: 0 };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };

        if ret == 0 {
            // Set receive timeout so we don't block forever in recv_message
            let tv = libc::timeval { tv_sec: 0, tv_usec: 100_000 }; // 100ms
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const libc::timeval as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            return Some(fd);
        }

        unsafe { libc::close(fd) };

        let errno = unsafe { *libc::__errno_location() };
        eprintln!("clone-agent: vsock connect to cid={cid} port={port} failed (errno={errno}, attempt {attempt})");
        std::thread::sleep(Duration::from_secs(1));
    }
    None
}

/// Send a length-prefixed JSON message over the vsock fd.
fn send_message(fd: i32, msg: &AgentMessage) -> Result<(), ()> {
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

/// Try to receive a length-prefixed JSON message (non-blocking with timeout).
fn recv_message(fd: i32) -> Option<VmmMessage> {
    // Read 4-byte length header
    let mut len_buf = [0u8; 4];
    let n = unsafe {
        libc::recv(fd, len_buf.as_mut_ptr() as *mut libc::c_void, 4, 0)
    };
    if n != 4 {
        return None;
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return None; // sanity limit
    }

    let mut body = vec![0u8; len];
    let mut read = 0;
    while read < len {
        let n = unsafe {
            libc::recv(
                fd,
                body[read..].as_mut_ptr() as *mut libc::c_void,
                len - read,
                0,
            )
        };
        if n <= 0 {
            return None;
        }
        read += n as usize;
    }

    serde_json::from_slice(&body).ok()
}

fn close_fd(fd: i32) {
    unsafe { libc::close(fd) };
}
