//! Clone Guest Agent
//!
//! Runs inside the guest VM as a lightweight daemon (<1MB).
//! Communicates with the VMM over virtio-vsock.
//!
//! After a CoW fork, the VMM injects VIRTIO_VSOCK_EVENT_TRANSPORT_RESET
//! into the vsock event virtqueue. The guest kernel resets all vsock
//! connections (ECONNRESET). The agent detects this and reconnects.

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
    Heartbeat {
        active: bool,
        load_avg_1m: f64,
        mem_pressure_pct: f64,
        mem_available_pct: f64,
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
#[derive(Deserialize)]
#[serde(tag = "type")]
enum VmmMessage {
    Poll,
    Shutdown,
    Exec {
        command: String,
        args: Vec<String>,
    },
}

/// Runs on every reconnect (fork or not). Fixes state that drifts
/// from the template snapshot regardless of whether a fork happened.
fn on_reconnect() {
    // Sync system clock in background — don't block agent readiness.
    // Clock sync needs network, which may not be up yet after fork.
    // shell-setup.sh handles network setup via exec (vsock).
    std::thread::spawn(|| {
        let _ = std::process::Command::new("bash")
            .args(["-c", "systemctl restart systemd-timesyncd 2>/dev/null; sleep 2; true"])
            .output();
        eprintln!("clone-agent: clock synced (background)");
    });
    eprintln!("clone-agent: reconnect (clock sync in background)");
}

/// Clean up stale state after VM fork (D-Bus sockets, services, etc).
/// Only runs when identity IP changes (actual fork).
fn cleanup_after_fork() {
    // Restart D-Bus to clear stale sockets
    let _ = std::process::Command::new("systemctl")
        .args(["restart", "dbus"]).output();
    // Remove stale user session sockets
    let _ = std::fs::remove_file("/run/nologin");
    if let Ok(entries) = std::fs::read_dir("/run/user") {
        for entry in entries.flatten() {
            let bus = entry.path().join("bus");
            let _ = std::fs::remove_file(&bus);
        }
    }
    // Restart services that use Go runtime (crashes after fork due to
    // stale goroutine stacks). Latch is the main one.
    let _ = std::process::Command::new("systemctl")
        .args(["restart", "latch"]).output();
    // Restart user latch service if lingering is enabled
    if let Ok(entries) = std::fs::read_dir("/home") {
        for entry in entries.flatten() {
            let user = entry.file_name();
            let _ = std::process::Command::new("su")
                .args(["-c", "systemctl --user restart latch 2>/dev/null", user.to_str().unwrap_or("shell")])
                .output();
        }
    }
    // Rebind virtio-balloon driver — the balloon device state from the
    // snapshot doesn't properly reconnect after fork. Unbind+bind forces
    // the guest kernel to re-probe the device with fresh VMM state.
    let _ = std::process::Command::new("bash")
        .args(["-c", "echo virtio0 > /sys/bus/virtio/drivers/virtio_balloon/unbind 2>/dev/null; sleep 0.5; echo virtio0 > /sys/bus/virtio/drivers/virtio_balloon/bind 2>/dev/null"])
        .output();
    eprintln!("clone-agent: cleaned up stale state after fork");
}

/// Read IP from the identity page injected by the VMM.
/// The page address mirrors Clone's identity_page_addr():
///   ram_size - 0x20000, clamped below the MMIO hole at 0xBFFE0000.
fn read_identity_ip() -> Option<String> {
    const MMIO_HOLE_START: u64 = 0xC000_0000;

    // Find total RAM from /proc/iomem to compute the identity page address.
    let iomem = std::fs::read_to_string("/proc/iomem").ok()?;
    let mut ram_end: u64 = 0;
    for line in iomem.lines() {
        if !line.contains("System RAM") { continue; }
        let range = line.split(':').next()?.trim();
        let end_str = range.split('-').nth(1)?.trim();
        if let Ok(end) = u64::from_str_radix(end_str, 16) {
            if end > ram_end { ram_end = end; }
        }
    }

    // Compute address: same logic as Clone's identity_page_addr
    if ram_end > 0x20000 {
        let ram_size = ram_end + 1;
        let addr = ram_size - 0x20000;
        let addr = if addr >= MMIO_HOLE_START {
            MMIO_HOLE_START - 0x20000 // 0xBFFE0000
        } else {
            addr
        };
        if let Some(ip) = read_identity_from_devmem(addr) {
            return Some(ip);
        }
    }

    // Also try the well-known address directly (covers edge cases)
    if let Some(ip) = read_identity_from_devmem(MMIO_HOLE_START - 0x20000) {
        return Some(ip);
    }

    // Last resort: /run/clone-identity
    read_identity_from_file("/run/clone-identity").and_then(|_|
        parse_identity_ip(&std::fs::read("/run/clone-identity").ok()?))

}

fn read_identity_from_file(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    parse_identity_ip(&data)
}

fn read_identity_from_devmem(addr: u64) -> Option<String> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::File::open("/dev/mem").ok()?;
    let page_size = 4096u64;
    let aligned = addr & !(page_size - 1);
    let offset_in_page = (addr - aligned) as usize;
    let map_size = offset_in_page + 0x100;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(), map_size,
            libc::PROT_READ, libc::MAP_SHARED,
            f.as_raw_fd(), aligned as libc::off_t,
        )
    };
    if ptr == libc::MAP_FAILED { return None; }
    let data = unsafe { std::slice::from_raw_parts(ptr.add(offset_in_page) as *const u8, 0x6C) };
    let result = parse_identity_ip(data);
    unsafe { libc::munmap(ptr, map_size); }
    result
}

fn read_identity_mac() -> Option<String> {
    // Try /run/clone-identity first, then /dev/mem
    if let Some(mac) = read_identity_from_file("/run/clone-identity").and_then(|_| parse_identity_mac(&std::fs::read("/run/clone-identity").ok()?)) {
        return Some(mac);
    }
    let iomem = std::fs::read_to_string("/proc/iomem").ok()?;
    for line in iomem.lines() {
        if !line.contains("reserved") && !line.contains("Reserved") { continue; }
        let range = line.split(':').next()?.trim();
        let start_str = range.split('-').next()?.trim();
        let start = u64::from_str_radix(start_str, 16).ok()?;
        if start < 0x100000 { continue; }
        if let Some(mac) = read_mac_from_devmem(start) {
            return Some(mac);
        }
    }
    None
}

fn read_mac_from_devmem(addr: u64) -> Option<String> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::File::open("/dev/mem").ok()?;
    let page_size = 4096u64;
    let aligned = addr & !(page_size - 1);
    let offset_in_page = (addr - aligned) as usize;
    let map_size = offset_in_page + 0x100;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(), map_size,
            libc::PROT_READ, libc::MAP_SHARED,
            f.as_raw_fd(), aligned as libc::off_t,
        )
    };
    if ptr == libc::MAP_FAILED { return None; }
    let data = unsafe { std::slice::from_raw_parts(ptr.add(offset_in_page) as *const u8, 0x6C) };
    let result = parse_identity_mac(data);
    unsafe { libc::munmap(ptr, map_size); }
    result
}

fn parse_identity_mac(data: &[u8]) -> Option<String> {
    if data.len() < 0x66 { return None; }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != 0x494D564E { return None; } // "NVMI"
    // MAC at offset 0x060 (6 bytes)
    let mac = &data[0x60..0x66];
    if mac == [0, 0, 0, 0, 0, 0] { return None; }
    Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]))
}

fn parse_identity_ip(data: &[u8]) -> Option<String> {
    if data.len() < 0x6C { return None; }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != 0x494D564E { return None; } // "NVMI"
    let ip = &data[0x68..0x6C];
    if ip == [0, 0, 0, 0] { return None; }
    Some(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
}

#[cfg(target_os = "linux")]
fn early_serial_write(s: &str) {
    unsafe {
        libc::iopl(3);
    }
    for &b in s.as_bytes() {
        unsafe {
            for _ in 0..10000 {
                let lsr: u8;
                std::arch::asm!("in al, dx", out("al") lsr, in("dx") 0x3FDu16);
                if lsr & 0x20 != 0 {
                    break;
                }
            }
            std::arch::asm!("out dx, al", in("al") b, in("dx") 0x3F8u16);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn early_serial_write(_s: &str) {}

fn main() {
    eprintln!("clone-agent: starting");

    configure_guest_network();

    let agent_port = {
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
        parse_cmdline_param(&cmdline, "clone.agent_port")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(AGENT_VSOCK_PORT)
    };

    // Use the cmdline IP as baseline — the identity page already has the
    // fork's new IP (injected before vCPUs resume), so reading it here
    // would make fork detection impossible.
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let mut current_ip: Option<String> = parse_cmdline_param(&cmdline, "clone.net_ip")
        .or_else(|| read_identity_ip());

    loop {
        let fd = match connect_vsock(VMADDR_CID_HOST, agent_port) {
            Some(fd) => fd,
            None => {
                eprintln!("clone-agent: connect failed, retrying...");
                // sched_yield instead of blocking sleep — see run_agent comment.
                for _ in 0..1000 {
                    unsafe {
                        libc::sched_yield();
                    }
                }
                continue;
            }
        };

        eprintln!("clone-agent: connected (port {})", agent_port);
        run_agent(fd);
        close_fd(fd);
        eprintln!("clone-agent: disconnected, reconnecting...");

        // Run reconnect tasks in background — don't block agent readiness.
        on_reconnect();
        // sched_yield instead of blocking sleep — see run_agent comment.
        for _ in 0..1000 {
            unsafe {
                libc::sched_yield();
            }
        }
    }
}

fn run_agent(fd: i32) {
    if send_message(fd, &AgentMessage::Ready).is_err() {
        return;
    }

    let mut last_load = 0.0f64;
    let mut last_heartbeat = std::time::Instant::now();
    let heartbeat_interval = Duration::from_secs(2);

    // Make the socket non-blocking — we drive the pacing ourselves.
    set_nonblocking(fd);

    loop {
        // Yield to scheduler without blocking. Forking off PID 1 of the
        // initrd produces a process where blocking sleeps (nanosleep,
        // usleep, std::thread::sleep) never wake; a sched_yield-driven busy
        // poll keeps the loop responsive without consuming a full vCPU.
        unsafe {
            libc::sched_yield();
        }
        // Poll for VMM messages
        if let Some(msg) = recv_message(fd) {
            match msg {
                VmmMessage::Poll => {
                    let metrics = collect_metrics();
                    let active = is_active(&metrics, last_load);
                    last_load = metrics.load_avg_1m;
                    let _ = send_message(fd, &AgentMessage::Heartbeat {
                        active,
                        load_avg_1m: metrics.load_avg_1m,
                        mem_pressure_pct: metrics.mem_pressure_pct,
                        mem_available_pct: metrics.mem_available_pct,
                        process_count: metrics.process_count,
                        uptime_secs: metrics.uptime_secs,
                    });
                    last_heartbeat = std::time::Instant::now();
                    continue;
                }
                VmmMessage::Shutdown => {
                    eprintln!("clone-agent: shutdown");
                    request_shutdown();
                    return;
                }
                VmmMessage::Exec { command, args } => {
                    let result = std::process::Command::new(&command)
                        .args(&args)
                        .env("HOME", "/root")
                        .env("USER", "root")
                        .env("SHELL", "/bin/bash")
                        .env("TERM", "xterm-256color")
                        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin")
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .and_then(|child| {
                            let mut child = child;
                            let start = std::time::Instant::now();
                            loop {
                                match child.try_wait() {
                                    Ok(Some(status)) => {
                                        // Process exited. Read available output without blocking
                                        // forever — background children may hold the pipe open.
                                        let mut stdout_data = Vec::new();
                                        let mut stderr_data = Vec::new();
                                        if let Some(out) = child.stdout.take() {
                                            use std::os::unix::io::AsRawFd;
                                            set_nonblocking(out.as_raw_fd());
                                            let mut r = std::io::BufReader::new(out);
                                            let _ = std::io::Read::read_to_end(&mut r, &mut stdout_data);
                                        }
                                        if let Some(err) = child.stderr.take() {
                                            use std::os::unix::io::AsRawFd;
                                            set_nonblocking(err.as_raw_fd());
                                            let mut r = std::io::BufReader::new(err);
                                            let _ = std::io::Read::read_to_end(&mut r, &mut stderr_data);
                                        }
                                        return Ok(std::process::Output {
                                            status,
                                            stdout: stdout_data,
                                            stderr: stderr_data,
                                        });
                                    }
                                    Ok(None) => {
                                        if start.elapsed() > Duration::from_secs(30) {
                                            let _ = child.kill();
                                            let _ = child.wait();
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::TimedOut,
                                                "command timed out after 30s",
                                            ));
                                        }
                                        // sched_yield instead of sleep — see run_agent loop.
                                        unsafe {
                                            libc::sched_yield();
                                        }
                                    }
                                    Err(e) => return Err(e),
                                }
                            }
                        });
                    let msg = match result {
                        Ok(output) => AgentMessage::ExecResult {
                            exit_code: output.status.code().unwrap_or(-1),
                            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                        },
                        Err(e) => AgentMessage::ExecResult {
                            exit_code: -1,
                            stdout: String::new(),
                            stderr: format!("Failed to execute: {e}"),
                        },
                    };
                    let _ = send_message(fd, &msg);
                    continue;
                }
            }
        }

        // Send heartbeat if interval elapsed (no sleep — recv timeout is the pacer)
        if last_heartbeat.elapsed() >= heartbeat_interval {
            let metrics = collect_metrics();
            let active = is_active(&metrics, last_load);
            last_load = metrics.load_avg_1m;
            if send_message(fd, &AgentMessage::Heartbeat {
                active,
                load_avg_1m: metrics.load_avg_1m,
                mem_pressure_pct: metrics.mem_pressure_pct,
                mem_available_pct: metrics.mem_available_pct,
                process_count: metrics.process_count,
                uptime_secs: metrics.uptime_secs,
            }).is_err() {
                return;
            }
            last_heartbeat = std::time::Instant::now();
        }
    }
}

// ---------------------------------------------------------------------------
// Guest networking
// ---------------------------------------------------------------------------

fn configure_guest_network() {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let ip = parse_cmdline_param(&cmdline, "clone.net_ip");
    let gw = parse_cmdline_param(&cmdline, "clone.net_gw");
    let mask = parse_cmdline_param(&cmdline, "clone.net_mask");

    let (ip, gw, mask) = match (ip, gw, mask) {
        (Some(ip), Some(gw), Some(mask)) => (ip, gw, mask),
        _ => return,
    };

    eprintln!("clone-agent: configuring eth0: {ip}/{mask} gw {gw}");

    let _ = std::process::Command::new("ip")
        .args(["addr", "add", &format!("{ip}/{mask}"), "dev", "eth0"])
        .status();
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "eth0", "up"])
        .status();
    let _ = std::process::Command::new("ip")
        .args(["route", "add", "default", "via", &gw])
        .status();
    let _ = fs::write("/etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 8.8.4.4\n");

    eprintln!("clone-agent: network configured");
}

fn parse_cmdline_param(cmdline: &str, key: &str) -> Option<String> {
    for part in cmdline.split_whitespace() {
        if let Some(val) = part.strip_prefix(&format!("{key}=")) {
            return Some(val.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

struct GuestMetrics {
    load_avg_1m: f64,
    mem_pressure_pct: f64,
    mem_available_pct: f64,
    process_count: u32,
    uptime_secs: u64,
}

fn collect_metrics() -> GuestMetrics {
    GuestMetrics {
        load_avg_1m: read_load_avg(),
        mem_pressure_pct: read_psi_memory(),
        mem_available_pct: read_mem_available_pct(),
        process_count: count_processes(),
        uptime_secs: read_uptime(),
    }
}

fn is_active(metrics: &GuestMetrics, prev_load: f64) -> bool {
    metrics.load_avg_1m > 0.05
        || metrics.load_avg_1m > prev_load
        || metrics.mem_pressure_pct > 1.0
        || metrics.mem_available_pct < 25.0
}

fn read_load_avg() -> f64 {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0)
}

fn read_psi_memory() -> f64 {
    fs::read_to_string("/proc/pressure/memory")
        .ok()
        .and_then(|s| {
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

fn read_mem_available_pct() -> f64 {
    let contents = match fs::read_to_string("/proc/meminfo") {
        Ok(s) => s,
        Err(_) => return 100.0,
    };
    let mut total_kb: u64 = 0;
    let mut available_kb: u64 = 0;
    for line in contents.lines() {
        if let Some(val) = line.strip_prefix("MemTotal:") {
            total_kb = val.trim().split_whitespace().next()
                .and_then(|v| v.parse().ok()).unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("MemAvailable:") {
            available_kb = val.trim().split_whitespace().next()
                .and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }
    if total_kb == 0 {
        return 100.0;
    }
    (available_kb as f64 / total_kb as f64) * 100.0
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

#[cfg(target_os = "linux")]
fn request_shutdown() {
    unsafe {
        libc::sync();
        libc::syscall(
            libc::SYS_reboot,
            0xfee1dead_u32 as libc::c_long,
            0x28121969_u32 as libc::c_long,
            0x4321fedc_u32 as libc::c_long,
            0_i64,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn request_shutdown() {}

// ---------------------------------------------------------------------------
// Vsock I/O
// ---------------------------------------------------------------------------

const AF_VSOCK: libc::c_int = 40;

fn connect_vsock(cid: u32, port: u32) -> Option<i32> {
    for attempt in 0..20 {
        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            // Exponential backoff: 10ms, 20ms, 40ms, ...
            std::thread::sleep(Duration::from_millis(10 << attempt.min(6)));
            continue;
        }

        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        addr.svm_family = AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;

        // Fast connect timeout (vsock connects in microseconds)
        let tv = libc::timeval { tv_sec: 0, tv_usec: 500_000 };
        unsafe {
            libc::setsockopt(
                fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO,
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
            return Some(fd);
        }

        unsafe { libc::close(fd) };

        // Exponential backoff: 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms
        std::thread::sleep(Duration::from_millis(10 << attempt.min(6)));
    }
    None
}

fn send_message(fd: i32, msg: &AgentMessage) -> Result<(), ()> {
    let json = serde_json::to_vec(msg).map_err(|_| ())?;
    let len = (json.len() as u32).to_le_bytes();

    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&json);

    let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    let poll_ret = unsafe { libc::poll(&mut pfd, 1, 3000) };
    if poll_ret <= 0 || (pfd.revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
        return Err(());
    }

    let written = unsafe {
        libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
    };

    if written as usize == buf.len() {
        Ok(())
    } else {
        Err(())
    }
}

fn recv_message(fd: i32) -> Option<VmmMessage> {
    // Socket is non-blocking; recv returns -1/EAGAIN when no data is ready.
    let mut len_buf = [0u8; 4];
    let n = unsafe {
        libc::recv(
            fd,
            len_buf.as_mut_ptr() as *mut libc::c_void,
            4,
            libc::MSG_PEEK,
        )
    };
    if n != 4 {
        return None;
    }
    let mut got = 0;
    while got < 4 {
        let n = unsafe { libc::recv(fd, len_buf[got..].as_mut_ptr() as *mut libc::c_void, 4 - got, 0) };
        if n <= 0 {
            return None;
        }
        got += n as usize;
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1_048_576 {
        return None;
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

fn set_nonblocking(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}
