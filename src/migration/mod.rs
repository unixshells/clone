//! Live migration: pre-copy memory transfer over TCP.
//!
//! Algorithm:
//! 1. Connect sender → receiver over TCP
//! 2. Send Hello (VM config metadata)
//! 3. Send full memory (VM keeps running, dirty logging tracks changes)
//! 4. Iterative rounds: get_dirty_log → send dirty pages
//! 5. When dirty pages < threshold or max rounds: final round
//! 6. Pause VM → collect final dirty + vCPU + device state → send → cutover
//! 7. Receiver applies final state, starts VM. Source shuts down.
//!
//! Wire format: `[type: u8][length: u32 LE][payload]`

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::boot::template::{DeviceStates, VcpuState};

// ---------------------------------------------------------------------------
// Wire protocol message types
// ---------------------------------------------------------------------------

const MSG_HELLO: u8 = 1;
const MSG_MEMORY_PAGE_BATCH: u8 = 2;
const MSG_FINAL_ROUND: u8 = 3;
const MSG_VCPU_STATE: u8 = 4;
const MSG_DEVICE_STATE: u8 = 5;
const MSG_COMPLETE: u8 = 6;
const MSG_READY: u8 = 10;
const MSG_ACK_FINAL: u8 = 11;

const PAGE_SIZE: u64 = 4096;
const BATCH_SIZE: usize = 64; // pages per batch

// ---------------------------------------------------------------------------
// Hello message (JSON payload)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct HelloMsg {
    pub mem_size: u64,
    pub kvm_slot_size: u64,
    pub num_vcpus: u32,
    pub num_devices: u32,
}

// ---------------------------------------------------------------------------
// Migration statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationStats {
    pub total_pages_sent: u64,
    pub rounds: u32,
    pub downtime_ms: u64,
    pub total_time_ms: u64,
    pub final_dirty_pages: u64,
}

// ---------------------------------------------------------------------------
// Sender configuration
// ---------------------------------------------------------------------------

pub struct MigrationSenderConfig {
    pub dest_host: String,
    pub dest_port: u16,
    pub max_rounds: u32,
    pub dirty_threshold: u64, // pages — converge when below this
}

impl Default for MigrationSenderConfig {
    fn default() -> Self {
        Self {
            dest_host: "127.0.0.1".into(),
            dest_port: 14242,
            max_rounds: 30,
            dirty_threshold: 256, // 1MB
        }
    }
}

// ---------------------------------------------------------------------------
// Frame I/O helpers
// ---------------------------------------------------------------------------

fn write_msg(stream: &mut TcpStream, msg_type: u8, payload: &[u8]) -> Result<()> {
    let len = payload.len() as u32;
    stream.write_all(&[msg_type])?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_msg(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let msg_type = header[0];
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        stream.read_exact(&mut payload)?;
    }
    Ok((msg_type, payload))
}

// ---------------------------------------------------------------------------
// Page batch encoding
// ---------------------------------------------------------------------------

/// Encode a batch of (page_offset, page_data) pairs.
///
/// Format: [count: u32 LE] [page_offset: u64 LE, data: [u8; 4096]] × count
fn encode_page_batch(pages: &[(u64, &[u8])]) -> Vec<u8> {
    let count = pages.len() as u32;
    let mut buf = Vec::with_capacity(4 + pages.len() * (8 + 4096));
    buf.extend_from_slice(&count.to_le_bytes());
    for (offset, data) in pages {
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
}

/// Decode a page batch into (page_offset, page_data) pairs.
fn decode_page_batch(payload: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    if payload.len() < 4 {
        anyhow::bail!("page batch too short");
    }
    let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let mut offset = 4;
    let mut pages = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 8 + 4096 > payload.len() {
            anyhow::bail!("page batch truncated");
        }
        let page_offset = u64::from_le_bytes(
            payload[offset..offset + 8].try_into().unwrap(),
        );
        let data = payload[offset + 8..offset + 8 + 4096].to_vec();
        pages.push((page_offset, data));
        offset += 8 + 4096;
    }
    Ok(pages)
}

// ---------------------------------------------------------------------------
// Zero-page detection
// ---------------------------------------------------------------------------

fn is_zero_page(data: &[u8]) -> bool {
    // Check in 8-byte chunks for speed
    let (prefix, aligned, suffix) = unsafe { data.align_to::<u64>() };
    prefix.iter().all(|&b| b == 0)
        && aligned.iter().all(|&w| w == 0)
        && suffix.iter().all(|&b| b == 0)
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn run_sender(
    vm: &crate::control::sync_server::VmHandle,
    config: MigrationSenderConfig,
) -> Result<MigrationStats> {
    use crate::memory::overcommit::DirtyPageTracker;

    let start = Instant::now();
    let mut total_pages_sent: u64 = 0;

    let vm_fd = vm.vm_fd.as_ref()
        .context("VM fd not available for migration")?;

    // Connect to receiver
    let addr = format!("{}:{}", config.dest_host, config.dest_port);
    tracing::info!("Connecting to migration receiver at {addr}");
    let mut stream = TcpStream::connect(&addr)
        .with_context(|| format!("Failed to connect to receiver at {addr}"))?;

    // Set TCP_NODELAY for lower latency on small messages
    stream.set_nodelay(true)?;

    // Count devices
    let num_devices = {
        let bus = vm.mmio_bus.lock().unwrap();
        bus.snapshot_all().len() as u32
    };

    // 1. Send Hello
    let hello = HelloMsg {
        mem_size: vm.mem_size,
        kvm_slot_size: vm.kvm_slot_size,
        num_vcpus: vm.num_vcpus,
        num_devices,
    };
    let hello_json = serde_json::to_vec(&hello)?;
    write_msg(&mut stream, MSG_HELLO, &hello_json)?;
    tracing::info!("Sent Hello: {}MB, {} vCPUs, {} devices",
        vm.mem_size >> 20, vm.num_vcpus, num_devices);

    // 2. Wait for Ready
    let (msg_type, _) = read_msg(&mut stream)?;
    if msg_type != MSG_READY {
        anyhow::bail!("Expected Ready from receiver, got type {msg_type}");
    }
    tracing::info!("Receiver ready");

    // 3. Clear dirty bitmap before initial transfer (so we track changes during transfer)
    {
        let tracker = DirtyPageTracker::new(vm.kvm_slot_size);
        let _ = tracker.get_dirty_bitmap(vm_fd);
    }

    // 4. Send full memory (VM continues running)
    let total_pages = vm.mem_size / PAGE_SIZE;
    tracing::info!("Sending initial memory: {} pages ({} MB)",
        total_pages, vm.mem_size >> 20);

    let mut batch: Vec<(u64, &[u8])> = Vec::with_capacity(BATCH_SIZE);

    for page_idx in 0..total_pages {
        let offset = page_idx * PAGE_SIZE;
        let page_data = unsafe {
            std::slice::from_raw_parts(vm.guest_memory.add(offset as usize), PAGE_SIZE as usize)
        };

        // Skip zero pages (receiver memory is already zeroed)
        if is_zero_page(page_data) {
            continue;
        }

        batch.push((offset, page_data));

        if batch.len() >= BATCH_SIZE {
            let encoded = encode_page_batch(&batch);
            write_msg(&mut stream, MSG_MEMORY_PAGE_BATCH, &encoded)?;
            total_pages_sent += batch.len() as u64;
            batch.clear();
        }
    }
    // Flush remaining batch
    if !batch.is_empty() {
        let encoded = encode_page_batch(&batch);
        write_msg(&mut stream, MSG_MEMORY_PAGE_BATCH, &encoded)?;
        total_pages_sent += batch.len() as u64;
        batch.clear();
    }

    tracing::info!("Initial transfer complete: {total_pages_sent} non-zero pages sent");

    // 5. Iterative dirty page rounds
    let tracker = DirtyPageTracker::new(vm.kvm_slot_size);
    let mut round = 0u32;

    loop {
        round += 1;

        // Get dirty bitmap (atomically clears it)
        let bitmap = tracker.get_dirty_bitmap(vm_fd)?;

        // Count dirty pages
        let usable_pages = vm.mem_size / PAGE_SIZE;
        let mut dirty_count: u64 = 0;
        for page_idx in 0..usable_pages {
            let byte_idx = (page_idx / 8) as usize;
            let bit_idx = (page_idx % 8) as u8;
            if byte_idx < bitmap.len() && (bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                dirty_count += 1;
            }
        }

        tracing::info!("Round {round}: {dirty_count} dirty pages");

        // Check convergence
        if dirty_count < config.dirty_threshold || round >= config.max_rounds {
            tracing::info!(
                "Converged at round {round}: {dirty_count} dirty pages (threshold: {})",
                config.dirty_threshold
            );
            break;
        }

        // Send dirty pages
        let mut round_batch: Vec<(u64, &[u8])> = Vec::with_capacity(BATCH_SIZE);
        for page_idx in 0..usable_pages {
            let byte_idx = (page_idx / 8) as usize;
            let bit_idx = (page_idx % 8) as u8;
            if byte_idx < bitmap.len() && (bitmap[byte_idx] & (1 << bit_idx)) != 0 {
                let offset = page_idx * PAGE_SIZE;
                let page_data = unsafe {
                    std::slice::from_raw_parts(
                        vm.guest_memory.add(offset as usize),
                        PAGE_SIZE as usize,
                    )
                };
                round_batch.push((offset, page_data));

                if round_batch.len() >= BATCH_SIZE {
                    let encoded = encode_page_batch(&round_batch);
                    write_msg(&mut stream, MSG_MEMORY_PAGE_BATCH, &encoded)?;
                    total_pages_sent += round_batch.len() as u64;
                    round_batch.clear();
                }
            }
        }
        if !round_batch.is_empty() {
            let encoded = encode_page_batch(&round_batch);
            write_msg(&mut stream, MSG_MEMORY_PAGE_BATCH, &encoded)?;
            total_pages_sent += round_batch.len() as u64;
            round_batch.clear();
        }
    }

    // 6. Final round: pause VM, collect last dirty + state
    let pause_start = Instant::now();

    // Pause all vCPUs
    crate::control::sync_server::pause_vcpus_pub(vm)
        .map_err(|e| anyhow::anyhow!("Failed to pause vCPUs for final round: {e}"))?;

    // Signal final round
    write_msg(&mut stream, MSG_FINAL_ROUND, &[])?;

    // Get final dirty pages
    let bitmap = tracker.get_dirty_bitmap(vm_fd)?;
    let usable_pages = vm.mem_size / PAGE_SIZE;
    let mut final_dirty: u64 = 0;

    let mut final_batch: Vec<(u64, &[u8])> = Vec::with_capacity(BATCH_SIZE);
    for page_idx in 0..usable_pages {
        let byte_idx = (page_idx / 8) as usize;
        let bit_idx = (page_idx % 8) as u8;
        if byte_idx < bitmap.len() && (bitmap[byte_idx] & (1 << bit_idx)) != 0 {
            let offset = page_idx * PAGE_SIZE;
            let page_data = unsafe {
                std::slice::from_raw_parts(
                    vm.guest_memory.add(offset as usize),
                    PAGE_SIZE as usize,
                )
            };
            final_batch.push((offset, page_data));
            final_dirty += 1;

            if final_batch.len() >= BATCH_SIZE {
                let encoded = encode_page_batch(&final_batch);
                write_msg(&mut stream, MSG_MEMORY_PAGE_BATCH, &encoded)?;
                total_pages_sent += final_batch.len() as u64;
                final_batch.clear();
            }
        }
    }
    if !final_batch.is_empty() {
        let encoded = encode_page_batch(&final_batch);
        write_msg(&mut stream, MSG_MEMORY_PAGE_BATCH, &encoded)?;
        total_pages_sent += final_batch.len() as u64;
    }

    tracing::info!("Final round: {final_dirty} dirty pages");

    // 7. Send vCPU states
    let vcpu_states: Vec<VcpuState> = {
        let states = vm.pause_state.captured_states.lock().unwrap();
        states.iter().enumerate().map(|(i, s)| {
            s.clone().unwrap_or_else(|| {
                tracing::error!("vCPU {i} state not captured");
                VcpuState { regs: Vec::new(), sregs: Vec::new() }
            })
        }).collect()
    };

    for (i, state) in vcpu_states.iter().enumerate() {
        let mut payload = Vec::with_capacity(4 + state.regs.len() + 4 + state.sregs.len());
        payload.extend_from_slice(&(i as u32).to_le_bytes());
        payload.extend_from_slice(&(state.regs.len() as u32).to_le_bytes());
        payload.extend_from_slice(&state.regs);
        payload.extend_from_slice(&(state.sregs.len() as u32).to_le_bytes());
        payload.extend_from_slice(&state.sregs);
        write_msg(&mut stream, MSG_VCPU_STATE, &payload)?;
    }

    // 8. Send device states
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
    let device_json = serde_json::to_vec(&device_states)?;
    write_msg(&mut stream, MSG_DEVICE_STATE, &device_json)?;

    // 9. Send Complete
    write_msg(&mut stream, MSG_COMPLETE, &[])?;

    // 10. Wait for AckFinal
    let (msg_type, _) = read_msg(&mut stream)?;
    if msg_type != MSG_ACK_FINAL {
        anyhow::bail!("Expected AckFinal from receiver, got type {msg_type}");
    }

    let downtime = pause_start.elapsed();
    let total_time = start.elapsed();

    let stats = MigrationStats {
        total_pages_sent,
        rounds: round,
        downtime_ms: downtime.as_millis() as u64,
        total_time_ms: total_time.as_millis() as u64,
        final_dirty_pages: final_dirty,
    };

    tracing::info!(
        "Migration complete: {} pages sent, {} rounds, {}ms downtime, {}ms total",
        stats.total_pages_sent, stats.rounds, stats.downtime_ms, stats.total_time_ms
    );

    // Shut down source VM
    crate::vmm::vcpu::SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
    vm.shutdown_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    // Resume vCPUs so they can exit
    crate::control::sync_server::resume_vcpus_pub(vm);
    for &tid in &vm.vcpu_threads {
        unsafe { libc::pthread_kill(tid, libc::SIGUSR1); }
    }

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn run_receiver(
    port: u16,
    kernel_path: &str,
    mem_mb: u32,
) -> Result<()> {
    use std::net::TcpListener;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use kvm_bindings::{
        kvm_pit_config, kvm_userspace_memory_region,
        KVM_MEM_LOG_DIRTY_PAGES, KVM_PIT_SPEAKER_DUMMY,
    };
    use kvm_ioctls::Kvm;

    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .with_context(|| format!("Failed to bind migration receiver on port {port}"))?;
    eprintln!("Migration receiver listening on port {port}");

    let (mut stream, peer) = listener.accept()?;
    stream.set_nodelay(true)?;
    eprintln!("Accepted migration from {peer}");

    // 1. Read Hello
    let (msg_type, payload) = read_msg(&mut stream)?;
    if msg_type != MSG_HELLO {
        anyhow::bail!("Expected Hello, got type {msg_type}");
    }
    let hello: HelloMsg = serde_json::from_slice(&payload)?;
    eprintln!(
        "Migration Hello: {}MB, {} vCPUs, {} devices",
        hello.mem_size >> 20, hello.num_vcpus, hello.num_devices
    );

    // 2. Pre-allocate guest memory and KVM VM
    let kvm = Kvm::new().context("Failed to open /dev/kvm")?;
    let vm_fd = Arc::new(kvm.create_vm().context("Failed to create VM")?);

    let mem_size = hello.mem_size;
    let guard_size: u64 = 128 << 20;
    let alloc_size = mem_size + guard_size;
    let guest_memory = crate::memory::create_guest_memory(alloc_size)
        .context("Failed to allocate guest memory")?;

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: alloc_size,
        userspace_addr: guest_memory.as_ptr() as u64,
        flags: KVM_MEM_LOG_DIRTY_PAGES,
    };
    unsafe {
        vm_fd.set_user_memory_region(mem_region)
            .context("Failed to set KVM memory region")?;
    }

    // Create irqchip + PIT + GSI routing
    vm_fd.create_irq_chip().context("Failed to create irqchip")?;
    let pit_config = kvm_pit_config {
        flags: KVM_PIT_SPEAKER_DUMMY,
        ..Default::default()
    };
    vm_fd.create_pit2(pit_config).context("Failed to create PIT")?;
    crate::vmm::setup_gsi_routing(&vm_fd)?;

    // Send Ready
    write_msg(&mut stream, MSG_READY, &[])?;
    eprintln!("Sent Ready, receiving memory pages...");

    // 3. Receive pages until Final/Complete
    let mut pages_received: u64 = 0;
    let mut vcpu_states: Vec<VcpuState> = Vec::new();
    let mut device_states: Option<DeviceStates> = None;
    let mut got_final = false;

    loop {
        let (msg_type, payload) = read_msg(&mut stream)?;
        match msg_type {
            MSG_MEMORY_PAGE_BATCH => {
                let batch = decode_page_batch(&payload)?;
                for (page_offset, page_data) in &batch {
                    if *page_offset + PAGE_SIZE <= alloc_size {
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                page_data.as_ptr(),
                                guest_memory.as_ptr().add(*page_offset as usize),
                                PAGE_SIZE as usize,
                            );
                        }
                        pages_received += 1;
                    }
                }
            }
            MSG_FINAL_ROUND => {
                got_final = true;
                eprintln!("Received FinalRound marker, {pages_received} pages so far");
            }
            MSG_VCPU_STATE => {
                let state = decode_vcpu_state(&payload)?;
                vcpu_states.push(state);
            }
            MSG_DEVICE_STATE => {
                let ds: DeviceStates = serde_json::from_slice(&payload)?;
                device_states = Some(ds);
            }
            MSG_COMPLETE => {
                eprintln!("Migration complete: {pages_received} total pages received");
                break;
            }
            other => {
                tracing::warn!("Unknown message type {other}, skipping");
            }
        }
    }

    if !got_final {
        anyhow::bail!("Never received FinalRound marker");
    }

    // 4. Create vCPUs from received state
    let mmio_bus = Arc::new(std::sync::Mutex::new(crate::virtio::mmio::MmioBus::new()));
    let serial = Arc::new(std::sync::Mutex::new(crate::vmm::serial::Serial::new()));

    // Register virtio devices (balloon + vsock, same as fork_boot)
    {
        let mut bus = mmio_bus.lock().unwrap();
        let balloon = crate::virtio::balloon::VirtioBalloon::new(guest_memory.as_ptr(), mem_size);
        bus.register(Box::new(balloon));

        match crate::virtio::vsock::VirtioVsock::new(3) {
            Ok(vsock) => { bus.register(Box::new(vsock)); }
            Err(e) => { tracing::warn!("Failed to create vsock: {e}"); }
        }

        bus.set_guest_memory(guest_memory.as_ptr(), mem_size);

        // Restore device states if provided
        if let Some(ref ds) = device_states {
            if let Err(e) = bus.restore_all_from_json(&ds.transports) {
                tracing::warn!("Failed to restore some device states: {e}");
            }
        }
    }

    // Create vCPUs
    let mut vcpus = Vec::new();
    for (id, state) in vcpu_states.iter().enumerate() {
        let vcpu = crate::vmm::vcpu::Vcpu::from_template(
            &kvm,
            &vm_fd,
            id as u32,
            state,
            Arc::clone(&mmio_bus),
            Arc::clone(&serial),
        )?;
        vcpus.push(vcpu);
    }

    // Send AckFinal
    write_msg(&mut stream, MSG_ACK_FINAL, &[])?;
    drop(stream);

    eprintln!("Migration applied. Starting VM with {} vCPUs...", vcpus.len());

    // 5. Run the VM (same as Vm::run but standalone)
    crate::vmm::vcpu::install_signal_handlers();
    crate::vmm::vcpu::install_pause_signal_handler();

    let num_vcpus = vcpus.len() as u32;
    let pause_state = Arc::new(crate::vmm::vcpu::VcpuPauseState::new(num_vcpus));
    for vcpu in &mut vcpus {
        vcpu.set_pause_state(Arc::clone(&pause_state));
    }

    // Raw terminal
    let _raw_guard = crate::vmm::serial::RawModeGuard::enter();

    // Stdin reader
    let serial_clone = Arc::clone(&serial);
    let vm_fd_clone = Arc::clone(&vm_fd);
    std::thread::spawn(move || {
        use std::io::Read;
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        let mut buf = [0u8; 1];
        while handle.read_exact(&mut buf).is_ok() {
            let mut serial = serial_clone.lock().unwrap();
            serial.enqueue_input(buf[0]);
            if serial.interrupt_enabled() {
                drop(serial);
                let _ = vm_fd_clone.set_irq_line(4, true);
                let _ = vm_fd_clone.set_irq_line(4, false);
            }
        }
    });

    // Control socket
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let _agent_state = crate::vmm::agent_listener::start_listener(Arc::clone(&shutdown_flag), crate::vmm::agent_listener::AGENT_VSOCK_PORT_BASE);

    let mut vcpu_threads: Vec<libc::pthread_t> = Vec::new();
    let mut ap_handles = Vec::new();

    let mut all_vcpus: Vec<crate::vmm::vcpu::Vcpu> = vcpus.drain(..).collect();

    for vcpu in all_vcpus.drain(1..) {
        let (tx, rx) = std::sync::mpsc::channel::<libc::pthread_t>();
        let handle = std::thread::Builder::new()
            .name(format!("vcpu-{}", vcpu.id()))
            .spawn(move || {
                let _ = tx.send(unsafe { libc::pthread_self() });
                let mut vcpu = vcpu;
                if let Err(e) = vcpu.run_loop() {
                    tracing::error!("vCPU {} exited with error: {e}", vcpu.id());
                }
            })?;
        if let Ok(tid) = rx.recv() {
            vcpu_threads.push(tid);
        }
        ap_handles.push(handle);
    }

    let bsp_tid = unsafe { libc::pthread_self() };
    vcpu_threads.insert(0, bsp_tid);

    let vm_handle = Arc::new(crate::control::sync_server::VmHandle {
        guest_memory: guest_memory.as_ptr(),
        mem_size,
        kvm_slot_size: alloc_size,
        pause_state: Arc::clone(&pause_state),
        vcpu_threads,
        num_vcpus,
        shutdown_flag: Arc::clone(&shutdown_flag),
        mmio_bus: Arc::clone(&mmio_bus),
        vm_fd: Some(Arc::clone(&vm_fd)),
        agent_state: None,
    });

    match crate::control::sync_server::start_control_socket(Arc::clone(&vm_handle)) {
        Ok(path) => {
            eprintln!("Control socket: {path}");
        }
        Err(e) => {
            tracing::warn!("Failed to start control socket: {e}");
        }
    }

    // Run BSP
    if let Some(mut bsp) = all_vcpus.into_iter().next() {
        bsp.run_loop()?;
    }

    shutdown_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    for handle in ap_handles {
        let _ = handle.join();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: decode vCPU state from wire format
// ---------------------------------------------------------------------------

fn decode_vcpu_state(payload: &[u8]) -> Result<VcpuState> {
    if payload.len() < 12 {
        anyhow::bail!("vCPU state payload too short");
    }
    let mut offset = 0;
    // vcpu_id (u32) — we don't need it, states are pushed in order
    let _vcpu_id = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
    offset += 4;

    let regs_len = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + regs_len > payload.len() {
        anyhow::bail!("regs truncated");
    }
    let regs = payload[offset..offset + regs_len].to_vec();
    offset += regs_len;

    if offset + 4 > payload.len() {
        anyhow::bail!("sregs length truncated");
    }
    let sregs_len = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + sregs_len > payload.len() {
        anyhow::bail!("sregs truncated");
    }
    let sregs = payload[offset..offset + sregs_len].to_vec();

    Ok(VcpuState { regs, sregs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_page_detection() {
        let zero = vec![0u8; 4096];
        assert!(is_zero_page(&zero));

        let mut nonzero = vec![0u8; 4096];
        nonzero[2048] = 1;
        assert!(!is_zero_page(&nonzero));
    }

    #[test]
    fn test_page_batch_roundtrip() {
        let page1 = vec![0xAA; 4096];
        let page2 = vec![0xBB; 4096];
        let pages: Vec<(u64, &[u8])> = vec![
            (0x1000, &page1),
            (0x5000, &page2),
        ];
        let encoded = encode_page_batch(&pages);
        let decoded = decode_page_batch(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].0, 0x1000);
        assert_eq!(decoded[0].1, page1);
        assert_eq!(decoded[1].0, 0x5000);
        assert_eq!(decoded[1].1, page2);
    }

    #[test]
    fn test_vcpu_state_roundtrip() {
        let regs = vec![1, 2, 3, 4, 5];
        let sregs = vec![10, 20, 30];

        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_le_bytes()); // vcpu_id
        payload.extend_from_slice(&(regs.len() as u32).to_le_bytes());
        payload.extend_from_slice(&regs);
        payload.extend_from_slice(&(sregs.len() as u32).to_le_bytes());
        payload.extend_from_slice(&sregs);

        let state = decode_vcpu_state(&payload).unwrap();
        assert_eq!(state.regs, regs);
        assert_eq!(state.sregs, sregs);
    }

    #[test]
    fn test_hello_serialization() {
        let hello = HelloMsg {
            mem_size: 512 << 20,
            kvm_slot_size: 640 << 20,
            num_vcpus: 2,
            num_devices: 3,
        };
        let json = serde_json::to_vec(&hello).unwrap();
        let decoded: HelloMsg = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.mem_size, 512 << 20);
        assert_eq!(decoded.num_vcpus, 2);
    }
}
