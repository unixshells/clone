use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use anyhow::{Context, Result};
use kvm_bindings::{KVM_MAX_CPUID_ENTRIES, Msrs};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use vm_memory::GuestAddress;

use crate::virtio::mmio::MmioBus;
use super::serial::{Serial, COM1_PORT_BASE, COM1_PORT_COUNT};

/// Global shutdown flag — set by SIGTERM/SIGINT handler.
/// The vCPU run loop checks this and exits cleanly so Drop runs.
pub static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Install signal handlers for clean shutdown.
/// SIGTERM/SIGINT set the SHUTDOWN_REQUESTED flag, which causes the
/// vCPU run loop to exit, allowing Drop impls to close vhost fds.
pub fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
    }
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Shared state for pausing all vCPUs to take a consistent snapshot.
///
/// The control socket sets `pause_requested`, kicks vCPUs out of KVM_RUN
/// with SIGUSR1, then waits on `all_paused`. Each vCPU captures its
/// register state, parks on `resume`, and the control socket collects
/// the states and resumes.
pub struct VcpuPauseState {
    pub pause_requested: AtomicBool,
    pub paused_count: AtomicU32,
    pub total_vcpus: u32,
    pub resume: Condvar,
    pub resume_lock: Mutex<bool>,
    pub all_paused: Condvar,
    pub all_paused_lock: Mutex<bool>,
    /// Captured register states, indexed by vCPU ID.
    pub captured_states: Mutex<Vec<Option<crate::boot::template::VcpuState>>>,
}

impl VcpuPauseState {
    pub fn new(total_vcpus: u32) -> Self {
        let mut states = Vec::with_capacity(total_vcpus as usize);
        states.resize_with(total_vcpus as usize, || None);
        Self {
            pause_requested: AtomicBool::new(false),
            paused_count: AtomicU32::new(0),
            total_vcpus,
            resume: Condvar::new(),
            resume_lock: Mutex::new(false),
            all_paused: Condvar::new(),
            all_paused_lock: Mutex::new(false),
            captured_states: Mutex::new(states),
        }
    }
}

/// Install a no-op SIGUSR1 handler.
///
/// SIGUSR1 is used to kick vCPUs out of KVM_RUN (causes EINTR).
/// The handler itself does nothing — we just need the signal delivery.
pub fn install_pause_signal_handler() {
    unsafe {
        libc::signal(libc::SIGUSR1, pause_signal_handler as *const () as libc::sighandler_t);
    }
}

extern "C" fn pause_signal_handler(_sig: libc::c_int) {
    // No-op — just interrupts KVM_RUN with EINTR.
}

/// CMOS/RTC ports
const CMOS_ADDR_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16 = 0x71;

pub struct Vcpu {
    id: u32,
    fd: VcpuFd,
    vm_fd: Arc<VmFd>,
    mmio_bus: Arc<Mutex<MmioBus>>,
    serial: Arc<Mutex<Serial>>,
    /// Currently selected CMOS register index (written via port 0x70).
    cmos_index: u8,
    /// ACPI PM1 registers (ports 0x600-0x607).
    /// PM1_STS (0x600-0x601), PM1_EN (0x602-0x603), PM1_CNT (0x604-0x605).
    pm_regs: [u8; 8],
    /// Shared pause state for snapshot coordination.
    pub pause_state: Option<Arc<VcpuPauseState>>,
    /// PCI bus for VFIO passthrough MMIO routing.
    pci_bus: Option<Arc<Mutex<crate::pci::PciBus>>>,
}

// SAFETY: VcpuFd wraps a file descriptor and is safe to move between threads.
// Each vCPU thread has exclusive ownership of its VcpuFd.
unsafe impl Send for Vcpu {}

impl Vcpu {
    /// Get the vCPU ID.
    pub fn id(&self) -> u32 {
        self.id
    }
}

/// Categorized exit for processing after dropping borrow on VcpuFd.
enum ExitAction {
    Hlt,
    Shutdown,
    IoOut { port: u16, byte: u8 },
    IoIn { port: u16 },
    MmioRead { addr: u64, len: usize },
    MmioWrite { addr: u64, data_bytes: [u8; 8], len: usize },
    Debug { pc: u64, dr6: u64 },
    Unknown(String),
}

impl Vcpu {
    pub fn new(
        kvm: &Kvm,
        vm_fd: &Arc<VmFd>,
        id: u32,
        entry_addr: GuestAddress,
        mmio_bus: Arc<Mutex<MmioBus>>,
        serial: Arc<Mutex<Serial>>,
    ) -> Result<Self> {
        let fd = vm_fd
            .create_vcpu(id as u64)
            .context("Failed to create vCPU")?;

        // Set up CPUID -- pass through host CPUID with KVM filtering
        let mut cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .context("Failed to get supported CPUID")?;

        // Minimal CPUID filtering — pass through host features.
        // Minimal CPUID filtering — pass through host features with a few tweaks.
        for entry in cpuid.as_mut_slice().iter_mut() {
            if entry.function == 0x1 {
                entry.edx |= 1 << 9; // APIC support (required)
                entry.edx &= !(1 << 7); // Disable MCE (machine check exception)
                entry.edx &= !(1 << 14); // Disable MCA (machine check architecture)
            }
            if entry.function == 0x7 && entry.index == 0 {
                entry.ecx &= !(1 << 16); // Disable LA57 (5-level paging)
            }
        }

        fd.set_cpuid2(&cpuid)
            .context("Failed to set CPUID")?;

        // Set up MSRs — enable MTRRs so the kernel initializes PAT correctly.
        // Without this, the kernel sees "MTRRs disabled" and skips PAT init,
        // resulting in wrong cache attributes (WB WT UC- UC instead of WB WC UC- UC).
        {
            let mut msrs = Msrs::new(2).context("Failed to allocate Msrs")?;
            let entries = msrs.as_mut_slice();
            // MTRRdefType (MSR 0x2FF): E=1 (bit 11), FE=1 (bit 10), default type=WB (6)
            entries[0].index = 0x2FF;
            entries[0].data = (1 << 11) | (1 << 10) | 6; // 0xC06
            // PAT MSR (0x277): Intel recommended defaults matching QEMU/SeaBIOS
            // PA0=WB(06) PA1=WC(01) PA2=UC-(07) PA3=UC(00)
            // PA4=WB(06) PA5=WP(05) PA6=UC-(07) PA7=WT(04)
            entries[1].index = 0x277;
            entries[1].data = 0x0007_0106_0007_0506_u64.swap_bytes();
            // Correct byte layout: PA7..PA0 = 04 07 05 06 00 07 01 06
            entries[1].data = 0x0407_0506_0007_0106;
            fd.set_msrs(&msrs).context("Failed to set MSRs")?;
        }

        // Set up LAPIC -- enable it via the spurious interrupt vector register
        let mut lapic = fd.get_lapic().context("Failed to get LAPIC state")?;
        // The APIC Spurious Interrupt Vector Register is at offset 0xF0.
        // Bit 8 = APIC Software Enable. Set it along with spurious vector 0xFF.
        let sivr_offset = 0xF0;
        let mut sivr = u32::from_le_bytes([
            lapic.regs[sivr_offset] as u8,
            lapic.regs[sivr_offset + 1] as u8,
            lapic.regs[sivr_offset + 2] as u8,
            lapic.regs[sivr_offset + 3] as u8,
        ]);
        sivr |= 1 << 8;   // Software enable
        sivr |= 0xFF;      // Spurious vector = 0xFF
        let sivr_bytes = sivr.to_le_bytes();
        lapic.regs[sivr_offset] = sivr_bytes[0] as i8;
        lapic.regs[sivr_offset + 1] = sivr_bytes[1] as i8;
        lapic.regs[sivr_offset + 2] = sivr_bytes[2] as i8;
        lapic.regs[sivr_offset + 3] = sivr_bytes[3] as i8;

        // Configure LINT0 for ExtINT delivery (PIT → 8259 PIC → LINT0).
        // Without this, PIC interrupts are masked and the PIT timer never fires.
        // LVT LINT0 at offset 0x350: delivery mode ExtINT (111b << 8 = 0x700), unmasked.
        let lint0_offset = 0x350;
        let lint0_val: u32 = 0x700; // ExtINT, unmasked, edge-triggered
        let lint0_bytes = lint0_val.to_le_bytes();
        lapic.regs[lint0_offset] = lint0_bytes[0] as i8;
        lapic.regs[lint0_offset + 1] = lint0_bytes[1] as i8;
        lapic.regs[lint0_offset + 2] = lint0_bytes[2] as i8;
        lapic.regs[lint0_offset + 3] = lint0_bytes[3] as i8;

        // Configure LINT1 for NMI delivery (standard).
        // LVT LINT1 at offset 0x360: delivery mode NMI (100b << 8 = 0x400), unmasked.
        let lint1_offset = 0x360;
        let lint1_val: u32 = 0x400; // NMI, unmasked
        let lint1_bytes = lint1_val.to_le_bytes();
        lapic.regs[lint1_offset] = lint1_bytes[0] as i8;
        lapic.regs[lint1_offset + 1] = lint1_bytes[1] as i8;
        lapic.regs[lint1_offset + 2] = lint1_bytes[2] as i8;
        lapic.regs[lint1_offset + 3] = lint1_bytes[3] as i8;

        fd.set_lapic(&lapic).context("Failed to set LAPIC state")?;

        // Set up special registers (sregs) -- configure long mode (64-bit)
        let mut sregs = fd.get_sregs().context("Failed to get sregs")?;
        setup_long_mode(&mut sregs);
        fd.set_sregs(&sregs).context("Failed to set sregs")?;

        // Only set up registers for BSP (vCPU 0). AP vCPUs start in
        // "wait for SIPI" state — KVM + in-kernel LAPIC handles the
        // INIT/SIPI sequence automatically when the kernel brings up APs.
        if id == 0 {
            let mut regs = fd.get_regs().context("Failed to get regs")?;
            regs.rip = entry_addr.0;
            regs.rflags = 0x2; // bit 1 is always set
            // Linux boot protocol: rsi = pointer to boot_params (at 0x7000 by convention)
            regs.rsi = boot_params_addr();
            fd.set_regs(&regs).context("Failed to set regs")?;
        }

        Ok(Self { id, fd, vm_fd: Arc::clone(vm_fd), mmio_bus, serial, cmos_index: 0, pm_regs: [0u8; 8], pause_state: None, pci_bus: None })
    }

    /// Set the shared pause state for snapshot coordination.
    pub fn set_pause_state(&mut self, state: Arc<VcpuPauseState>) {
        self.pause_state = Some(state);
    }

    /// Set the PCI bus for VFIO passthrough MMIO routing.
    pub fn set_pci_bus(&mut self, bus: Arc<Mutex<crate::pci::PciBus>>) {
        self.pci_bus = Some(bus);
    }

    /// Create a vCPU and restore its register state from a template snapshot.
    ///
    /// Used by `clone fork` to resume from a CoW template without re-booting.
    pub fn from_template(
        kvm: &Kvm,
        vm_fd: &Arc<VmFd>,
        id: u32,
        vcpu_state: &crate::boot::template::VcpuState,
        mmio_bus: Arc<Mutex<MmioBus>>,
        serial: Arc<Mutex<Serial>>,
    ) -> Result<Self> {
        let fd = vm_fd
            .create_vcpu(id as u64)
            .context("Failed to create vCPU")?;

        // Set up CPUID (same as cold boot)
        let mut cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .context("Failed to get supported CPUID")?;

        for entry in cpuid.as_mut_slice().iter_mut() {
            if entry.function == 0x1 {
                entry.edx |= 1 << 9;
                entry.edx &= !(1 << 7);
                entry.edx &= !(1 << 14);
            }
            if entry.function == 0x7 && entry.index == 0 {
                entry.ecx &= !(1 << 16);
            }
        }
        fd.set_cpuid2(&cpuid).context("Failed to set CPUID")?;

        // Restore general-purpose registers from template
        if vcpu_state.regs.len() == std::mem::size_of::<kvm_bindings::kvm_regs>() {
            let regs: kvm_bindings::kvm_regs =
                unsafe { std::ptr::read(vcpu_state.regs.as_ptr() as *const _) };
            fd.set_regs(&regs).context("Failed to restore kvm_regs from template")?;
        } else {
            anyhow::bail!(
                "Template vcpu_state.regs has wrong size: {} (expected {})",
                vcpu_state.regs.len(),
                std::mem::size_of::<kvm_bindings::kvm_regs>()
            );
        }

        // Restore special registers from template
        if vcpu_state.sregs.len() == std::mem::size_of::<kvm_bindings::kvm_sregs>() {
            let sregs: kvm_bindings::kvm_sregs =
                unsafe { std::ptr::read(vcpu_state.sregs.as_ptr() as *const _) };
            fd.set_sregs(&sregs).context("Failed to restore kvm_sregs from template")?;
        } else {
            anyhow::bail!(
                "Template vcpu_state.sregs has wrong size: {} (expected {})",
                vcpu_state.sregs.len(),
                std::mem::size_of::<kvm_bindings::kvm_sregs>()
            );
        }

        // Set up LAPIC (same as cold boot)
        let mut lapic = fd.get_lapic().context("Failed to get LAPIC state")?;
        let sivr_offset = 0xF0;
        let mut sivr = u32::from_le_bytes([
            lapic.regs[sivr_offset] as u8,
            lapic.regs[sivr_offset + 1] as u8,
            lapic.regs[sivr_offset + 2] as u8,
            lapic.regs[sivr_offset + 3] as u8,
        ]);
        sivr |= 1 << 8;
        sivr |= 0xFF;
        let sivr_bytes = sivr.to_le_bytes();
        lapic.regs[sivr_offset] = sivr_bytes[0] as i8;
        lapic.regs[sivr_offset + 1] = sivr_bytes[1] as i8;
        lapic.regs[sivr_offset + 2] = sivr_bytes[2] as i8;
        lapic.regs[sivr_offset + 3] = sivr_bytes[3] as i8;

        let lint0_offset = 0x350;
        let lint0_val: u32 = 0x700;
        let lint0_bytes = lint0_val.to_le_bytes();
        lapic.regs[lint0_offset] = lint0_bytes[0] as i8;
        lapic.regs[lint0_offset + 1] = lint0_bytes[1] as i8;
        lapic.regs[lint0_offset + 2] = lint0_bytes[2] as i8;
        lapic.regs[lint0_offset + 3] = lint0_bytes[3] as i8;

        let lint1_offset = 0x360;
        let lint1_val: u32 = 0x400;
        let lint1_bytes = lint1_val.to_le_bytes();
        lapic.regs[lint1_offset] = lint1_bytes[0] as i8;
        lapic.regs[lint1_offset + 1] = lint1_bytes[1] as i8;
        lapic.regs[lint1_offset + 2] = lint1_bytes[2] as i8;
        lapic.regs[lint1_offset + 3] = lint1_bytes[3] as i8;

        fd.set_lapic(&lapic).context("Failed to set LAPIC state")?;

        tracing::info!("vCPU {} restored from template", id);

        Ok(Self { id, fd, vm_fd: Arc::clone(vm_fd), mmio_bus, serial, cmos_index: 0, pm_regs: [0u8; 8], pause_state: None, pci_bus: None })
    }

    /// Capture current vCPU register state for snapshotting.
    pub fn capture_state(&self) -> Result<crate::boot::template::VcpuState> {
        let regs = self.fd.get_regs().context("Failed to get kvm_regs")?;
        let sregs = self.fd.get_sregs().context("Failed to get kvm_sregs")?;

        let regs_bytes = unsafe {
            std::slice::from_raw_parts(
                &regs as *const kvm_bindings::kvm_regs as *const u8,
                std::mem::size_of::<kvm_bindings::kvm_regs>(),
            )
            .to_vec()
        };

        let sregs_bytes = unsafe {
            std::slice::from_raw_parts(
                &sregs as *const kvm_bindings::kvm_sregs as *const u8,
                std::mem::size_of::<kvm_bindings::kvm_sregs>(),
            )
            .to_vec()
        };

        Ok(crate::boot::template::VcpuState {
            regs: regs_bytes,
            sregs: sregs_bytes,
        })
    }

    /// Check if a pause has been requested and handle it.
    ///
    /// Captures register state, increments paused count, notifies the
    /// control socket, then parks until resumed.
    fn check_pause(&self) {
        if let Some(ref ps) = self.pause_state {
            if ps.pause_requested.load(Ordering::SeqCst) {
                // Capture register state
                match self.capture_state() {
                    Ok(state) => {
                        let mut states = ps.captured_states.lock().unwrap();
                        states[self.id as usize] = Some(state);
                    }
                    Err(e) => {
                        tracing::error!("vCPU {} failed to capture state: {e}", self.id);
                    }
                }

                // Increment paused count and notify waiter
                let prev = ps.paused_count.fetch_add(1, Ordering::SeqCst);
                if prev + 1 >= ps.total_vcpus {
                    let mut locked = ps.all_paused_lock.lock().unwrap();
                    *locked = true;
                    ps.all_paused.notify_all();
                }

                // Park until resumed
                let mut resumed = ps.resume_lock.lock().unwrap();
                while ps.pause_requested.load(Ordering::SeqCst) {
                    resumed = ps.resume.wait(resumed).unwrap();
                }
            }
        }
    }

    pub fn run_loop(&mut self) -> Result<()> {
        tracing::info!("vCPU {} entering run loop", self.id);
        let mut exit_count: u64 = 0;
        let mut serial_bytes: u64 = 0;

        loop {
            if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                self.serial.lock().unwrap().flush_output();
                if let Ok(regs) = self.fd.get_regs() {
                    tracing::info!(
                        "vCPU {} shutting down: RIP={:#x} RSP={:#x} RFLAGS={:#x} exits={} serial={}",
                        self.id, regs.rip, regs.rsp, regs.rflags, exit_count, serial_bytes
                    );
                } else {
                    tracing::info!("vCPU {} shutting down (signal received)", self.id);
                }
                break;
            }
            let action = match self.fd.run() {
                Ok(exit) => match exit {
                    VcpuExit::Hlt => ExitAction::Hlt,
                    VcpuExit::Shutdown => ExitAction::Shutdown,
                    VcpuExit::IoOut(port, data) => {
                        let byte = data.first().copied().unwrap_or(0);
                        ExitAction::IoOut { port, byte }
                    }
                    VcpuExit::IoIn(port, data) => {
                        if port >= COM1_PORT_BASE && port < COM1_PORT_BASE + COM1_PORT_COUNT {
                            let offset = port - COM1_PORT_BASE;
                            let val = self.serial.lock().unwrap().read(offset);
                            if let Some(b) = data.first_mut() { *b = val; }
                        } else if port == CMOS_DATA_PORT {
                            if let Some(b) = data.first_mut() { *b = cmos_read(self.cmos_index); }
                        } else if port >= 0x600 && port <= 0x607 {
                            let offset = (port - 0x600) as usize;
                            if let Some(b) = data.first_mut() {
                                *b = self.pm_regs[offset];
                            }
                        } else {
                            data.fill(0x00);
                            tracing::trace!("IoIn port={port:#x} len={}", data.len());
                        }
                        ExitAction::IoIn { port }
                    }
                    VcpuExit::MmioRead(addr, data) => {
                        let mut handled = false;
                        // Try PCI bus first (ECAM + BAR regions)
                        if let Some(ref pci_bus) = self.pci_bus {
                            let bus = pci_bus.lock().unwrap();
                            if bus.handle_ecam_read(addr, data) {
                                handled = true;
                            } else if bus.handle_bar_read(addr, data) {
                                handled = true;
                            }
                        }
                        if !handled {
                            let bus = self.mmio_bus.lock().unwrap();
                            if !bus.handle_read(addr, data) {
                                data.fill(0xFF);
                                tracing::warn!("MMIO read: unhandled addr={addr:#x}, len={}", data.len());
                            }
                        }
                        ExitAction::MmioRead { addr, len: data.len() }
                    }
                    VcpuExit::MmioWrite(addr, data) => {
                        let len = data.len();
                        let mut data_bytes = [0u8; 8];
                        let copy_len = len.min(8);
                        data_bytes[..copy_len].copy_from_slice(&data[..copy_len]);
                        ExitAction::MmioWrite { addr, data_bytes, len }
                    }
                    VcpuExit::Debug(dbg_info) => ExitAction::Debug { pc: dbg_info.pc, dr6: dbg_info.dr6 },
                    other => ExitAction::Unknown(format!("{:?}", other)),
                },
                Err(e) => {
                    if e.errno() == libc::EAGAIN || e.errno() == libc::EINTR {
                        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                            self.serial.lock().unwrap().flush_output();
                            if let Ok(regs) = self.fd.get_regs() {
                                let cr2 = self.fd.get_sregs().map(|s| s.cr2).unwrap_or(0);
                                tracing::info!(
                                    "vCPU {} signal shutdown: RIP={:#x} RSP={:#x} CR2={:#x} RFLAGS={:#x} exits={} serial={}",
                                    self.id, regs.rip, regs.rsp, cr2, regs.rflags, exit_count, serial_bytes
                                );
                            } else {
                                tracing::info!("vCPU {} received shutdown signal", self.id);
                            }
                            break;
                        }
                        // Check if this EINTR was from a pause request (SIGUSR1)
                        self.check_pause();
                        continue;
                    }
                    if let Ok(regs) = self.fd.get_regs() {
                        if let Ok(sregs) = self.fd.get_sregs() {
                            tracing::error!(
                                "vCPU {} FATAL: RIP={:#x} RSP={:#x} CR3={:#x} CR2={:#x} RFLAGS={:#x} exit={}",
                                self.id, regs.rip, regs.rsp, sregs.cr3, sregs.cr2, regs.rflags, exit_count
                            );
                        }
                    }
                    anyhow::bail!("vCPU {} run failed: {e}", self.id);
                }
            };

            exit_count += 1;
            if exit_count % 100_000 == 0 {
                tracing::info!(
                    "vCPU {} exits={}, serial_bytes={}",
                    self.id, exit_count, serial_bytes
                );
            }

            match action {
                ExitAction::Hlt => {
                    self.serial.lock().unwrap().flush_output();
                    tracing::info!(
                        "vCPU {} halted (exits={}, serial_bytes={})",
                        self.id, exit_count, serial_bytes
                    );
                    break;
                }
                ExitAction::Shutdown => {
                    self.serial.lock().unwrap().flush_output();
                    tracing::info!("vCPU {} shutdown", self.id);
                    break;
                }
                ExitAction::IoOut { port, byte } => {
                    if port >= COM1_PORT_BASE && port < COM1_PORT_BASE + COM1_PORT_COUNT {
                        let offset = port - COM1_PORT_BASE;
                        if offset == 0 {
                            serial_bytes += 1;
                        }
                        let mut serial = self.serial.lock().unwrap();
                        serial.write(offset, byte);
                        // If serial now has a pending interrupt, raise IRQ 4
                        let needs_irq = serial.interrupt_pending();
                        drop(serial);
                        if needs_irq {
                            let _ = self.vm_fd.set_irq_line(4, true);
                            let _ = self.vm_fd.set_irq_line(4, false);
                        }
                    } else if port == CMOS_ADDR_PORT {
                        self.cmos_index = byte & 0x7F;
                    } else if port == CMOS_DATA_PORT {
                        // ignore
                    } else if port >= 0x600 && port <= 0x607 {
                        let offset = (port - 0x600) as usize;
                        self.pm_regs[offset] = byte;
                    } else {
                        tracing::trace!("IoOut port={port:#x}");
                    }
                }
                ExitAction::IoIn { .. } => {}
                ExitAction::MmioRead { .. } => {}
                ExitAction::MmioWrite { addr, data_bytes, len } => {
                    let mut pci_handled = false;
                    // Try PCI bus first (ECAM + BAR regions)
                    if let Some(ref pci_bus) = self.pci_bus {
                        let mut bus = pci_bus.lock().unwrap();
                        if bus.handle_ecam_write(addr, &data_bytes[..len]) {
                            pci_handled = true;
                        } else if bus.handle_bar_write(addr, &data_bytes[..len]) {
                            pci_handled = true;
                        }
                    }
                    if !pci_handled {
                        let (handled, irq) = {
                            let mut bus = self.mmio_bus.lock().unwrap();
                            bus.handle_write(addr, &data_bytes[..len])
                        };
                        if !handled {
                            tracing::warn!("MMIO write: unhandled addr={addr:#x}, len={len}");
                        }
                        if let Some(irq) = irq {
                            let _ = self.vm_fd.set_irq_line(irq, true);
                            let _ = self.vm_fd.set_irq_line(irq, false);
                        }
                    }
                }
                ExitAction::Debug { pc, dr6 } => {
                    tracing::warn!("Debug exit: PC={:#x} DR6={:#x} exit={}", pc, dr6, exit_count);
                }
                ExitAction::Unknown(desc) => {
                    tracing::warn!("vCPU {} unhandled exit: {}", self.id, desc);
                    break;
                }
            }
        }

        Ok(())
    }
}


/// Minimal CMOS/RTC register read.
///
/// The kernel reads CMOS during boot for time-of-day and hardware detection.
/// Critical: register 0x0A bit 7 must be 0 (no update in progress) or the
/// kernel spins forever waiting for the RTC update cycle to finish.
fn cmos_read(index: u8) -> u8 {
    match index {
        // RTC time registers — return epoch-ish values (BCD format)
        0x00 => 0x00, // Seconds
        0x02 => 0x00, // Minutes
        0x04 => 0x00, // Hours
        0x06 => 0x04, // Day of week (Thursday)
        0x07 => 0x01, // Day of month
        0x08 => 0x01, // Month (January)
        0x09 => 0x24, // Year (BCD: 24 → 2024)
        0x0A => 0x26, // Status Register A: divider=010 (32.768kHz), rate=0110, UIP=0
        0x0B => 0x02, // Status Register B: 24-hour mode, BCD format
        0x0C => 0x00, // Status Register C: no interrupt flags
        0x0D => 0x80, // Status Register D: RTC has power (bit 7)
        0x32 => 0x20, // Century (BCD: 20)
        _ => 0x00,
    }
}

/// Address where boot_params struct is placed in guest memory.
/// Convention from Linux x86 boot protocol.
fn boot_params_addr() -> u64 {
    0x7000
}

/// Configure segment registers and page tables for 64-bit long mode.
fn setup_long_mode(sregs: &mut kvm_bindings::kvm_sregs) {
    // Set up page tables for identity mapping
    // PML4 at 0x9000, PDPT at 0xA000, PD at 0xB000
    // (actual page table contents written to guest memory during boot::load_kernel)

    // GDT at 0x500 in guest memory (4 entries = 32 bytes)
    sregs.gdt.base = 0x500;
    sregs.gdt.limit = 31; // 4 entries * 8 bytes - 1

    // IDT: empty initially, kernel will set up its own
    sregs.idt.base = 0;
    sregs.idt.limit = 0;

    sregs.cr0 = 0x8003_0001; // PG | PE | WP | ET
    sregs.cr3 = 0x9000;       // PML4 base
    sregs.cr4 = 0x20;         // PAE
    sregs.efer = 0x500;       // LME | LMA (long mode enable + active)

    // Code segment -- 64-bit mode
    sregs.cs.base = 0;
    sregs.cs.limit = 0xFFFF_FFFF;
    sregs.cs.selector = 0x10; // GDT entry 2
    sregs.cs.type_ = 0xB;    // execute/read, accessed
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 0;         // must be 0 for 64-bit
    sregs.cs.s = 1;
    sregs.cs.l = 1;          // 64-bit mode
    sregs.cs.g = 1;

    // Data segment
    sregs.ds.base = 0;
    sregs.ds.limit = 0xFFFF_FFFF;
    sregs.ds.selector = 0x18; // GDT entry 3
    sregs.ds.type_ = 0x3;    // read/write, accessed
    sregs.ds.present = 1;
    sregs.ds.dpl = 0;
    sregs.ds.db = 1;
    sregs.ds.s = 1;
    sregs.ds.g = 1;

    sregs.es = sregs.ds;
    sregs.fs = sregs.ds;
    sregs.gs = sregs.ds;
    sregs.ss = sregs.ds;
}
