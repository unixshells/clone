pub mod agent_listener;
pub mod serial;
pub mod vcpu;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use kvm_bindings::{
    kvm_pit_config, kvm_userspace_memory_region,
    kvm_irq_routing, kvm_irq_routing_entry,
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQCHIP_IOAPIC,
    KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    KVM_PIT_SPEAKER_DUMMY, KVM_MEM_LOG_DIRTY_PAGES,
};
use kvm_ioctls::{Kvm, VmFd};

use crate::boot;
use crate::memory;
use std::os::unix::io::AsRawFd;

use crate::virtio::balloon::VirtioBalloon;
use crate::virtio::mmio::MmioBus;
use crate::virtio::vsock::VirtioVsock;
use crate::virtio::MMIO_STRIDE;

use self::serial::{RawModeGuard, Serial};

pub struct VmConfig {
    pub kernel_path: String,
    pub initrd_path: Option<String>,
    pub cmdline: String,
    pub mem_mb: u32,
    pub vcpus: u32,
    pub block_device: Option<String>,
    /// Secondary block device for overlay storage (mounted as /dev/vdb in guest).
    pub overlay_device: Option<String>,
    pub tap_device: Option<String>,
    /// Host directory to share via virtio-fs, format: "/host/path:tag".
    pub shared_dir: Option<String>,
    /// PCI devices to pass through via VFIO (BDF strings, e.g., "0000:01:00.0").
    pub passthrough_devices: Vec<String>,
    /// Enable seccomp BPF filter.
    pub seccomp: bool,
    /// Chroot directory for full jail.
    pub jail: Option<String>,
    /// Guest vsock CID (default: 3).
    pub cid: Option<u64>,
    /// Pre-opened TAP file descriptor (from auto_setup_network).
    /// If set, boot() uses this fd directly instead of calling create_tap().
    pub tap_fd: Option<i32>,
    /// Guest IP address for point-to-point networking (from auto_setup_network).
    pub guest_ip: Option<[u8; 4]>,
}

pub struct Vm {
    config: VmConfig,
    kvm: Kvm,
    vm_fd: Arc<VmFd>,
    guest_memory: Option<memory::GuestMem>,
    vcpus: Vec<vcpu::Vcpu>,
    mmio_bus: Arc<Mutex<MmioBus>>,
    serial: Arc<Mutex<Serial>>,
    /// (call_fds, device_index, irq) for the vhost-net call eventfd monitoring thread.
    net_call_info: Option<([i32; 2], usize, u32)>,
    /// (tap_fd, device_index, irq, kick_eventfd) for userspace net (fork path).
    net_tap_info: Option<(i32, usize, u32, i32)>,
    /// Vsock host-side fd (for agent_listener), device index, and IRQ.
    vsock_host_fd: Option<i32>,
    vsock_dev_index: Option<usize>,
    vsock_irq: Option<u32>,
    /// Shared balloon target (num_pages) for the tick thread.
    balloon_num_pages: Option<Arc<std::sync::atomic::AtomicU32>>,
    /// Balloon device IRQ number (for injecting config-change interrupts).
    balloon_irq: Option<u32>,
    /// Total guest memory in bytes (for balloon policy).
    mem_size: u64,
    /// Actual KVM memory slot size in bytes (includes guard region).
    /// Must be used for get_dirty_log to match the registered slot size.
    kvm_slot_size: u64,
    /// PCI bus for VFIO passthrough devices.
    pci_bus: Option<Arc<Mutex<crate::pci::PciBus>>>,
}

impl Vm {
    pub fn new(config: VmConfig) -> Result<Self> {
        let kvm = Kvm::new().context("Failed to open /dev/kvm")?;

        // Check KVM API version
        let api_version = kvm.get_api_version();
        if api_version != 12 {
            anyhow::bail!("Unsupported KVM API version: {api_version} (expected 12)");
        }

        let vm_fd = Arc::new(kvm.create_vm().context("Failed to create VM")?);

        Ok(Self {
            config,
            kvm,
            vm_fd,
            guest_memory: None,
            vcpus: Vec::new(),
            mmio_bus: Arc::new(Mutex::new(MmioBus::new())),
            serial: Arc::new(Mutex::new(Serial::new())),
            net_call_info: None,
            net_tap_info: None,
            vsock_host_fd: None,
            vsock_dev_index: None,
            vsock_irq: None,
            balloon_num_pages: None,
            balloon_irq: None,
            mem_size: 0,
            kvm_slot_size: 0,
            pci_bus: None,
        })
    }

    /// Get a reference to the MMIO bus for registering devices.
    pub fn mmio_bus(&self) -> &Arc<Mutex<MmioBus>> {
        &self.mmio_bus
    }

    pub fn boot(&mut self) -> Result<()> {
        let boot_start = std::time::Instant::now();

        // 1. Set up guest memory with overcommit (MAP_NORESERVE)
        let mem_size = (self.config.mem_mb as u64) << 20;
        let guard_size: u64 = 128 << 20; // 128MB guard past e820 end
        let mmio_hole_start: u64 = 0xC000_0000; // 3 GB — MMIO hole starts here
        let mmio_hole_end: u64 = 0x1_0000_0000; // 4 GB — MMIO hole ends here

        let alloc_size = if mem_size <= mmio_hole_start {
            mem_size + guard_size
        } else {
            mmio_hole_start + (mem_size - mmio_hole_start) + guard_size
        };

        let guest_memory = if mem_size <= mmio_hole_start {
            memory::create_guest_memory(alloc_size)
                .context("Failed to create guest memory")?
        } else {
            memory::create_guest_memory_with_hole(alloc_size, mmio_hole_start, mmio_hole_end)
                .context("Failed to create guest memory")?
        };

        // 2. Register memory region(s) with KVM
        if !guest_memory.has_hole() {
            // Small VM: single KVM slot
            let mem_region = kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: mem_size + guard_size,
                userspace_addr: guest_memory.as_ptr() as u64,
                flags: KVM_MEM_LOG_DIRTY_PAGES,
            };
            unsafe {
                self.vm_fd
                    .set_user_memory_region(mem_region)
                    .context("Failed to set KVM memory region")?;
            }
        } else {
            // Large VM: two KVM slots around the MMIO hole
            let above_hole = mem_size - mmio_hole_start;

            // Slot 0: GPA [0, hole_start) — below MMIO hole
            let region0 = kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: mmio_hole_start,
                userspace_addr: guest_memory.as_ptr() as u64,
                flags: KVM_MEM_LOG_DIRTY_PAGES,
            };
            unsafe {
                self.vm_fd
                    .set_user_memory_region(region0)
                    .context("Failed to set KVM memory region (below MMIO hole)")?;
            }

            // Slot 1: GPA [hole_end, hole_end + above_hole + guard) — above 4GB
            let region1 = kvm_userspace_memory_region {
                slot: 1,
                guest_phys_addr: mmio_hole_end,
                memory_size: above_hole + guard_size,
                userspace_addr: (guest_memory.as_ptr() as u64) + mmio_hole_start,
                flags: KVM_MEM_LOG_DIRTY_PAGES,
            };
            unsafe {
                self.vm_fd
                    .set_user_memory_region(region1)
                    .context("Failed to set KVM memory region (above 4GB)")?;
            }

            tracing::info!(
                "Split memory: slot0=0..{:#x} ({}MB), slot1={:#x}..+{}MB, total={}MB",
                mmio_hole_start, mmio_hole_start >> 20,
                mmio_hole_end, above_hole >> 20,
                mem_size >> 20,
            );
        }

        let t_memory = boot_start.elapsed();

        // 3. Create in-kernel irqchip (LAPIC + IOAPIC) -- must happen before vCPU creation
        self.vm_fd
            .create_irq_chip()
            .context("Failed to create in-kernel irqchip (LAPIC + IOAPIC)")?;

        // 4. Create in-kernel PIT (i8254 timer) -- must happen before vCPU creation
        //    KVM_PIT_SPEAKER_DUMMY: handle port 0x61 in-kernel so the kernel's
        //    PIT verification loop (which reads port 0x61 bit 5) works correctly.
        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        self.vm_fd
            .create_pit2(pit_config)
            .context("Failed to create in-kernel PIT (i8254)")?;

        // 5. Set up explicit GSI routing (PIT/PIC/IOAPIC)
        setup_gsi_routing(&self.vm_fd)?;

        let t_irqchip = boot_start.elapsed();
        tracing::info!("In-kernel irqchip (LAPIC + IOAPIC) and PIT created");

        // 5. Register virtio devices with the MMIO bus
        let mut virtio_cmdline_params = Vec::new();

        {
            let mut mmio_bus = self.mmio_bus.lock().unwrap();

            // Register virtio-balloon (use alloc_size so PFNs above the MMIO hole are valid)
            let balloon = VirtioBalloon::new(guest_memory.as_ptr(), alloc_size);
            let balloon_num_pages = Arc::clone(&balloon.config().num_pages);
            self.balloon_num_pages = Some(balloon_num_pages);
            self.mem_size = mem_size;
            self.kvm_slot_size = alloc_size;
            let (base, irq) = mmio_bus.register(Box::new(balloon));
            self.balloon_irq = Some(irq);
            virtio_cmdline_params.push(format!(
                "virtio_mmio.device=0x{:x}@0x{:x}:{}",
                MMIO_STRIDE, base, irq
            ));

            // Register virtio-vsock (userspace backend)
            match VirtioVsock::new(self.config.cid.unwrap_or(3)) {
                Ok(mut vsock) => {
                    let dev_idx = mmio_bus.device_count();
                    let predicted_irq = crate::virtio::IRQ_BASE + dev_idx as u32;
                    self.vsock_host_fd = Some(vsock.take_host_fd());
                    self.vsock_dev_index = Some(dev_idx);
                    self.vsock_irq = Some(predicted_irq);
                    let (base, irq) = mmio_bus.register(Box::new(vsock));
                    debug_assert_eq!(irq, predicted_irq);
                    virtio_cmdline_params.push(format!(
                        "virtio_mmio.device=0x{:x}@0x{:x}:{}",
                        MMIO_STRIDE, base, irq
                    ));
                }
                Err(e) => {
                    tracing::warn!("Failed to create virtio-vsock: {e}");
                }
            }

            // Register virtio-block if a disk image was provided
            if let Some(ref block_path) = self.config.block_device {
                match crate::virtio::block::VirtioBlock::open(block_path, false) {
                    Ok(block) => {
                        let (base, irq) = mmio_bus.register(Box::new(block));
                        virtio_cmdline_params.push(format!(
                            "virtio_mmio.device=0x{:x}@0x{:x}:{}",
                            MMIO_STRIDE, base, irq
                        ));
                    }
                    Err(e) => {
                        tracing::warn!("Failed to open block device {block_path}: {e}");
                    }
                }
            }

            // Register overlay block device (/dev/vdb in guest)
            if let Some(ref overlay_path) = self.config.overlay_device {
                match crate::virtio::block::VirtioBlock::open(overlay_path, false) {
                    Ok(block) => {
                        let (base, irq) = mmio_bus.register(Box::new(block));
                        virtio_cmdline_params.push(format!(
                            "virtio_mmio.device=0x{:x}@0x{:x}:{}",
                            MMIO_STRIDE, base, irq
                        ));
                        tracing::info!("Overlay block device registered: {overlay_path}");
                    }
                    Err(e) => {
                        tracing::warn!("Failed to open overlay device {overlay_path}: {e}");
                    }
                }
            }

            // Register virtio-fs if a shared directory was provided
            if let Some(ref shared_dir_spec) = self.config.shared_dir {
                // Format: "/host/path:tag" or just "/host/path" (tag defaults to "fs0")
                let (dir_path, tag) = if let Some(colon_pos) = shared_dir_spec.rfind(':') {
                    let path = &shared_dir_spec[..colon_pos];
                    let tag = &shared_dir_spec[colon_pos + 1..];
                    (path.to_string(), tag.to_string())
                } else {
                    (shared_dir_spec.clone(), "fs0".to_string())
                };

                let root_dir = std::path::PathBuf::from(&dir_path);
                if root_dir.is_dir() {
                    let fs_dev = crate::virtio::fs::VirtioFs::new(root_dir, tag.clone());
                    let (base, irq) = mmio_bus.register(Box::new(fs_dev));
                    virtio_cmdline_params.push(format!(
                        "virtio_mmio.device=0x{:x}@0x{:x}:{}",
                        MMIO_STRIDE, base, irq
                    ));
                    tracing::info!("virtio-fs registered: dir={dir_path}, tag={tag}");
                } else {
                    tracing::warn!("Shared directory does not exist: {dir_path}");
                }
            }

            // Register virtio-net if a TAP device was provided
            if let Some(ref tap_name) = self.config.tap_device {
                // Use pre-opened TAP fd if available (from auto_setup_network),
                // otherwise create a new TAP device by name.
                let tap_result = if let Some(fd) = self.config.tap_fd {
                    tracing::info!("Using pre-opened TAP fd={fd} for {tap_name}");
                    Ok(fd)
                } else {
                    crate::net::create_tap(tap_name)
                };
                match tap_result {
                    Ok(tap_fd) => {
                        let mac = crate::net::NetworkConfig::mac_from_id(1);
                        let mut net_dev = crate::virtio::net::VirtioNet::new(tap_fd, mac);
                        // Pre-compute IRQ and pass VM fd for vhost-net setup
                        let irq = crate::virtio::IRQ_BASE + mmio_bus.device_count() as u32;
                        net_dev.set_vm_info(self.vm_fd.as_raw_fd(), irq);
                        let call_fds = net_dev.call_fds();
                        let dev_index = mmio_bus.device_count();
                        let (base, actual_irq) = mmio_bus.register(Box::new(net_dev));
                        debug_assert_eq!(irq, actual_irq);
                        virtio_cmdline_params.push(format!(
                            "virtio_mmio.device=0x{:x}@0x{:x}:{}",
                            MMIO_STRIDE, base, actual_irq
                        ));
                        self.net_call_info = Some((call_fds, dev_index, actual_irq));
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create TAP device {tap_name}: {e}");
                    }
                }
            }
        }

        // Set guest memory on the MMIO bus for virtqueue descriptor chain processing
        {
            let mut mmio_bus = self.mmio_bus.lock().unwrap();
            mmio_bus.set_guest_memory_with_hole(guest_memory.as_ptr(), guest_memory.size(), guest_memory.hole_start(), guest_memory.hole_end());
        }

        // Build the final kernel command line with virtio_mmio.device parameters
        let mut cmdline = self.config.cmdline.clone();

        // Append agent port to cmdline so the guest agent connects to the right port.
        // Use the fixed base port — after CoW fork the kernel cmdline is immutable,
        // so the agent must always connect to the same port.
        let agent_port = agent_listener::AGENT_VSOCK_PORT_BASE;
        if !cmdline.contains("clone.agent_port=") {
            cmdline.push_str(&format!(" clone.agent_port={}", agent_port));
        }

        for param in &virtio_cmdline_params {
            cmdline.push(' ');
            cmdline.push_str(param);
        }

        // 5b. Set up PCI bus and VFIO passthrough devices
        let pci_enabled = !self.config.passthrough_devices.is_empty();
        if pci_enabled {
            let mut pci_bus = crate::pci::PciBus::new();
            for bdf_str in &self.config.passthrough_devices {
                match crate::pci::vfio::VfioDevice::open(bdf_str) {
                    Ok(mut vfio_dev) => {
                        // Map guest memory for DMA
                        if let Err(e) = vfio_dev.map_dma(guest_memory.as_ptr(), alloc_size) {
                            tracing::error!("Failed to map DMA for {bdf_str}: {e}");
                            continue;
                        }
                        match pci_bus.add_vfio_device(vfio_dev) {
                            Ok(bdf) => {
                                tracing::info!("VFIO passthrough: {bdf_str} → PCI {bdf}");
                            }
                            Err(e) => {
                                tracing::error!("Failed to add VFIO device {bdf_str}: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to open VFIO device {bdf_str}: {e}");
                    }
                }
            }
            self.pci_bus = Some(Arc::new(Mutex::new(pci_bus)));
        }

        let t_devices = boot_start.elapsed();
        tracing::info!("Kernel command line: {cmdline}");

        // 6. Load kernel into guest memory
        let kernel_entry = boot::load_kernel_with_pci(
            &guest_memory,
            &self.config.kernel_path,
            self.config.initrd_path.as_deref(),
            &cmdline,
            self.config.vcpus,
            mem_size,
            pci_enabled,
        )
        .context("Failed to load kernel")?;

        let t_kernel = boot_start.elapsed();
        tracing::info!("Kernel entry point: {:#x}", kernel_entry.0);

        // 7. Create vCPUs
        for id in 0..self.config.vcpus {
            let mut vcpu = vcpu::Vcpu::new(
                &self.kvm,
                &self.vm_fd,
                id,
                kernel_entry,
                Arc::clone(&self.mmio_bus),
                Arc::clone(&self.serial),
            )?;
            if let Some(ref pci_bus) = self.pci_bus {
                vcpu.set_pci_bus(Arc::clone(pci_bus));
            }
            self.vcpus.push(vcpu);
        }

        self.guest_memory = Some(guest_memory);

        let t_total = boot_start.elapsed();
        tracing::info!(
            memory_us = t_memory.as_micros(),
            irqchip_us = t_irqchip.as_micros(),
            devices_us = t_devices.as_micros(),
            kernel_us = t_kernel.as_micros(),
            total_us = t_total.as_micros(),
            "Boot timing breakdown (microseconds)"
        );

        Ok(())
    }

    /// Boot from a CoW template snapshot (fork path).
    ///
    /// Instead of loading a kernel, this maps the template's memory file
    /// with MAP_PRIVATE (CoW) and restores vCPU register state. This is the
    /// primary mechanism for <20ms cold starts.
    pub fn fork_boot(&mut self, template_dir: &str, skip_verify: bool, mem_limit_mb: Option<u32>, vcpu_limit: Option<u32>, overlay_size: Option<&str>) -> Result<()> {
        use crate::boot::template::{TemplateSnapshot, fork_from_template};
        use crate::boot::identity;

        let template = TemplateSnapshot::load(template_dir, !skip_verify)?;

        // 1. Fork guest memory from template (CoW mmap)
        let guest_memory = fork_from_template(&template)
            .context("Failed to fork memory from template")?;

        let mem_size = template.memory_size;

        // 2. Register memory region(s) with KVM
        // KVM_MEM_LOG_DIRTY_PAGES enables dirty page tracking for incremental snapshots.
        let mmio_hole_start: u64 = 0xC000_0000;
        let mmio_hole_end: u64 = 0x1_0000_0000;
        let guard_size: u64 = 128 << 20;

        if mem_size <= mmio_hole_start {
            // Small VM: single KVM slot
            let mem_region = kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: mem_size,
                userspace_addr: guest_memory.as_ptr() as u64,
                flags: KVM_MEM_LOG_DIRTY_PAGES,
            };
            unsafe {
                self.vm_fd
                    .set_user_memory_region(mem_region)
                    .context("Failed to set KVM memory region")?;
            }
            self.kvm_slot_size = mem_size;
        } else {
            // Large VM: two KVM slots around the MMIO hole
            let above_hole = mem_size - mmio_hole_start;

            // Slot 0: GPA [0, hole_start)
            let region0 = kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: mmio_hole_start,
                userspace_addr: guest_memory.as_ptr() as u64,
                flags: KVM_MEM_LOG_DIRTY_PAGES,
            };
            unsafe {
                self.vm_fd
                    .set_user_memory_region(region0)
                    .context("Failed to set KVM memory region (slot 0)")?;
            }

            // Slot 1: GPA [hole_end, ...)
            let region1 = kvm_userspace_memory_region {
                slot: 1,
                guest_phys_addr: mmio_hole_end,
                memory_size: above_hole,
                userspace_addr: (guest_memory.as_ptr() as u64) + mmio_hole_start,
                flags: KVM_MEM_LOG_DIRTY_PAGES,
            };
            unsafe {
                self.vm_fd
                    .set_user_memory_region(region1)
                    .context("Failed to set KVM memory region (slot 1)")?;
            }

            tracing::info!(
                "Split memory: slot0=0..{:#x} ({}MB), slot1={:#x}..+{}MB, total={}MB",
                mmio_hole_start, mmio_hole_start >> 20,
                mmio_hole_end, above_hole >> 20,
                mem_size >> 20,
            );
            self.kvm_slot_size = mmio_hole_start; // for dirty log
        }

        // 3. Create in-kernel irqchip and PIT (required before restore)
        self.vm_fd
            .create_irq_chip()
            .context("Failed to create in-kernel irqchip")?;
        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        self.vm_fd
            .create_pit2(pit_config)
            .context("Failed to create in-kernel PIT")?;
        setup_gsi_routing(&self.vm_fd)?;

        // 3b. Restore VM state: PIT → clock → PICs → IOAPIC
        // (matches Firecracker's restore_state order exactly)

        // Restore PIT state from snapshot
        if !template.device_states.pit.is_empty() {
            let expected = std::mem::size_of::<kvm_bindings::kvm_pit_state2>();
            if template.device_states.pit.len() == expected {
                let pit_state = unsafe {
                    std::ptr::read(template.device_states.pit.as_ptr() as *const kvm_bindings::kvm_pit_state2)
                };
                self.vm_fd.set_pit2(&pit_state)
                    .context("Failed to restore PIT state")?;
                tracing::info!("Restored PIT state from template");
            }
        }

        // Restore kvmclock
        // Skip set_clock — guest uses TSC clocksource, not kvmclock.
        // set_clock can interfere with KVM's internal timekeeping.
        if template.clock_ns > 0 {
            tracing::info!("kvmclock: skipped (guest uses TSC), was {}ns", template.clock_ns);
        }

        // Restore irqchip (PIC master, PIC slave, IOAPIC) from snapshot
        if template.device_states.irqchip.len() == 3 {
            use kvm_bindings::kvm_irqchip;
            let expected_size = std::mem::size_of::<kvm_irqchip>();
            for (i, name) in ["PIC_MASTER", "PIC_SLAVE", "IOAPIC"].iter().enumerate() {
                if template.device_states.irqchip[i].len() == expected_size {
                    let chip = unsafe {
                        std::ptr::read(template.device_states.irqchip[i].as_ptr() as *const kvm_irqchip)
                    };
                    self.vm_fd.set_irqchip(&chip)
                        .context(format!("Failed to restore {name}"))?;
                }
            }
            tracing::info!("Restored irqchip (PICs + IOAPIC) from template");
        }

        // 4. Register virtio devices (balloon + vsock)
        {
            let mut mmio_bus = self.mmio_bus.lock().unwrap();

            // For VMs > 3GB, memory is split around the MMIO hole (3-4GB).
            // The balloon needs the full addressable range so PFNs above the hole are valid.
            let balloon_mem_size = if mem_size > mmio_hole_start {
                mmio_hole_end + (mem_size - mmio_hole_start)
            } else {
                mem_size
            };
            let balloon = VirtioBalloon::new(guest_memory.as_ptr(), balloon_mem_size);
            let balloon_num_pages = Arc::clone(&balloon.config().num_pages);
            self.balloon_num_pages = Some(balloon_num_pages);
            self.mem_size = mem_size;
            self.kvm_slot_size = mem_size;
            let (_base, irq) = mmio_bus.register(Box::new(balloon));
            self.balloon_irq = Some(irq);

            // vsock with a new unique CID
            let mut identity = identity::generate_identity()?;
            // Override IP with the point-to-point /30 address from auto_setup_network
            if let Some(ip) = self.config.guest_ip {
                identity.ip_address = ip;
            }
            let cid = identity.vsock_cid as u64;
            match VirtioVsock::new(cid) {
                Ok(mut vsock) => {
                    let dev_idx = mmio_bus.device_count();
                    let predicted_irq = crate::virtio::IRQ_BASE + dev_idx as u32;
                    self.vsock_host_fd = Some(vsock.take_host_fd());
                    self.vsock_dev_index = Some(dev_idx);
                    self.vsock_irq = Some(predicted_irq);
                    mmio_bus.register(Box::new(vsock));
                }
                Err(e) => { tracing::warn!("Failed to create virtio-vsock: {e}"); }
            }

            // Register virtio-block: use CLI --block, or fall back to template metadata.
            // The block device MUST be registered if the template had one, otherwise
            // device indices are misaligned and transport state restore breaks.
            let block_path = self.config.block_device.clone()
                .or_else(|| template.block_device.clone());
            if let Some(ref block_path) = block_path {
                match crate::virtio::block::VirtioBlock::open(block_path, false) {
                    Ok(block) => {
                        mmio_bus.register(Box::new(block));
                        tracing::info!("Fork: virtio-block registered: {block_path}");
                    }
                    Err(e) => {
                        tracing::warn!("Fork: failed to open block device {block_path}: {e}");
                    }
                }
            }

            // Register virtio-fs BEFORE net (matching clone run order).
            // Template device order: [balloon(0), vsock(1), block(2), fs(3), net(4)]
            if let Some(ref shared_dir_spec) = self.config.shared_dir {
                let (dir_path, tag) = if let Some(colon_pos) = shared_dir_spec.rfind(':') {
                    let path = &shared_dir_spec[..colon_pos];
                    let tag = &shared_dir_spec[colon_pos + 1..];
                    (path.to_string(), tag.to_string())
                } else {
                    (shared_dir_spec.clone(), "fs0".to_string())
                };
                let root_dir = std::path::PathBuf::from(&dir_path);
                if root_dir.is_dir() {
                    let fs_dev = crate::virtio::fs::VirtioFs::new(root_dir, tag.clone());
                    mmio_bus.register(Box::new(fs_dev));
                    tracing::info!("Fork: virtio-fs registered: dir={dir_path}, tag={tag}");
                } else {
                    tracing::warn!("Fork: shared directory does not exist: {dir_path}");
                }
            }

            // Register virtio-net with a fresh TAP.
            if let Some(ref tap_name) = self.config.tap_device {
                let tap_result = if let Some(fd) = self.config.tap_fd {
                    Ok(fd)
                } else {
                    crate::net::create_tap(tap_name)
                };
                match tap_result {
                    Ok(tap_fd) => {
                        let mac = identity.mac_address;
                        let net_dev = crate::virtio::net::VirtioNet::new(tap_fd, mac);
                        let dev_index = mmio_bus.device_count();
                        let (_base, actual_irq) = mmio_bus.register(Box::new(net_dev));
                        unsafe {
                            let flags = libc::fcntl(tap_fd, libc::F_GETFL);
                            libc::fcntl(tap_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                        }
                        let notify_addr = crate::virtio::MMIO_BASE + dev_index as u64 * MMIO_STRIDE + 0x50;
                        let kick_evt = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
                        if kick_evt >= 0 {
                            let mut ioeventfd = kvm_bindings::kvm_ioeventfd {
                                datamatch: 1, len: 4, addr: notify_addr, fd: kick_evt,
                                flags: 1, ..Default::default()
                            };
                            let ret = unsafe {
                                libc::ioctl(self.vm_fd.as_raw_fd(), 0x4040AE79u64 as libc::c_ulong, &ioeventfd)
                            };
                            if ret != 0 {
                                ioeventfd.flags = 0;
                                ioeventfd.datamatch = 0;
                                unsafe { libc::ioctl(self.vm_fd.as_raw_fd(), 0x4040AE79u64 as libc::c_ulong, &ioeventfd); }
                            }
                        }
                        self.net_tap_info = Some((tap_fd, dev_index, actual_irq, kick_evt));
                        tracing::info!("Fork: virtio-net registered (userspace): tap={tap_name}");
                    }
                    Err(e) => {
                        tracing::warn!("Fork: failed to create TAP device {tap_name}: {e}");
                    }
                }
            }

            // (virtio-fs registered above, before net)

            mmio_bus.set_guest_memory_with_hole(guest_memory.as_ptr(), guest_memory.size(), guest_memory.hole_start(), guest_memory.hole_end());

            // Restore transport state from the template snapshot so devices are
            // in the same state the guest kernel expects (queue addresses, activated).
            // The vhost backends read avail_idx from guest memory to set the correct
            // ring base, so they don't reprocess old descriptors.
            if !template.device_states.transports.is_empty() {
                mmio_bus.restore_all_from_json(&template.device_states.transports)?;
            }
            // Notify guest that vsock connections were reset (new CID after fork).
            // Without this, the agent blocks on a read() on the stale connection
            // Send transport reset to close stale connections from the snapshot.
            if let Some(dev_idx) = self.vsock_dev_index {
                if let Some(transport) = mmio_bus.transport_mut(dev_idx) {
                    if let Some(vsock) = transport.device_mut().as_any_mut()
                        .downcast_mut::<VirtioVsock>()
                    {
                        vsock.send_transport_reset();
                    }
                }
            }

            // 6. Inject unique identity into guest memory
            identity::inject_identity_at(&guest_memory, &identity, mem_size)?;
        }

        // (TAP swap removed — net device is registered fresh above with correct TAP)

        // 7. Set balloon target if memory limit is specified.
        // Template has N MB, user gets mem_limit_mb MB. Inflate balloon
        // by the difference so the guest sees reduced available memory.
        if let Some(limit_mb) = mem_limit_mb {
            let template_mb = (mem_size / (1024 * 1024)) as u32;
            if limit_mb < template_mb {
                let reclaim_mb = template_mb - limit_mb;
                let reclaim_pages = reclaim_mb * 256; // 1 MB = 256 x 4KB pages
                // Use update_target() via the MMIO bus so config_interrupt_pending
                // is set and the guest driver gets notified.
                let mut bus = self.mmio_bus.lock().unwrap();
                if let Some(transport) = bus.transport_mut(0) {
                    if let Some(balloon) = transport.device_mut().as_any_mut()
                        .downcast_mut::<VirtioBalloon>()
                    {
                        balloon.update_target(reclaim_pages);
                        tracing::info!(
                            template_mb,
                            limit_mb,
                            reclaim_pages,
                            "balloon: set initial inflate target"
                        );
                    }
                }
            }
        }

        // 7. Create vCPUs from template state.
        // If vcpu_limit is set, only activate that many (rest stay offline).
        let num_vcpus = template.vcpu_states.len();
        let active_vcpus = vcpu_limit
            .map(|v| (v as usize).min(num_vcpus).max(1))
            .unwrap_or(num_vcpus);
        for (id, vcpu_state) in template.vcpu_states.iter().enumerate() {
            if id >= active_vcpus {
                tracing::info!(vcpu_id = id, "skipping vCPU (over limit)");
                break;
            }
            let vcpu = vcpu::Vcpu::from_template(
                &self.kvm,
                &self.vm_fd,
                id as u32,
                vcpu_state,
                Arc::clone(&self.mmio_bus),
                Arc::clone(&self.serial),
            )?;
            // Notify guest this vCPU was paused (prevents soft lockup watchdog)
            let _ = vcpu.fd().kvmclock_ctrl();
            self.vcpus.push(vcpu);
        }

        self.guest_memory = Some(guest_memory);

        // Kick vsock IRQ after vCPU creation to deliver the transport reset.
        // Must come after set_lapic (which overwrites pending interrupts).
        if let (Some(dev_index), Some(irq)) = (self.vsock_dev_index, self.vsock_irq) {
            let bus = self.mmio_bus.lock().unwrap();
            if let Some(transport) = bus.transport(dev_index) {
                transport.vhost_interrupt().fetch_or(1, std::sync::atomic::Ordering::Release);
            }
            drop(bus);
            let _ = self.vm_fd.set_irq_line(irq, true);
            let _ = self.vm_fd.set_irq_line(irq, false);
        }

        tracing::info!(
            "Forked VM from template: {}MB, {} vCPUs",
            mem_size >> 20,
            num_vcpus,
        );

        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        // Install signal handlers for clean shutdown (closes vhost fds on SIGTERM)
        vcpu::install_signal_handlers();
        // Install SIGUSR1 handler for vCPU pause (no-op, just interrupts KVM_RUN)
        vcpu::install_pause_signal_handler();

        // Create shared vCPU pause state
        let num_vcpus = self.vcpus.len() as u32;
        let pause_state = Arc::new(vcpu::VcpuPauseState::new(num_vcpus));

        // Attach pause state to each vCPU
        for vcpu in &mut self.vcpus {
            vcpu.set_pause_state(Arc::clone(&pause_state));
        }

        // Set terminal to raw mode so keystrokes are sent immediately
        let _raw_guard = RawModeGuard::enter();

        // Spawn stdin reader thread — raises IRQ 4 (COM1) when data arrives
        let serial_clone = Arc::clone(&self.serial);
        let vm_fd_clone = Arc::clone(&self.vm_fd);
        std::thread::spawn(move || {
            use std::io::Read;
            let stdin = std::io::stdin();
            let mut handle = stdin.lock();
            let mut buf = [0u8; 1];
            while handle.read_exact(&mut buf).is_ok() {
                let mut serial = serial_clone.lock().unwrap();
                serial.enqueue_input(buf[0]);
                // Raise IRQ 4 if the guest enabled data-available interrupts (IER bit 0)
                if serial.interrupt_enabled() {
                    drop(serial); // release lock before ioctl
                    let _ = vm_fd_clone.set_irq_line(4, true);
                    let _ = vm_fd_clone.set_irq_line(4, false);
                }
            }
        });

        // Spawn vhost-net call eventfd monitoring thread.
        // vhost-net handles RX/TX data path in kernel, but we need to
        // translate call eventfd signals into MMIO interrupt_status +
        // IRQ injection so the guest can properly ack interrupts.
        if let Some((call_fds, dev_index, irq)) = self.net_call_info {
            let mmio_bus_clone = Arc::clone(&self.mmio_bus);
            let vm_fd_clone = Arc::clone(&self.vm_fd);
            std::thread::spawn(move || {
                let mut pollfds = [
                    libc::pollfd {
                        fd: call_fds[0],
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: call_fds[1],
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                loop {
                    let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, -1) };
                    if ret <= 0 {
                        continue;
                    }
                    let mut need_irq = false;
                    for pfd in &mut pollfds {
                        if pfd.revents & libc::POLLIN != 0 {
                            // Read to clear the eventfd
                            let mut val: u64 = 0;
                            unsafe {
                                libc::read(
                                    pfd.fd,
                                    &mut val as *mut u64 as *mut libc::c_void,
                                    8,
                                );
                            }
                            need_irq = true;
                            pfd.revents = 0;
                        }
                    }
                    if need_irq {
                        // Set interrupt status on the transport so the guest
                        // can read it via INTERRUPT_STATUS and ack it
                        {
                            let mut bus = mmio_bus_clone.lock().unwrap();
                            if let Some(transport) = bus.transport_mut(dev_index) {
                                transport.raise_used_ring_interrupt();
                            }
                        }
                        // Inject IRQ (edge-triggered)
                        let _ = vm_fd_clone.set_irq_line(irq, true);
                        let _ = vm_fd_clone.set_irq_line(irq, false);
                    }
                }
            });
        }

        // Set up vsock IRQ signal so the device can interrupt the guest.
        if let (Some(dev_index), Some(irq)) = (self.vsock_dev_index, self.vsock_irq) {
            let mut bus = self.mmio_bus.lock().unwrap();
            if let Some(transport) = bus.transport_mut(dev_index) {
                let interrupt_status = transport.vhost_interrupt();
                let vm_fd = Arc::clone(&self.vm_fd);
                let signal = Arc::new(crate::virtio::vsock::IrqSignal {
                    interrupt_status,
                    signal_fn: Box::new(move || {
                        let _ = vm_fd.set_irq_line(irq, true);
                        let _ = vm_fd.set_irq_line(irq, false);
                    }),
                });
                if let Some(vsock) = transport.device_mut().as_any_mut().downcast_mut::<VirtioVsock>() {
                    vsock.set_irq_signal(signal);
                }
            }
        }

        // Start vsock RX poll thread: monitors the device-side unix socket for
        // data from the agent. When data arrives, triggers RX queue processing
        // so the response is delivered to the guest.
        if let (Some(dev_index), Some(irq)) = (self.vsock_dev_index, self.vsock_irq) {
            let mut bus = self.mmio_bus.lock().unwrap();
            if let Some(transport) = bus.transport_mut(dev_index) {
                if let Some(vsock) = transport.device_mut().as_any_mut().downcast_mut::<VirtioVsock>() {
                    let device_fd = vsock.device_fd();
                    let mmio_bus_clone = Arc::clone(&self.mmio_bus);
                    let vm_fd_clone = Arc::clone(&self.vm_fd);
                    std::thread::Builder::new()
                        .name("vsock-rx-poll".into())
                        .spawn(move || {
                            let mut pfd = libc::pollfd { fd: device_fd, events: libc::POLLIN, revents: 0 };
                            loop {
                                let ret = unsafe { libc::poll(&mut pfd, 1, 500) };
                                if ret <= 0 { continue; }
                                if pfd.revents & libc::POLLIN != 0 {
                                    pfd.revents = 0;
                                    // Trigger RX processing on the vsock device
                                    let mut bus = mmio_bus_clone.lock().unwrap();
                                    if let Some(transport) = bus.transport_mut(dev_index) {
                                        let vhost_int = transport.vhost_interrupt();
                                        let _ = transport.device_mut().process_queue(0); // RX_QUEUE
                                        // Signal guest interrupt
                                        vhost_int.fetch_or(1, std::sync::atomic::Ordering::Release);
                                        drop(bus);
                                        let _ = vm_fd_clone.set_irq_line(irq, true);
                                        let _ = vm_fd_clone.set_irq_line(irq, false);
                                    }
                                }
                            }
                        })
                        .expect("Failed to spawn vsock-rx-poll thread");
                }
            }
        }

        // Spawn net IO thread for userspace net (fork path only).
        // Monitors TAP for incoming packets AND kick eventfd for TX notifications.
        if let Some((tap_fd, dev_index, irq, kick_evt)) = self.net_tap_info {
            let mmio_bus_clone = Arc::clone(&self.mmio_bus);
            let vm_fd_clone = Arc::clone(&self.vm_fd);
            std::thread::Builder::new()
                .name("net-io-poll".into())
                .spawn(move || {
                    let mut pollfds = [
                        libc::pollfd { fd: tap_fd, events: libc::POLLIN, revents: 0 },
                        libc::pollfd { fd: kick_evt, events: libc::POLLIN, revents: 0 },
                    ];
                    let nfds = if kick_evt >= 0 { 2 } else { 1 };
                    loop {
                        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), nfds, 500) };
                        if ret <= 0 { continue; }

                        let tap_readable = pollfds[0].revents & libc::POLLIN != 0;
                        let tx_kicked = nfds > 1 && pollfds[1].revents & libc::POLLIN != 0;
                        pollfds[0].revents = 0;
                        if nfds > 1 { pollfds[1].revents = 0; }

                        // Drain kick eventfd
                        if tx_kicked {
                            let mut val: u64 = 0;
                            unsafe { libc::read(kick_evt, &mut val as *mut u64 as *mut libc::c_void, 8); }
                        }

                        let mut need_irq = false;
                        {
                            let mut bus = mmio_bus_clone.lock().unwrap();
                            if let Some(transport) = bus.transport_mut(dev_index) {
                                // Process TX if guest kicked
                                if tx_kicked {
                                    let _ = transport.device_mut().process_queue(1); // TX_QUEUE
                                    // Also process descriptor chains for TX
                                    transport.process_queue_descriptors_pub(1);
                                }

                                // Process RX from TAP
                                if tap_readable {
                                    if let Some(net) = transport.device_mut().as_any_mut()
                                        .downcast_mut::<crate::virtio::net::VirtioNet>()
                                    {
                                        while net.process_rx_from_tap() {
                                            need_irq = true;
                                        }
                                    }
                                }

                                if need_irq || tx_kicked {
                                    transport.vhost_interrupt()
                                        .fetch_or(1, std::sync::atomic::Ordering::Release);
                                    need_irq = true;
                                }
                            }
                        }
                        if need_irq {
                            let _ = vm_fd_clone.set_irq_line(irq, true);
                            let _ = vm_fd_clone.set_irq_line(irq, false);
                        }
                    }
                })
                .expect("Failed to spawn net-io-poll thread");
        }

        // Start agent listener and balloon tick thread.
        let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let agent_state = if let Some(fd) = self.vsock_host_fd.take() {
            // Userspace vsock: agent communicates via unix socket pair
            agent_listener::start_listener_fd(Arc::clone(&shutdown_flag), fd)
        } else {
            let agent_port = agent_listener::AGENT_VSOCK_PORT_BASE;
            agent_listener::start_listener(Arc::clone(&shutdown_flag), agent_port)
        };

        if let Some(ref balloon_num_pages) = self.balloon_num_pages {
            let balloon_num_pages = Arc::clone(balloon_num_pages);
            let agent_state_clone = Arc::clone(&agent_state);
            let shutdown_clone = Arc::clone(&shutdown_flag);
            let total_pages = self.mem_size / 4096;
            let mem_size = self.mem_size;
            let guest_mem_ptr = self.guest_memory.as_ref()
                .map(|m| m.as_ptr() as usize)
                .unwrap_or(0);
            // Floor: retain at least 50% of guest RAM or 512MB, whichever is larger.
            // Prevents balloon from starving small VMs (e.g. 2GB with Claude Code).
            let mem_mb = (self.mem_size / (1024 * 1024)) as u32;
            let floor_mb = std::cmp::max(512, mem_mb / 2);
            let mmio_bus_clone = Arc::clone(&self.mmio_bus);
            let vm_fd_clone = Arc::clone(&self.vm_fd);
            let balloon_irq = self.balloon_irq.unwrap_or(5);
            std::thread::Builder::new()
                .name("balloon-tick".into())
                .spawn(move || {
                    use crate::memory::balloon::{BalloonAction, BalloonPolicy};
                    let mut policy = BalloonPolicy::new(total_pages, floor_mb);
                    let mut overcommit = crate::memory::overcommit::OvercommitTracker::new(total_pages);

                    while !shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
                        std::thread::sleep(std::time::Duration::from_secs(1));

                        // Only drive balloon policy when agent is connected
                        if !agent_state_clone.connected.load(std::sync::atomic::Ordering::Relaxed) {
                            continue;
                        }

                        let active = agent_state_clone.active.load(std::sync::atomic::Ordering::Relaxed);
                        let mem_available_pct = *agent_state_clone.mem_available_pct.lock().unwrap();
                        let action = policy.report_activity_with_mem(active, mem_available_pct);

                        let mut changed = false;
                        match action {
                            BalloonAction::Inflate(pages) => {
                                let current = balloon_num_pages.load(std::sync::atomic::Ordering::Relaxed);
                                let new_target = current.saturating_add(pages as u32);
                                balloon_num_pages.store(new_target, std::sync::atomic::Ordering::Release);
                                tracing::info!(inflate_pages = pages, new_target, "balloon tick: inflate");
                                changed = true;
                            }
                            BalloonAction::Deflate(pages) => {
                                let current = balloon_num_pages.load(std::sync::atomic::Ordering::Relaxed);
                                let new_target = current.saturating_sub(pages as u32);
                                balloon_num_pages.store(new_target, std::sync::atomic::Ordering::Release);
                                tracing::info!(deflate_pages = pages, new_target, "balloon tick: deflate");
                                changed = true;
                            }
                            BalloonAction::Hold => {}
                        }

                        // Notify guest of config change via interrupt.
                        if changed {
                            if let Ok(mut bus) = mmio_bus_clone.lock() {
                                if let Some(transport) = bus.transport_mut(0) {
                                    transport.raise_config_change_interrupt();
                                }
                            }
                            let _ = vm_fd_clone.set_irq_line(balloon_irq, true);
                            let _ = vm_fd_clone.set_irq_line(balloon_irq, false);
                        }

                        // Periodically refresh overcommit tracking (every 10 ticks = 10s)
                        static TICK_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                        let tick = TICK_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if tick % 10 == 0 && guest_mem_ptr != 0 {
                            overcommit.refresh(guest_mem_ptr as *const u8, mem_size);
                            tracing::debug!(
                                private_pages = overcommit.private_pages(),
                                total_pages = overcommit.total_pages(),
                                overcommit_ratio = %format!("{:.1}x", overcommit.overcommit_ratio()),
                                effective_mb = overcommit.effective_bytes() / (1024 * 1024),
                                "overcommit tracker"
                            );
                        }
                    }
                })
                .expect("Failed to spawn balloon tick thread");
        }

        // Run all vCPUs — BSP on main thread, APs on spawned threads.
        let mut ap_handles = Vec::new();
        let mut vcpu_threads: Vec<libc::pthread_t> = Vec::new();

        // Drain vCPUs: take APs first (index 1+), then BSP (index 0) runs on main thread.
        let mut all_vcpus: Vec<vcpu::Vcpu> = self.vcpus.drain(..).collect();

        // Spawn AP threads (vCPU 1, 2, ...) and capture their pthread_t handles
        for vcpu in all_vcpus.drain(1..) {
            // Use a channel to get the pthread_t from inside the spawned thread
            let (tx, rx) = std::sync::mpsc::channel::<libc::pthread_t>();
            let handle = std::thread::Builder::new()
                .name(format!("vcpu-{}", vcpu.id()))
                .spawn(move || {
                    // Send our pthread_t to the main thread
                    let _ = tx.send(unsafe { libc::pthread_self() });
                    let mut vcpu = vcpu;
                    if let Err(e) = vcpu.run_loop() {
                        tracing::error!("vCPU {} exited with error: {e}", vcpu.id());
                    }
                })
                .context("Failed to spawn AP vCPU thread")?;
            // Receive the pthread_t handle
            if let Ok(tid) = rx.recv() {
                vcpu_threads.push(tid);
            }
            ap_handles.push(handle);
        }

        // BSP (vCPU 0) runs on the main thread — store its pthread_t
        let bsp_tid = unsafe { libc::pthread_self() };
        // Insert BSP at front so vcpu_threads[0] = BSP
        vcpu_threads.insert(0, bsp_tid);

        // Start the per-VM control socket now that we have all pthread_t handles
        let guest_mem_ptr = self.guest_memory.as_ref()
            .map(|m| m.as_ptr())
            .unwrap_or(std::ptr::null_mut());
        let vm_handle = Arc::new(crate::control::sync_server::VmHandle {
            guest_memory: guest_mem_ptr,
            mem_size: self.mem_size,
            kvm_slot_size: self.kvm_slot_size,
            pause_state: Arc::clone(&pause_state),
            vcpu_threads,
            num_vcpus,
            shutdown_flag: Arc::clone(&shutdown_flag),
            mmio_bus: Arc::clone(&self.mmio_bus),
            vm_fd: Some(Arc::clone(&self.vm_fd)),
            agent_state: Some(Arc::clone(&agent_state)),
            block_device: self.config.block_device.clone(),
        });

        match crate::control::sync_server::start_control_socket(Arc::clone(&vm_handle)) {
            Ok(path) => {
                eprintln!("Control socket: {path}");
                tracing::info!(path = %path, "Control socket listening");
            }
            Err(e) => {
                tracing::warn!("Failed to start control socket: {e}");
            }
        }

        // Start console socket for `clone attach`
        {
            let pid = std::process::id();
            let console_path = format!("/tmp/clone-{pid}.console");
            let _ = std::fs::remove_file(&console_path);

            let serial_for_console = Arc::clone(&self.serial);
            let vm_fd_for_console = Arc::clone(&self.vm_fd);
            let console_fd_handle = self.serial.lock().unwrap().console_fd_handle();
            let shutdown_for_console = Arc::clone(&shutdown_flag);

            match std::os::unix::net::UnixListener::bind(&console_path) {
                Ok(listener) => {
                    tracing::info!("Console socket: {console_path}");
                    std::thread::Builder::new()
                        .name("console-socket".into())
                        .spawn(move || {
                            // Set accept timeout
                            unsafe {
                                let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
                                libc::setsockopt(
                                    std::os::unix::io::AsRawFd::as_raw_fd(&listener),
                                    libc::SOL_SOCKET,
                                    libc::SO_RCVTIMEO,
                                    &tv as *const _ as *const libc::c_void,
                                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                                );
                            }

                            while !shutdown_for_console.load(std::sync::atomic::Ordering::Relaxed) {
                                match listener.accept() {
                                    Ok((stream, _)) => {
                                        use std::os::unix::io::AsRawFd;
                                        let client_fd = stream.as_raw_fd();

                                        // Replay recent serial output so a late attach
                                        // sees the boot banner / login prompt that was
                                        // printed before connecting. Then register the
                                        // client_fd for live tee.
                                        let history = {
                                            let serial = serial_for_console.lock().unwrap();
                                            serial.snapshot_history()
                                        };
                                        if !history.is_empty() {
                                            let mut written = 0;
                                            while written < history.len() {
                                                let n = unsafe {
                                                    libc::write(
                                                        client_fd,
                                                        history[written..].as_ptr() as *const libc::c_void,
                                                        history.len() - written,
                                                    )
                                                };
                                                if n <= 0 {
                                                    break;
                                                }
                                                written += n as usize;
                                            }
                                        }
                                        if let Ok(mut guard) = console_fd_handle.lock() {
                                            *guard = Some(client_fd);
                                        }

                                        tracing::info!("Console client attached");

                                        // Read from console socket and inject into serial
                                        let mut buf = [0u8; 256];
                                        loop {
                                            if shutdown_for_console.load(std::sync::atomic::Ordering::Relaxed) {
                                                break;
                                            }
                                            let n = unsafe {
                                                libc::read(
                                                    client_fd,
                                                    buf.as_mut_ptr() as *mut libc::c_void,
                                                    buf.len(),
                                                )
                                            };
                                            if n <= 0 {
                                                break; // client disconnected
                                            }
                                            for i in 0..n as usize {
                                                let mut serial = serial_for_console.lock().unwrap();
                                                serial.enqueue_input(buf[i]);
                                                if serial.interrupt_enabled() {
                                                    drop(serial);
                                                    let _ = vm_fd_for_console.set_irq_line(4, true);
                                                    let _ = vm_fd_for_console.set_irq_line(4, false);
                                                }
                                            }
                                        }

                                        // Unregister console fd
                                        if let Ok(mut guard) = console_fd_handle.lock() {
                                            *guard = None;
                                        }
                                        tracing::info!("Console client detached");
                                        // stream drops here, closing the fd
                                    }
                                    Err(_) => continue, // timeout, retry
                                }
                            }

                            let _ = std::fs::remove_file(&console_path);
                        })
                        .expect("Failed to spawn console socket thread");
                }
                Err(e) => {
                    tracing::warn!("Failed to bind console socket: {e}");
                }
            }
        }

        // Apply security jail/seccomp if configured
        if let Some(ref jail_dir) = self.config.jail {
            crate::control::jailer::apply_jail(jail_dir, &crate::control::jailer::SeccompPolicy::default())?;
        } else if self.config.seccomp {
            crate::control::jailer::apply_seccomp_filter(&crate::control::jailer::SeccompPolicy::default())?;
        }

        // Run BSP (vCPU 0) on the main thread
        if let Some(mut bsp) = all_vcpus.into_iter().next() {
            bsp.run_loop()?;
        }

        // Signal background threads to stop
        shutdown_flag.store(true, std::sync::atomic::Ordering::SeqCst);

        // Wait for AP threads to finish
        for handle in ap_handles {
            let _ = handle.join();
        }

        Ok(())
    }
}

/// Set up explicit GSI routing for all 24 IOAPIC pins + legacy PIC.
///
/// This matches what KVM sets up by default with create_irq_chip(), but
/// being explicit ensures nothing is missed. GSI 0-7 go to both PIC master
/// and IOAPIC, GSI 8-15 to PIC slave and IOAPIC, GSI 16-23 to IOAPIC only.
pub fn setup_gsi_routing(vm_fd: &VmFd) -> Result<()> {
    // Build routing entries: 24 IOAPIC + 8 PIC master + 8 PIC slave = 40 entries
    let mut entries: Vec<kvm_irq_routing_entry> = Vec::with_capacity(40);

    // IOAPIC entries for all 24 pins
    for i in 0u32..24 {
        let mut entry = kvm_irq_routing_entry::default();
        entry.gsi = i;
        entry.type_ = KVM_IRQ_ROUTING_IRQCHIP;
        // SAFETY: union access — we know the type_ is IRQCHIP
        unsafe {
            entry.u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC;
            entry.u.irqchip.pin = i;
        }
        entries.push(entry);
    }

    // PIC master entries for IRQ 0-7
    for i in 0u32..8 {
        let mut entry = kvm_irq_routing_entry::default();
        entry.gsi = i;
        entry.type_ = KVM_IRQ_ROUTING_IRQCHIP;
        unsafe {
            entry.u.irqchip.irqchip = KVM_IRQCHIP_PIC_MASTER;
            entry.u.irqchip.pin = i;
        }
        entries.push(entry);
    }

    // PIC slave entries for IRQ 8-15
    for i in 0u32..8 {
        let mut entry = kvm_irq_routing_entry::default();
        entry.gsi = i + 8;
        entry.type_ = KVM_IRQ_ROUTING_IRQCHIP;
        unsafe {
            entry.u.irqchip.irqchip = KVM_IRQCHIP_PIC_SLAVE;
            entry.u.irqchip.pin = i;
        }
        entries.push(entry);
    }

    // Build the FAM-backed kvm_irq_routing via kvm-bindings' fam-wrappers
    // (kvm-bindings 0.12+ provides KvmIrqRouting; no manual alloc needed).
    let mut irq_routing = kvm_bindings::KvmIrqRouting::new(entries.len())
        .context("Failed to allocate kvm_irq_routing")?;
    irq_routing.as_mut_slice().copy_from_slice(&entries);
    vm_fd
        .set_gsi_routing(&irq_routing)
        .context("Failed to set GSI routing")?;

    tracing::info!("GSI routing configured: 24 IOAPIC + 16 PIC entries");
    Ok(())
}
