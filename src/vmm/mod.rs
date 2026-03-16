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
    /// (call_fds[0..2], device_index, irq) for the vhost-vsock call eventfd monitoring thread.
    vsock_call_info: Option<([i32; 2], usize, u32)>,
    /// Shared balloon target (num_pages) for the tick thread.
    balloon_num_pages: Option<Arc<std::sync::atomic::AtomicU32>>,
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
            vsock_call_info: None,
            balloon_num_pages: None,
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
        // Allocate 2MB extra beyond what the e820 map reports to the kernel.
        // The kernel probes one past the declared RAM end during
        // init_mem_mapping / struct page setup, so the KVM memory region
        // must extend beyond the e820 boundary.
        let mem_size = (self.config.mem_mb as u64) << 20;
        // Add guard region past e820 end — the kernel accesses multiple pages past
        // max_pfn through the direct mapping during init (likely struct page / zone
        // setup). The VMM injects PDE entries into the kernel page tables to cover
        // these accesses, backed by this extra KVM memory.
        let guard_size: u64 = 128 << 20; // 128MB (one SPARSEMEM section)
        let alloc_size = mem_size + guard_size;
        let guest_memory = memory::create_guest_memory(alloc_size)
            .context("Failed to create guest memory")?;

        // 2. Register memory region with KVM (includes guard pages)
        // KVM_MEM_LOG_DIRTY_PAGES enables dirty page tracking for incremental snapshots.
        let mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: alloc_size,
            userspace_addr: guest_memory.as_ptr() as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe {
            self.vm_fd
                .set_user_memory_region(mem_region)
                .context("Failed to set KVM memory region")?;
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

            // Register virtio-balloon
            let balloon = VirtioBalloon::new(guest_memory.as_ptr(), mem_size);
            let balloon_num_pages = Arc::clone(&balloon.config().num_pages);
            self.balloon_num_pages = Some(balloon_num_pages);
            self.mem_size = mem_size;
            self.kvm_slot_size = alloc_size;
            let (base, irq) = mmio_bus.register(Box::new(balloon));
            virtio_cmdline_params.push(format!(
                "virtio_mmio.device=0x{:x}@0x{:x}:{}",
                MMIO_STRIDE, base, irq
            ));

            // Register virtio-vsock
            match VirtioVsock::new(self.config.cid.unwrap_or(3)) {
                Ok(mut vsock) => {
                    // Pre-compute IRQ and MMIO base so irqfd/ioeventfd can be registered during activation.
                    let dev_idx = mmio_bus.device_count();
                    let predicted_irq = crate::virtio::IRQ_BASE + dev_idx as u32;
                    let predicted_base = crate::virtio::MMIO_BASE + (dev_idx as u64) * MMIO_STRIDE;
                    vsock.set_vm_info(self.vm_fd.as_raw_fd(), predicted_irq, predicted_base);
                    // Capture call_fds for the poll thread (RX=0, TX=1)
                    let vsock_call_fds = [vsock.call_fds()[0], vsock.call_fds()[1]];
                    let vsock_dev_index = dev_idx;
                    let (base, irq) = mmio_bus.register(Box::new(vsock));
                    debug_assert_eq!(irq, predicted_irq);
                    debug_assert_eq!(base, predicted_base);
                    virtio_cmdline_params.push(format!(
                        "virtio_mmio.device=0x{:x}@0x{:x}:{}",
                        MMIO_STRIDE, base, irq
                    ));
                    self.vsock_call_info = Some((vsock_call_fds, vsock_dev_index, predicted_irq));
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
            mmio_bus.set_guest_memory(guest_memory.as_ptr(), mem_size);
        }

        // Build the final kernel command line with virtio_mmio.device parameters
        let mut cmdline = self.config.cmdline.clone();

        // Append agent port to cmdline so the guest agent connects to the right port.
        // This is derived from the CID to ensure unique ports for concurrent VMs.
        let vsock_cid = self.config.cid.unwrap_or(3);
        let agent_port = agent_listener::AGENT_VSOCK_PORT_BASE + (vsock_cid as u32 - 3);
        if !cmdline.contains("clone.agent_port=") {
            cmdline.push_str(&format!(" clone.agent_port={}", agent_port));
        }

        // Append guest networking params if TAP is configured but no net params present.
        // The daemon adds these via its dispatch, but direct `clone run --net` doesn't.
        if self.config.tap_device.is_some() && !cmdline.contains("clone.net_ip=") {
            let vm_index = vsock_cid - 3;
            let guest_ip = format!("172.30.0.{}", 2 + vm_index);
            cmdline.push_str(&format!(
                " clone.net_ip={} clone.net_gw=172.30.0.1 clone.net_mask=24",
                guest_ip
            ));
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
    pub fn fork_boot(&mut self, template_dir: &str, skip_verify: bool) -> Result<()> {
        use crate::boot::template::{TemplateSnapshot, fork_from_template};
        use crate::boot::identity;

        let template = TemplateSnapshot::load(template_dir, !skip_verify)?;

        // 1. Fork guest memory from template (CoW mmap)
        let guest_memory = fork_from_template(&template)
            .context("Failed to fork memory from template")?;

        let mem_size = template.memory_size;

        // 2. Register memory region with KVM
        // KVM_MEM_LOG_DIRTY_PAGES enables dirty page tracking for incremental snapshots.
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

        // 3. Create in-kernel irqchip and PIT (same as cold boot)
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

        // 4. Register virtio devices (balloon + vsock)
        {
            let mut mmio_bus = self.mmio_bus.lock().unwrap();

            let balloon = VirtioBalloon::new(guest_memory.as_ptr(), mem_size);
            let balloon_num_pages = Arc::clone(&balloon.config().num_pages);
            self.balloon_num_pages = Some(balloon_num_pages);
            self.mem_size = mem_size;
            self.kvm_slot_size = mem_size;
            mmio_bus.register(Box::new(balloon));

            // vsock with a new unique CID
            let identity = identity::generate_identity()?;
            let cid = identity.vsock_cid as u64;
            match VirtioVsock::new(cid) {
                Ok(mut vsock) => {
                    let dev_idx = mmio_bus.device_count();
                    let predicted_irq = crate::virtio::IRQ_BASE + dev_idx as u32;
                    let predicted_base = crate::virtio::MMIO_BASE + (dev_idx as u64) * MMIO_STRIDE;
                    vsock.set_vm_info(self.vm_fd.as_raw_fd(), predicted_irq, predicted_base);
                    let vsock_call_fds = [vsock.call_fds()[0], vsock.call_fds()[1]];
                    let vsock_dev_index = dev_idx;
                    mmio_bus.register(Box::new(vsock));
                    self.vsock_call_info = Some((vsock_call_fds, vsock_dev_index, predicted_irq));
                }
                Err(e) => { tracing::warn!("Failed to create virtio-vsock: {e}"); }
            }

            // Register virtio-block if configured
            if let Some(ref block_path) = self.config.block_device {
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

            // Register virtio-fs if configured
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

            // Register virtio-net if configured
            if let Some(ref tap_name) = self.config.tap_device {
                let tap_result = if let Some(fd) = self.config.tap_fd {
                    Ok(fd)
                } else {
                    crate::net::create_tap(tap_name)
                };
                match tap_result {
                    Ok(tap_fd) => {
                        let mac = crate::net::NetworkConfig::mac_from_id(1);
                        let mut net_dev = crate::virtio::net::VirtioNet::new(tap_fd, mac);
                        let irq = crate::virtio::IRQ_BASE + mmio_bus.device_count() as u32;
                        net_dev.set_vm_info(self.vm_fd.as_raw_fd(), irq);
                        let call_fds = net_dev.call_fds();
                        let dev_index = mmio_bus.device_count();
                        let (_base, actual_irq) = mmio_bus.register(Box::new(net_dev));
                        self.net_call_info = Some((call_fds, dev_index, actual_irq));
                        tracing::info!("Fork: virtio-net registered: tap={tap_name}");
                    }
                    Err(e) => {
                        tracing::warn!("Fork: failed to create TAP device {tap_name}: {e}");
                    }
                }
            }

            mmio_bus.set_guest_memory(guest_memory.as_ptr(), mem_size);

            // 5. Inject unique identity into guest memory
            identity::inject_identity(&guest_memory, &identity)?;
        }

        // 6. Create vCPUs from template state
        let num_vcpus = template.vcpu_states.len();
        for (id, vcpu_state) in template.vcpu_states.iter().enumerate() {
            let vcpu = vcpu::Vcpu::from_template(
                &self.kvm,
                &self.vm_fd,
                id as u32,
                vcpu_state,
                Arc::clone(&self.mmio_bus),
                Arc::clone(&self.serial),
            )?;
            self.vcpus.push(vcpu);
        }

        self.guest_memory = Some(guest_memory);

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

        // Spawn vhost-vsock call eventfd monitoring thread.
        // This thread monitors the vsock call_fds (RX and TX), and when data
        // arrives: (1) sets INTERRUPT_STATUS bit 0 via the vhost_interrupt atomic,
        // then (2) injects the IRQ via set_irq_line. This ordering ensures the
        // guest ISR sees the used-buffer notification BEFORE processing the vring.
        //
        // We intentionally do NOT use KVM_IRQFD for vsock because irqfd fires
        // the IRQ in-kernel (instantly) before userspace can set INTERRUPT_STATUS,
        // causing the guest ISR to see status=0 and skip vring processing.
        if let Some((call_fds, dev_index, irq)) = self.vsock_call_info {
            let mmio_bus_clone = Arc::clone(&self.mmio_bus);
            let vm_fd_clone = Arc::clone(&self.vm_fd);
            std::thread::spawn(move || {
                // Get the vhost_interrupt atomic from the transport
                let vhost_int = {
                    let bus = mmio_bus_clone.lock().unwrap();
                    bus.transport(dev_index)
                        .map(|t| t.vhost_interrupt())
                };
                let Some(vhost_int) = vhost_int else { return; };

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
                        // Step 1: Set INTERRUPT_STATUS bit 0 (used-buffer notification)
                        vhost_int.fetch_or(1, std::sync::atomic::Ordering::Release);
                        // Step 2: Inject IRQ (edge-triggered) — guest ISR will now
                        // read INTERRUPT_STATUS and see bit 0 set
                        let _ = vm_fd_clone.set_irq_line(irq, true);
                        let _ = vm_fd_clone.set_irq_line(irq, false);
                    }
                }
            });
        }

        // Start agent listener (vsock) and balloon tick thread.
        // The agent listener receives heartbeats from the guest agent;
        // the tick thread feeds activity state into the balloon policy.
        let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Derive vsock port from CID so concurrent VMs don't conflict.
        // CID 3 → port 9999, CID 4 → port 10000, etc.
        let vsock_cid = self.config.cid.unwrap_or(3);
        let agent_port = agent_listener::AGENT_VSOCK_PORT_BASE + (vsock_cid as u32 - 3);
        let agent_state = agent_listener::start_listener(Arc::clone(&shutdown_flag), agent_port);

        if let Some(ref balloon_num_pages) = self.balloon_num_pages {
            let balloon_num_pages = Arc::clone(balloon_num_pages);
            let agent_state_clone = Arc::clone(&agent_state);
            let shutdown_clone = Arc::clone(&shutdown_flag);
            let total_pages = self.mem_size / 4096;
            let mem_size = self.mem_size;
            let guest_mem_ptr = self.guest_memory.as_ref()
                .map(|m| m.as_ptr() as usize)
                .unwrap_or(0);
            let floor_mb = 64u32; // minimum 64MB retained by guest
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
                        let action = policy.report_activity(active);

                        match action {
                            BalloonAction::Inflate(pages) => {
                                let current = balloon_num_pages.load(std::sync::atomic::Ordering::Relaxed);
                                let new_target = current.saturating_add(pages as u32);
                                balloon_num_pages.store(new_target, std::sync::atomic::Ordering::Release);
                                tracing::info!(inflate_pages = pages, new_target, "balloon tick: inflate");
                            }
                            BalloonAction::Deflate(pages) => {
                                let current = balloon_num_pages.load(std::sync::atomic::Ordering::Relaxed);
                                let new_target = current.saturating_sub(pages as u32);
                                balloon_num_pages.store(new_target, std::sync::atomic::Ordering::Release);
                                tracing::info!(deflate_pages = pages, new_target, "balloon tick: deflate");
                            }
                            BalloonAction::Hold => {}
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

                                        // Register console fd with serial
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

    // Allocate kvm_irq_routing with flexible array member
    let entry_size = std::mem::size_of::<kvm_irq_routing_entry>();
    let header_size = std::mem::size_of::<kvm_irq_routing>();
    let total_size = header_size + entries.len() * entry_size;

    let layout = std::alloc::Layout::from_size_align(total_size, 8)
        .context("Invalid layout for kvm_irq_routing")?;

    // SAFETY: We allocate, zero, fill, pass to ioctl, then dealloc.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout);
        if ptr.is_null() {
            anyhow::bail!("Failed to allocate kvm_irq_routing");
        }

        let routing = &mut *(ptr as *mut kvm_irq_routing);
        routing.nr = entries.len() as u32;
        routing.flags = 0;

        // Copy entries into the flexible array
        let entries_ptr = routing.entries.as_mut_ptr();
        for (i, entry) in entries.iter().enumerate() {
            std::ptr::write(entries_ptr.add(i), *entry);
        }

        let result = vm_fd
            .set_gsi_routing(routing)
            .context("Failed to set GSI routing");

        std::alloc::dealloc(ptr, layout);

        result?;
    }

    tracing::info!("GSI routing configured: 24 IOAPIC + 16 PIC entries");
    Ok(())
}
