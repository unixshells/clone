//! arm64 guest boot: Image loader + hand-built FDT + vCPU register contract.
//!
//! Direct port of the proven `dom0/kvmhost.c` boot path (worked against this
//! exact 5.10 kernel with a boot to real rootfs mounting):
//!   - Image header: magic "ARM\x64" @0x38, text_offset u32 LE @0x04
//!   - kernel Image loaded whole at RAM_BASE + text_offset (default 0x80000)
//!   - BSP enters at the Image load address with x0 = DTB physical address
//!   - FDT v17 builder, no libfdt (token-faithful port of fdt_build())
//!
//! All constants confirmed against this system's uapi headers
//! (/usr/include/linux/kvm.h, /usr/include/aarch64-linux-gnu/asm/kvm.h).

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use vm_memory::GuestAddress;

use crate::memory::GuestMem;
use crate::virtio::{IRQ_BASE, MMIO_BASE, MMIO_STRIDE};

/// Guest RAM base — aarch64 Linux kernel expects RAM well above 0.
pub const RAM_BASE: u64 = 0x4000_0000;
/// Default Image text offset (header overrides).
pub const DEFAULT_TEXT_OFFSET: u64 = 0x8_0000;
/// DTB load address (kvmhost: image ends lower, 64 KiB DTB budget).
pub const DTB_ADDR: u64 = 0x4700_0000;
/// Initrd load address.
pub const INITRD_ADDR: u64 = 0x4800_0000;
/// Cap initrd size like kvmhost (0x10000000 - 0x800000).
pub const INITRD_MAX: u64 = 0x1000_0000 - 0x80_0000;
/// PL011 UART window the DTB advertises. The kernel's earlycon writes land
/// here as KVM_EXIT_MMIO; the vCPU run loop forwards them to host stdout.
pub const PL011_BASE: u64 = 0x0A00_0000;
pub const PL011_SIZE: u64 = 0x1000;
/// vGICv3 placement (kvmhost: dist@0x09000000, redist@0x080b0000).
pub const GIC_DIST_BASE: u64 = 0x0900_0000;
pub const GIC_REDIST_BASE: u64 = 0x080b_0000;

/// DTB physical address — read by Vcpu::new to set x0 for the BSP.
pub static GUEST_DTB_ADDR: AtomicU64 = AtomicU64::new(DTB_ADDR);

// --- KVM uapi constants (arm64) -------------------------------------------

/// KVM_DEV_TYPE_ARM_VGIC_V3 (enum value 7, /usr/include/linux/kvm.h).
pub const KVM_DEV_TYPE_ARM_VGIC_V3: u32 = 7;
/// KVM_DEV_ARM_VGIC_GRP_ADDR.
pub const KVM_DEV_ARM_VGIC_GRP_ADDR: u32 = 0;
/// KVM_DEV_ARM_VGIC_GRP_CTRL.
pub const KVM_DEV_ARM_VGIC_GRP_CTRL: u32 = 4;
/// KVM_DEV_ARM_VGIC_CTRL_INIT.
pub const KVM_DEV_ARM_VGIC_CTRL_INIT: u64 = 0;
/// KVM_VGIC_V3_ADDR_TYPE_DIST.
pub const KVM_VGIC_V3_ADDR_TYPE_DIST: u64 = 2;
/// KVM_VGIC_V3_ADDR_TYPE_REDIST.
pub const KVM_VGIC_V3_ADDR_TYPE_REDIST: u64 = 3;
/// KVM_ARM_TARGET_GENERIC_V8 (/usr/include/aarch64-linux-gnu/asm/kvm.h).
pub const KVM_ARM_TARGET_GENERIC_V8: u32 = 5;
/// KVM_ARM_VCPU_PSCI_0_2 bit index.
pub const KVM_ARM_VCPU_PSCI_0_2: u32 = 2;

/// KVM_CREATE_DEVICE = _IOWR(0xAE, 0xe0, kvm_create_device)
pub const KVM_CREATE_DEVICE: u64 = 0xC010AEE0;
/// KVM_SET_DEVICE_ATTR = _IOW(0xAE, 0xe1, kvm_device_attr)
pub const KVM_SET_DEVICE_ATTR: u64 = 0x4018AEE1;
/// KVM_SET_ONE_REG = _IOW(0xAE, 0xac, kvm_one_reg)
pub const KVM_SET_ONE_REG: u64 = 0x4010AEAC;
/// KVM_ARM_VCPU_INIT = _IOW(0xAE, 0xae, kvm_vcpu_init)  (struct is 132 bytes)
pub const KVM_ARM_VCPU_INIT: u64 = 0x4084AEEE;

/// KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | offset/4
/// KVM_REG_ARM64=0x6000_0000_0000_0000, SIZE_U64=0x0030_0000_0000_0000,
/// ARM_CORE=0x0010<<16.
pub const fn core_reg_id(offset_u32: u64) -> u64 {
    0x6000_0000_0000_0000 | 0x0030_0000_0000_0000 | 0x0010_0000 | offset_u32
}
/// id for regs.pc (offsetof = 31*8 + 8 = 256; CORE_REG divides by 4)
pub const REG_ID_PC: u64 = core_reg_id(256 / 4);
/// id for regs.regs[0] (x0)
pub const REG_ID_X0: u64 = core_reg_id(0);

#[repr(C)]
#[derive(Default)]
pub struct KvmVcpuInit {
    pub target: u32,
    pub features: [u32; 32],
}

#[repr(C)]
#[derive(Default)]
pub struct KvmCreateDevice {
    pub dev_type: u32,
    pub fd: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct KvmDeviceAttr {
    pub flags: u32,
    pub group: u32,
    pub attr: u64,
    pub addr: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct KvmOneReg {
    pub id: u64,
    pub addr: u64,
}

// --- FDT builder (token-faithful port of kvmhost.c fdt_build) --------------

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_HDR: usize = 40;
const FDT_STRUCT_OFF: usize = 56; // after header + 16-byte reservation map

struct FdtBuilder {
    /// struct blob (starts at FDT_STRUCT_OFF in the final DTB)
    st: Vec<u8>,
    strings: Vec<u8>,
}

impl FdtBuilder {
    fn new() -> Self {
        FdtBuilder { st: Vec::new(), strings: Vec::new() }
    }

    fn put32(&mut self, v: u32) {
        self.st.extend_from_slice(&v.to_be_bytes());
    }

    fn name_off(&mut self, name: &str) -> u32 {
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        off
    }

    fn begin_node(&mut self, name: &str) {
        self.put32(1); // FDT_BEGIN_NODE
        let n = name.as_bytes();
        self.st.extend_from_slice(n);
        self.st.push(0);
        while self.st.len() % 4 != 0 {
            self.st.push(0);
        }
    }

    fn end_node(&mut self) {
        self.put32(2); // FDT_END_NODE
    }

    fn end(&mut self) {
        self.put32(9); // FDT_END
    }

    fn prop(&mut self, name: &str, data: &[u8]) {
        self.put32(3); // FDT_PROP
        self.put32(data.len() as u32);
        self.put32(self.name_off(name));
        self.st.extend_from_slice(data);
        while self.st.len() % 4 != 0 {
            self.st.push(0);
        }
    }

    fn prop_str(&mut self, name: &str, s: &str) {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        self.prop(name, &v);
    }

    /// NUL-separated list "a\0b\0"
    fn prop_strlist(&mut self, name: &str, list: &[&str]) {
        let mut v = Vec::new();
        for s in list {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        self.prop(name, &v);
    }

    fn prop_u32(&mut self, name: &str, vals: &[u32]) {
        let mut v = Vec::with_capacity(vals.len() * 4);
        for x in vals {
            v.extend_from_slice(&x.to_be_bytes());
        }
        self.prop(name, &v);
    }

    fn finish(self) -> Vec<u8> {
        let mut dtb = vec![0u8; FDT_STRUCT_OFF];
        let mut strings = self.strings;
        while strings.len() % 4 != 0 {
            strings.push(0);
        }
        let st_padded = {
            let mut s = self.st;
            while s.len() % 4 != 0 {
                s.push(0);
            }
            s
        };
        let strings_off = (FDT_STRUCT_OFF + st_padded.len()) as u32;
        let total = strings_off + strings.len() as u32;

        let mut w = |off: usize, v: u32| dtb[off..off + 4].copy_from_slice(&v.to_be_bytes());
        w(0, FDT_MAGIC);
        w(4, total);
        w(8, FDT_STRUCT_OFF as u32); // off_dt_struct
        w(12, strings_off); // off_dt_strings
        w(16, FDT_HDR as u32); // off_mem_rsvmap
        w(20, 17); // version
        w(24, 16); // last_comp_version
        w(28, 0); // boot_cpuid_phys
        w(32, strings.len() as u32); // size_dt_strings
        w(36, self.st.len() as u32); // size_dt_struct

        dtb.extend_from_slice(&st_padded);
        dtb.extend_from_slice(&strings);
        dtb
    }
}

/// Build the guest DTB. `ram_span` = usable RAM bytes starting at RAM_BASE.
/// `mmio_devices` = (mmio base, SPI number 0-based) for virtio-mmio nodes.
pub fn build_dtb(
    ram_span: u64,
    cmdline: &str,
    num_cpus: u32,
    initrd_size: u64,
    mmio_devices: &[(u64, u32)],
) -> Vec<u8> {
    let mut b = FdtBuilder::new();

    let memreg: [u32; 4] = [0, RAM_BASE as u32, 0, ram_span as u32];
    let gicreg: [u32; 8] = [
        0, GIC_DIST_BASE as u32, 0, 0x10000,
        0, GIC_REDIST_BASE as u32, 0, 0x20000,
    ];
    let uartreg: [u32; 4] = [0, PL011_BASE as u32, 0, PL011_SIZE as u32];

    b.begin_node(""); // root
    b.prop_u32("#address-cells", &[2]);
    b.prop_u32("#size-cells", &[2]);
    b.prop_str("model", "loki thin-dom0 vm");
    b.prop_str("compatible", "loki-dom0-vm");

    b.begin_node("memory@40000000");
    b.prop_str("device_type", "memory");
    b.prop_u32("numa-node-id", &[0]);
    b.prop_u32("reg", &memreg);
    b.end_node();

    // OF NUMA: single explicit node — stops the kernel's fake-node path
    // ever leaving cpu_to_node(0) unassigned (which made
    // node_zonelists(-1) OOB-read in nr_free_zone_pages). See kvmhost.c.
    b.begin_node("distance-map");
    b.prop_str("compatible", "numa-distance-map-v1");
    b.prop_u32("distance-matrix", &[0, 0, 10]);
    b.end_node();

    b.begin_node("chosen");
    let bootargs = format!(
        "console=ttyAMA0 earlycon=pl011,mmio32,{:#x} {} panic=-1",
        PL011_BASE, cmdline
    );
    b.prop_str("bootargs", bootargs.trim());
    b.prop_str("stdout-path", "pl011");
    if initrd_size > 0 {
        b.prop_u32("linux,initrd-start", &[0, INITRD_ADDR as u32]);
        b.prop_u32("linux,initrd-end", &[0, (INITRD_ADDR + initrd_size) as u32]);
    }
    b.end_node();

    b.begin_node("cpus");
    b.prop_u32("#address-cells", &[1]);
    b.prop_u32("#size-cells", &[0]);
    for cpu in 0..num_cpus {
        b.begin_node(&format!("cpu@{cpu}"));
        b.prop_u32("reg", &[cpu]);
        b.prop_u32("numa-node-id", &[0]);
        b.prop_str("device_type", "cpu");
        b.prop_str("compatible", "arm,arm-v8");
        b.prop_str("enable-method", "psci");
        b.end_node();
    }
    b.end_node();

    // arch timer: PPIs 29(13)/30(14)/27(11)/26(10), cpu0, level-low
    b.begin_node("timer");
    b.prop_str("compatible", "arm,armv8-timer");
    b.prop_u32("interrupt-parent", &[1]);
    b.prop_u32(
        "interrupts",
        &[1, 13, 0x108, 1, 14, 0x108, 1, 11, 0x108, 1, 10, 0x108],
    );
    b.end_node();

    b.begin_node("psci");
    b.prop_str("compatible", "arm,psci-0.2");
    b.prop_str("method", "hvc");
    b.end_node();

    b.begin_node("uartclk");
    b.prop_str("compatible", "fixed-clock");
    b.prop_u32("#clock-cells", &[0]);
    b.prop_u32("phandle", &[2]);
    b.prop_u32("clock-frequency", &[24000000]);
    b.end_node();

    b.begin_node("pl011@0A000000");
    b.prop_strlist("compatible", &["arm,pl011", "arm,primecell"]);
    b.prop_u32("reg", &uartreg);
    b.prop_u32("interrupt-parent", &[1]);
    b.prop_u32("interrupts", &[0, 1, 4]);
    b.prop_u32("clocks", &[2, 2]);
    b.prop_strlist("clock-names", &["apb_pclk", "uartclk"]);
    b.prop_str("status", "okay");
    b.end_node();

    b.begin_node("gic@09000000");
    b.prop_str("compatible", "arm,gic-v3");
    b.prop_str("interrupt-controller", "");
    b.prop_u32("phandle", &[1]);
    b.prop_u32("#interrupt-cells", &[1]);
    b.prop_u32("#address-cells", &[1]);
    b.prop_u32("reg", &gicreg);
    b.end_node();

    for &(base, spi) in mmio_devices {
        b.begin_node(&format!("virtio_mmio@{base:08x}"));
        b.prop_str("compatible", "virtio,mmio");
        b.prop_u32("reg", &[0, base as u32, 0, MMIO_STRIDE as u32]);
        b.prop_u32("interrupt-parent", &[1]);
        b.prop_u32("interrupts", &[0, spi, 4]);
        b.prop_str("status", "okay");
        b.end_node();
    }

    b.end_node(); // root
    b.end();
    b.finish()
}

// --- Loader ----------------------------------------------------------------

/// arm64 Image header magic at offset 0x38.
pub fn is_arm64_image(data: &[u8]) -> bool {
    data.len() > 0x3C && &data[0x38..0x3C] == b"ARM\x64"
}

/// Load kernel Image + initrd + DTB into guest memory.
/// Returns the BSP entry address (Image load address).
pub fn load_image_boot(
    mem: &GuestMem,
    kernel_path: &str,
    initrd_path: Option<&str>,
    cmdline: &str,
    num_cpus: u32,
    ram_size: u64,
    mmio_devices: &[(u64, u32)],
) -> Result<GuestAddress> {
    if ram_size <= RAM_BASE {
        bail!(
            "arm64 guest needs RAM above {RAM_BASE:#x}: configured {ram_size:#x} \
             (mem_mb must be ≥ (RAM_BASE+256MB)/1MB = 1536)"
        );
    }
    let ram_span = (ram_size - RAM_BASE).min(0xC000_0000 - RAM_BASE);

    let kernel_data = std::fs::read(kernel_path)
        .with_context(|| format!("Failed to read kernel Image: {kernel_path}"))?;
    if !is_arm64_image(&kernel_data) {
        bail!(
            "not an arm64 kernel Image (missing 'ARM\\x64' magic at 0x38): {kernel_path}"
        );
    }
    let text_offset = if kernel_data.len() >= 8 {
        let t = u32::from_le_bytes(kernel_data[4..8].try_into().unwrap()) as u64;
        if t != 0 {
            t
        } else {
            DEFAULT_TEXT_OFFSET
        }
    } else {
        DEFAULT_TEXT_OFFSET
    };
    let load = RAM_BASE + text_offset;
    if load + kernel_data.len() as u64 >= DTB_ADDR {
        bail!("kernel Image too large for the layout (overlaps DTB slot)");
    }
    mem.write_at(load, &kernel_data)
        .context("Failed to write kernel Image into guest memory")?;

    // Initrd
    let mut initrd_size = 0u64;
    if let Some(path) = initrd_path {
        let initrd = std::fs::read(path)
            .with_context(|| format!("Failed to read initrd: {path}"))?;
        if initrd.len() as u64 > INITRD_MAX {
            bail!("initrd too large: {} > {INITRD_MAX}", initrd.len());
        }
        mem.write_at(INITRD_ADDR, &initrd)
            .context("Failed to write initrd into guest memory")?;
        initrd_size = initrd.len() as u64;
    }

    // DTB
    let dtb = build_dtb(ram_span, cmdline, num_cpus, initrd_size, mmio_devices);
    if dtb.len() > 0x1_0000 {
        bail!("DTB exceeds 64 KiB budget: {} bytes", dtb.len());
    }
    mem.write_at(DTB_ADDR, &dtb)
        .context("Failed to write DTB into guest memory")?;
    GUEST_DTB_ADDR.store(DTB_ADDR, Ordering::Relaxed);

    tracing::info!(
        "arm64 boot: image={:#x}+{:#x} dtb={:#x}({}B) initrd={:#x}({}B) cpus={} mmio_devs={}",
        load,
        kernel_data.len(),
        DTB_ADDR,
        dtb.len(),
        INITRD_ADDR,
        initrd_size,
        num_cpus,
        mmio_devices.len(),
    );

    Ok(GuestAddress(load))
}

/// virtio-mmio device table for the DTB: (base, SPI). Mirrors MmioBus layout:
/// base = MMIO_BASE + i*MMIO_STRIDE, irq = IRQ_BASE + i.
pub fn dtb_device_list(count: usize) -> Vec<(u64, u32)> {
    (0..count)
        .map(|i| (MMIO_BASE + (i as u64) * MMIO_STRIDE, IRQ_BASE + i as u32))
        .collect()
}
